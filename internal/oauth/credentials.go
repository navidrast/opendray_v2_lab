package oauth

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// credentialsPayload matches the on-disk shape Claude Code 2.x
// writes to <CLAUDE_CONFIG_DIR>/.credentials.json. The wrapping
// object key is "claudeAiOauth" (lowercase first letter, camelCase
// rest) and expiresAt is unix **milliseconds** (NOT seconds —
// losing the factor of 1000 is the canonical introductory bug).
//
// Writing this exact shape is what lets the Claude Code CLI pick
// the credentials up transparently when spawned with
// CLAUDE_CONFIG_DIR=<accountsRoot>/<name>.
//
// Layout history (worth knowing because RCC's notes describe the
// older form):
//   - Claude Code 1.x  → <CONFIG>/.claude/.credentials.json
//   - Claude Code 2.x  → <CONFIG>/.credentials.json   (current; verified
//     against the CLI's own writes in 2.1.143)
// We target the 2.x layout; if a user is on 1.x they need to upgrade.
type credentialsPayload struct {
	ClaudeAiOauth oauthInner `json:"claudeAiOauth"`
}

type oauthInner struct {
	AccessToken      string   `json:"accessToken"`
	RefreshToken     string   `json:"refreshToken"`
	ExpiresAt        int64    `json:"expiresAt"`                  // milliseconds since unix epoch
	Scopes           []string `json:"scopes,omitempty"`           // parsed from the OAuth response's space-separated scope string
	SubscriptionType string   `json:"subscriptionType,omitempty"` // e.g. "max", "pro" — derived from /api/oauth/profile
	RateLimitTier    string   `json:"rateLimitTier,omitempty"`    // e.g. "default_claude_max_20x" — from /api/oauth/profile
}

// WriteCredentials persists the OAuth tokens for an account into the
// canonical per-account layout. Idempotent: re-writes on every
// refresh; safe to call from the refresh goroutine without
// coordination.
//
// accountsRoot is the per-install configured root (default
// ~/.claude-accounts), name is the slug. Final layout:
//
//	<root>/<name>/.credentials.json   (Claude Code 2.x layout, mode 0600)
//	<root>/tokens/<name>.token        (legacy claude-acc bare-token file, mode 0600)
//
// Two files because we straddle two consumers:
//
//   - Claude Code 2.x itself reads <CLAUDE_CONFIG_DIR>/.credentials.json
//     when opendray spawns a session with CLAUDE_CONFIG_DIR pointing
//     at this account's dir. The file carries access + refresh tokens,
//     expiry, scopes, subscription tier — everything needed for the
//     CLI to operate and self-refresh.
//   - opendray's session provider (internal/cliacct) was built for the
//     v1.x claude-acc host tool's convention: a bare-string token file
//     at <root>/tokens/<name>.token, injected as CLAUDE_CODE_OAUTH_TOKEN
//     at spawn time. Without this file, sessions bound to this account
//     spawn with the right CLAUDE_CONFIG_DIR but no env-var token, and
//     Claude Code falls through to its own auth prompt inside the PTY
//     (because the env var, when absent, is treated as a hard signal
//     to ignore disk creds in some Claude Code 2.x paths).
//
// Writing both keeps the new wizard compatible with the existing
// spawn provider. Phase 2 (long-term): update opendray's session
// provider to prefer .credentials.json + drop the bare-token
// expectation, at which point this dual write can collapse.
//
// Parent dirs are forced to mode 0700. Re-Chmoding a pre-existing
// dir ensures opendray's mode invariants hold even if the operator
// manually created the tree with permissive defaults.
//
// NOTE: we deliberately do NOT write <root>/<name>/.claude.json
// here, despite older RCC notes suggesting it as an "onboarding
// bypass." Claude Code 2.x writes its own .claude.json on first run
// (~1 KiB of userID / oauthAccount / migration state) and an
// opendray-written stub would silently clobber that state.
func WriteCredentials(accountsRoot, name string, tok Tokens, enrich Enrichment) error {
	configDir := filepath.Join(accountsRoot, name)
	if err := os.MkdirAll(configDir, 0o700); err != nil {
		return fmt.Errorf("oauth: mkdir %s: %w", configDir, err)
	}
	if err := os.Chmod(configDir, 0o700); err != nil {
		return fmt.Errorf("oauth: chmod %s: %w", configDir, err)
	}

	expiresAt := time.Now().Add(time.Duration(tok.ExpiresIn) * time.Second).UnixMilli()
	creds := credentialsPayload{
		ClaudeAiOauth: oauthInner{
			AccessToken:      tok.AccessToken,
			RefreshToken:     tok.RefreshToken,
			ExpiresAt:        expiresAt,
			Scopes:           splitScopes(tok.Scope),
			SubscriptionType: enrich.SubscriptionType,
			RateLimitTier:    enrich.RateLimitTier,
		},
	}
	if err := writeJSONAtomic(filepath.Join(configDir, ".credentials.json"), creds, 0o600); err != nil {
		return err
	}

	// Legacy bare-token file for opendray's cliacct session provider.
	// See function doc for rationale. The order matters: credentials.json
	// first so a partial write leaves the disk in a state where
	// Claude Code 2.x can still run (the .token file is opendray's
	// session-provider concern, not Claude Code's).
	tokensDir := filepath.Join(accountsRoot, "tokens")
	if err := os.MkdirAll(tokensDir, 0o700); err != nil {
		return fmt.Errorf("oauth: mkdir %s: %w", tokensDir, err)
	}
	if err := os.Chmod(tokensDir, 0o700); err != nil {
		return fmt.Errorf("oauth: chmod %s: %w", tokensDir, err)
	}
	tokenPath := filepath.Join(tokensDir, name+".token")
	if err := writeBytesAtomic(tokenPath, []byte(tok.AccessToken), 0o600); err != nil {
		return err
	}
	return nil
}

// EnrichmentFromProfile is the canonical mapping from a fetched
// Anthropic /api/oauth/profile response to the on-disk Enrichment
// shape. Centralised so handler + refresher + tests all agree on
// the same projection.
func EnrichmentFromProfile(p Profile) Enrichment {
	return Enrichment{
		SubscriptionType: SubscriptionTypeFromOrgType(p.Organization.OrganizationType),
		RateLimitTier:    p.Organization.RateLimitTier,
	}
}

// Enrichment carries the cosmetic-but-useful per-account profile
// fields that come from /api/oauth/profile (subscription tier, rate
// limit tier). These are persisted on disk so the UI doesn't lose
// the "Max" / "Pro" badge across server restarts or token refreshes.
// Empty Enrichment is valid — it just means we haven't enriched
// (or the enrichment call failed at enrollment time).
type Enrichment struct {
	SubscriptionType string
	RateLimitTier    string
}

// ReadCredentials parses an existing per-account credentials.json
// back into Tokens + Enrichment. The refresh goroutine uses this to
// (a) decide whether to refresh and (b) preserve enrichment across
// the write that follows.
//
// os.ErrNotExist passes through unwrapped so callers can
// `errors.Is(err, os.ErrNotExist)` it without unwrapping noise.
//
// Path matches the Claude Code 2.x layout written above:
// <accountsRoot>/<name>/.credentials.json (NOT under .claude/).
func ReadCredentials(accountsRoot, name string) (Tokens, Enrichment, error) {
	path := filepath.Join(accountsRoot, name, ".credentials.json")
	b, err := os.ReadFile(path)
	if err != nil {
		return Tokens{}, Enrichment{}, err
	}
	var p credentialsPayload
	if err := json.Unmarshal(b, &p); err != nil {
		return Tokens{}, Enrichment{}, fmt.Errorf("oauth: parse %s: %w", path, err)
	}
	remaining := time.UnixMilli(p.ClaudeAiOauth.ExpiresAt).Sub(time.Now())
	return Tokens{
			AccessToken:  p.ClaudeAiOauth.AccessToken,
			RefreshToken: p.ClaudeAiOauth.RefreshToken,
			ExpiresIn:    int(remaining.Seconds()),
			Scope:        strings.Join(p.ClaudeAiOauth.Scopes, " "),
		}, Enrichment{
			SubscriptionType: p.ClaudeAiOauth.SubscriptionType,
			RateLimitTier:    p.ClaudeAiOauth.RateLimitTier,
		}, nil
}

// splitScopes converts an OAuth-spec space-separated scope string
// into the array shape Claude Code's .credentials.json expects.
// Empty input yields nil so the omitempty JSON tag drops the field
// rather than emitting an empty array.
func splitScopes(s string) []string {
	if s == "" {
		return nil
	}
	return strings.Fields(s)
}

// writeJSONAtomic marshals v as indented JSON and writes via the
// temp-then-rename pattern. Wraps writeBytesAtomic.
func writeJSONAtomic(path string, v any, mode os.FileMode) error {
	body, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return fmt.Errorf("oauth: marshal %s: %w", path, err)
	}
	return writeBytesAtomic(path, body, mode)
}

// writeBytesAtomic writes body to path via temp-then-rename. A
// crash mid-write leaves the previous file intact rather than
// producing a half-written file the next read would choke on.
// Mirrors the pattern in internal/auth/keyfile.go (WriteKeyFile)
// so reviewers don't have to context-switch.
func writeBytesAtomic(path string, body []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, filepath.Base(path)+".tmp-*")
	if err != nil {
		return fmt.Errorf("oauth: create temp %s: %w", path, err)
	}
	tmpPath := tmp.Name()
	defer func() { _ = os.Remove(tmpPath) }() // no-op if the rename succeeded

	if err := tmp.Chmod(mode); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("oauth: chmod %s: %w", tmpPath, err)
	}
	if _, err := tmp.Write(body); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("oauth: write %s: %w", tmpPath, err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("oauth: fsync %s: %w", tmpPath, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("oauth: close %s: %w", tmpPath, err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("oauth: rename %s: %w", path, err)
	}
	return nil
}
