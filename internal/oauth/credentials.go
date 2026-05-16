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
	AccessToken  string   `json:"accessToken"`
	RefreshToken string   `json:"refreshToken"`
	ExpiresAt    int64    `json:"expiresAt"`        // milliseconds since unix epoch
	Scopes       []string `json:"scopes,omitempty"` // parsed from the OAuth response's space-separated scope string
}

// WriteCredentials persists the OAuth tokens for an account into the
// canonical per-account layout. Idempotent: re-writes on every
// refresh; safe to call from the refresh goroutine without
// coordination.
//
// accountsRoot is the per-install configured root (default
// ~/.claude-accounts), name is the slug. Final layout:
//
//	<root>/<name>/.credentials.json   (the tokens, mode 0600)
//
// Parent dir is forced to mode 0700. Re-Chmoding a pre-existing dir
// ensures opendray's mode invariants hold even if the operator
// manually created the tree with permissive defaults.
//
// NOTE: we deliberately do NOT write <root>/<name>/.claude.json
// here, despite older RCC notes suggesting it as an "onboarding
// bypass." Claude Code 2.x writes its own .claude.json on first run
// (~1 KiB of userID / oauthAccount / migration state) and an
// opendray-written stub would silently clobber that state. If the
// onboarding-prompt-on-first-spawn issue resurfaces, the right fix
// is a merge — read existing .claude.json, set
// hasCompletedOnboarding=true, write back — not a wholesale
// overwrite.
//
// Same reasoning for <root>/<name>/.claude/settings.json: the path
// is no longer canonical in 2.x; Claude Code reads its permissions
// model from elsewhere. We'll add settings management when the user
// actually requests a non-default permissions posture, via a
// separate, properly-scoped writer.
func WriteCredentials(accountsRoot, name string, tok Tokens) error {
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
			AccessToken:  tok.AccessToken,
			RefreshToken: tok.RefreshToken,
			ExpiresAt:    expiresAt,
			Scopes:       splitScopes(tok.Scope),
		},
	}
	return writeJSONAtomic(filepath.Join(configDir, ".credentials.json"), creds, 0o600)
}

// ReadCredentials parses an existing per-account credentials.json
// back into Tokens (with ExpiresIn computed relative to now, which
// is what the refresh goroutine needs to decide whether a refresh
// is due). os.ErrNotExist passes through unwrapped so callers can
// `errors.Is(err, os.ErrNotExist)` it without unwrapping noise.
//
// Path matches the Claude Code 2.x layout written above:
// <accountsRoot>/<name>/.credentials.json (NOT under .claude/).
func ReadCredentials(accountsRoot, name string) (Tokens, error) {
	path := filepath.Join(accountsRoot, name, ".credentials.json")
	b, err := os.ReadFile(path)
	if err != nil {
		return Tokens{}, err
	}
	var p credentialsPayload
	if err := json.Unmarshal(b, &p); err != nil {
		return Tokens{}, fmt.Errorf("oauth: parse %s: %w", path, err)
	}
	remaining := time.UnixMilli(p.ClaudeAiOauth.ExpiresAt).Sub(time.Now())
	return Tokens{
		AccessToken:  p.ClaudeAiOauth.AccessToken,
		RefreshToken: p.ClaudeAiOauth.RefreshToken,
		ExpiresIn:    int(remaining.Seconds()),
		Scope:        strings.Join(p.ClaudeAiOauth.Scopes, " "),
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
// temp-then-rename pattern. A crash mid-write leaves the previous
// file intact rather than producing a half-written file the next
// read would choke on. Mirrors the pattern in internal/auth/keyfile.go
// (WriteKeyFile) so reviewers don't have to context-switch.
func writeJSONAtomic(path string, v any, mode os.FileMode) error {
	body, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return fmt.Errorf("oauth: marshal %s: %w", path, err)
	}
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
