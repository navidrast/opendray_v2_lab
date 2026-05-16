package oauth

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// credentialsPayload matches the on-disk shape Claude Code itself
// writes to ~/.claude/.credentials.json. The wrapping object key is
// "claudeAiOauth" (lowercase first letter, camelCase rest) and
// expiresAt is unix **milliseconds** (NOT seconds — losing the
// factor of 1000 is the canonical introductory bug).
//
// Writing this exact shape is what lets the Claude Code CLI pick
// the credentials up transparently when spawned with
// CLAUDE_CONFIG_DIR=<accountsRoot>/<name>.
type credentialsPayload struct {
	ClaudeAiOauth oauthInner `json:"claudeAiOauth"`
}

type oauthInner struct {
	AccessToken  string `json:"accessToken"`
	RefreshToken string `json:"refreshToken"`
	ExpiresAt    int64  `json:"expiresAt"` // milliseconds since unix epoch
}

// settingsPayload is dropped at <configDir>/.claude/settings.json
// to pre-accept the "Allow tool use?" prompt that otherwise blocks
// the first session under a fresh CLAUDE_CONFIG_DIR. acceptEdits is
// the least-invasive default that still permits file edits inside
// the session's cwd — operators who want a stricter posture should
// edit this file post-enrollment.
type settingsPayload struct {
	Permissions permissionsBlock `json:"permissions"`
}

type permissionsBlock struct {
	DefaultMode string `json:"defaultMode"`
}

// onboardingPayload is dropped at <configDir>/.claude.json (note: not
// under .claude/) to skip the theme picker + onboarding flow that
// otherwise hangs every first interactive spawn under a new
// CLAUDE_CONFIG_DIR. Without this file, an opendray session that
// inherits CLAUDE_CONFIG_DIR for the first time would just sit there
// waiting for keyboard input nobody will ever send.
type onboardingPayload struct {
	HasCompletedOnboarding bool   `json:"hasCompletedOnboarding"`
	Theme                  string `json:"theme"`
	AutoUpdates            bool   `json:"autoUpdates"`
}

// WriteCredentials persists the OAuth tokens for an account into the
// canonical per-account layout AND drops the two onboarding-bypass
// files alongside. Idempotent: re-writes on every refresh; safe to
// call from the refresh goroutine without coordination.
//
// accountsRoot is the per-install configured root (default
// ~/.claude-accounts), name is the slug. Final layout:
//
//	<root>/<name>/.claude.json                   (onboarding bypass)
//	<root>/<name>/.claude/settings.json          (permissions defaults)
//	<root>/<name>/.claude/.credentials.json      (the tokens)
//
// All three are mode 0600 (or 0644 for the non-secret ones), parent
// dirs 0700. Re-Chmoding pre-existing dirs ensures opendray's mode
// invariants hold even if the operator manually created the tree
// with permissive defaults.
func WriteCredentials(accountsRoot, name string, tok Tokens) error {
	configDir := filepath.Join(accountsRoot, name)
	claudeDir := filepath.Join(configDir, ".claude")
	if err := os.MkdirAll(claudeDir, 0o700); err != nil {
		return fmt.Errorf("oauth: mkdir %s: %w", claudeDir, err)
	}
	if err := os.Chmod(configDir, 0o700); err != nil {
		return fmt.Errorf("oauth: chmod %s: %w", configDir, err)
	}
	if err := os.Chmod(claudeDir, 0o700); err != nil {
		return fmt.Errorf("oauth: chmod %s: %w", claudeDir, err)
	}

	expiresAt := time.Now().Add(time.Duration(tok.ExpiresIn) * time.Second).UnixMilli()
	creds := credentialsPayload{
		ClaudeAiOauth: oauthInner{
			AccessToken:  tok.AccessToken,
			RefreshToken: tok.RefreshToken,
			ExpiresAt:    expiresAt,
		},
	}
	if err := writeJSONAtomic(filepath.Join(claudeDir, ".credentials.json"), creds, 0o600); err != nil {
		return err
	}
	if err := writeJSONAtomic(
		filepath.Join(claudeDir, "settings.json"),
		settingsPayload{Permissions: permissionsBlock{DefaultMode: "acceptEdits"}},
		0o644,
	); err != nil {
		return err
	}
	if err := writeJSONAtomic(
		filepath.Join(configDir, ".claude.json"),
		onboardingPayload{HasCompletedOnboarding: true, Theme: "dark", AutoUpdates: false},
		0o644,
	); err != nil {
		return err
	}
	return nil
}

// ReadCredentials parses an existing per-account credentials.json
// back into Tokens (with ExpiresIn computed relative to now, which
// is what the refresh goroutine needs to decide whether a refresh
// is due). os.ErrNotExist passes through unwrapped so callers can
// `errors.Is(err, os.ErrNotExist)` it without unwrapping noise.
func ReadCredentials(accountsRoot, name string) (Tokens, error) {
	path := filepath.Join(accountsRoot, name, ".claude", ".credentials.json")
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
	}, nil
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
