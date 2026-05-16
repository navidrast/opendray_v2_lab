// Package oauth implements the server-driven OAuth PKCE flow for
// Claude / Anthropic accounts. Structured so a Gemini (Google) sibling
// can drop in alongside without rewrites: only the client_id, scopes,
// and token-endpoint URL change.
//
// Relationship to internal/cliacct: cliacct owns account *metadata*
// (the claude_accounts row, the on-disk dir layout, the spawn-time
// env injection). This package owns *credential acquisition* (PKCE +
// code exchange) and *credential keep-alive* (the refresh goroutine).
// The two collaborate via the per-account directory:
//
//	<accountsRoot>/<name>/.claude/.credentials.json   (this package writes)
//	cliacct.Account.ConfigDir → <accountsRoot>/<name> (cliacct reads)
//
// Design lineage: the working PKCE implementation lives in the RCC
// codebase (Remote Claude Code). This is a port to opendray's
// per-account directory layout — credentials.json under
// ~/.claude-accounts/<name>/.claude/ rather than RCC's singleton
// ~/.claude/.credentials.json.
//
// Two gotchas worth flagging in code so the next reader doesn't re-
// discover them:
//
//   - The Anthropic token endpoint at platform.claude.com expects a
//     **JSON** body, not form-encoded. claude.ai/oauth/token is behind
//     Cloudflare and is form-encoded; do not use it.
//   - `claude auth status` reports loggedIn=true even when the access
//     token is expired (it only checks file existence). Always compute
//     expiry locally from the credentials file rather than shelling
//     out to the CLI.

package oauth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"strings"
	"sync"
	"time"
)

// Anthropic OAuth client details. Same values the official `claude`
// CLI uses — reusing the published client_id keeps us inside the
// audience Anthropic expects without needing to register a separate
// client (which Anthropic doesn't generally offer to third parties
// for the Claude-subscription path anyway).
const (
	AnthropicAuthorizeURL = "https://claude.com/cai/oauth/authorize"
	AnthropicTokenURL     = "https://platform.claude.com/v1/oauth/token"
	AnthropicClientID     = "9d1c250a-e61b-44d9-88ed-5944d1962f5e"
	AnthropicRedirectURI  = "https://platform.claude.com/oauth/code/callback"
	AnthropicScopes       = "org:create_api_key user:profile user:inference user:sessions:claude_code user:mcp_servers user:file_upload"
)

// FlowID is an opaque handle returned to the caller of StartFlow.
// The wizard embeds it in the same modal that displays the authorize
// URL; on callback the caller passes it back to Complete so the
// server can look up the stored verifier and target account name.
type FlowID string

// flow is the per-outstanding-OAuth-flow state held server-side. The
// verifier is the secret half of the PKCE pair and must never leave
// process memory.
type flow struct {
	id        FlowID
	state     string // CSRF protection token; echoed back by Anthropic
	verifier  string // PKCE code_verifier
	name      string // claude-accounts/<name> target slug
	createdAt time.Time
}

// StartFlowResult is what callers return to the user's wizard.
// AuthorizeURL is the URL the user opens to sign in; ID is the
// handle to pass back when they paste the callback code.
type StartFlowResult struct {
	ID           FlowID `json:"id"`
	AuthorizeURL string `json:"authorize_url"`
	ExpiresIn    int    `json:"expires_in_seconds"`
}

// Tokens is the runtime shape parsed from the Anthropic token
// endpoint response. Keep field tags lowercase to match the wire.
type Tokens struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int    `json:"expires_in"` // seconds
	TokenType    string `json:"token_type"` // typically "Bearer"
	Scope        string `json:"scope"`
}

// flowTTL bounds how long an outstanding flow can sit in memory
// before the user must restart. 10 min is generous for a manual
// browser+paste workflow on a slow phone but short enough that a
// stale flow can't be exploited by a stolen FlowID hours later.
const flowTTL = 10 * time.Minute

// ErrFlowNotFound is returned by Take when the FlowID is unknown,
// already consumed, or has expired past flowTTL.
var ErrFlowNotFound = errors.New("oauth flow not found or expired")

// Flows is a thread-safe in-memory store of outstanding PKCE flows.
// Memory-only is correct here: a server restart abandons all
// in-progress flows, which is the right failure mode (forces the
// user to retry rather than complete a half-trusted exchange against
// stale state).
type Flows struct {
	mu  sync.Mutex
	log *slog.Logger
	m   map[FlowID]*flow
}

func NewFlows(log *slog.Logger) *Flows {
	if log == nil {
		log = slog.Default()
	}
	return &Flows{
		log: log.With("component", "oauth.flows"),
		m:   make(map[FlowID]*flow),
	}
}

// Start materialises a new flow and returns the URL + handle the
// caller hands back to the user. `name` is the claude-accounts slug
// the new credentials will eventually be written under; it's stored
// on the flow so the completion step doesn't need to be told again.
func (f *Flows) Start(name string) (StartFlowResult, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return StartFlowResult{}, errors.New("account name is required")
	}
	verifier, err := generateVerifier()
	if err != nil {
		return StartFlowResult{}, fmt.Errorf("oauth: generate verifier: %w", err)
	}
	state, err := generateState()
	if err != nil {
		return StartFlowResult{}, fmt.Errorf("oauth: generate state: %w", err)
	}
	id := FlowID("flw_" + state[:12])
	fl := &flow{
		id:        id,
		state:     state,
		verifier:  verifier,
		name:      name,
		createdAt: time.Now(),
	}
	f.mu.Lock()
	f.gcLocked()
	f.m[id] = fl
	f.mu.Unlock()
	return StartFlowResult{
		ID:           id,
		AuthorizeURL: authorizeURL(state, challengeFromVerifier(verifier)),
		ExpiresIn:    int(flowTTL.Seconds()),
	}, nil
}

// Take removes the flow from the store and returns its verifier,
// target account name, and state token. After a successful Take the
// flow cannot be replayed — the caller is expected to perform the
// code exchange immediately.
func (f *Flows) Take(id FlowID) (verifier, name, state string, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.gcLocked()
	fl, ok := f.m[id]
	if !ok {
		return "", "", "", ErrFlowNotFound
	}
	delete(f.m, id)
	return fl.verifier, fl.name, fl.state, nil
}

// gcLocked drops flows older than flowTTL. Caller must hold f.mu.
// Runs opportunistically on every Start/Take rather than on a timer
// so the store stays bounded without a dedicated goroutine.
func (f *Flows) gcLocked() {
	cutoff := time.Now().Add(-flowTTL)
	for id, fl := range f.m {
		if fl.createdAt.Before(cutoff) {
			delete(f.m, id)
		}
	}
}

// generateVerifier produces a 43-byte URL-safe random string that
// satisfies RFC 7636 §4.1 (43-128 chars, [A-Z]/[a-z]/[0-9]/-._~).
// 32 bytes of entropy → 43 chars after base64url-no-pad encoding.
func generateVerifier() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// generateState is the CSRF / replay token. 16 random bytes is
// enough to be unguessable; we store + echo it both ways for
// belt-and-braces verification on callback.
func generateState() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// challengeFromVerifier implements RFC 7636 §4.2 (S256 method):
// challenge = base64url-no-pad(sha256(verifier)).
func challengeFromVerifier(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// authorizeURL assembles the full URL the user opens in their
// browser. Built with net/url so escaping handles every character
// the scope string could ever contain.
func authorizeURL(state, challenge string) string {
	v := url.Values{}
	v.Set("code", "true")
	v.Set("client_id", AnthropicClientID)
	v.Set("response_type", "code")
	v.Set("redirect_uri", AnthropicRedirectURI)
	v.Set("scope", AnthropicScopes)
	v.Set("code_challenge", challenge)
	v.Set("code_challenge_method", "S256")
	v.Set("state", state)
	return AnthropicAuthorizeURL + "?" + v.Encode()
}
