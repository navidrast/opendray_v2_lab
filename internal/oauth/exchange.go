package oauth

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// httpTimeout is generous enough for slow Anthropic responses but
// short enough that a stuck request doesn't tie up a refresh
// goroutine for minutes. The refresh sweep tolerates a missed
// account; it just retries next interval.
const httpTimeout = 30 * time.Second

// ExchangeCode trades an authorization code for an access/refresh
// pair via the Anthropic token endpoint.
//
// Splits the input on '#' before passing — Anthropic's callback URL
// is shaped like `…/callback?code=AUTHCODE#STATE` and a naive paste
// of the whole code= parameter (or even just the query string)
// commonly includes the fragment marker. The part after '#' is NOT
// part of the code and rejecting it would force the user to manually
// trim, which is a guaranteed support burden.
//
// JSON body is required, NOT form-encoded — see package doc.
func ExchangeCode(ctx context.Context, code, state, verifier string) (Tokens, error) {
	code = strings.TrimSpace(code)
	if i := strings.IndexByte(code, '#'); i >= 0 {
		code = code[:i]
	}
	if code == "" {
		return Tokens{}, errors.New("oauth: code is empty")
	}
	body := map[string]string{
		"grant_type":    "authorization_code",
		"client_id":     AnthropicClientID,
		"code":          code,
		"redirect_uri":  AnthropicRedirectURI,
		"code_verifier": verifier,
		"state":         state,
	}
	return postToken(ctx, body)
}

// Refresh swaps the refresh_token for a fresh access_token (and,
// sometimes, a rotated refresh_token — Anthropic doesn't always
// rotate, but when they do the caller must persist whatever comes
// back, hence returning the full Tokens struct).
func Refresh(ctx context.Context, refreshToken string) (Tokens, error) {
	if strings.TrimSpace(refreshToken) == "" {
		return Tokens{}, errors.New("oauth: refresh_token is empty")
	}
	body := map[string]string{
		"grant_type":    "refresh_token",
		"client_id":     AnthropicClientID,
		"refresh_token": refreshToken,
	}
	return postToken(ctx, body)
}

// postToken is the shared HTTP path used by both grant types. Kept
// private so the exported wrappers can constrain what callers send
// to the token endpoint.
func postToken(ctx context.Context, body map[string]string) (Tokens, error) {
	payload, err := json.Marshal(body)
	if err != nil {
		return Tokens{}, fmt.Errorf("oauth: marshal request: %w", err)
	}
	ctx, cancel := context.WithTimeout(ctx, httpTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, AnthropicTokenURL, bytes.NewReader(payload))
	if err != nil {
		return Tokens{}, fmt.Errorf("oauth: new request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return Tokens{}, fmt.Errorf("oauth: do request: %w", err)
	}
	defer resp.Body.Close()
	// Cap the response read at 64 KiB — Anthropic's token responses
	// are <1 KiB in practice; anything larger is either an error
	// page or a misrouted response and we don't want to consume it
	// in full.
	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		return Tokens{}, fmt.Errorf("oauth: read response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return Tokens{}, fmt.Errorf("oauth: token endpoint %d: %s", resp.StatusCode, truncate(string(respBody), 200))
	}
	var tok Tokens
	if err := json.Unmarshal(respBody, &tok); err != nil {
		return Tokens{}, fmt.Errorf("oauth: parse response: %w", err)
	}
	if tok.AccessToken == "" {
		return Tokens{}, errors.New("oauth: response missing access_token")
	}
	return tok, nil
}

// truncate keeps logged error bodies sane. Used only in error paths
// so the cost of allocating a new string isn't a concern.
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// AnthropicProfileURL is the post-OAuth enrichment endpoint —
// reverse-engineered from the `claude` CLI binary (strings probe +
// curl validation against a live access token, 2026-05-16). Not
// part of the public OAuth2 spec; specific to Anthropic.
//
// Reading this enrichment gives us the fields Claude Code itself
// writes into .credentials.json after a fresh login:
// subscriptionType ("max" / "pro") and rateLimitTier
// ("default_claude_max_20x"). Without it, those fields are absent
// from our credentials.json and the operator UI can't tell which
// tier each account is on until the CLI re-fills them on its own
// first API call.
const AnthropicProfileURL = "https://api.anthropic.com/api/oauth/profile"

// Profile is the parsed shape returned by AnthropicProfileURL.
// Field naming matches the wire (snake_case → Go struct tags).
type Profile struct {
	Account struct {
		UUID         string `json:"uuid"`
		FullName     string `json:"full_name"`
		DisplayName  string `json:"display_name"`
		Email        string `json:"email"`
		HasClaudeMax bool   `json:"has_claude_max"`
		HasClaudePro bool   `json:"has_claude_pro"`
		CreatedAt    string `json:"created_at"`
	} `json:"account"`
	Organization struct {
		UUID                 string `json:"uuid"`
		Name                 string `json:"name"`
		OrganizationType     string `json:"organization_type"`     // e.g. "claude_max"
		BillingType          string `json:"billing_type"`          // e.g. "stripe_subscription"
		RateLimitTier        string `json:"rate_limit_tier"`       // e.g. "default_claude_max_20x"
		SeatTier             string `json:"seat_tier"`
		HasExtraUsageEnabled bool   `json:"has_extra_usage_enabled"`
	} `json:"organization"`
}

// FetchProfile retrieves the operator's profile from the
// post-OAuth enrichment endpoint. Failures are propagated to the
// caller; the OAuth handler treats them as soft errors (credentials
// still get written, just without the cosmetic subscription badge).
func FetchProfile(ctx context.Context, accessToken string) (Profile, error) {
	ctx, cancel := context.WithTimeout(ctx, httpTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, AnthropicProfileURL, nil)
	if err != nil {
		return Profile{}, fmt.Errorf("oauth: new profile request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/json")
	// The "anthropic-beta: oauth-2025-04-20" header is what the
	// official CLI sends; without it, some accounts get
	// inconsistent responses (some endpoints 403 for missing beta).
	req.Header.Set("anthropic-beta", "oauth-2025-04-20")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return Profile{}, fmt.Errorf("oauth: do profile request: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		return Profile{}, fmt.Errorf("oauth: read profile response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return Profile{}, fmt.Errorf("oauth: profile endpoint %d: %s", resp.StatusCode, truncate(string(body), 200))
	}
	var p Profile
	if err := json.Unmarshal(body, &p); err != nil {
		return Profile{}, fmt.Errorf("oauth: parse profile: %w", err)
	}
	return p, nil
}

// SubscriptionTypeFromOrgType maps Anthropic's organization_type
// ("claude_max", "claude_pro", "claude_team", …) to the short
// label Claude Code's credentials.json + UIs expect ("max", "pro",
// "team"). Unknown values pass through with the "claude_" prefix
// stripped so a new tier doesn't render as empty.
func SubscriptionTypeFromOrgType(orgType string) string {
	const prefix = "claude_"
	if strings.HasPrefix(orgType, prefix) {
		return orgType[len(prefix):]
	}
	return orgType
}
