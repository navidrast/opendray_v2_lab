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
