package oauth

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/go-chi/chi/v5"
)

// AccountUpserter is the callback the handler invokes once credentials
// are persisted to disk, so the cliacct registry materialises a
// matching row. Defined here (not imported from cliacct) to keep
// this package free of a circular import: cliacct can import oauth,
// not the other way around.
type AccountUpserter func(name string) error

// Handlers wires the OAuth flow over HTTP. Caller mounts this under
// the authenticated /api/v1/claude-accounts/oauth/ subtree.
type Handlers struct {
	flows           *Flows
	accountsRoot    string
	log             *slog.Logger
	accountUpserter AccountUpserter
}

func NewHandlers(flows *Flows, accountsRoot string, upserter AccountUpserter, log *slog.Logger) *Handlers {
	if log == nil {
		log = slog.Default()
	}
	return &Handlers{
		flows:           flows,
		accountsRoot:    accountsRoot,
		log:             log.With("component", "oauth.http"),
		accountUpserter: upserter,
	}
}

// Mount attaches the routes under the supplied router. Caller is
// expected to have already wrapped r with the admin-auth middleware.
//
// Endpoint shape (as a wizard-facing contract):
//
//	POST /oauth/start   { "name": "personal" }
//	                    → { "id":"flw_…", "authorize_url":"…", "expires_in_seconds":600 }
//
//	POST /oauth/code    { "flow_id":"flw_…", "code":"AUTHCODE…STATE" }
//	                    → { "name":"personal", "expires_in_seconds":28800 }
func (h *Handlers) Mount(r chi.Router) {
	r.Route("/oauth", func(r chi.Router) {
		r.Post("/start", h.start)
		r.Post("/code", h.complete)
	})
}

type startRequest struct {
	Name string `json:"name"`
}

func (h *Handlers) start(w http.ResponseWriter, r *http.Request) {
	var req startRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, fmt.Errorf("decode body: %w", err))
		return
	}
	res, err := h.flows.Start(req.Name)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, http.StatusOK, res)
}

type completeRequest struct {
	FlowID FlowID `json:"flow_id"`
	Code   string `json:"code"`
}

type completeResponse struct {
	Name      string `json:"name"`
	ExpiresIn int    `json:"expires_in_seconds"`
}

func (h *Handlers) complete(w http.ResponseWriter, r *http.Request) {
	var req completeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, fmt.Errorf("decode body: %w", err))
		return
	}
	verifier, name, state, err := h.flows.Take(req.FlowID)
	if err != nil {
		if errors.Is(err, ErrFlowNotFound) {
			writeErr(w, http.StatusNotFound, err)
			return
		}
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	tok, err := ExchangeCode(r.Context(), req.Code, state, verifier)
	if err != nil {
		// 502 is the right status — the upstream (Anthropic) failed,
		// not the gateway. Surfaces "external service problem" rather
		// than "you sent bad data" to the wizard.
		writeErr(w, http.StatusBadGateway, err)
		return
	}
	if err := WriteCredentials(h.accountsRoot, name, tok); err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	if h.accountUpserter != nil {
		if err := h.accountUpserter(name); err != nil {
			// Credentials are on disk; an upsert failure is
			// recoverable via Import local. Log + continue rather
			// than failing the call.
			h.log.Warn("upsert account row failed", "name", name, "err", err)
		}
	}
	h.log.Info("oauth account enrolled", "name", name, "expires_in_seconds", tok.ExpiresIn)
	writeJSON(w, http.StatusOK, completeResponse{Name: name, ExpiresIn: tok.ExpiresIn})
}

func writeJSON(w http.ResponseWriter, code int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(body)
}

func writeErr(w http.ResponseWriter, code int, err error) {
	writeJSON(w, code, map[string]string{"error": err.Error()})
}
