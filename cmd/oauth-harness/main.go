// Command oauth-harness is a standalone smoke-test entry point for the
// internal/oauth package. It mounts the OAuth Handlers under
// /api/v1/claude-accounts/oauth/ and runs the Refresher in the
// background — but does NOT pull in the rest of opendray (no
// database, no auth gate, no catalog, no app composition). The point
// is to validate the OAuth code path end-to-end against the real
// Anthropic endpoint with the minimum possible surface area, so a
// failure narrows immediately to "the OAuth package itself."
//
// Build:  go build -trimpath -o oauth-harness ./cmd/oauth-harness
// Run:    ACCOUNTS_ROOT=/root/.claude-accounts ./oauth-harness :8088
//
// Endpoints exposed:
//   GET  /healthz
//   POST /api/v1/claude-accounts/oauth/start  {"name":"personal"}
//   POST /api/v1/claude-accounts/oauth/code   {"flow_id":"flw_…","code":"AUTHCODE#STATE"}
//
// Side effects on success: writes credentials.json + onboarding
// bypass files under ACCOUNTS_ROOT/<name>/. The refresh goroutine
// then ticks every 30 min and refreshes any account whose token has
// <1 h remaining.
//
// Do NOT mount this anywhere reachable from the public internet —
// no auth middleware, no rate limiting, no abuse defences.

package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"

	"github.com/opendray/opendray-v2/internal/oauth"
)

func main() {
	addr := ":8088"
	if len(os.Args) > 1 {
		addr = os.Args[1]
	}
	accountsRoot := os.Getenv("ACCOUNTS_ROOT")
	if accountsRoot == "" {
		home, _ := os.UserHomeDir()
		accountsRoot = filepath.Join(home, ".claude-accounts")
	}
	log := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))

	flows := oauth.NewFlows(log)
	upserter := func(name string) error {
		log.Info("would upsert account row", "name", name)
		return nil
	}
	handlers := oauth.NewHandlers(flows, accountsRoot, upserter, log)
	refresher := oauth.NewRefresher(log, accountsRoot, fsLister{root: accountsRoot})

	r := chi.NewRouter()
	r.Use(middleware.RequestID)
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Get("/healthz", func(w http.ResponseWriter, _ *http.Request) { fmt.Fprintln(w, "ok") })
	r.Route("/api/v1/claude-accounts", handlers.Mount)

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()
	go refresher.Run(ctx)

	log.Info("oauth-harness listening", "addr", addr, "accounts_root", accountsRoot)
	srv := &http.Server{Addr: addr, Handler: r, ReadHeaderTimeout: 10 * time.Second}
	errCh := make(chan error, 1)
	go func() { errCh <- srv.ListenAndServe() }()
	select {
	case err := <-errCh:
		if err != nil && err != http.ErrServerClosed {
			log.Error("server died", "err", err)
			os.Exit(1)
		}
	case <-ctx.Done():
		log.Info("shutting down")
		shCtx, shCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer shCancel()
		_ = srv.Shutdown(shCtx)
	}
}

// fsLister implements oauth.AccountLister by scanning accountsRoot
// for direct subdirectories. Each subdirectory whose name doesn't
// start with '.' is treated as one account. This mirrors the
// behaviour cliacct.Service uses internally so the harness's
// refresh-target list matches what the real service would compute.
type fsLister struct{ root string }

func (l fsLister) AccountNames(_ context.Context) ([]string, error) {
	entries, err := os.ReadDir(l.root)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var names []string
	for _, e := range entries {
		if e.IsDir() && len(e.Name()) > 0 && e.Name()[0] != '.' {
			names = append(names, e.Name())
		}
	}
	return names, nil
}
