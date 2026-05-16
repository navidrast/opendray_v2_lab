package oauth

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"time"
)

// Refresh policy:
//   - Sweep every 30 min.
//   - For each account, refresh if expires_at - now < 1h.
//
// Conservative on both axes: the 30-min cadence + 1h window means a
// token never sees its last hour without being attempted-refreshed,
// even if the previous sweep landed at a worst-case-aligned moment
// just outside the threshold.
//
// Anthropic access tokens are ~8h-lived; refresh tokens last weeks.
// The thresholds above leave plenty of headroom for a network blip
// to take out two consecutive sweeps without an account expiring.
const (
	sweepInterval = 30 * time.Minute
	refreshThresh = 1 * time.Hour
)

// AccountLister is the minimum surface the refresher needs from the
// account registry. Wired to a cliacct-backed adapter in production;
// tests pass a stub. Returning slugs only (not full Account structs)
// keeps the contract tight and avoids importing cliacct into oauth.
type AccountLister interface {
	AccountNames(ctx context.Context) ([]string, error)
}

// Refresher periodically refreshes every account's credentials.
// One goroutine sweeps all accounts (rather than one per account) so
// we can bound concurrency against the token endpoint and so account
// adds/removes don't require goroutine bookkeeping. The cost is that
// a slow refresh on one account delays the sweep of all subsequent
// ones in the same iteration — acceptable given the 30-min cadence.
type Refresher struct {
	log          *slog.Logger
	accountsRoot string
	lister       AccountLister
}

func NewRefresher(log *slog.Logger, accountsRoot string, lister AccountLister) *Refresher {
	if log == nil {
		log = slog.Default()
	}
	return &Refresher{
		log:          log.With("component", "oauth.refresh"),
		accountsRoot: accountsRoot,
		lister:       lister,
	}
}

// Run blocks until ctx is cancelled. Intended to be launched from
// app.App's supervisor goroutine alongside the other long-running
// subsystems (capture engine, journaler, vault sync). On ctx
// cancellation it returns immediately — the in-flight HTTP request
// (if any) is cancelled via the request's context.
func (r *Refresher) Run(ctx context.Context) {
	r.log.Info("refresher running", "interval", sweepInterval, "threshold", refreshThresh)
	// Sweep once at start so a long-stopped gateway catches up
	// immediately rather than waiting the full interval. This is
	// what prevents a "weekend off → Monday morning all-tokens-
	// expired" failure mode.
	r.sweep(ctx)
	t := time.NewTicker(sweepInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			r.sweep(ctx)
		}
	}
}

func (r *Refresher) sweep(ctx context.Context) {
	names, err := r.lister.AccountNames(ctx)
	if err != nil {
		r.log.Warn("list accounts failed", "err", err)
		return
	}
	for _, name := range names {
		if ctx.Err() != nil {
			return
		}
		if err := r.refreshOne(ctx, name); err != nil {
			r.log.Warn("refresh account failed", "name", name, "err", err)
		}
	}
}

// refreshOne is the per-account inner loop. Returns nil for the
// expected no-op states (account exists but has no credentials yet,
// or credentials are still fresh enough), and an error only on
// actual failures the operator should know about.
func (r *Refresher) refreshOne(ctx context.Context, name string) error {
	tok, enrich, err := ReadCredentials(r.accountsRoot, name)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			// Account row exists but no credentials on disk yet —
			// that's a user-action-pending state (operator hasn't
			// completed the OAuth wizard), not an error.
			return nil
		}
		return err
	}
	if time.Duration(tok.ExpiresIn)*time.Second > refreshThresh {
		// Still fresh enough; skip.
		return nil
	}
	if tok.RefreshToken == "" {
		// Manually-imported credential without a refresh token —
		// there's nothing we can do, but surface it once per sweep
		// so the operator can notice and re-enrol with a real
		// OAuth flow.
		r.log.Warn("account has no refresh_token; cannot auto-refresh",
			"name", name, "expires_in_seconds", tok.ExpiresIn)
		return nil
	}
	fresh, err := Refresh(ctx, tok.RefreshToken)
	if err != nil {
		return err
	}
	// Preserve the existing Enrichment across the rotation —
	// subscription tier and rate-limit tier don't change between
	// access-token refreshes, only when the operator changes
	// subscription on Anthropic's side. Re-fetching profile on
	// every refresh would burn API calls for no signal.
	if err := WriteCredentials(r.accountsRoot, name, fresh, enrich); err != nil {
		return err
	}
	r.log.Info("refreshed account credentials",
		"name", name, "new_expires_in_seconds", fresh.ExpiresIn)
	return nil
}
