import { api } from './api'

// OAuth flow handles for the multi-account enrolment wizard. The
// backend exposes the start + complete pair under
// /api/v1/oauth/ — see internal/oauth/handler.go for the canonical
// contract. The wizard is fully server-driven: the verifier and
// state stay on the gateway, the client only sees an opaque flow
// id + the authorize URL it needs to open in the user's browser.

export interface ClaudeOAuthStartResponse {
  id: string                  // FlowID — opaque handle to pass to /code
  authorize_url: string       // URL the user opens in their browser
  expires_in_seconds: number  // how long this flow stays valid server-side
}

export interface ClaudeOAuthCompleteResponse {
  name: string                      // claude-accounts slug just enrolled
  expires_in_seconds: number        // access-token lifetime in seconds (~8h)
  email?: string                    // operator email (from /api/oauth/profile)
  subscription_type?: string        // "max" / "pro" / "team" (mapped from organization_type)
  organization_name?: string
}

export async function startClaudeOAuth(
  name: string,
): Promise<ClaudeOAuthStartResponse> {
  return api<ClaudeOAuthStartResponse>('/api/v1/oauth/start', {
    method: 'POST',
    body: { name },
  })
}

export async function completeClaudeOAuth(
  flowId: string,
  code: string,
): Promise<ClaudeOAuthCompleteResponse> {
  return api<ClaudeOAuthCompleteResponse>('/api/v1/oauth/code', {
    method: 'POST',
    body: { flow_id: flowId, code },
  })
}
