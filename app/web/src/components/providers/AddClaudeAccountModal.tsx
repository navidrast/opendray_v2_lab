import { useState, useEffect } from 'react'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import { Copy, ExternalLink, Loader2, Check } from 'lucide-react'
import { toast } from 'sonner'
import { useTranslation } from 'react-i18next'

import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import {
  startClaudeOAuth,
  completeClaudeOAuth,
  type ClaudeOAuthStartResponse,
  type ClaudeOAuthCompleteResponse,
} from '@/lib/oauth'

// AddClaudeAccountModal walks the operator through enrolling a new
// Claude OAuth account end-to-end without SSH. Three steps:
//
//   1. name    — operator picks a short slug (becomes the
//                claude-accounts/<name>/ directory) and an optional
//                display name. We start the OAuth flow server-side.
//   2. browser — operator opens the authorize URL in their browser
//                (any device that can reach claude.ai), signs in,
//                clicks Authorize, then pastes the resulting code
//                back into a textarea. We exchange it server-side.
//   3. done    — show success + subscription badge, close after
//                2s, parent panel auto-refreshes via query
//                invalidation.
//
// The "deliberately no Add-account form" rationale in the older
// tutorial assumed pasted bearer tokens (which don't refresh).
// This wizard pastes the OAuth authorization code, which the
// gateway exchanges server-side for a full refresh-able token —
// so the dies-in-an-hour failure mode doesn't apply.

interface Props {
  open: boolean
  onOpenChange: (v: boolean) => void
}

type Step = 'name' | 'browser' | 'done'

export function AddClaudeAccountModal({ open, onOpenChange }: Props) {
  const { t } = useTranslation()
  const qc = useQueryClient()
  const [step, setStep] = useState<Step>('name')
  const [name, setName] = useState('')
  const [code, setCode] = useState('')
  const [flow, setFlow] = useState<ClaudeOAuthStartResponse | null>(null)
  const [result, setResult] = useState<ClaudeOAuthCompleteResponse | null>(null)
  const [copied, setCopied] = useState(false)

  // Reset state whenever the modal reopens — operator may add a
  // second account immediately after the first lands.
  useEffect(() => {
    if (open) {
      setStep('name')
      setName('')
      setCode('')
      setFlow(null)
      setResult(null)
      setCopied(false)
    }
  }, [open])

  const startFlow = useMutation({
    mutationFn: () => startClaudeOAuth(name.trim()),
    onSuccess: (res) => {
      setFlow(res)
      setStep('browser')
    },
    onError: (e: Error) =>
      toast.error(t('web.providers.claudeAccounts.addModal.startFailedToast'), {
        description: e.message,
      }),
  })

  const completeFlow = useMutation({
    mutationFn: () => completeClaudeOAuth(flow!.id, code.trim()),
    onSuccess: (res) => {
      setResult(res)
      setStep('done')
      qc.invalidateQueries({ queryKey: ['claude-accounts'] })
      // Auto-close after a brief moment so the operator sees the
      // confirmation, but doesn't need an extra click.
      setTimeout(() => onOpenChange(false), 2500)
    },
    onError: (e: Error) =>
      toast.error(t('web.providers.claudeAccounts.addModal.completeFailedToast'), {
        description: e.message,
      }),
  })

  const copyURL = async () => {
    if (!flow) return
    try {
      await navigator.clipboard.writeText(flow.authorize_url)
      setCopied(true)
      setTimeout(() => setCopied(false), 1500)
    } catch (e) {
      toast.error((e as Error).message)
    }
  }

  // Slug validation: lowercase letters/digits/hyphens, 1-32 chars.
  // Loose enough to accept "personal", "work-laptop", "labs2";
  // strict enough that the resulting dir name is filesystem-safe.
  const nameValid = /^[a-z0-9-]{1,32}$/.test(name.trim())

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-lg">
        <DialogHeader>
          <DialogTitle>{t('web.providers.claudeAccounts.addModal.title')}</DialogTitle>
          <DialogDescription>
            {step === 'name' && t('web.providers.claudeAccounts.addModal.nameDescription')}
            {step === 'browser' && t('web.providers.claudeAccounts.addModal.browserDescription')}
            {step === 'done' && t('web.providers.claudeAccounts.addModal.doneDescription')}
          </DialogDescription>
        </DialogHeader>

        {step === 'name' && (
          <form
            onSubmit={(e) => {
              e.preventDefault()
              if (nameValid && !startFlow.isPending) startFlow.mutate()
            }}
            className="space-y-3"
          >
            <div className="space-y-1.5">
              <Label htmlFor="account-name">
                {t('web.providers.claudeAccounts.addModal.nameLabel')}
              </Label>
              <Input
                id="account-name"
                value={name}
                onChange={(e) => setName(e.target.value)}
                placeholder={t('web.providers.claudeAccounts.addModal.namePlaceholder')}
                autoFocus
              />
              <p className="text-xs text-muted-foreground">
                {t('web.providers.claudeAccounts.addModal.nameHelp')}
              </p>
            </div>
            <DialogFooter>
              <Button
                type="button"
                variant="ghost"
                onClick={() => onOpenChange(false)}
                disabled={startFlow.isPending}
              >
                {t('web.providers.claudeAccounts.addModal.cancel')}
              </Button>
              <Button type="submit" disabled={!nameValid || startFlow.isPending}>
                {startFlow.isPending && <Loader2 className="mr-2 size-4 animate-spin" />}
                {t('web.providers.claudeAccounts.addModal.continue')}
              </Button>
            </DialogFooter>
          </form>
        )}

        {step === 'browser' && flow && (
          <form
            onSubmit={(e) => {
              e.preventDefault()
              if (code.trim() && !completeFlow.isPending) completeFlow.mutate()
            }}
            className="space-y-4"
          >
            <div className="space-y-2">
              <Label>{t('web.providers.claudeAccounts.addModal.step1Heading')}</Label>
              <div className="flex gap-2">
                <Button
                  type="button"
                  variant="default"
                  size="sm"
                  onClick={() => window.open(flow.authorize_url, '_blank', 'noopener,noreferrer')}
                  className="flex-1"
                >
                  <ExternalLink className="mr-2 size-4" />
                  {t('web.providers.claudeAccounts.addModal.openAuthorize')}
                </Button>
                <Button
                  type="button"
                  variant="outline"
                  size="sm"
                  onClick={copyURL}
                  title={t('web.providers.claudeAccounts.addModal.copyURL')}
                >
                  {copied ? <Check className="size-4" /> : <Copy className="size-4" />}
                </Button>
              </div>
              <p className="text-xs text-muted-foreground">
                {t('web.providers.claudeAccounts.addModal.browserHint')}
              </p>
            </div>

            <div className="space-y-1.5">
              <Label htmlFor="oauth-code">
                {t('web.providers.claudeAccounts.addModal.step2Heading')}
              </Label>
              <Input
                id="oauth-code"
                value={code}
                onChange={(e) => setCode(e.target.value)}
                placeholder={t('web.providers.claudeAccounts.addModal.codePlaceholder')}
                className="font-mono text-xs"
              />
              <p className="text-xs text-muted-foreground">
                {t('web.providers.claudeAccounts.addModal.codeHelp')}
              </p>
            </div>

            <DialogFooter>
              <Button
                type="button"
                variant="ghost"
                onClick={() => onOpenChange(false)}
                disabled={completeFlow.isPending}
              >
                {t('web.providers.claudeAccounts.addModal.cancel')}
              </Button>
              <Button type="submit" disabled={!code.trim() || completeFlow.isPending}>
                {completeFlow.isPending && <Loader2 className="mr-2 size-4 animate-spin" />}
                {t('web.providers.claudeAccounts.addModal.complete')}
              </Button>
            </DialogFooter>
          </form>
        )}

        {step === 'done' && result && (
          <div className="space-y-3 py-4 text-center">
            <div className="inline-flex size-12 items-center justify-center rounded-full bg-emerald-500/15 text-emerald-500">
              <Check className="size-7" />
            </div>
            <div>
              <p className="font-medium">
                {t('web.providers.claudeAccounts.addModal.doneTitle', { name: result.name })}
              </p>
              {result.email && (
                <p className="mt-1 text-sm text-muted-foreground">
                  {result.email}
                  {result.subscription_type && (
                    <span className="ml-2 rounded bg-primary/10 px-1.5 py-0.5 text-xs font-medium uppercase tracking-wide text-primary">
                      {result.subscription_type}
                    </span>
                  )}
                </p>
              )}
            </div>
          </div>
        )}
      </DialogContent>
    </Dialog>
  )
}
