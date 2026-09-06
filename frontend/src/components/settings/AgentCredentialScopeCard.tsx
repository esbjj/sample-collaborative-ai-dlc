import { useCallback, useEffect, useLayoutEffect, useRef, useState } from 'react';
import { AlertCircle, KeyRound } from 'lucide-react';
import { Skeleton } from '@/components/ui/skeleton';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import {
  agentsService,
  type AgentCredentialStatus,
  type BedrockPreflightFailure,
  type SpaceAgentCredentialStatus,
} from '@/services/agents';
import { ApiError } from '@/services/api';
import { SettingsCard } from '@/components/settings/SettingsCard';
import { ConfigStatusBadge } from '@/components/settings/ConfigStatusBadge';
import { SecretField } from '@/components/settings/SecretField';
import { RevealableValue } from '@/components/settings/RevealableValue';
import { SaveStatusButton, type SaveResult } from '@/components/settings/SaveStatusButton';

// Credential storage scopes. Intents pin an opaque binding to one of these;
// they do not store a separate secret.
type Scope = 'platform' | 'space' | 'personal';
type SecretName = 'bedrockBearerToken' | 'kiroApiKey';

interface Props {
  scope: Scope;
  projectId?: string;
}

const COPY: Record<Scope, { title: string; description: string }> = {
  platform: {
    title: 'Platform Agent Credentials',
    description: 'Fallback credentials used when no personal or space credential is configured.',
  },
  space: {
    title: 'Space Agent Credentials',
    description: 'Used for members without a personal credential; overrides the platform fallback.',
  },
  personal: {
    title: 'Personal Agent Credentials',
    description: 'Used for your agent runs in every space and overrides space and platform keys.',
  },
};

export function AgentCredentialScopeCard({ scope, projectId }: Props) {
  const identity = `${scope}\0${projectId ?? ''}`;
  const activeIdentityRef = useRef<string | null>(null);
  const isCurrentIdentity = useCallback(() => activeIdentityRef.current === identity, [identity]);
  useLayoutEffect(() => {
    activeIdentityRef.current = identity;
    return () => {
      if (activeIdentityRef.current === identity) activeIdentityRef.current = null;
    };
  }, [identity]);

  const [settings, setSettings] = useState<AgentCredentialStatus | null>(null);
  const [platformFallback, setPlatformFallback] = useState<AgentCredentialStatus | null>(null);
  const [loading, setLoading] = useState(true);
  const [bearerToken, setBearerToken] = useState('');
  const [roleArn, setRoleArn] = useState('');
  const [kiroApiKey, setKiroApiKey] = useState('');
  const [saving, setSaving] = useState(false);
  const [clearingSecret, setClearingSecret] = useState<SecretName | null>(null);
  const [saveResult, setSaveResult] = useState<SaveResult>(null);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [preflight, setPreflight] = useState<BedrockPreflightFailure | null>(null);
  // Held separately from `settings` so it survives a REJECTED save: the operator
  // needs the value precisely when the preflight has just failed, because that is
  // the trust policy they are about to write (dec-external-id-storage).
  const [externalId, setExternalId] = useState<string | null>(null);

  // Role mode is deliberately unavailable at personal scope: that endpoint is gated
  // only on authentication, so any member could otherwise name a role ARN
  // (dec-user-scope-role-deferred).
  const roleSupported = scope !== 'personal';

  const load = useCallback(async () => {
    if (!isCurrentIdentity()) return false;
    const applied = (result: AgentCredentialStatus) => {
      setSettings(result);
      // An idempotent read, not a one-time reveal: recovering the value is a plain
      // read rather than a rotation (dec-external-id-not-secret).
      //
      // A read that omits the field does NOT clear a value already in hand — the
      // field is absent on any read not gated to a principal who may modify the
      // binding, and losing it would strand an operator mid-bootstrap.
      setExternalId((current) => result.bedrockExternalId ?? current);
    };
    if (scope === 'platform') {
      const result = await agentsService.getSettings();
      if (!isCurrentIdentity()) return false;
      applied(result);
      setPlatformFallback(null);
      return true;
    }
    if (scope === 'personal') {
      const result = await agentsService.getPersonalCredentials();
      if (!isCurrentIdentity()) return false;
      applied(result);
      setPlatformFallback(null);
      return true;
    }
    if (!projectId) throw new Error('projectId is required for space credentials');
    const result: SpaceAgentCredentialStatus = await agentsService.getProjectCredentials(projectId);
    if (!isCurrentIdentity()) return false;
    applied(result);
    setPlatformFallback(result.platformFallback);
    return true;
  }, [isCurrentIdentity, projectId, scope]);

  useEffect(() => {
    setLoading(true);
    setSettings(null);
    setPlatformFallback(null);
    setBearerToken('');
    setRoleArn('');
    setKiroApiKey('');
    setSaving(false);
    setClearingSecret(null);
    setSaveResult(null);
    setErrorMessage(null);
    setPreflight(null);
    setExternalId(null);
    load()
      .catch((error) => {
        if (!isCurrentIdentity()) return;
        console.error(`Failed to load ${scope} agent credentials:`, error);
        setErrorMessage(
          error instanceof Error ? error.message : 'Failed to load agent credentials',
        );
      })
      .finally(() => {
        if (isCurrentIdentity()) setLoading(false);
      });
  }, [identity, isCurrentIdentity, load, scope]);

  const update = async (value: { bedrockBearerToken?: string; kiroApiKey?: string }) => {
    if (scope === 'platform') return agentsService.updateSettings(value);
    if (scope === 'personal') return agentsService.updatePersonalCredentials(value);
    if (!projectId) throw new Error('projectId is required for space credentials');
    return agentsService.updateProjectCredentials(projectId, value);
  };

  const trimmedRoleArn = roleArn.trim();
  const hasChanges = bearerToken !== '' || kiroApiKey !== '' || trimmedRoleArn !== '';
  // A scope holds ONE Bedrock binding, so a role ARN and a bearer token in the same
  // save is ambiguous rather than additive.
  const conflictingBedrockInput = trimmedRoleArn !== '' && bearerToken !== '';

  const save = async () => {
    if (conflictingBedrockInput) {
      setErrorMessage(
        'Choose one Bedrock credential: an IAM role ARN or a bearer token, not both.',
      );
      setSaveResult('error');
      return;
    }
    setSaving(true);
    setSaveResult(null);
    setErrorMessage(null);
    setPreflight(null);
    try {
      const value: { bedrockBearerToken?: string; kiroApiKey?: string } = {};
      // The role binding travels in the SAME field as the bearer token: which shape
      // the value holds is a property of the value, so no new field, no new
      // parameter and no new provider (req-single-parameter-encoding). The external
      // ID is never sent — the server generates and attaches its own.
      if (trimmedRoleArn !== '') {
        value.bedrockBearerToken = JSON.stringify({ roleArn: trimmedRoleArn });
      } else if (bearerToken !== '') {
        value.bedrockBearerToken = bearerToken;
      }
      if (kiroApiKey !== '') value.kiroApiKey = kiroApiKey;
      const result = await update(value);
      if (result?.bedrockExternalId) setExternalId(result.bedrockExternalId);
      if (!isCurrentIdentity() || !(await load())) return;
      setBearerToken('');
      setRoleArn('');
      setKiroApiKey('');
      setSaveResult('saved');
    } catch (error) {
      if (!isCurrentIdentity()) return;
      console.error(`Failed to save ${scope} agent credentials:`, error);
      // A rejected preflight is an INPUT error, so it is rendered as guidance the
      // operator can act on rather than as a generic failure. The external ID comes
      // back with the rejection precisely so the trust policy can be fixed.
      if (error instanceof ApiError && error.body?.code === 'BEDROCK_ROLE_PREFLIGHT_FAILED') {
        const body = error.body as {
          preflight?: BedrockPreflightFailure;
          bedrockExternalId?: string | null;
        };
        if (body.preflight) setPreflight(body.preflight);
        if (body.bedrockExternalId) setExternalId(body.bedrockExternalId);
      }
      setErrorMessage(error instanceof Error ? error.message : 'Failed to save agent credentials');
      setSaveResult('error');
    } finally {
      if (isCurrentIdentity()) {
        setSaving(false);
        window.setTimeout(() => {
          if (isCurrentIdentity()) {
            setSaveResult((current) => (current === 'saved' ? null : current));
          }
        }, 4000);
      }
    }
  };

  const clearSecret = async (field: SecretName) => {
    setClearingSecret(field);
    setSaveResult(null);
    setErrorMessage(null);
    try {
      await update({ [field]: '' });
      if (!isCurrentIdentity() || !(await load())) return;
      if (field === 'bedrockBearerToken') setBearerToken('');
      else setKiroApiKey('');
      setSaveResult('saved');
    } catch (error) {
      if (!isCurrentIdentity()) return;
      console.error(`Failed to clear ${scope} agent credential:`, error);
      setErrorMessage(error instanceof Error ? error.message : 'Failed to clear agent credential');
      setSaveResult('error');
    } finally {
      if (isCurrentIdentity()) {
        setClearingSecret(null);
        window.setTimeout(() => {
          if (isCurrentIdentity()) {
            setSaveResult((current) => (current === 'saved' ? null : current));
          }
        }, 4000);
      }
    }
  };

  // req-configured-semantics: configured means a USABLE BINDING exists, not that a
  // secret is set. A scope holding only a role ARN has no secret at all, and
  // counting only secrets would render it as having no credentials.
  const bedrockConfigured = settings?.bedrockMode
    ? settings.bedrockMode !== null
    : Boolean(settings?.bedrockBearerTokenSet);
  const configuredCount = Number(bedrockConfigured) + Number(Boolean(settings?.kiroApiKeySet));
  const bedrockMode = settings?.bedrockMode ?? null;
  const fallbackText = (provider: 'bedrock' | 'kiro') => {
    if (scope !== 'space') return null;
    const available =
      provider === 'bedrock'
        ? Boolean(platformFallback?.bedrockMode ?? platformFallback?.bedrockBearerTokenSet)
        : platformFallback?.kiroApiKeySet;
    return available ? ' A platform fallback is available.' : ' No platform fallback is set.';
  };

  return (
    <SettingsCard
      icon={<KeyRound />}
      title={COPY[scope].title}
      description={COPY[scope].description}
      badge={
        !loading && (
          <ConfigStatusBadge
            ok={configuredCount > 0}
            okLabel={`${configuredCount} provider${configuredCount === 1 ? '' : 's'} configured`}
            notOkLabel="No credentials"
            notOkTone="warning"
          />
        )
      }
    >
      {loading ? (
        <div className="space-y-3">
          <Skeleton className="h-4 w-40" />
          <Skeleton className="h-9 w-full" />
          <Skeleton className="mt-4 h-4 w-40" />
          <Skeleton className="h-9 w-full" />
        </div>
      ) : !settings && errorMessage ? (
        <div
          role="alert"
          className="flex items-start justify-between gap-3 rounded-md border border-destructive/30 bg-destructive/5 px-3 py-2.5"
        >
          <p className="flex items-center gap-2 text-xs text-destructive">
            <AlertCircle className="h-3.5 w-3.5 shrink-0" />
            {errorMessage}
          </p>
          <Button
            type="button"
            variant="outline"
            size="sm"
            onClick={() => {
              setLoading(true);
              setErrorMessage(null);
              load()
                .catch((error) => {
                  if (!isCurrentIdentity()) return;
                  setErrorMessage(
                    error instanceof Error ? error.message : 'Failed to load agent credentials',
                  );
                })
                .finally(() => {
                  if (isCurrentIdentity()) setLoading(false);
                });
            }}
          >
            Retry
          </Button>
        </div>
      ) : (
        <div className="space-y-5">
          {roleSupported && (
            <div className="space-y-1.5" data-testid={`${scope}-bedrock-role`}>
              <div className="flex items-center justify-between gap-2">
                <label
                  htmlFor={`${scope}-bedrock-role-arn`}
                  className="flex items-center gap-2 text-xs font-medium text-foreground"
                >
                  Bedrock IAM Role
                  <span className="rounded-sm bg-primary/10 px-1.5 py-0.5 text-[10px] font-medium text-primary">
                    Recommended
                  </span>
                  <ConfigStatusBadge
                    ok={bedrockMode === 'role'}
                    okLabel="Set"
                    notOkLabel="Not set"
                  />
                </label>
              </div>
              {settings?.bedrockRoleArn && (
                <p className="truncate font-mono text-[11px] text-muted-foreground">
                  {settings.bedrockRoleArn}
                </p>
              )}
              <Input
                id={`${scope}-bedrock-role-arn`}
                value={roleArn}
                onChange={(e) => setRoleArn(e.target.value)}
                disabled={saving || clearingSecret !== null}
                placeholder={
                  bedrockMode === 'role'
                    ? 'Enter a new role ARN to replace it, or leave blank'
                    : 'arn:aws:iam::111122223333:role/aidlc-bedrock-inference'
                }
                className="font-mono text-xs"
              />
              <p className="text-[11px] text-muted-foreground">
                Short-lived credentials are minted per invocation by assuming this role, so no
                secret is stored. Its trust policy must name this deployment&apos;s credential
                broker.
              </p>
              {settings?.bedrockBrokerRoleArn && (
                <RevealableValue
                  id={`${scope}-bedrock-broker-role`}
                  label="Principal to trust"
                  value={settings.bedrockBrokerRoleArn}
                  helpText="The role's trust policy must allow sts:AssumeRole for this principal. Add an sts:RoleSessionName condition to limit which spaces may use the role."
                />
              )}
              {externalId && (
                <RevealableValue
                  id={`${scope}-bedrock-external-id`}
                  label="External ID"
                  value={externalId}
                  helpText="Add this as an sts:ExternalId condition in the role's trust policy. Generated by the platform, required for a role in another AWS account, and safe to read again at any time."
                />
              )}
              {preflight && (
                <div
                  role="alert"
                  className="space-y-1 rounded-md border border-destructive/30 bg-destructive/5 px-3 py-2.5"
                >
                  <p className="text-[11px] font-medium text-destructive">
                    The role could not be assumed ({preflight.cause}). The binding was not saved.
                  </p>
                  {preflight.candidates?.length ? (
                    <ul className="list-inside list-disc space-y-0.5 text-[11px] text-muted-foreground">
                      {preflight.candidates.map((candidate) => (
                        <li key={candidate.candidate}>{candidate.detail}</li>
                      ))}
                    </ul>
                  ) : null}
                </div>
              )}
            </div>
          )}
          <SecretField
            id={`${scope}-bedrock-bearer-token`}
            label={roleSupported ? 'Bedrock Bearer Token (deprecated)' : 'Bedrock Bearer Token'}
            isSet={bedrockMode === 'bearer'}
            value={bearerToken}
            onChange={setBearerToken}
            emptyPlaceholder="Enter AWS_BEARER_TOKEN_BEDROCK value"
            rotatePlaceholder="Enter a new token to rotate, or leave blank"
            onClear={() => clearSecret('bedrockBearerToken')}
            clearing={clearingSecret === 'bedrockBearerToken'}
            disabled={saving || clearingSecret !== null}
            helpText={`Enables Claude Code, OpenCode and Codex.${
              roleSupported
                ? ' Deprecated: a long-lived key stored as a secret, where an IAM role needs none.'
                : ''
            }${fallbackText('bedrock') ?? ''}`}
          />
          <SecretField
            id={`${scope}-kiro-api-key`}
            label="Kiro API Key"
            isSet={Boolean(settings?.kiroApiKeySet)}
            value={kiroApiKey}
            onChange={setKiroApiKey}
            emptyPlaceholder="Enter KIRO_API_KEY value"
            rotatePlaceholder="Enter a new key to rotate, or leave blank"
            onClear={() => clearSecret('kiroApiKey')}
            clearing={clearingSecret === 'kiroApiKey'}
            disabled={saving || clearingSecret !== null}
            helpText={`Enables the Kiro CLI.${fallbackText('kiro') ?? ''}`}
          />
          <SaveStatusButton
            onClick={save}
            disabled={!hasChanges || conflictingBedrockInput || clearingSecret !== null}
            saving={saving}
            label="Save Credentials"
            result={saveResult}
            errorMessage={errorMessage}
          />
        </div>
      )}
    </SettingsCard>
  );
}
