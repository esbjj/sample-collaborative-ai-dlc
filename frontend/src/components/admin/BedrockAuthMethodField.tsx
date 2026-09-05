// Controlled radio group choosing the Bedrock auth path: "API key" or
// "Short-lived role (STS)". Part of unit-admin-auth-path-selection
// (frontend-components); realizes fr-sts-admin-auth-path-choice and drives the
// conditional disclosure of fr-sts-precedence-rule (BR-5).
//
// This is a thin, controlled selector: it holds no state of its own — the host
// (AgentCredentialsCard) owns `authMethod`. It renders the disclosed slot for
// the selected path (the API-key SecretField, or the role info note), which the
// host composes and passes in. Uses a native fieldset/legend + native radios so
// keyboard operability and grouping semantics come for free (accessibility-
// checklist: WCAG 2.1 AA, meaning in text not colour).

import type { ReactNode } from 'react';
import type { BedrockAuthMethod } from '@/services/agents';

interface Props {
  /** Current selection (parent-owned). */
  value: BedrockAuthMethod;
  /** Called with the next enum value when the admin changes the radio. */
  onChange: (next: BedrockAuthMethod) => void;
  /** True while a save/clear is in flight — disables the radios. */
  disabled?: boolean;
  /** Content shown when 'api-key' is selected (the Bedrock SecretField). */
  apiKeySlot: ReactNode;
  /** Content shown when 'role' is selected (the BedrockRoleInfoNote). */
  roleSlot: ReactNode;
}

const OPTIONS: Array<{ value: BedrockAuthMethod; label: string; hint: string }> = [
  {
    value: 'api-key',
    label: 'API key',
    hint: 'Store a long-lived Bedrock bearer token.',
  },
  {
    value: 'role',
    label: 'Short-lived role (STS) — recommended',
    hint: 'Use short-lived execution-role credentials; no stored secret.',
  },
];

export function BedrockAuthMethodField({
  value,
  onChange,
  disabled = false,
  apiKeySlot,
  roleSlot,
}: Props) {
  return (
    <div className="space-y-3" data-testid="bedrock-auth-method-field">
      <fieldset className="space-y-2" disabled={disabled}>
        <legend className="text-xs font-medium text-foreground">Bedrock authentication</legend>
        <div className="space-y-1.5">
          {OPTIONS.map((opt) => {
            const id = `bedrock-auth-method-${opt.value}`;
            return (
              <label
                key={opt.value}
                htmlFor={id}
                className="flex cursor-pointer items-start gap-2 text-xs text-foreground"
              >
                <input
                  type="radio"
                  id={id}
                  name="bedrock-auth-method"
                  value={opt.value}
                  checked={value === opt.value}
                  onChange={() => onChange(opt.value)}
                  disabled={disabled}
                  data-testid={`bedrock-auth-method-radio-${opt.value}`}
                  className="mt-0.5"
                />
                <span className="space-y-0.5">
                  <span className="block font-medium">{opt.label}</span>
                  <span className="block text-[11px] text-muted-foreground">{opt.hint}</span>
                </span>
              </label>
            );
          })}
        </div>
      </fieldset>

      {/* Conditional disclosure (BR-5.1 / BR-5.2): the API-key path shows the
          SecretField; the role path hides it and shows the role info note. */}
      {value === 'api-key' ? apiKeySlot : roleSlot}
    </div>
  );
}
