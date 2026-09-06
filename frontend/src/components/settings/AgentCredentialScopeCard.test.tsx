import { beforeEach, describe, expect, it, vi } from 'vitest';
import { act, render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';

const getPersonalCredentials = vi.fn();
const updatePersonalCredentials = vi.fn();
const getProjectCredentials = vi.fn();
const updateProjectCredentials = vi.fn();

vi.mock('@/services/agents', () => ({
  agentsService: {
    getPersonalCredentials: (...args: unknown[]) => getPersonalCredentials(...args),
    updatePersonalCredentials: (...args: unknown[]) => updatePersonalCredentials(...args),
    getProjectCredentials: (...args: unknown[]) => getProjectCredentials(...args),
    updateProjectCredentials: (...args: unknown[]) => updateProjectCredentials(...args),
  },
}));

import { AgentCredentialScopeCard } from './AgentCredentialScopeCard';

const SPACE_A_STATUS = {
  bedrockBearerTokenSet: true,
  kiroApiKeySet: false,
  platformFallback: {
    bedrockBearerTokenSet: true,
    kiroApiKeySet: false,
  },
};

const SPACE_B_STATUS = {
  bedrockBearerTokenSet: false,
  kiroApiKeySet: true,
  platformFallback: {
    bedrockBearerTokenSet: false,
    kiroApiKeySet: true,
  },
};

const deferred = <T,>() => {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((done) => {
    resolve = done;
  });
  return { promise, resolve };
};

beforeEach(() => {
  vi.clearAllMocks();
  getPersonalCredentials.mockResolvedValue({
    bedrockBearerTokenSet: false,
    kiroApiKeySet: false,
  });
  updatePersonalCredentials.mockResolvedValue({ saved: true });
  getProjectCredentials.mockResolvedValue({
    bedrockBearerTokenSet: false,
    kiroApiKeySet: false,
    platformFallback: {
      bedrockBearerTokenSet: true,
      kiroApiKeySet: false,
    },
  });
  updateProjectCredentials.mockResolvedValue({ saved: true });
});

describe('AgentCredentialScopeCard', () => {
  it('writes a personal credential without reading a secret value back', async () => {
    const user = userEvent.setup();
    render(<AgentCredentialScopeCard scope="personal" />);

    const token = await screen.findByLabelText(/Bedrock Bearer Token/);
    expect(token).toHaveValue('');
    await user.type(token, 'personal-token');
    await user.click(screen.getByRole('button', { name: 'Save Credentials' }));

    await waitFor(() =>
      expect(updatePersonalCredentials).toHaveBeenCalledWith({
        bedrockBearerToken: 'personal-token',
      }),
    );
    expect(getPersonalCredentials).toHaveBeenCalledTimes(2);
  });

  it('shows platform inheritance and writes credentials to the requested space', async () => {
    const user = userEvent.setup();
    render(<AgentCredentialScopeCard scope="space" projectId="space-1" />);

    expect(await screen.findByText(/A platform fallback is available/)).toBeInTheDocument();
    expect(screen.getByText(/No platform fallback is set/)).toBeInTheDocument();

    await user.type(screen.getByLabelText(/Kiro API Key/), 'space-key');
    await user.click(screen.getByRole('button', { name: 'Save Credentials' }));

    await waitFor(() =>
      expect(updateProjectCredentials).toHaveBeenCalledWith('space-1', {
        kiroApiKey: 'space-key',
      }),
    );
  });

  it('clears write-only drafts when the space changes', async () => {
    getProjectCredentials.mockImplementation((projectId) =>
      Promise.resolve(projectId === 'space-a' ? SPACE_A_STATUS : SPACE_B_STATUS),
    );
    const user = userEvent.setup();
    const { rerender } = render(<AgentCredentialScopeCard scope="space" projectId="space-a" />);

    const spaceAKey = await screen.findByLabelText(/Kiro API Key/);
    await user.type(spaceAKey, 'space-a-key');
    expect(spaceAKey).toHaveValue('space-a-key');

    rerender(<AgentCredentialScopeCard scope="space" projectId="space-b" />);

    const spaceBKey = await screen.findByLabelText(/Kiro API Key/);
    expect(spaceBKey).toHaveValue('');
    expect(screen.getByRole('button', { name: 'Save Credentials' })).toBeDisabled();
  });

  it('ignores a delayed response from the previous space', async () => {
    const lateSpaceA = deferred<typeof SPACE_A_STATUS>();
    getProjectCredentials.mockImplementation((projectId) =>
      projectId === 'space-a' ? lateSpaceA.promise : Promise.resolve(SPACE_B_STATUS),
    );
    const { rerender } = render(<AgentCredentialScopeCard scope="space" projectId="space-a" />);
    await waitFor(() => expect(getProjectCredentials).toHaveBeenCalledWith('space-a'));

    rerender(<AgentCredentialScopeCard scope="space" projectId="space-b" />);

    const bedrock = await screen.findByLabelText(/Bedrock Bearer Token/);
    const kiro = screen.getByLabelText(/Kiro API Key/);
    expect(bedrock).toHaveAttribute('placeholder', 'Enter AWS_BEARER_TOKEN_BEDROCK value');
    expect(kiro).toHaveAttribute('placeholder', 'Enter a new key to rotate, or leave blank');

    await act(async () => {
      lateSpaceA.resolve(SPACE_A_STATUS);
      await lateSpaceA.promise;
    });

    expect(bedrock).toHaveAttribute('placeholder', 'Enter AWS_BEARER_TOKEN_BEDROCK value');
    expect(kiro).toHaveAttribute('placeholder', 'Enter a new key to rotate, or leave blank');
  });

  it('drops an in-flight save when the space changes', async () => {
    const pendingSpaceAUpdate = deferred<{ saved: boolean }>();
    getProjectCredentials.mockImplementation((projectId) =>
      Promise.resolve(projectId === 'space-a' ? SPACE_A_STATUS : SPACE_B_STATUS),
    );
    updateProjectCredentials.mockImplementation((projectId) =>
      projectId === 'space-a' ? pendingSpaceAUpdate.promise : Promise.resolve({ saved: true }),
    );
    const user = userEvent.setup();
    const { rerender } = render(<AgentCredentialScopeCard scope="space" projectId="space-a" />);

    await user.type(await screen.findByLabelText(/Kiro API Key/), 'space-a-key');
    await user.click(screen.getByRole('button', { name: 'Save Credentials' }));
    expect(screen.getByRole('button', { name: 'Saving…' })).toBeDisabled();

    rerender(<AgentCredentialScopeCard scope="space" projectId="space-b" />);

    await screen.findByLabelText(/Kiro API Key/);
    expect(screen.getByRole('button', { name: 'Save Credentials' })).toBeDisabled();

    await act(async () => {
      pendingSpaceAUpdate.resolve({ saved: true });
      await pendingSpaceAUpdate.promise;
    });

    expect(
      getProjectCredentials.mock.calls.filter(([projectId]) => projectId === 'space-a'),
    ).toHaveLength(1);
    expect(screen.queryByText('Saved')).not.toBeInTheDocument();
  });

  it('surfaces a load failure and retries', async () => {
    getPersonalCredentials
      .mockRejectedValueOnce(new Error('Credential service unavailable'))
      .mockResolvedValueOnce({
        bedrockBearerTokenSet: true,
        kiroApiKeySet: false,
      });
    const user = userEvent.setup();
    render(<AgentCredentialScopeCard scope="personal" />);

    expect(await screen.findByRole('alert')).toHaveTextContent('Credential service unavailable');
    await user.click(screen.getByRole('button', { name: 'Retry' }));

    expect(await screen.findByText('1 provider configured')).toBeInTheDocument();
    expect(getPersonalCredentials).toHaveBeenCalledTimes(2);
  });
});

// specs/bedrock-iam-role-credential-mode — req-configured-semantics,
// req-bearer-deprecated, req-external-id-lifecycle, req-binding-preflight.
describe('AgentCredentialScopeCard bedrock role mode', () => {
  const ROLE_ARN = 'arn:aws:iam::444455556666:role/aidlc-bedrock-inference';

  it('reports a role-only scope as configured, with no secret stored', async () => {
    // The load-bearing case: this scope has NO bedrock secret at all, so a card
    // deriving "configured" from a secret would render it as having no credentials.
    getProjectCredentials.mockResolvedValue({
      bedrockBearerTokenSet: false,
      kiroApiKeySet: false,
      bedrockMode: 'role',
      bedrockRoleArn: ROLE_ARN,
      bedrockExternalIdSet: false,
      platformFallback: { bedrockBearerTokenSet: false, kiroApiKeySet: false },
    });

    render(<AgentCredentialScopeCard scope="space" projectId="p-1" />);

    expect(await screen.findByText('1 provider configured')).toBeInTheDocument();
    expect(screen.getByText(ROLE_ARN)).toBeInTheDocument();
    expect(screen.getByText('Recommended')).toBeInTheDocument();
    // And the bearer field is present but marked deprecated, not removed: existing
    // bearer deployments keep working.
    expect(screen.getByLabelText(/Bedrock Bearer Token \(deprecated\)/)).toBeInTheDocument();
  });

  it('sends only the role ARN, never an external ID', async () => {
    const user = userEvent.setup();
    render(<AgentCredentialScopeCard scope="space" projectId="p-1" />);

    await user.type(await screen.findByLabelText(/Bedrock IAM Role/), ROLE_ARN);
    await user.click(screen.getByRole('button', { name: 'Save Credentials' }));

    // The role travels in the same field as a bearer token — which shape the value
    // holds is a property of the value. The external ID is the server's to generate.
    await waitFor(() =>
      expect(updateProjectCredentials).toHaveBeenCalledWith('p-1', {
        bedrockBearerToken: JSON.stringify({ roleArn: ROLE_ARN }),
      }),
    );
  });

  it('shows a returned external ID masked, with an explicit reveal', async () => {
    const user = userEvent.setup();
    updateProjectCredentials.mockResolvedValue({
      saved: true,
      bedrockRoleArn: ROLE_ARN,
      bedrockExternalId: 'generated-external-id',
    });

    render(<AgentCredentialScopeCard scope="space" projectId="p-1" />);
    await user.type(await screen.findByLabelText(/Bedrock IAM Role/), ROLE_ARN);
    await user.click(screen.getByRole('button', { name: 'Save Credentials' }));

    const value = await screen.findByTestId('space-bedrock-external-id-value');
    // Masked by default — presentation hygiene, not a security control, since AWS
    // states the value is not a secret.
    expect(value).not.toHaveTextContent('generated-external-id');
    await user.click(screen.getByRole('button', { name: /Reveal External ID/ }));
    expect(await screen.findByText('generated-external-id')).toBeInTheDocument();
  });

  it('keeps the external ID visible when the preflight rejects the save', async () => {
    const user = userEvent.setup();
    const { ApiError } = await import('@/services/api');
    updateProjectCredentials.mockRejectedValue(
      new ApiError(400, 'The Bedrock role could not be assumed with this binding', {
        code: 'BEDROCK_ROLE_PREFLIGHT_FAILED',
        preflight: {
          cause: 'trust-policy-rejected',
          candidates: [{ candidate: 'principal-not-trusted', detail: 'Trust the broker role.' }],
        },
        bedrockExternalId: 'value-to-paste',
      }),
    );

    render(<AgentCredentialScopeCard scope="space" projectId="p-1" />);
    await user.type(await screen.findByLabelText(/Bedrock IAM Role/), ROLE_ARN);
    await user.click(screen.getByRole('button', { name: 'Save Credentials' }));

    // This is the bootstrap: the operator cannot write the trust policy the
    // preflight is checking until they have the value, so a rejection must surface
    // both the reason and the value.
    expect(await screen.findByText(/trust-policy-rejected/)).toBeInTheDocument();
    expect(screen.getByText('Trust the broker role.')).toBeInTheDocument();
    expect(screen.getByTestId('space-bedrock-external-id-value')).toBeInTheDocument();
  });

  it('surfaces the broker principal an operator must trust', async () => {
    getProjectCredentials.mockResolvedValue({
      bedrockBearerTokenSet: false,
      kiroApiKeySet: false,
      bedrockMode: 'role',
      bedrockRoleArn: ROLE_ARN,
      bedrockBrokerRoleArn: 'arn:aws:iam::111122223333:role/collab-credential-broker-dev',
      platformFallback: { bedrockBearerTokenSet: false, kiroApiKeySet: false },
    });

    render(<AgentCredentialScopeCard scope="space" projectId="p-1" />);

    // Without this the operator cannot write the trust policy at all, so it is
    // shown rather than documented (req-same-and-cross-account).
    await screen.findByTestId('space-bedrock-broker-role-value');
    await userEvent
      .setup()
      .click(screen.getByRole('button', { name: /Reveal Principal to trust/ }));
    expect(
      await screen.findByText('arn:aws:iam::111122223333:role/collab-credential-broker-dev'),
    ).toBeInTheDocument();
  });

  it('refuses a role ARN and a bearer token in the same save', async () => {
    const user = userEvent.setup();
    render(<AgentCredentialScopeCard scope="space" projectId="p-1" />);

    await user.type(await screen.findByLabelText(/Bedrock IAM Role/), ROLE_ARN);
    await user.type(screen.getByLabelText(/Bedrock Bearer Token/), 'a-bearer-token');

    // A scope holds ONE bedrock binding, so this is ambiguous rather than additive.
    expect(screen.getByRole('button', { name: 'Save Credentials' })).toBeDisabled();
    expect(updateProjectCredentials).not.toHaveBeenCalled();
  });

  it('offers no role field at personal scope', async () => {
    render(<AgentCredentialScopeCard scope="personal" />);
    await screen.findByLabelText(/Bedrock Bearer Token/);
    // That endpoint is gated only on authentication, so any member could otherwise
    // name a role ARN (dec-user-scope-role-deferred).
    expect(screen.queryByLabelText(/Bedrock IAM Role/)).not.toBeInTheDocument();
    expect(screen.queryByText(/deprecated/)).not.toBeInTheDocument();
  });
});
