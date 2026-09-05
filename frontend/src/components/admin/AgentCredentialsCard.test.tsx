import { beforeEach, describe, expect, it, vi } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';

const getSettings = vi.fn();
const updateSettings = vi.fn();

vi.mock('@/services/agents', () => ({
  agentsService: {
    getSettings: (...a: unknown[]) => getSettings(...a),
    updateSettings: (...a: unknown[]) => updateSettings(...a),
  },
}));

import { AgentCredentialsCard } from './AgentCredentialsCard';

const settings = (over: Record<string, unknown> = {}) => ({
  bedrockBearerTokenSet: false,
  kiroApiKeySet: false,
  bedrockAuthMethod: 'api-key' as const,
  ...over,
});

beforeEach(() => {
  vi.clearAllMocks();
});

describe('AgentCredentialsCard — Bedrock auth path', () => {
  it('defaults to the api-key path with the SecretField visible (zero regression)', async () => {
    getSettings.mockResolvedValue(settings());
    const { container } = render(<AgentCredentialsCard />);

    expect(await screen.findByTestId('bedrock-auth-method-radio-api-key')).toBeChecked();
    // The Bedrock SecretField is the api-key slot (queried by its stable id).
    expect(container.querySelector('#bedrock-bearer-token')).toBeInTheDocument();
    expect(screen.queryByTestId('bedrock-role-info-note')).not.toBeInTheDocument();
  });

  it('switches to the role path: hides the SecretField, shows the role note, enables Save', async () => {
    getSettings.mockResolvedValue(settings());
    const user = userEvent.setup();
    const { container } = render(<AgentCredentialsCard />);

    const roleRadio = await screen.findByTestId('bedrock-auth-method-radio-role');
    await user.click(roleRadio);

    expect(roleRadio).toBeChecked();
    expect(screen.getByTestId('bedrock-role-info-note')).toBeInTheDocument();
    expect(container.querySelector('#bedrock-bearer-token')).not.toBeInTheDocument();
    // Save enables on a method-only change (BR-6.1).
    expect(screen.getByRole('button', { name: /Save Credentials/i })).toBeEnabled();
  });

  it('shows the informational precedence note when role is selected with a stored key', async () => {
    getSettings.mockResolvedValue(settings({ bedrockBearerTokenSet: true }));
    const user = userEvent.setup();
    render(<AgentCredentialsCard />);

    await user.click(await screen.findByTestId('bedrock-auth-method-radio-role'));
    expect(screen.getByText(/takes precedence/i)).toBeInTheDocument();
  });

  it('sends bedrockAuthMethod in the PUT only when it changed', async () => {
    getSettings.mockResolvedValue(settings());
    updateSettings.mockResolvedValue({});
    const user = userEvent.setup();
    render(<AgentCredentialsCard />);

    await user.click(await screen.findByTestId('bedrock-auth-method-radio-role'));
    await user.click(screen.getByRole('button', { name: /Save Credentials/i }));

    await waitFor(() => expect(updateSettings).toHaveBeenCalledWith({ bedrockAuthMethod: 'role' }));
  });

  it('preserves the selection when the save fails', async () => {
    getSettings.mockResolvedValue(settings());
    updateSettings.mockRejectedValue(new Error('boom'));
    const user = userEvent.setup();
    render(<AgentCredentialsCard />);

    const roleRadio = await screen.findByTestId('bedrock-auth-method-radio-role');
    await user.click(roleRadio);
    await user.click(screen.getByRole('button', { name: /Save Credentials/i }));

    // Selection is not reverted on failure (BR-6.3).
    await waitFor(() => expect(screen.getByTestId('bedrock-auth-method-radio-role')).toBeChecked());
  });
});
