import { describe, expect, it, vi } from 'vitest';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';

import { BedrockAuthMethodField } from './BedrockAuthMethodField';

const slots = {
  apiKeySlot: <div data-testid="api-key-slot">api key slot</div>,
  roleSlot: <div data-testid="role-slot">role slot</div>,
};

describe('BedrockAuthMethodField', () => {
  it('discloses the API-key slot when api-key is selected', () => {
    render(<BedrockAuthMethodField value="api-key" onChange={vi.fn()} {...slots} />);
    expect(screen.getByTestId('api-key-slot')).toBeInTheDocument();
    expect(screen.queryByTestId('role-slot')).not.toBeInTheDocument();
    expect(screen.getByTestId('bedrock-auth-method-radio-api-key')).toBeChecked();
  });

  it('discloses the role slot when role is selected (hides the API-key slot)', () => {
    render(<BedrockAuthMethodField value="role" onChange={vi.fn()} {...slots} />);
    expect(screen.getByTestId('role-slot')).toBeInTheDocument();
    expect(screen.queryByTestId('api-key-slot')).not.toBeInTheDocument();
    expect(screen.getByTestId('bedrock-auth-method-radio-role')).toBeChecked();
  });

  it('emits the next enum value on selection change', async () => {
    const onChange = vi.fn();
    const user = userEvent.setup();
    render(<BedrockAuthMethodField value="api-key" onChange={onChange} {...slots} />);
    await user.click(screen.getByTestId('bedrock-auth-method-radio-role'));
    expect(onChange).toHaveBeenCalledWith('role');
  });

  it('disables the radios when disabled', () => {
    render(<BedrockAuthMethodField value="api-key" onChange={vi.fn()} disabled {...slots} />);
    expect(screen.getByTestId('bedrock-auth-method-radio-api-key')).toBeDisabled();
    expect(screen.getByTestId('bedrock-auth-method-radio-role')).toBeDisabled();
  });

  it('groups the radios in a labelled fieldset for accessibility', () => {
    render(<BedrockAuthMethodField value="api-key" onChange={vi.fn()} {...slots} />);
    expect(screen.getByRole('group', { name: /Bedrock authentication/i })).toBeInTheDocument();
  });
});
