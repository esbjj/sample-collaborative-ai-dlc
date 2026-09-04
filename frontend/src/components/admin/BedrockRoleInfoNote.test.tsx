import { describe, expect, it, vi } from 'vitest';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';

import { BedrockRoleInfoNote } from './BedrockRoleInfoNote';

describe('BedrockRoleInfoNote', () => {
  it('shows the no-secret info line when no key is stored', () => {
    render(<BedrockRoleInfoNote bothConfigured={false} />);
    expect(screen.getByTestId('bedrock-role-info-note')).toBeInTheDocument();
    expect(screen.getByText(/No secret is required/i)).toBeInTheDocument();
    // Non-blocking, informational — never rendered as an error.
    expect(screen.queryByRole('alert')).not.toBeInTheDocument();
  });

  it('shows an informational precedence note (role wins) when both are configured', () => {
    render(<BedrockRoleInfoNote bothConfigured />);
    expect(screen.getByText(/takes precedence/i)).toBeInTheDocument();
    expect(screen.getByText(/unused/i)).toBeInTheDocument();
    // Announced politely, not as an error/alert.
    expect(screen.getByRole('status')).toBeInTheDocument();
    expect(screen.queryByRole('alert')).not.toBeInTheDocument();
  });

  it('offers an optional Clear-the-unused-key action only when both configured and handler given', async () => {
    const onClearKey = vi.fn();
    const user = userEvent.setup();
    render(<BedrockRoleInfoNote bothConfigured onClearKey={onClearKey} />);
    const clear = screen.getByTestId('bedrock-role-info-note-clear-key');
    await user.click(clear);
    expect(onClearKey).toHaveBeenCalledTimes(1);
  });

  it('does not render the clear action when only the role path is selected', () => {
    const onClearKey = vi.fn();
    render(<BedrockRoleInfoNote bothConfigured={false} onClearKey={onClearKey} />);
    expect(screen.queryByTestId('bedrock-role-info-note-clear-key')).not.toBeInTheDocument();
  });

  it('always exposes a read-only "View role scope" disclosure for the security reviewer', () => {
    render(<BedrockRoleInfoNote bothConfigured={false} />);
    expect(screen.getByTestId('bedrock-role-scope-disclosure')).toBeInTheDocument();
    expect(screen.getByText('View role scope')).toBeInTheDocument();
    expect(screen.getByText('bedrock:InvokeModel')).toBeInTheDocument();
  });
});
