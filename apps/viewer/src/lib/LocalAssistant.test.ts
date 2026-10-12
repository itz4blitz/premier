import { render, screen, waitFor } from '@testing-library/svelte';
import userEvent from '@testing-library/user-event';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import LocalAssistant, { resetAssistantSessions } from './LocalAssistant.svelte';
import type { TraceEvent } from './types';

const mocks = vi.hoisted(() => ({ assistants: vi.fn(), askAssistant: vi.fn(), previewAssistant: vi.fn() }));
vi.mock('./api', () => ({ api: mocks }));

const selectedEvent: TraceEvent = {
  event_id: 'event-9', trace_id: 'trace-1', sequence: 9, timestamp: '2026-07-13T20:51:39Z',
  kind: 'tool.error', source: 'test', payload_json: '{"detail":"failed"}', actor_id: 'worker',
  actor_type: 'subagent', parent_event_id: '', span_id: '', parent_span_id: '', correlation_id: '',
  status: 'error', duration_ms: 18, links: []
};

const providers = [
  { provider: 'claude', label: 'Claude', installed: true, available: true },
  { provider: 'codex', label: 'Codex', installed: true, available: true },
  { provider: 'opencode', label: 'OpenCode', installed: true, available: false, reason: 'No verified tool-deny mode.' }
];

/** A run of 300 events of which the newest 40 fit the prompt. */
const windowed = { scope: 'run' as const, total_events: 300, included_events: 40, first_sequence: 261, last_sequence: 300, history_messages: 0, prompt_chars: 18250 };

/** Tick the consent box for the provider that is selected now. */
async function consent(user: ReturnType<typeof userEvent.setup>, vendor: string): Promise<void> {
  await user.click(screen.getByRole('checkbox', { name: `Send redacted trace content to ${vendor}` }));
}

describe('LocalAssistant', () => {
  beforeEach(() => {
    resetAssistantSessions();
    mocks.previewAssistant.mockReset().mockResolvedValue({ context: windowed, prompt: 'TRACE OUTCOME (JSON):\n{"exit_code":1}\n\nUSER QUESTION:\n' });
    mocks.assistants.mockReset().mockResolvedValue(providers);
    mocks.askAssistant.mockReset().mockResolvedValue({ provider: 'claude', answer: 'The compiler failed in worker.', elapsed_ms: 125 });
  });

  it('discovers safe providers and keeps unavailable providers visible with a reason', async () => {
    render(LocalAssistant, { props: { traceId: 'trace-1' } });

    expect(screen.getByText('Discovering installed CLIs…')).toBeInTheDocument();
    const provider = await screen.findByRole('button', { name: 'Provider CLI' });
    await userEvent.click(provider);
    expect(screen.getByRole('option', { name: /Claude/ })).toBeInTheDocument();
    expect(screen.getByRole('option', { name: /Codex/ })).toBeInTheDocument();
    await userEvent.click(screen.getByText('1 unavailable provider'));
    expect(screen.getByText('OpenCode')).toBeInTheDocument();
    expect(screen.getByText('No verified tool-deny mode.')).toBeInTheDocument();
  });

  it('uses starters to fill the composer without submitting', async () => {
    const user = userEvent.setup();
    render(LocalAssistant, { props: { traceId: 'trace-1' } });
    await screen.findByRole('button', { name: 'Provider CLI' });

    await user.click(screen.getByRole('button', { name: /Summarize the run/ }));
    expect(screen.getByLabelText('Question for the provider')).toHaveValue('Summarize the run and identify the highest-impact issue.');
    expect(mocks.askAssistant).not.toHaveBeenCalled();
  });

  it('sends real history and selected-event scope and renders the measured answer', async () => {
    const user = userEvent.setup();
    render(LocalAssistant, { props: { traceId: 'trace-1', selectedEvent } });
    await user.click(await screen.findByRole('button', { name: 'Provider CLI' }));
    await user.click(screen.getByRole('option', { name: /Codex/ }));
    await user.click(screen.getByRole('radio', { name: /Selected event/ }));
    await user.type(screen.getByLabelText('Question for the provider'), 'Why did this fail?');
    await consent(user, 'OpenAI');
    mocks.askAssistant.mockResolvedValueOnce({ provider: 'codex', answer: 'Event 9 contains the compiler failure.', elapsed_ms: 240 });
    await user.click(screen.getByRole('button', { name: 'Ask Codex' }));

    await screen.findByText('Event 9 contains the compiler failure.');
    expect(mocks.askAssistant).toHaveBeenCalledWith('trace-1', {
      provider: 'codex', prompt: 'Why did this fail?', history: [], selected_event_id: 'event-9'
    });
    expect(screen.getByText('240 ms')).toBeInTheDocument();

    await user.type(screen.getByLabelText('Question for the provider'), 'What next?');
    await user.click(screen.getByRole('button', { name: 'Ask Codex' }));
    await waitFor(() => expect(mocks.askAssistant).toHaveBeenCalledTimes(2));
    expect(mocks.askAssistant.mock.calls[1][1].history).toEqual([
      { role: 'user', content: 'Why did this fail?' },
      { role: 'assistant', content: 'Event 9 contains the compiler failure.' }
    ]);
  });

  it('renders provider Markdown as semantic, readable trace analysis', async () => {
    const user = userEvent.setup();
    mocks.askAssistant.mockResolvedValueOnce({
      provider: 'claude',
      answer: '## Highest-impact issue\n\n**Missing evidence:**\n\n- No model call\n- No tool execution\n\n`correlation_id` is empty.',
      elapsed_ms: 25_400
    });
    render(LocalAssistant, { props: { traceId: 'trace-1' } });
    await screen.findByRole('button', { name: 'Provider CLI' });
    await user.type(screen.getByLabelText('Question for the provider'), 'Review the run');
    await consent(user, 'Anthropic');
    await user.click(screen.getByRole('button', { name: 'Ask Claude' }));

    expect(await screen.findByRole('heading', { level: 2, name: 'Highest-impact issue' })).toBeInTheDocument();
    expect(screen.getByText('Missing evidence:').tagName).toBe('STRONG');
    expect(screen.getByText('No model call').closest('ul')).toHaveTextContent('No model call No tool execution');
    expect(screen.getByText('correlation_id').tagName).toBe('CODE');
    expect(screen.getByText('25.4 s')).toBeInTheDocument();
  });

  it('preserves a failed question and exposes the real backend error', async () => {
    const user = userEvent.setup();
    mocks.askAssistant.mockRejectedValueOnce(new Error('Claude exited with status 1: login required'));
    render(LocalAssistant, { props: { traceId: 'trace-1' } });
    await screen.findByRole('button', { name: 'Provider CLI' });
    const input = screen.getByLabelText('Question for the provider');
    await user.type(input, 'Diagnose this');
    await consent(user, 'Anthropic');
    await user.click(screen.getByRole('button', { name: 'Ask Claude' }));

    expect(await screen.findByRole('alert')).toHaveTextContent('Claude exited with status 1: login required');
    expect(input).toHaveValue('Diagnose this');
  });

  it('shows a truthful waiting state while the provider is running', async () => {
    const user = userEvent.setup();
    let resolveAnswer!: (value: { provider: string; answer: string; elapsed_ms: number }) => void;
    mocks.askAssistant.mockReturnValueOnce(new Promise((resolve) => { resolveAnswer = resolve; }));
    render(LocalAssistant, { props: { traceId: 'trace-1' } });
    await screen.findByRole('button', { name: 'Provider CLI' });
    await user.type(screen.getByLabelText('Question for the provider'), 'Inspect latency');
    await consent(user, 'Anthropic');
    await user.click(screen.getByRole('button', { name: 'Ask Claude' }));

    expect(screen.getByRole('status')).toHaveTextContent('Claude is analyzing the trace');
    expect(screen.getByRole('button', { name: 'Waiting' })).toBeDisabled();
    resolveAnswer({ provider: 'claude', answer: 'Latency is concentrated in tools.', elapsed_ms: 80 });
    expect(await screen.findByText('Latency is concentrated in tools.')).toBeInTheDocument();
  });

  it('bounds the visible transcript and reports hidden earlier messages', async () => {
    const user = userEvent.setup();
    mocks.askAssistant.mockImplementation(async (_traceId: string, body: { prompt: string }) => ({
      provider: 'claude', answer: `Answer to ${body.prompt}`, elapsed_ms: 10
    }));
    render(LocalAssistant, { props: { traceId: 'trace-1' } });
    await screen.findByRole('button', { name: 'Provider CLI' });
    const input = screen.getByLabelText('Question for the provider');
    await consent(user, 'Anthropic');
    for (let index = 1; index <= 7; index += 1) {
      await user.type(input, `Question ${index}`);
      await user.click(screen.getByRole('button', { name: 'Ask Claude' }));
      await screen.findByText(`Answer to Question ${index}`);
    }
    expect(screen.getByText('2 earlier messages hidden')).toBeInTheDocument();
    expect(screen.queryByText('Question 1')).not.toBeInTheDocument();
    expect(screen.getByText('Question 7')).toBeInTheDocument();
  });

  it('shows the no-provider state without enabling fake interaction', async () => {
    mocks.assistants.mockResolvedValueOnce([
      { provider: 'opencode', label: 'OpenCode', installed: true, available: false, reason: 'No safe invocation.' }
    ]);
    render(LocalAssistant, { props: { traceId: 'trace-1' } });

    const provider = await screen.findByRole('button', { name: 'Provider CLI' });
    expect(provider).toHaveTextContent('No safe provider available');
    expect(provider).toBeDisabled();
    expect(screen.getByLabelText('Question for the provider')).toBeDisabled();
    expect(screen.getByRole('button', { name: 'Ask assistant' })).toBeDisabled();
  });

  it('says where trace content goes and sends nothing until the user agrees, per provider', async () => {
    const user = userEvent.setup();
    render(LocalAssistant, { props: { traceId: 'trace-1' } });
    await screen.findByRole('button', { name: 'Provider CLI' });
    expect(screen.getByRole('heading', { name: 'Ask an AI CLI installed here' })).toBeInTheDocument();
    expect(screen.getByText(/Asking sends trace content off this machine/)).toHaveTextContent("Anthropic's model service");

    await user.type(screen.getByLabelText('Question for the provider'), 'Summarize');
    const ask = screen.getByRole('button', { name: 'Ask Claude' });
    expect(ask).toBeDisabled();
    await user.keyboard('{Control>}{Enter}{/Control}');
    expect(mocks.askAssistant).not.toHaveBeenCalled();

    await consent(user, 'Anthropic');
    expect(ask).toBeEnabled();

    // Agreeing to one provider is not agreeing to another.
    await user.click(screen.getByRole('button', { name: 'Provider CLI' }));
    await user.click(screen.getByRole('option', { name: /Codex/ }));
    expect(screen.getByText(/Asking sends trace content off this machine/)).toHaveTextContent("OpenAI's model service");
    expect(screen.getByRole('checkbox', { name: 'Send redacted trace content to OpenAI' })).not.toBeChecked();
    expect(screen.getByRole('button', { name: 'Ask Codex' })).toBeDisabled();
    expect(mocks.askAssistant).not.toHaveBeenCalled();
  });

  it('shows which events will be sent, and the exact text on request, before anything is asked', async () => {
    const user = userEvent.setup();
    render(LocalAssistant, { props: { traceId: 'trace-1', selectedEvent } });
    const coverage = await screen.findByTestId('assistant-coverage');
    await waitFor(() => expect(coverage).toHaveTextContent('events #261–#300 (the newest 40 of 300)'));
    expect(coverage).toHaveTextContent('about 18,250 characters');
    // A whole-run question would be answered from a window: say so before it is asked.
    expect(coverage).toHaveTextContent('260 earlier events are not sent, so a question about the whole run is answered from this range only.');
    // Working this out asks the local server only; no provider has been run.
    expect(mocks.previewAssistant).toHaveBeenCalledWith('trace-1', { provider: 'claude', prompt: '', history: [] });
    expect(mocks.askAssistant).not.toHaveBeenCalled();
    expect(screen.queryByTestId('assistant-prompt-preview')).not.toBeInTheDocument();

    // The exact text includes the question as typed so far.
    await user.type(screen.getByLabelText('Question for the provider'), 'Why?');
    mocks.previewAssistant.mockResolvedValueOnce({ context: windowed, prompt: 'TRACE OUTCOME (JSON):\n{"exit_code":1}\n\nUSER QUESTION:\nWhy?' });
    await user.click(screen.getByRole('button', { name: 'Show the exact text' }));
    const text = await screen.findByTestId('assistant-prompt-preview');
    await waitFor(() => expect(text.textContent).toBe('TRACE OUTCOME (JSON):\n{"exit_code":1}\n\nUSER QUESTION:\nWhy?'));
    expect(mocks.previewAssistant).toHaveBeenLastCalledWith('trace-1', { provider: 'claude', prompt: 'Why?', history: [] });
    await user.click(screen.getByRole('button', { name: 'Hide the exact text' }));
    expect(screen.queryByTestId('assistant-prompt-preview')).not.toBeInTheDocument();

    // Changing the scope asks again, for the selected event this time.
    mocks.previewAssistant.mockResolvedValue({ context: { ...windowed, scope: 'event', selected_sequence: 9 }, prompt: 'p' });
    await user.click(screen.getByRole('radio', { name: /Selected event/ }));
    await waitFor(() => expect(coverage).toHaveTextContent('the selected event #9 and events #261–#300'));
    expect(mocks.previewAssistant).toHaveBeenLastCalledWith('trace-1', expect.objectContaining({ selected_event_id: 'event-9' }));
    expect(mocks.askAssistant).not.toHaveBeenCalled();
  });

  it('states the event range each answer was based on', async () => {
    const user = userEvent.setup();
    mocks.askAssistant.mockResolvedValueOnce({ provider: 'claude', answer: 'The last tool call failed.', elapsed_ms: 90, context: windowed });
    render(LocalAssistant, { props: { traceId: 'trace-1' } });
    await screen.findByRole('button', { name: 'Provider CLI' });
    await user.type(screen.getByLabelText('Question for the provider'), 'Summarize the run');
    await consent(user, 'Anthropic');
    await user.click(screen.getByRole('button', { name: 'Ask Claude' }));
    const basis = await screen.findByTestId('assistant-answer-basis');
    expect(basis).toHaveTextContent('Based on events #261–#300 (the newest 40 of 300). 260 earlier events were not sent to the model.');

    // A run that fits entirely says so, with no caveat.
    mocks.askAssistant.mockResolvedValueOnce({
      provider: 'claude', answer: 'Second answer.', elapsed_ms: 80,
      context: { scope: 'run', total_events: 3, included_events: 3, first_sequence: 1, last_sequence: 3, history_messages: 2, prompt_chars: 900 }
    });
    await user.type(screen.getByLabelText('Question for the provider'), 'And then?');
    await user.click(screen.getByRole('button', { name: 'Ask Claude' }));
    await screen.findByText('Second answer.');
    const all = screen.getAllByTestId('assistant-answer-basis');
    expect(all).toHaveLength(2);
    expect(all[1]).toHaveTextContent('Based on all 3 events (events #1–#3).');
    expect(all[1]).not.toHaveTextContent('not sent');
  });

  it('keeps the conversation, the draft and an answer still on its way when the panel is closed', async () => {
    const user = userEvent.setup();
    let answer: (value: unknown) => void = () => undefined;
    mocks.askAssistant.mockReturnValueOnce(new Promise((resolve) => { answer = resolve; }));
    const first = render(LocalAssistant, { props: { traceId: 'trace-1' } });
    await screen.findByRole('button', { name: 'Provider CLI' });
    await user.type(screen.getByLabelText('Question for the provider'), 'What failed?');
    await consent(user, 'Anthropic');
    await user.click(screen.getByRole('button', { name: 'Ask Claude' }));
    expect(await screen.findByText(/is analyzing the trace/)).toBeInTheDocument();
    // Closed while the provider is still working.
    first.unmount();
    answer({ provider: 'claude', answer: 'The deploy step failed.', elapsed_ms: 300, context: windowed });

    const second = render(LocalAssistant, { props: { traceId: 'trace-1' } });
    expect(await screen.findByText('What failed?')).toBeInTheDocument();
    expect(await screen.findByText('The deploy step failed.')).toBeInTheDocument();
    // Consent and the chosen provider are remembered for this page too.
    expect(screen.getByRole('checkbox', { name: 'Send redacted trace content to Anthropic' })).toBeChecked();
    await user.type(screen.getByLabelText('Question for the provider'), 'half a thought');
    second.unmount();

    render(LocalAssistant, { props: { traceId: 'trace-1' } });
    await screen.findByRole('button', { name: 'Provider CLI' });
    expect(screen.getByLabelText('Question for the provider')).toHaveValue('half a thought');
    expect(screen.getByText('The deploy step failed.')).toBeInTheDocument();
    expect(mocks.askAssistant).toHaveBeenCalledTimes(1);
  });

  it('keeps conversations of different traces apart', async () => {
    const user = userEvent.setup();
    const first = render(LocalAssistant, { props: { traceId: 'trace-1' } });
    await screen.findByRole('button', { name: 'Provider CLI' });
    await user.type(screen.getByLabelText('Question for the provider'), 'draft for one');
    first.unmount();
    render(LocalAssistant, { props: { traceId: 'trace-2' } });
    await screen.findByRole('button', { name: 'Provider CLI' });
    expect(screen.getByLabelText('Question for the provider')).toHaveValue('');
  });

  it('explains an empty provider list and a provider these credentials may not use', async () => {
    mocks.assistants.mockResolvedValueOnce([]);
    const empty = render(LocalAssistant, { props: { traceId: 'trace-1' } });
    expect(await screen.findByText(/the assistant is turned off/)).toBeInTheDocument();
    expect(mocks.previewAssistant).not.toHaveBeenCalled();
    empty.unmount();

    mocks.assistants.mockResolvedValueOnce([
      { provider: 'claude', label: 'Claude', installed: true, available: false, reason: 'these credentials lack the assistant:use scope' }
    ]);
    render(LocalAssistant, { props: { traceId: 'trace-2' } });
    expect(await screen.findByText('these credentials lack the assistant:use scope')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Ask assistant' })).toBeDisabled();
    expect(mocks.previewAssistant).not.toHaveBeenCalled();
  });
});
