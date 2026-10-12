<script lang="ts" module>
  import type { AssistantContext as Context, AssistantHistoryMessage as HistoryMessage } from './types';

  type SessionMessage = HistoryMessage & { id: number; provider?: string; elapsedMs?: number; context?: Context };

  /**
   * One conversation per trace, kept for as long as the page is open. The panel is unmounted when it
   * closes (Escape, the backdrop, the close button); the conversation, the draft and an answer that
   * is still on its way must outlive that.
   */
  interface Session {
    messages: SessionMessage[];
    draft: string;
    provider: string;
    scope: 'run' | 'event';
    consented: Record<string, boolean>;
    messageId: number;
    /** The request in flight, if any. Settles after `messages` and `error` were updated. */
    pending: Promise<void> | null;
    error: string;
  }

  const sessions = new Map<string, Session>();

  /** Forget every kept conversation. For tests. */
  export function resetAssistantSessions(): void {
    sessions.clear();
  }
</script>

<script lang="ts">
  import { onMount, untrack } from 'svelte';
  import { api } from './api';
  import { eventSummary } from './analysis';
  import { renderAssistantMarkdown } from './markdown';
  import PremierSelect from './PremierSelect.svelte';
  import type {
    AssistantAvailability,
    AssistantContext,
    AssistantHistoryMessage,
    AssistantPreview,
    AssistantRequest,
    TraceEvent
  } from './types';

  let { traceId, selectedEvent = null, onclose }: {
    traceId: string;
    selectedEvent?: TraceEvent | null;
    onclose?: () => void;
  } = $props();

  type Scope = 'run' | 'event';
  type ChatMessage = SessionMessage;

  const MAX_DISPLAY_MESSAGES = 12;
  const MAX_RETAINED_MESSAGES = 24;
  const MAX_HISTORY_CHARS = 12_000;
  const sendShortcutLabel = typeof navigator !== 'undefined' && navigator.platform.includes('Mac') ? '⌘' : 'Ctrl';
  const starters = [
    'Summarize the run and identify the highest-impact issue.',
    'Explain the critical path and where time was spent.',
    'What evidence should I inspect next, and why?'
  ];

  const session: Session = untrack(() => {
    const known = sessions.get(traceId);
    if (known) return known;
    const fresh: Session = { messages: [], draft: '', provider: '', scope: 'run', consented: {}, messageId: 0, pending: null, error: '' };
    sessions.set(traceId, fresh);
    return fresh;
  });

  let providers = $state<AssistantAvailability[]>([]);
  let provider = $state(session.provider);
  let scope = $state<Scope>(session.scope);
  let prompt = $state(session.draft);
  let messages = $state<ChatMessage[]>(session.messages);
  let loadingProviders = $state(true);
  let waiting = $state(session.pending !== null);
  let loadError = $state('');
  let sendError = $state(session.error);
  let providerNotice = $state('');
  let textarea: HTMLTextAreaElement;
  /** What the next question would send, as the server would build it. */
  let preview = $state<AssistantPreview | null>(null);
  let previewError = $state('');
  let promptShown = $state(false);
  let previewRequest = 0;

  const availableProviders = $derived(providers.filter((item) => item.available));
  const unavailableProviders = $derived(providers.filter((item) => !item.available));
  const selectedProvider = $derived(providers.find((item) => item.provider === provider) ?? null);
  const displayedMessages = $derived(messages.slice(-MAX_DISPLAY_MESSAGES));
  const hiddenMessageCount = $derived(Math.max(0, messages.length - displayedMessages.length));
  /** Who receives what the selected CLI sends: the CLI runs here, the model does not. */
  const VENDORS: Record<string, string> = { claude: 'Anthropic', codex: 'OpenAI', gemini: 'Google', grok: 'xAI' };
  const vendor = $derived(VENDORS[provider] ?? 'the provider');
  /** Providers the user agreed to send trace content to, for as long as this panel is open. */
  let consented = $state<Record<string, boolean>>(session.consented);
  const hasConsent = $derived(Boolean(provider && consented[provider]));
  const canSubmit = $derived(Boolean(traceId && provider && prompt.trim() && !waiting && selectedProvider?.available && hasConsent));

  $effect(() => {
    if (!selectedEvent && scope === 'event') scope = 'run';
  });

  // What is typed and chosen is kept with the trace, not with this mounted panel.
  $effect(() => {
    session.draft = prompt;
    session.provider = provider;
    session.scope = scope;
    session.consented = consented;
  });

  // The coverage line follows the scope and the selected event.
  $effect(() => {
    void scope;
    void selectedEvent?.event_id;
    void messages.length;
    if (!loadingProviders && provider) untrack(() => void refreshPreview());
  });

  onMount(() => {
    void loadProviders();
    // A question asked before the panel was closed is still being answered: wait for it here too.
    const pending = session.pending;
    if (pending) void pending.then(() => adoptSession());
  });

  /** Take over what a request that outlived an earlier mount of this panel left in the session. */
  function adoptSession(): void {
    messages = session.messages;
    sendError = session.error;
    if (session.error) prompt = session.draft;
    waiting = session.pending !== null;
  }

  function requestBody(question: string, history: AssistantHistoryMessage[]): AssistantRequest {
    return {
      provider,
      prompt: question,
      history,
      ...(scope === 'event' && selectedEvent ? { selected_event_id: selectedEvent.event_id } : {})
    };
  }

  /** Ask the server what a question would send. Nothing leaves this machine to answer that. */
  async function refreshPreview(): Promise<void> {
    if (!provider) return;
    const request = ++previewRequest;
    try {
      const next = await api.previewAssistant(traceId, requestBody(prompt.trim(), boundedHistory(messages)));
      if (request !== previewRequest) return;
      preview = next;
      previewError = '';
    } catch (error) {
      if (request !== previewRequest) return;
      preview = null;
      previewError = error instanceof Error ? error.message : 'Could not work out what would be sent.';
    }
  }

  async function togglePrompt(): Promise<void> {
    promptShown = !promptShown;
    // Include the question as it stands now.
    if (promptShown) await refreshPreview();
  }

  function range(context: AssistantContext): string {
    if (context.first_sequence === undefined || context.last_sequence === undefined) return 'no events';
    return context.first_sequence === context.last_sequence
      ? `event #${context.first_sequence}`
      : `events #${context.first_sequence}–#${context.last_sequence}`;
  }

  /** "events #12–#51 (40 of 300)", with the selected event named first when one is sent. */
  function coverage(context: AssistantContext): string {
    const all = context.included_events >= context.total_events;
    const recent = context.total_events === 0
      ? 'no events (the trace has none)'
      : all
        ? `all ${context.total_events} event${context.total_events === 1 ? '' : 's'} (${range(context)})`
        : `${range(context)} (the newest ${context.included_events} of ${context.total_events})`;
    return context.selected_sequence !== undefined ? `the selected event #${context.selected_sequence} and ${recent}` : recent;
  }

  function notSent(context: AssistantContext): string {
    const missing = omitted(context);
    return `${missing.toLocaleString()} earlier event${missing === 1 ? ' is' : 's are'} not sent, so a question about the whole run is answered from this range only.`;
  }

  /** What an answer was based on, said with the answer. */
  function basis(context: AssistantContext): string {
    const missing = omitted(context);
    return `Based on ${coverage(context)}.${missing ? ` ${missing.toLocaleString()} earlier event${missing === 1 ? ' was' : 's were'} not sent to the model.` : ''}`;
  }

  function omitted(context: AssistantContext): number {
    return Math.max(0, context.total_events - context.included_events);
  }

  async function loadProviders(): Promise<void> {
    loadingProviders = true;
    loadError = '';
    try {
      providers = await api.assistants();
      if (!providers.some((item) => item.provider === provider && item.available)) {
        provider = providers.find((item) => item.available)?.provider ?? '';
      }
    } catch (error) {
      loadError = error instanceof Error ? error.message : 'Could not discover local assistants.';
    } finally {
      loadingProviders = false;
    }
  }

  function useStarter(starter: string): void {
    prompt = starter;
    textarea?.focus();
  }

  function changeProvider(next: string): void {
    if (next !== provider && messages.length) {
      session.messages = [];
      session.error = '';
      messages = [];
      sendError = '';
      providerNotice = 'Conversation cleared because each provider receives its own context.';
    }
    provider = next;
  }

  async function submit(event: SubmitEvent): Promise<void> {
    event.preventDefault();
    const question = prompt.trim();
    if (!canSubmit || !question) return;

    const body = requestBody(question, boundedHistory(messages));
    const userMessage: ChatMessage = { id: ++session.messageId, role: 'user', content: question };
    session.messages = [...session.messages, userMessage].slice(-MAX_RETAINED_MESSAGES);
    session.error = '';
    session.draft = '';
    messages = session.messages;
    prompt = '';
    sendError = '';
    waiting = true;
    // The outcome is written to the session first: this panel may be closed before the answer arrives.
    const pending = api.askAssistant(traceId, body).then((response) => {
      const answerMessage: ChatMessage = {
        id: ++session.messageId,
        role: 'assistant',
        content: response.answer,
        provider: response.provider,
        elapsedMs: response.elapsed_ms,
        context: response.context
      };
      session.messages = [...session.messages, answerMessage].slice(-MAX_RETAINED_MESSAGES);
    }, (error: unknown) => {
      session.messages = session.messages.filter((message) => message.id !== userMessage.id);
      session.error = error instanceof Error ? error.message : 'The local assistant did not respond.';
      // The question goes back to the composer, ahead of anything typed since.
      session.draft = session.draft.trim() ? `${question}\n${session.draft}` : question;
    }).finally(() => {
      if (session.pending === pending) session.pending = null;
    });
    session.pending = pending;
    await pending;
    adoptSession();
  }

  function boundedHistory(input: ChatMessage[]): AssistantHistoryMessage[] {
    const result: AssistantHistoryMessage[] = [];
    let remaining = MAX_HISTORY_CHARS;
    for (const message of input.slice(-MAX_DISPLAY_MESSAGES).reverse()) {
      if (remaining === 0) break;
      const content = message.content.slice(0, remaining);
      result.unshift({ role: message.role, content });
      remaining -= content.length;
    }
    return result;
  }

  function submitShortcut(event: KeyboardEvent): void {
    if ((event.metaKey || event.ctrlKey) && event.key === 'Enter') {
      event.preventDefault();
      textarea?.form?.requestSubmit();
    }
  }

  function elapsedLabel(ms: number): string {
    return ms < 1_000 ? `${ms} ms` : `${(ms / 1_000).toFixed(1)} s`;
  }
</script>

<section class="assistant-workspace" aria-labelledby="assistant-title">
  <header class="assistant-header">
    <div class="assistant-identity">
      <span class="assistant-mark" aria-hidden="true">
        <svg viewBox="0 0 24 24"><path d="M12 3.5a8.5 8.5 0 1 0 8.5 8.5M12 1v5m0 12v5M1 12h5m12 0h5"/><circle cx="12" cy="12" r="2.5"/></svg>
      </span>
      <div>
        <span class="eyebrow">Trace copilot</span>
        <h2 id="assistant-title">Ask an AI CLI installed here</h2>
      </div>
    </div>
    {#if selectedProvider}
      <span class="privacy-note"><i aria-hidden="true"></i>{selectedProvider.label} CLI · sends to {vendor}</span>
    {/if}
    {#if onclose}<button class="assistant-close" type="button" onclick={onclose}>Close AI workspace</button>{/if}
  </header>

  <div class="assistant-controls">
    <div class="provider-control">
      <label for="assistant-provider">Provider CLI</label>
      {#if loadingProviders}
        <div class="provider-loading" role="status"><span aria-hidden="true"></span>Discovering installed CLIs…</div>
      {:else if loadError}
        <div class="provider-error" role="alert">
          <span>{loadError}</span>
          <button type="button" onclick={loadProviders}>Retry</button>
        </div>
      {:else}
        <PremierSelect
          id="assistant-provider"
          label="Provider CLI"
          value={provider}
          options={availableProviders.length
            ? availableProviders.map((item) => ({
                value: item.provider,
                label: item.label,
                description: `Sends to ${VENDORS[item.provider] ?? 'the provider'} · CLI runs on this machine`
              }))
            : [{ value: '', label: 'No provider available', disabled: true }]}
          disabled={!availableProviders.length || waiting}
          onchange={changeProvider}
        />
      {/if}
    </div>

    <fieldset class="scope-control">
      <legend>Context scope</legend>
      <div class="scope-options">
        <label class:active={scope === 'run'}>
          <input type="radio" name="assistant-scope" value="run" bind:group={scope} disabled={waiting} />
          <span><strong>Run context</strong><small>{preview && preview.context.scope === 'run' && preview.context.total_events ? `Manifest + ${coverage(preview.context)}` : 'Manifest + recent events'}</small></span>
        </label>
        <label class:active={scope === 'event'} class:disabled={!selectedEvent}>
          <input type="radio" name="assistant-scope" value="event" bind:group={scope} disabled={!selectedEvent || waiting} />
          <span><strong>Selected event</strong><small>{selectedEvent ? `#${selectedEvent.sequence} · ${eventSummary(selectedEvent)}` : 'Select an event first'}</small></span>
        </label>
      </div>
    </fieldset>
    <div class="context-disclosure">
      <p>Asking sends trace content off this machine: the run's manifest and its most recent events (or the selected event), redacted by Premier's secret rules, go with your question to {vendor}'s model service through the {selectedProvider?.label ?? 'selected'} CLI and the account it is signed in to. Captured output is sent as recorded. Nothing is sent until you ask.</p>
      {#if provider}
        {#if selectedProvider?.containment_summary}
          <p class="containment" class:weaker={selectedProvider.containment !== 'no_tools'} data-testid="assistant-containment" data-containment={selectedProvider.containment}>
            <strong>What the CLI can do while it answers:</strong> {selectedProvider.containment_summary}
            {#if selectedProvider.containment !== 'no_tools'}<em>Trace content is untrusted input to it: text recorded in the trace could steer what it does with those abilities.</em>{/if}
          </p>
        {/if}
        <label class="consent">
          <input type="checkbox" checked={hasConsent} disabled={waiting} onchange={(event) => { consented = { ...consented, [provider]: event.currentTarget.checked }; }} />
          <span>Send redacted trace content to {vendor}</span>
        </label>
        <div class="coverage" data-testid="assistant-coverage" aria-live="polite">
          {#if preview}
            <span>
              <strong>What will be sent:</strong> the run's outcome and manifest, {coverage(preview.context)}{#if preview.context.history_messages}, {preview.context.history_messages} earlier message{preview.context.history_messages === 1 ? '' : 's'} of this conversation{/if} and your question — about {preview.context.prompt_chars.toLocaleString()} characters.
              {#if omitted(preview.context)}<em>{notSent(preview.context)}</em>{/if}
            </span>
            <button type="button" aria-expanded={promptShown} aria-controls="assistant-prompt-preview" onclick={togglePrompt}>{promptShown ? 'Hide the exact text' : 'Show the exact text'}</button>
          {:else if previewError}
            <span>What would be sent could not be worked out: {previewError}</span>
            <button type="button" onclick={refreshPreview}>Retry</button>
          {:else}
            <span>Working out what would be sent…</span>
          {/if}
        </div>
        {#if promptShown && preview}
          <!-- A scrolling region has to be reachable by keyboard to be scrolled by keyboard. -->
          <!-- svelte-ignore a11y_no_noninteractive_tabindex -->
          <pre id="assistant-prompt-preview" class="prompt-preview" data-testid="assistant-prompt-preview" role="region" tabindex="0" aria-label="The exact text that will be sent">{preview.prompt}</pre>
        {/if}
      {:else if !loadingProviders && !loadError && providers.length === 0}
        <p class="assistant-off" role="status">No provider is offered by this server: the assistant is turned off (<code>--no-assistant</code>) or none of the supported CLIs is installed.</p>
      {/if}
    </div>
  </div>

  {#if unavailableProviders.length && !loadingProviders}
    <details class="unavailable-providers">
      <summary>{unavailableProviders.length} unavailable provider{unavailableProviders.length === 1 ? '' : 's'}</summary>
      <ul>
        {#each unavailableProviders as item (item.provider)}
          <li><strong>{item.label}</strong><span>{item.reason ?? (item.installed ? 'The CLI cannot be run for a single answer.' : 'CLI is not installed.')}</span></li>
        {/each}
      </ul>
    </details>
  {/if}

  <div class="conversation" aria-live="polite" aria-busy={waiting}>
    {#if providerNotice}<div class="provider-notice" role="status">{providerNotice}</div>{/if}
    {#if hiddenMessageCount > 0}
      <div class="history-boundary">{hiddenMessageCount} earlier message{hiddenMessageCount === 1 ? '' : 's'} hidden</div>
    {/if}
    {#if displayedMessages.length === 0}
      <div class="conversation-empty">
        <span aria-hidden="true">⌁</span>
        <strong>Interrogate the evidence</strong>
        <p>Ask for a diagnosis, a causal explanation, or the next evidence worth inspecting. The selected scope is attached by Premier.</p>
      </div>
    {:else}
      {#each displayedMessages as message (message.id)}
        <article class:answer={message.role === 'assistant'} class="message">
          <div class="message-meta">
            <strong>{message.role === 'assistant' ? providers.find((item) => item.provider === message.provider)?.label ?? message.provider ?? 'Assistant' : 'You'}</strong>
            {#if message.elapsedMs !== undefined}<span>{elapsedLabel(message.elapsedMs)}</span>{/if}
          </div>
          {#if message.role === 'assistant'}
            <div class="markdown-content">{@html renderAssistantMarkdown(message.content)}</div>
            {#if message.context}
              <small class="message-basis" data-testid="assistant-answer-basis">
                {basis(message.context)}
              </small>
            {/if}
          {:else}
            <p>{message.content}</p>
          {/if}
        </article>
      {/each}
    {/if}
    {#if waiting}
      <div class="waiting-message" role="status">
        <span aria-hidden="true"><i></i><i></i><i></i></span>
        <div><strong>{selectedProvider?.label ?? 'Local assistant'} is analyzing the trace</strong><small>This can take up to 45 seconds.</small></div>
      </div>
    {/if}
  </div>

  <div class="starter-row" aria-label="Prompt starters">
    {#each starters as starter, index (starter)}
      <button type="button" onclick={() => useStarter(starter)} disabled={waiting || !availableProviders.length}>
        <span>{index + 1}</span>{starter}
      </button>
    {/each}
  </div>

  <form class="composer" onsubmit={submit}>
    <label for="assistant-prompt">Question for the provider</label>
    <div class="composer-field" class:error={Boolean(sendError)}>
      <textarea
        id="assistant-prompt"
        name="assistant-prompt"
        bind:this={textarea}
        bind:value={prompt}
        onkeydown={submitShortcut}
        maxlength="6000"
        rows="3"
        placeholder={availableProviders.length ? 'Ask what happened, why it happened, or what to inspect next…' : 'Install a supported provider CLI to ask about this trace.'}
        disabled={waiting || !availableProviders.length}
      ></textarea>
      <div class="composer-footer">
        <span>{prompt.length.toLocaleString()} / 6,000 · {sendShortcutLabel} Enter to send</span>
        <button type="submit" disabled={!canSubmit}>
          {#if waiting}<i class="send-spinner" aria-hidden="true"></i>Waiting{:else}Ask {selectedProvider?.label ?? 'assistant'}<span aria-hidden="true">↗</span>{/if}
        </button>
      </div>
    </div>
    {#if sendError}<p class="send-error" role="alert"><strong>Request failed.</strong> {sendError} Your question is still in the composer.</p>{/if}
  </form>
</section>

<style>
  .assistant-workspace { --assistant-line: rgba(255,255,255,.075); width: 100%; height: 100%; min-width: 0; min-height: 0; display: grid; grid-template-rows: auto auto auto minmax(0, 1fr) auto auto; overflow: hidden; border: 1px solid var(--assistant-line); border-radius: 10px; color: #e9edf4; background: linear-gradient(145deg, rgba(20,27,39,.86), rgba(7,9,13,.96) 42%, rgba(7,8,11,.98)); box-shadow: inset 0 1px rgba(255,255,255,.06), 0 22px 58px rgba(0,0,0,.3); font-family: 'Source Sans 3 Variable', 'Source Sans 3', sans-serif; backdrop-filter: blur(22px); }
  .assistant-header { grid-row: 1; min-width: 0; min-height: 68px; display: flex; align-items: center; justify-content: space-between; gap: 16px; padding: 12px 16px; border-bottom: 1px solid var(--assistant-line); background: linear-gradient(90deg, rgba(111,123,247,.12), rgba(255,255,255,.014) 40%, transparent); }
  .assistant-identity { min-width: 0; display: flex; align-items: center; gap: 11px; }
  .assistant-mark { flex: 0 0 auto; width: 34px; height: 34px; display: grid; place-items: center; border: 1px solid rgba(158,170,255,.38); border-radius: 8px; color: #83a3ff; background: rgba(111,123,247,.15); box-shadow: inset 0 1px rgba(255,255,255,.1), 0 8px 24px rgba(25,51,127,.18); }
  .assistant-mark svg { width: 21px; fill: none; stroke: currentColor; stroke-width: 1.5; }
  .eyebrow { display: block; color: #7e8da3; font-size: 9px; font-weight: 800; letter-spacing: .14em; text-transform: uppercase; }
  h2 { margin: 2px 0 0; color: #f4f7fb; font: 750 16px/1.2 'IBM Plex Sans Variable', 'IBM Plex Sans', sans-serif; }
  .privacy-note { flex: 0 0 auto; display: inline-flex; align-items: center; gap: 6px; color: #9eabc0; font-size: 10px; font-weight: 650; }
  .privacy-note i { width: 6px; height: 6px; border-radius: 50%; background: #63dca5; box-shadow: 0 0 10px rgba(99,220,165,.45); }
  .assistant-close { flex: 0 0 auto; min-height: 30px; padding: 0 9px; border: 1px solid #354156; border-radius: 6px; color: #b8c3d3; background: #111722; font-size: 10px; font-weight: 700; cursor: pointer; }
  .assistant-close:hover { border-color: #596b89; color: white; }
  .assistant-controls { grid-row: 2; min-width: 0; display: grid; grid-template-columns: minmax(160px,.65fr) minmax(300px,1.35fr); gap: 14px; padding: 13px 16px; border-bottom: 1px solid var(--assistant-line); background: rgba(3,5,8,.28); }
  label, legend { color: #8391a6; font-size: 9px; font-weight: 800; letter-spacing: .1em; text-transform: uppercase; }
  .provider-control { min-width: 0; display: grid; align-content: start; gap: 6px; }
  textarea:focus-visible { border-color: #9eaaff; box-shadow: 0 0 0 3px rgba(111,123,247,.18); }
  .provider-loading, .provider-error { min-height: 42px; display: flex; align-items: center; gap: 8px; color: #9aa7b9; font-size: 11px; }
  .provider-loading > span { width: 13px; height: 13px; border: 2px solid #344159; border-top-color: #9eaaff; border-radius: 50%; animation: spin .8s linear infinite; }
  .provider-error { justify-content: space-between; color: #ffaaa6; }
  .provider-error button { padding: 5px 8px; border: 1px solid #744944; border-radius: 4px; color: #ffc0bc; background: rgba(255,113,109,.08); cursor: pointer; }
  fieldset { min-width: 0; margin: 0; padding: 0; border: 0; }
  legend { margin-bottom: 6px; }
  .scope-options { min-width: 0; display: grid; grid-template-columns: 1fr 1fr; gap: 6px; }
  .scope-options label { min-width: 0; min-height: 42px; display: flex; align-items: center; gap: 8px; padding: 6px 9px; border: 1px solid #2c3749; border-radius: 6px; color: inherit; background: rgba(12,17,25,.8); cursor: pointer; text-transform: none; letter-spacing: 0; }
  .scope-options label:hover { border-color: #435572; }
  .scope-options label.active { border-color: rgba(158,170,255,.55); background: rgba(111,123,247,.12); box-shadow: inset 0 -2px #6f7bf7; }
  .scope-options label.disabled { opacity: .48; cursor: not-allowed; }
  .scope-options input { flex: 0 0 auto; width: 14px; height: 14px; accent-color: #9eaaff; }
  .scope-options span { min-width: 0; }
  .scope-options strong, .scope-options small { display: block; overflow: hidden; white-space: nowrap; text-overflow: ellipsis; }
  .scope-options strong { color: #dce3ed; font-size: 11px; }
  .scope-options small { margin-top: 2px; color: #7f8da1; font-size: 9px; font-weight: 500; }
  .context-disclosure { grid-column: 1 / -1; display: grid; gap: 6px; margin: -2px 0 0; padding: 8px 10px; border: 1px solid rgba(241,190,115,.28); border-radius: 6px; background: rgba(241,190,115,.06); }
  .context-disclosure p { margin: 0; color: #c9d3e1; font-size: 12px; line-height: 1.45; }
  .context-disclosure .containment strong { color: #f0f4fa; }
  .context-disclosure .containment em { display: block; color: #f1be73; font-style: normal; }
  .context-disclosure .containment.weaker { padding-left: 8px; border-left: 2px solid #f1be73; }
  .context-disclosure .consent { display: flex; align-items: center; gap: 8px; color: #f0f4fa; font-size: 12px; font-weight: 650; text-transform: none; letter-spacing: 0; cursor: pointer; }
  .context-disclosure .consent input { width: 15px; height: 15px; accent-color: #f1be73; }
  .coverage { display: flex; flex-wrap: wrap; align-items: baseline; gap: 4px 10px; color: #c9d3e1; font-size: 12px; line-height: 1.45; }
  .coverage > span { flex: 1 1 260px; min-width: 0; }
  .coverage strong { color: #f0f4fa; }
  .coverage em { display: block; color: #f2c57f; font-style: normal; }
  .coverage button { flex: 0 0 auto; padding: 3px 8px; border: 1px solid #5a4a2c; border-radius: 4px; color: #f2d7a6; background: rgba(241,190,115,.08); font-size: 11px; font-weight: 650; cursor: pointer; }
  .coverage button:hover { border-color: #8a7242; color: white; }
  .prompt-preview { max-height: 180px; margin: 0; padding: 8px 10px; overflow: auto; border: 1px solid #2c3749; border-radius: 5px; color: #c5d0e0; background: #080b11; font: 11px/1.5 'IBM Plex Mono', monospace; white-space: pre-wrap; overflow-wrap: anywhere; }
  .assistant-off { color: #c9d3e1; }
  .message-basis { display: block; margin-top: 8px; padding-top: 6px; border-top: 1px solid rgba(255,255,255,.07); color: #93a1b6; font-size: 11px; line-height: 1.4; }
  .unavailable-providers { grid-row: 3; border-bottom: 1px solid var(--assistant-line); background: rgba(8,11,16,.64); }
  .unavailable-providers summary { padding: 8px 16px; color: #7f8da1; font-size: 10px; cursor: pointer; }
  .unavailable-providers ul { display: grid; gap: 7px; margin: 0; padding: 0 16px 11px 34px; }
  .unavailable-providers li { color: #8795a9; font-size: 10px; line-height: 1.35; }
  .unavailable-providers li strong { margin-right: 6px; color: #b7c1cf; }
  .conversation { grid-row: 4; min-width: 0; min-height: 0; overflow-y: auto; overscroll-behavior: contain; padding: 14px 16px; scrollbar-color: #354156 transparent; }
  .conversation-empty { height: 100%; min-height: 100px; display: grid; place-content: center; justify-items: center; gap: 5px; padding: 20px; text-align: center; }
  .conversation-empty > span { color: #9eaaff; font-size: 28px; }
  .conversation-empty strong { color: #dfe6f0; font-size: 13px; }
  .conversation-empty p { max-width: 410px; margin: 0; color: #7f8da1; font-size: 11px; line-height: 1.55; }
  .history-boundary { margin: 0 auto 10px; color: #687589; font-size: 9px; text-align: center; }
  .provider-notice { margin: 0 0 10px; padding: 7px 9px; border: 1px solid rgba(158,170,255,.2); border-radius: 6px; color: #91a3bd; background: rgba(111,123,247,.07); font-size: 10px; text-align: center; }
  .message { max-width: min(86%, 680px); margin: 0 0 12px auto; padding: 10px 12px; border: 1px solid rgba(158,170,255,.24); border-radius: 8px 8px 2px 8px; background: rgba(111,123,247,.1); }
  .message.answer { margin-right: auto; margin-left: 0; border-color: var(--assistant-line); border-radius: 8px 8px 8px 2px; background: rgba(255,255,255,.026); box-shadow: inset 2px 0 #6f7bf7; }
  .message-meta { display: flex; align-items: center; justify-content: space-between; gap: 12px; }
  .message-meta strong { color: #aebbd0; font-size: 9px; font-weight: 750; letter-spacing: .06em; text-transform: uppercase; }
  .message-meta span { color: #657388; font: 9px 'IBM Plex Mono', monospace; }
  .message > p { margin: 5px 0 0; color: #d9e0e9; font-size: 12px; line-height: 1.58; white-space: pre-wrap; overflow-wrap: anywhere; }
  .markdown-content { min-width: 0; margin-top: 9px; color: #d9e0e9; font-size: 12px; line-height: 1.62; overflow-wrap: anywhere; }
  .markdown-content :global(> :first-child) { margin-top: 0; }
  .markdown-content :global(> :last-child) { margin-bottom: 0; }
  .markdown-content :global(h1), .markdown-content :global(h2), .markdown-content :global(h3), .markdown-content :global(h4) { margin: 18px 0 7px; color: #f2f5fa; font-family: 'IBM Plex Sans Variable', 'IBM Plex Sans', sans-serif; font-weight: 720; line-height: 1.25; letter-spacing: -.012em; }
  .markdown-content :global(h1) { padding-bottom: 8px; border-bottom: 1px solid rgba(255,255,255,.09); font-size: 18px; }
  .markdown-content :global(h2) { padding-left: 9px; border-left: 2px solid #6790ff; font-size: 15px; }
  .markdown-content :global(h3) { color: #dfe6f1; font-size: 13px; }
  .markdown-content :global(h4) { color: #cbd5e3; font-size: 12px; }
  .markdown-content :global(p) { margin: 7px 0 11px; }
  .markdown-content :global(strong) { color: #f0f4fa; font-weight: 720; }
  .markdown-content :global(em) { color: #b9c6da; }
  .markdown-content :global(ul), .markdown-content :global(ol) { display: grid; gap: 5px; margin: 8px 0 12px; padding-left: 21px; }
  .markdown-content :global(li) { padding-left: 2px; }
  .markdown-content :global(li::marker) { color: #789bff; font-weight: 700; }
  .markdown-content :global(li > p) { margin: 0; }
  .markdown-content :global(code) { padding: 1px 5px; border: 1px solid rgba(126,163,255,.18); border-radius: 4px; color: #c4d2ff; background: rgba(65,105,225,.1); font: 10.5px/1.5 'IBM Plex Mono', monospace; overflow-wrap: anywhere; }
  .markdown-content :global(pre) { max-width: 100%; margin: 10px 0 13px; overflow: auto; border: 1px solid #263247; border-radius: 7px; background: #080c12; box-shadow: inset 3px 0 #315bcf; }
  .markdown-content :global(pre code) { display: block; min-width: max-content; padding: 11px 13px; border: 0; border-radius: 0; color: #d5deeb; background: transparent; font-size: 10px; line-height: 1.6; overflow-wrap: normal; }
  .markdown-content :global(blockquote) { margin: 10px 0; padding: 8px 11px; border-left: 2px solid #5277dc; color: #aebbd0; background: rgba(65,105,225,.065); }
  .markdown-content :global(blockquote p) { margin: 0; }
  .markdown-content :global(a) { color: #8caaff; text-decoration-color: rgba(140,170,255,.42); text-underline-offset: 2px; }
  .markdown-content :global(a:hover) { color: #b8c9ff; text-decoration-color: currentColor; }
  .markdown-content :global(hr) { height: 1px; margin: 15px 0; border: 0; background: rgba(255,255,255,.09); }
  .markdown-content :global(table) { display: block; width: 100%; max-width: 100%; margin: 10px 0 13px; overflow-x: auto; border-collapse: collapse; font-size: 10px; }
  .markdown-content :global(th), .markdown-content :global(td) { padding: 6px 8px; border: 1px solid #263247; text-align: left; white-space: nowrap; }
  .markdown-content :global(th) { color: #c7d2e2; background: #111722; }
  .markdown-content :global(.markdown-image-label) { color: #78879d; font-style: italic; }
  .waiting-message { display: flex; align-items: center; gap: 10px; margin-top: 4px; color: #aeb9c8; }
  .waiting-message > span { display: flex; gap: 3px; padding: 8px 10px; border: 1px solid var(--assistant-line); border-radius: 8px 8px 8px 2px; background: rgba(255,255,255,.025); }
  .waiting-message i { width: 4px; height: 4px; border-radius: 50%; background: #9eaaff; animation: pulse 1.1s infinite ease-in-out; }
  .waiting-message i:nth-child(2) { animation-delay: .16s; }.waiting-message i:nth-child(3) { animation-delay: .32s; }
  .waiting-message strong, .waiting-message small { display: block; }
  .waiting-message strong { font-size: 11px; }.waiting-message small { margin-top: 2px; color: #718096; font-size: 9px; }
  .starter-row { grid-row: 5; min-width: 0; display: flex; gap: 6px; overflow-x: auto; padding: 10px 16px 0; border-top: 1px solid var(--assistant-line); }
  .starter-row button { flex: 0 0 auto; max-width: 250px; display: flex; align-items: center; gap: 7px; padding: 7px 9px; border: 1px solid #293548; border-radius: 6px; color: #9eacbf; text-align: left; background: rgba(13,19,28,.8); font-size: 9px; cursor: pointer; }
  .starter-row button:hover { border-color: #496086; color: #d9e2ef; background: rgba(111,123,247,.09); }
  .starter-row button:disabled { opacity: .42; cursor: not-allowed; }
  .starter-row button span { flex: 0 0 auto; width: 16px; height: 16px; display: grid; place-items: center; border-radius: 4px; color: #9db3f2; background: rgba(111,123,247,.16); font: 8px 'IBM Plex Mono', monospace; }
  .composer { grid-row: 6; padding: 10px 16px 16px; }
  .composer > label { display: block; margin-bottom: 6px; }
  .composer-field { overflow: hidden; border: 1px solid #344156; border-radius: 8px; background: rgba(10,14,20,.96); box-shadow: inset 0 1px rgba(255,255,255,.025); }
  .composer-field:focus-within { border-color: #9eaaff; box-shadow: 0 0 0 3px rgba(111,123,247,.15); }
  .composer-field.error { border-color: rgba(255,113,109,.55); }
  textarea { box-sizing: border-box; width: 100%; min-height: 72px; max-height: 170px; resize: vertical; display: block; padding: 10px 11px 6px; border: 0; outline: 0; color: #e6ebf2; background: transparent; font: 12px/1.5 'Source Sans 3 Variable', sans-serif; }
  textarea::placeholder { color: #5f6d80; }
  .composer-footer { min-width: 0; min-height: 38px; display: flex; align-items: center; justify-content: space-between; gap: 12px; padding: 5px 6px 6px 11px; border-top: 1px solid rgba(255,255,255,.045); }
  .composer-footer > span { min-width: 0; overflow: hidden; color: #667489; font-size: 9px; white-space: nowrap; text-overflow: ellipsis; }
  .composer-footer button { min-height: 29px; display: inline-flex; align-items: center; gap: 7px; padding: 0 10px; border: 1px solid #567df0; border-radius: 5px; color: white; background: #6f7bf7; font-size: 10px; font-weight: 700; cursor: pointer; }
  .composer-footer button:hover { background: #4f5bd5; }.composer-footer button:disabled { border-color: #2e3848; color: #637085; background: #171d27; cursor: not-allowed; }
  .send-spinner { width: 10px; height: 10px; border: 1px solid rgba(255,255,255,.35); border-top-color: white; border-radius: 50%; animation: spin .8s linear infinite; }
  .send-error { margin: 7px 2px 0; color: #e89b97; font-size: 10px; line-height: 1.4; }.send-error strong { color: #ffb3af; }
  button:focus-visible, summary:focus-visible, .scope-options label:has(input:focus-visible) { outline: 2px solid #7c9cff; outline-offset: 2px; }
  @keyframes spin { to { transform: rotate(360deg); } }
  @keyframes pulse { 0%,70%,100% { opacity: .3; transform: translateY(0); } 35% { opacity: 1; transform: translateY(-2px); } }
  @media (max-width: 720px) { .assistant-controls { grid-template-columns: 1fr; }.scope-options { grid-template-columns: 1fr; }.privacy-note { display: none; }.message { max-width: 94%; }.starter-row button { max-width: 220px; } }
  @media (max-height: 620px) {
    .assistant-workspace { grid-template-rows: auto auto 0 minmax(40px, 1fr) 0 auto; overflow: hidden; }
    .assistant-header { min-height: 52px; padding-block: 8px; background: rgba(9, 13, 20, .98); }
    .assistant-controls { grid-template-columns: minmax(130px, .55fr) minmax(280px, 1.45fr); gap: 8px; padding-block: 8px; }
    /* The disclosure and its consent stay visible however short the window is. */
    .context-disclosure { padding: 5px 8px; }
    .context-disclosure p { font-size: 11px; line-height: 1.3; }
    .coverage { font-size: 11px; line-height: 1.3; }
    .prompt-preview { max-height: 84px; }
    .unavailable-providers { display: none; }
    .scope-options { grid-template-columns: 1fr 1fr; }
    .scope-options label { height: 36px; min-height: 36px; }
    .conversation { min-height: 0; padding-block: 8px; }
    .conversation-empty { min-height: 54px; padding: 8px; }
    .conversation-empty > span, .conversation-empty p { display: none; }
    .starter-row { display: none; }
    .composer { padding-block: 6px 8px; }
    textarea { min-height: 44px; height: 44px; padding-block: 7px 4px; resize: none; }
    .composer-footer { min-height: 32px; }
  }
  @media (prefers-reduced-motion: reduce) { .provider-loading > span, .send-spinner, .waiting-message i { animation: none; } }
</style>
