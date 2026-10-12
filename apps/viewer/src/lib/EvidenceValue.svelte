<script lang="ts">
  import { ChevronDown, ChevronUp, EyeOff } from '@lucide/svelte';
  let { value, limit = 700 }: { value: unknown; limit?: number } = $props();
  let expanded = $state(false);

  /** What the recorder (`[REDACTED]`) and the viewer's safe export (`[REDACTED BY PREMIER]`) write in place of a value. */
  const redactionMarker = /\[REDACTED(?: BY PREMIER)?\]/g;

  const text = $derived(format(value));
  const isLong = $derived(text.length > limit);
  const visible = $derived(expanded || !isLong ? text : `${text.slice(0, limit).trimEnd()}\n…`);
  const redactions = $derived(text.includes('[REDACTED') ? (text.match(redactionMarker)?.length ?? 0) : 0);
  const fullyRedacted = $derived(redactions === 1 && typeof value === 'string' && value.trim().replace(redactionMarker, '') === '');

  function format(current: unknown): string {
    if (current === null) return 'null';
    if (current === undefined) return '—';
    if (typeof current === 'string') return current;
    if (typeof current === 'number' || typeof current === 'boolean') return String(current);
    return JSON.stringify(current, null, 2);
  }
</script>

<div class="evidence-value" class:expanded>
  {#if redactions}
    <span class="redaction-chip" title="Premier replaced this before the event was stored. The original is not in the trace.">
      <EyeOff size={12} aria-hidden="true" />{fullyRedacted ? 'Redacted by Premier' : `Contains ${redactions} value${redactions === 1 ? '' : 's'} redacted by Premier`}
    </span>
  {/if}
  <pre class:redacted={fullyRedacted}>{visible}</pre>
  {#if isLong}
    <button type="button" class="value-toggle" aria-expanded={expanded} onclick={() => (expanded = !expanded)}>
      {#if expanded}<ChevronUp size={14} aria-hidden="true" />Collapse value{:else}<ChevronDown size={14} aria-hidden="true" />Show complete value <span>{text.length.toLocaleString()} characters</span>{/if}
    </button>
  {/if}
</div>

<style>
  .evidence-value { min-width: 0; }
  pre { margin: 8px 0 0; overflow: auto; color: #c8d0dc; font: 11.5px/1.65 'IBM Plex Mono', monospace; overflow-wrap: anywhere; white-space: pre-wrap; }
  pre.redacted { color: #8190a5; font-style: italic; }
  .redaction-chip { display: inline-flex; align-items: center; gap: 5px; margin-top: 8px; padding: 2px 7px; border: 1px solid rgba(240,189,118,.34); border-radius: 999px; color: #f0c88a; background: rgba(240,189,118,.08); font: 700 10px 'Source Sans 3 Variable', 'Source Sans 3', sans-serif; }
  .value-toggle { width: 100%; min-height: 34px; display: flex; align-items: center; gap: 7px; margin-top: 8px; padding: 0 9px; border: 1px solid #2a3547; border-radius: 5px; color: var(--blue-strong); background: #0e141e; font: 700 11px 'Source Sans 3 Variable', 'Source Sans 3', sans-serif; text-align: left; cursor: pointer; }
  .value-toggle span { margin-left: auto; color: #8190a5; font-size: 10px; font-weight: 600; }
  .value-toggle:hover { border-color: #4a5f8d; color: #e5ebff; background: #151d2b; }
  .value-toggle:focus-visible { outline: 2px solid var(--focus); outline-offset: 2px; }
</style>
