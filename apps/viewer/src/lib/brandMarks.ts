/** Resolve model/provider brand identity for badges and icons. */

export type ProviderBrand =
  | 'anthropic'
  | 'openai'
  | 'xai'
  | 'google'
  | 'meta'
  | 'mistral'
  | 'amazon'
  | 'cohere'
  | 'unknown';

export interface BrandIdentity {
  brand: ProviderBrand;
  label: string;
  /** CSS color for monochrome fills on dark UI */
  color: string;
}

const BRANDS: Record<ProviderBrand, Omit<BrandIdentity, 'brand'>> = {
  anthropic: { label: 'Anthropic', color: '#D4A27F' },
  openai: { label: 'OpenAI', color: '#10A37F' },
  xai: { label: 'xAI', color: '#E8E8E8' },
  google: { label: 'Google', color: '#8AB4F8' },
  meta: { label: 'Meta', color: '#66B2FF' },
  mistral: { label: 'Mistral', color: '#FF7000' },
  amazon: { label: 'Amazon', color: '#FF9900' },
  cohere: { label: 'Cohere', color: '#39594D' },
  unknown: { label: 'Model', color: '#8BA4FF' }
};

/**
 * Whole-word patterns, tried in order. Names are matched as words (`llama`, not the tail of
 * `ollama`; `meta`, not the head of `metadata`), and a host such as Ollama, Bedrock or Vertex is
 * never taken for the maker of the model it serves: the model name decides first.
 */
/** A family name as a word; a version may follow it directly (`llama3`, `gemma2`), letters may not. */
const names = (...list: string[]) => new RegExp(`\\b(?:${list.join('|')})(?![a-z])`);
const MODEL_PATTERNS: Array<[ProviderBrand, RegExp]> = [
  ['anthropic', names('anthropic', 'claude', 'sonnet', 'opus', 'haiku')],
  ['openai', new RegExp(`${names('openai', 'chatgpt', 'davinci', 'whisper', 'codex', 'gpt').source}|\\bo[134](?![a-z0-9])`)],
  ['xai', names('xai', 'grok', 'spacexai')],
  ['google', names('google', 'gemini', 'gemma', 'bard', 'palm')],
  ['meta', names('meta', 'facebook', 'llama', 'codellama')],
  ['mistral', names('mistral', 'mixtral', 'codestral', 'ministral', 'pixtral')],
  ['amazon', names('amazon', 'titan', 'nova')],
  ['cohere', names('cohere', 'command ?r')]
];
/** Hosts that only decide when the model name names no maker. */
const HOST_PATTERNS: Array<[ProviderBrand, RegExp]> = [
  ['google', names('vertex')],
  ['amazon', names('bedrock')]
];

function matchBrand(text: string, patterns: Array<[ProviderBrand, RegExp]>): ProviderBrand | null {
  // Separators become spaces so `claude-3`, `meta/llama` and `gpt_4` all present whole words.
  const words = text.toLowerCase().replace(/[^a-z0-9]+/g, ' ');
  return patterns.find(([, pattern]) => pattern.test(words))?.[0] ?? null;
}

export function resolveProviderBrand(
  provider?: string | null,
  model?: string | null
): BrandIdentity {
  const brand = matchBrand(model ?? '', MODEL_PATTERNS)
    ?? matchBrand(provider ?? '', MODEL_PATTERNS)
    ?? matchBrand(`${provider ?? ''} ${model ?? ''}`, HOST_PATTERNS)
    ?? 'unknown';
  return { brand, ...BRANDS[brand] };
}
