import { describe, expect, it } from 'vitest';
import { resolveProviderBrand } from './brandMarks';

describe('resolveProviderBrand', () => {
  it('maps anthropic / claude family', () => {
    expect(resolveProviderBrand('anthropic', 'claude-sonnet').brand).toBe('anthropic');
    expect(resolveProviderBrand(null, 'claude-3-opus').brand).toBe('anthropic');
  });

  it('maps openai / codex family', () => {
    expect(resolveProviderBrand('openai', 'gpt-5').brand).toBe('openai');
    expect(resolveProviderBrand(null, 'codex-mini').brand).toBe('openai');
  });

  it('maps xai / grok family', () => {
    expect(resolveProviderBrand('xai', 'grok-3').brand).toBe('xai');
    expect(resolveProviderBrand(null, 'grok-beta').brand).toBe('xai');
  });

  it('maps google / gemini family', () => {
    expect(resolveProviderBrand('google', 'gemini-2.0-flash').brand).toBe('google');
  });

  it('falls back to unknown', () => {
    expect(resolveProviderBrand('acme', 'custom-7b').brand).toBe('unknown');
  });

  it('matches names as whole words, so a host is not taken for the maker of its model', () => {
    // `ollama` ends in "llama": the model it serves decides.
    expect(resolveProviderBrand('ollama', 'qwen2.5-coder').brand).toBe('unknown');
    expect(resolveProviderBrand('ollama', 'mistral:7b').brand).toBe('mistral');
    expect(resolveProviderBrand('ollama', 'gemma2:9b').brand).toBe('google');
    expect(resolveProviderBrand('ollama', 'llama3.2').brand).toBe('meta');
    expect(resolveProviderBrand('ollama', 'codellama:13b').brand).toBe('meta');
    expect(resolveProviderBrand(null, 'meta/llama-3-70b').brand).toBe('meta');
    // Letters inside another word are not a brand.
    expect(resolveProviderBrand('writer', 'palmyra-x5').brand).toBe('unknown');
    expect(resolveProviderBrand('metadata-proxy', 'custom-7b').brand).toBe('unknown');
    expect(resolveProviderBrand('acme', 'turbo3-large').brand).toBe('unknown');
    expect(resolveProviderBrand('innovation-lab', 'custom').brand).toBe('unknown');
  });

  it('lets the model name outrank the service that hosts it', () => {
    expect(resolveProviderBrand('bedrock', 'anthropic.claude-3-5-sonnet').brand).toBe('anthropic');
    expect(resolveProviderBrand('vertex', 'claude-3-opus').brand).toBe('anthropic');
    expect(resolveProviderBrand('bedrock', 'custom-import').brand).toBe('amazon');
    expect(resolveProviderBrand('vertex', 'custom-import').brand).toBe('google');
    expect(resolveProviderBrand('openai', 'o3-mini').brand).toBe('openai');
    expect(resolveProviderBrand(null, 'gpt-4o').brand).toBe('openai');
    expect(resolveProviderBrand(null, 'command-r-plus').brand).toBe('cohere');
  });
});
