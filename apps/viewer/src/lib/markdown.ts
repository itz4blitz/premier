import { marked, Renderer, type Tokens } from 'marked';

const htmlEscapes: Record<string, string> = {
  '&': '&amp;',
  '<': '&lt;',
  '>': '&gt;',
  '"': '&quot;',
  "'": '&#39;'
};

function escapeHtml(value: string): string {
  return value.replace(/[&<>"']/g, (character) => htmlEscapes[character] ?? character);
}

/** Escape Markdown prose. Well-formed character references stay as written; they can only ever decode to text. */
function escapeText(value: string): string {
  return value.replace(/[<>"']|&(?!(?:#\d{1,7}|#[Xx][a-fA-F0-9]{1,6}|\w+);)/g, (character) => htmlEscapes[character] ?? character);
}

function safeHref(href: string): string | null {
  const trimmed = href.trim();
  // Protocol-relative and backslash forms leave the origin, so they are not "relative" links.
  if (/^[/\\]{2}|^\/\\/.test(trimmed)) return null;
  if (trimmed.startsWith('#') || trimmed.startsWith('/') || trimmed.startsWith('./') || trimmed.startsWith('../')) {
    return trimmed;
  }
  try {
    const url = new URL(trimmed);
    return ['http:', 'https:', 'mailto:'].includes(url.protocol) ? trimmed : null;
  } catch {
    return null;
  }
}

/**
 * Every renderer that receives source text escapes it unconditionally. marked hands raw HTML to `text`
 * (flagged `escaped`) while it is inside a `<code>`, `<pre>`, `<kbd>`, or `<script>` block, so the token's
 * own `escaped` flag is never trusted here.
 */
class AssistantRenderer extends Renderer {
  override html({ text }: Tokens.HTML | Tokens.Tag): string {
    return escapeHtml(text);
  }

  override text(token: Tokens.Text | Tokens.Escape): string {
    if ('tokens' in token && token.tokens) return this.parser.parseInline(token.tokens);
    return escapeText(token.text);
  }

  override code({ text, lang }: Tokens.Code): string {
    const language = (lang ?? '').match(/^[A-Za-z0-9_+#.-]+/)?.[0];
    const body = `${escapeHtml(text.replace(/\n$/, ''))}\n`;
    return language
      ? `<pre><code class="language-${escapeHtml(language)}">${body}</code></pre>\n`
      : `<pre><code>${body}</code></pre>\n`;
  }

  override codespan({ text }: Tokens.Codespan): string {
    return `<code>${escapeHtml(text)}</code>`;
  }

  override link({ href, title, tokens }: Tokens.Link): string {
    const label = this.parser.parseInline(tokens);
    const safe = safeHref(href);
    if (!safe) return label;
    const titleAttribute = title ? ` title="${escapeHtml(title)}"` : '';
    return `<a href="${escapeHtml(safe)}" target="_blank" rel="noreferrer noopener"${titleAttribute}>${label}</a>`;
  }

  override image({ text }: Tokens.Image): string {
    return `<span class="markdown-image-label">[Image: ${escapeHtml(text || 'attachment')}]</span>`;
  }
}

const allowedElements = new Set([
  'a', 'blockquote', 'br', 'code', 'del', 'em', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'hr', 'input',
  'li', 'ol', 'p', 'pre', 'span', 'strong', 'table', 'tbody', 'td', 'th', 'thead', 'tr', 'ul'
]);
const voidElements = new Set(['br', 'hr', 'input']);

/** The only attributes the assistant surface needs; everything else is dropped. */
function allowedAttributes(tag: string, element: Element): string | null {
  if (tag === 'a') {
    const href = safeHref(element.getAttribute('href') ?? '');
    if (!href) return null;
    const title = element.getAttribute('title');
    return ` href="${escapeHtml(href)}" target="_blank" rel="noreferrer noopener"${title ? ` title="${escapeHtml(title)}"` : ''}`;
  }
  if (tag === 'input') {
    if (element.getAttribute('type')?.toLowerCase() !== 'checkbox') return null;
    return ` type="checkbox" disabled${element.hasAttribute('checked') ? ' checked' : ''}`;
  }
  if (tag === 'code') {
    const language = element.getAttribute('class') ?? '';
    return /^language-[A-Za-z0-9_+#.-]+$/.test(language) ? ` class="${escapeHtml(language)}"` : '';
  }
  if (tag === 'span') {
    return element.getAttribute('class') === 'markdown-image-label' ? ' class="markdown-image-label"' : '';
  }
  if (tag === 'td' || tag === 'th') {
    const align = element.getAttribute('align')?.toLowerCase() ?? '';
    return ['left', 'center', 'right'].includes(align) ? ` align="${align}"` : '';
  }
  if (tag === 'ol') {
    const start = element.getAttribute('start') ?? '';
    return /^\d{1,9}$/.test(start) ? ` start="${start}"` : '';
  }
  return '';
}

function serializeAllowed(node: Node): string {
  let output = '';
  for (const child of node.childNodes) {
    if (child.nodeType === 3) {
      output += escapeHtml(child.nodeValue ?? '');
      continue;
    }
    if (child.nodeType !== 1) continue;
    const element = child as Element;
    const tag = element.localName.toLowerCase();
    // Anything outside the allowlist is removed together with its subtree.
    if (element.namespaceURI !== 'http://www.w3.org/1999/xhtml' || !allowedElements.has(tag)) continue;
    const attributes = allowedAttributes(tag, element);
    if (attributes === null) {
      // A link without a safe destination keeps its (already sanitized) label; other rejects vanish.
      if (tag === 'a') output += serializeAllowed(element);
      continue;
    }
    output += voidElements.has(tag) ? `<${tag}${attributes}>` : `<${tag}${attributes}>${serializeAllowed(element)}</${tag}>`;
  }
  return output;
}

/**
 * Rebuild HTML from a strict element and attribute allowlist. The markup is parsed in an inert document
 * (no script execution, no resource loads) and re-serialized, so nothing reaches `{@html}` that this
 * module did not write itself.
 */
export function sanitizeAssistantHtml(html: string): string {
  if (typeof DOMParser === 'undefined') return escapeHtml(html);
  const parsed = new DOMParser().parseFromString(`<!doctype html><body>${html}`, 'text/html');
  return serializeAllowed(parsed.body);
}

export function renderAssistantMarkdown(source: string): string {
  const rendered = marked.parse(source, {
    gfm: true,
    breaks: true,
    async: false,
    renderer: new AssistantRenderer()
  });
  return sanitizeAssistantHtml(rendered);
}
