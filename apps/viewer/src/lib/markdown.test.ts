import { describe, expect, it } from 'vitest';
import { renderAssistantMarkdown, sanitizeAssistantHtml } from './markdown';

describe('renderAssistantMarkdown', () => {
  it('renders the structured Markdown used by trace copilots', () => {
    const html = renderAssistantMarkdown([
      '## Highest-impact issue',
      '',
      '**The reviewer returned no evidence.**',
      '',
      '- No model call',
      '- No tool execution',
      '',
      '`correlation_id` was empty.',
      '',
      '```sh',
      'premier inspect trace-1',
      '```'
    ].join('\n'));

    expect(html).toContain('<h2>Highest-impact issue</h2>');
    expect(html).toContain('<strong>The reviewer returned no evidence.</strong>');
    expect(html).toContain('<ul>');
    expect(html).toContain('<code>correlation_id</code>');
    expect(html).toContain('<pre><code class="language-sh">premier inspect trace-1');
  });

  it('escapes raw HTML and refuses unsafe or embedded resources', () => {
    const html = renderAssistantMarkdown([
      '<script>alert("trace")</script>',
      '[unsafe](javascript:alert(1))',
      '![tracking](https://example.com/pixel.gif)',
      '[safe](https://premier.dev/docs)'
    ].join('\n\n'));

    expect(html).not.toContain('<script>');
    expect(html).not.toContain('javascript:');
    expect(html).not.toContain('<img');
    expect(html).toContain('href="https://premier.dev/docs"');
    expect(html).toContain('rel="noreferrer noopener"');
  });

  it('keeps tables, task lists, and image labels readable', () => {
    const html = renderAssistantMarkdown([
      '| Step | Result |',
      '| --- | :-: |',
      '| plan | ok |',
      '',
      '- [x] verified',
      '- [ ] pending',
      '',
      '![diagram](https://example.com/a.png)'
    ].join('\n'));
    const container = document.createElement('div');
    container.innerHTML = html;
    expect(container.querySelectorAll('table tbody td')).toHaveLength(2);
    expect(container.querySelector('td[align="center"]')).toHaveTextContent('ok');
    const boxes = [...container.querySelectorAll<HTMLInputElement>('input[type="checkbox"]')];
    expect(boxes).toHaveLength(2);
    expect(boxes.every((box) => box.disabled)).toBe(true);
    expect(boxes[0].checked).toBe(true);
    expect(container.querySelector('.markdown-image-label')).toHaveTextContent('[Image: diagram]');
  });
});

describe('renderAssistantMarkdown raw HTML safety', () => {
  const payloads = [
    '<script>alert(1)</script>',
    '<img src=x onerror=alert(1)>',
    '<svg/onload=alert(1)>',
    '<iframe src="javascript:alert(1)"></iframe>',
    '<a href="javascript:alert(1)">click</a>',
    '<base href="https://evil.example/">',
    '<form action="https://evil.example/"><input name=q></form>'
  ];
  const openers = ['<code>', '<pre>', '<kbd>', '<script>', '<style>', '<textarea>'];
  const allowedTags = new Set([
    'a', 'blockquote', 'br', 'code', 'del', 'em', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'hr', 'input',
    'li', 'ol', 'p', 'pre', 'span', 'strong', 'table', 'tbody', 'td', 'th', 'thead', 'tr', 'ul'
  ]);

  function assertInert(source: string): HTMLDivElement {
    const html = renderAssistantMarkdown(source);
    const container = document.createElement('div');
    container.innerHTML = html;
    for (const element of container.querySelectorAll('*')) {
      const tag = element.tagName.toLowerCase();
      expect(allowedTags.has(tag), `unexpected <${tag}> for ${JSON.stringify(source)} -> ${html}`).toBe(true);
      for (const attribute of element.attributes) {
        expect(attribute.name.startsWith('on'), `event handler ${attribute.name} for ${JSON.stringify(source)}`).toBe(false);
        expect(attribute.value.toLowerCase().replace(/\s/g, '')).not.toContain('javascript:');
      }
      if (tag === 'input') {
        expect(element.getAttribute('type')).toBe('checkbox');
        expect(element.hasAttribute('disabled')).toBe(true);
      }
    }
    expect(container.querySelector('script, img, svg, iframe, base, form, meta, style, object, embed, link')).toBeNull();
    return container;
  }

  it('keeps raw HTML inert after an inline code, pre, kbd, or script opener', () => {
    for (const opener of openers) {
      for (const payload of payloads) {
        assertInert(`x ${opener} ${payload}`);
        assertInert(`${opener}${payload}`);
        assertInert(`${opener}\n${payload}\n`);
        assertInert(`- item ${opener} ${payload}`);
        assertInert(`> quote ${opener} ${payload}`);
        assertInert(`| a |\n| - |\n| ${opener} ${payload} |`);
        assertInert(`# heading ${opener} ${payload}`);
        assertInert(`**bold ${opener} ${payload}**`);
      }
    }
  });

  it('shows raw HTML as literal text in inline, code span, and fenced contexts', () => {
    for (const payload of payloads) {
      assertInert(`plain text ${payload}`);
      assertInert(payload);
      expect(assertInert(`\`${payload}\``).querySelector('code')?.textContent).toBe(payload);
      expect(assertInert(`\`\`\`html\n${payload}\n\`\`\``).querySelector('pre code')?.textContent).toContain(payload);
    }
    expect(assertInert('x <code> <svg/onload=alert(1)>').textContent).toContain('<svg/onload=alert(1)>');
    expect(assertInert('x <kbd> <img src=x onerror=alert(1)>').textContent).toContain('<img src=x onerror=alert(1)>');
  });

  it('drops javascript:, data:, and vbscript: links however they are written', () => {
    for (const href of ['javascript:alert(1)', 'JaVaScRiPt:alert(1)', 'data:text/html,<script>alert(1)</script>', 'vbscript:msgbox(1)', '//evil.example/x']) {
      const container = assertInert(`[label](${href}) and <code> [again](${href})`);
      expect(container.querySelector('a')).toBeNull();
    }
    assertInert('<javascript:alert(1)>');
    assertInert('[x](https://ok.example "t\\" onmouseover=\\"alert(1)")');
    assertInert('```"><img src=x onerror=alert(1)>\ncode\n```');
  });

  it('strips anything outside the allowlist even if a renderer lets it through', () => {
    const html = sanitizeAssistantHtml('<p onclick="x()">ok <img src=x onerror=alert(1)><a href="javascript:alert(1)" target="_blank">l</a><script>alert(1)</script><a href="https://premier.dev" style="x">s</a><input type="text" value="x"></p>');
    const container = document.createElement('div');
    container.innerHTML = html;
    expect(container.querySelector('img, script, input')).toBeNull();
    expect(container.querySelector('p')?.attributes).toHaveLength(0);
    expect(container.textContent).not.toContain('alert(1)');
    const links = [...container.querySelectorAll('a')];
    expect(links).toHaveLength(1);
    expect(links[0].getAttribute('href')).toBe('https://premier.dev');
    expect(links[0].getAttribute('rel')).toBe('noreferrer noopener');
    expect(links[0].getAttribute('target')).toBe('_blank');
    expect(links[0].hasAttribute('style')).toBe(false);
  });
});
