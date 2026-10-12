import { fireEvent, render, screen } from '@testing-library/svelte';
import userEvent from '@testing-library/user-event';
import { expect, it, vi } from 'vitest';
import PremierSelect from './PremierSelect.svelte';

const options = [
  { value: 'claude', label: 'Claude', description: 'Verified local CLI' },
  { value: 'codex', label: 'Codex', description: 'Verified local CLI' },
  { value: 'unsafe', label: 'Unsafe provider', disabled: true }
];

it('renders a custom listbox and selects an option', async () => {
  const onchange = vi.fn();
  const user = userEvent.setup();
  render(PremierSelect, { props: { value: 'claude', options, label: 'Local provider', onchange } });
  await user.click(screen.getByRole('button', { name: 'Local provider' }));
  expect(screen.getByRole('listbox', { name: 'Local provider options' })).toBeInTheDocument();
  await user.click(screen.getByRole('option', { name: /Codex/ }));
  expect(onchange).toHaveBeenCalledWith('codex');
  expect(screen.queryByRole('listbox')).not.toBeInTheDocument();
});

it('supports keyboard navigation and escape close', async () => {
  const onchange = vi.fn();
  render(PremierSelect, { props: { value: 'claude', options, label: 'Local provider', onchange } });
  const trigger = screen.getByRole('button', { name: 'Local provider' });
  await fireEvent.keyDown(trigger, { key: 'ArrowDown' });
  await fireEvent.keyDown(screen.getByRole('option', { name: /Claude/ }), { key: 'ArrowDown' });
  await fireEvent.keyDown(screen.getByRole('option', { name: /Codex/ }), { key: 'Enter' });
  expect(onchange).toHaveBeenCalledWith('codex');
  await fireEvent.keyDown(trigger, { key: 'Enter' });
  await fireEvent.keyDown(screen.getByRole('option', { name: /Claude/ }), { key: 'Escape' });
  expect(screen.queryByRole('listbox')).not.toBeInTheDocument();
});

it('supports label typeahead while skipping disabled options', async () => {
  const onchange = vi.fn();
  render(PremierSelect, { props: { value: 'claude', options, label: 'Local provider', onchange } });
  const trigger = screen.getByRole('button', { name: 'Local provider' });
  await fireEvent.keyDown(trigger, { key: 'Enter' });
  await fireEvent.keyDown(screen.getByRole('option', { name: /Claude/ }), { key: 'c' });
  await fireEvent.keyDown(screen.getByRole('option', { name: /Claude/ }), { key: 'o' });
  expect(screen.getByRole('option', { name: /Codex/ })).toHaveFocus();
  await fireEvent.keyDown(screen.getByRole('option', { name: /Codex/ }), { key: 'Enter' });
  expect(onchange).toHaveBeenCalledWith('codex');
});

it('announces the selected value as the description of the labelled trigger', async () => {
  const { rerender } = render(PremierSelect, { props: { value: 'claude', options, label: 'Local provider', onchange: vi.fn() } });
  const trigger = screen.getByRole('button', { name: 'Local provider' });
  expect(trigger).toHaveAccessibleDescription(expect.stringMatching(/^Claude\s*Verified local CLI$/));
  await rerender({ value: 'codex', options, label: 'Local provider', onchange: vi.fn() });
  expect(trigger).toHaveAccessibleDescription(expect.stringMatching(/^Codex\s*Verified local CLI$/));
  await rerender({ value: 'missing', options, label: 'Local provider', onchange: vi.fn() });
  expect(trigger).toHaveAccessibleDescription('Select…');
});

it('keeps the menu inside the component for assistive technology and returns focus on Tab', async () => {
  const user = userEvent.setup();
  render(PremierSelect, { props: { value: 'claude', options, label: 'Local provider', onchange: vi.fn(), id: 'provider-field' } });
  const trigger = screen.getByRole('button', { name: 'Local provider' });
  expect(trigger).toHaveAttribute('id', 'provider-field');
  await user.click(trigger);
  const listbox = screen.getByRole('listbox', { name: 'Local provider options' });
  // Rendered at the document root, owned by the component.
  expect(listbox.parentElement).toBe(document.body);
  expect(trigger).toHaveAttribute('aria-controls', listbox.id);
  expect(trigger.closest('.premier-select')).toHaveAttribute('aria-owns', listbox.id);
  expect(screen.getByRole('option', { name: /Claude/ })).toHaveFocus();
  await user.keyboard('{Tab}');
  expect(screen.queryByRole('listbox')).not.toBeInTheDocument();
  expect(trigger).toHaveFocus();
  expect(trigger.closest('.premier-select')).not.toHaveAttribute('aria-owns');
});
