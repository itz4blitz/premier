import { render, screen } from '@testing-library/svelte';
import userEvent from '@testing-library/user-event';
import { expect, it, vi } from 'vitest';
import FilterBar from './FilterBar.svelte';

const filters = { search: '', category: 'all' as const, actorId: 'root', errorsOnly: false, correlationId: null };
const counts = { all: 39, agent: 1, model: 0, tool: 0, approval: 0, process: 37, other: 0, error: 1 };

it('shows scoped counts and disables unavailable categories', async () => {
  const onchange = vi.fn();
  render(FilterBar, { props: { filters, counts, visible: 39, total: 45, onchange } });
  expect(screen.getByRole('button', { name: 'models' })).toBeDisabled();
  expect(screen.getByRole('button', { name: 'tools' })).toBeDisabled();
  expect(screen.getByRole('button', { name: 'runtime' })).toHaveTextContent('37');
  expect(screen.getByText('39 scoped · 45 total')).toBeInTheDocument();
  await userEvent.click(screen.getByRole('button', { name: 'runtime' }));
  expect(onchange).toHaveBeenCalledWith({ ...filters, category: 'process', errorsOnly: false });
});

it('offers an Other tab only when the run has kinds no tab is named for', async () => {
  const onchange = vi.fn();
  const { rerender } = render(FilterBar, { props: { filters, counts, visible: 39, total: 45, onchange } });
  expect(screen.queryByRole('button', { name: 'other' })).not.toBeInTheDocument();
  await rerender({ filters, counts: { ...counts, other: 3 }, visible: 39, total: 45, onchange });
  const other = screen.getByRole('button', { name: 'other' });
  expect(other).toHaveTextContent('3');
  await userEvent.click(other);
  expect(onchange).toHaveBeenCalledWith({ ...filters, category: 'other', errorsOnly: false });
});
