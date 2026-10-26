import React, { act } from 'react';
import { createRoot } from 'react-dom/client';
import GlossaryTerm from './GlossaryTerm';
import RichText from '../explanations/RichText';

let container;
let root;

beforeEach(() => {
  container = document.createElement('div');
  document.body.appendChild(container);
  root = createRoot(container);
});

afterEach(() => {
  act(() => root.unmount());
  container.remove();
});

async function render(node) {
  await act(async () => {
    root.render(node);
  });
}

test('opens on hover and closes when the pointer leaves', async () => {
  await render(<p>Use <GlossaryTerm term="phishing">phishing</GlossaryTerm> here.</p>);
  const trigger = container.querySelector('[role="button"]');
  expect(container.querySelector('[role="tooltip"]')).toBeNull();

  await act(async () => {
    trigger.dispatchEvent(new MouseEvent('mouseover', { bubbles: true }));
  });
  expect(container.querySelector('[role="tooltip"]').textContent).toContain('tries to trick you');

  await act(async () => {
    trigger.dispatchEvent(new MouseEvent('mouseout', { bubbles: true }));
  });
  expect(container.querySelector('[role="tooltip"]')).toBeNull();
});

test('opens on keyboard focus, closes on blur, and closes on Escape', async () => {
  await render(<p><GlossaryTerm term="hostname">hostname</GlossaryTerm></p>);
  const trigger = container.querySelector('[role="button"]');

  await act(async () => { trigger.focus(); });
  expect(container.querySelector('[role="tooltip"]')).not.toBeNull();

  await act(async () => { trigger.blur(); });
  expect(container.querySelector('[role="tooltip"]')).toBeNull();

  await act(async () => { trigger.focus(); });
  await act(async () => {
    trigger.dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape', bubbles: true }));
  });
  expect(container.querySelector('[role="tooltip"]')).toBeNull();
});

test('tap pins the tooltip until it is tapped again or dismissed', async () => {
  await render(<p><GlossaryTerm term="review">review</GlossaryTerm></p>);
  const trigger = container.querySelector('[role="button"]');

  await act(async () => { trigger.click(); });
  expect(container.querySelector('[role="tooltip"]')).not.toBeNull();

  // A pinned tooltip survives the pointer leaving the term.
  await act(async () => {
    trigger.dispatchEvent(new MouseEvent('mouseout', { bubbles: true }));
  });
  expect(container.querySelector('[role="tooltip"]')).not.toBeNull();

  await act(async () => { trigger.click(); });
  expect(container.querySelector('[role="tooltip"]')).toBeNull();
});

test('an outside click dismisses a pinned tooltip', async () => {
  await render(<div><GlossaryTerm term="review">review</GlossaryTerm><button type="button">elsewhere</button></div>);
  const trigger = container.querySelector('[role="button"]');
  await act(async () => { trigger.click(); });
  expect(container.querySelector('[role="tooltip"]')).not.toBeNull();

  await act(async () => {
    document.body.dispatchEvent(new MouseEvent('mousedown', { bubbles: true }));
  });
  expect(container.querySelector('[role="tooltip"]')).toBeNull();
});

test('an unknown term is left unannotated', async () => {
  await render(<p><GlossaryTerm term="not-a-real-term">mystery</GlossaryTerm></p>);
  expect(container.querySelector('[role="button"]')).toBeNull();
  expect(container.querySelector('[role="tooltip"]')).toBeNull();
  expect(container.textContent).toBe('mystery');
});

test('RichText annotates the first occurrence of known terms and preserves punctuation', async () => {
  const original = 'Phishing is a scam. A hostname identifies a site, and phishing can repeat.';
  await render(<p><RichText text={original} /></p>);

  const triggers = [...container.querySelectorAll('[role="button"]')];
  expect(triggers).toHaveLength(2);
  expect(triggers[0].textContent).toBe('Phishing');
  expect(triggers[1].textContent).toBe('hostname');
  expect(container.textContent).toBe(original);
});
