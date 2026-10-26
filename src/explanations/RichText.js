import React from 'react';
import GlossaryTerm from '../components/GlossaryTerm';
import { GLOSSARY_TERMS, glossaryDefinition } from './glossary';

const escapeRegExp = (value) => value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
const TERM_SOURCE = GLOSSARY_TERMS.map(escapeRegExp).join('|');

// Wrap the first occurrence of each known glossary term in a tooltip trigger.
// Unknown terms and all surrounding punctuation stay exactly as written.
export function annotateText(text) {
  if (typeof text !== 'string' || !text) return [];
  const pattern = new RegExp(`\\b(${TERM_SOURCE})\\b`, 'gi');
  const nodes = [];
  const seen = new Set();
  let lastIndex = 0;
  let match;
  while ((match = pattern.exec(text)) !== null) {
    const canonical = match[0].toLowerCase();
    if (!glossaryDefinition(canonical) || seen.has(canonical)) continue;
    seen.add(canonical);
    if (match.index > lastIndex) nodes.push(text.slice(lastIndex, match.index));
    nodes.push(
      <GlossaryTerm key={`${canonical}-${match.index}`} term={canonical}>
        {match[0]}
      </GlossaryTerm>,
    );
    lastIndex = match.index + match[0].length;
  }
  if (lastIndex < text.length) nodes.push(text.slice(lastIndex));
  return nodes;
}

export default function RichText({ text }) {
  const nodes = annotateText(text);
  return <>{nodes.length ? nodes : text}</>;
}
