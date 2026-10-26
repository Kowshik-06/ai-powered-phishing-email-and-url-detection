import React, { useEffect, useId, useRef, useState } from 'react';
import { glossaryDefinition } from '../explanations/glossary';

// Accessible glossary trigger.
// - Desktop: hover and keyboard focus open the tooltip.
// - Touch: tap toggles a pinned tooltip; tap again, Escape, or an outside tap closes it.
// - Unknown terms are left unannotated by rendering the children only.
export default function GlossaryTerm({ term, children }) {
  const definition = glossaryDefinition(term);
  const tooltipId = useId();
  const rootRef = useRef(null);
  const triggerRef = useRef(null);
  const [open, setOpen] = useState(false);
  const [pinned, setPinned] = useState(false);
  const [placement, setPlacement] = useState('left');

  useEffect(() => {
    if (!open) return undefined;
    const onDocumentPointerDown = (event) => {
      if (rootRef.current && !rootRef.current.contains(event.target)) {
        setPinned(false);
        setOpen(false);
      }
    };
    document.addEventListener('mousedown', onDocumentPointerDown);
    document.addEventListener('touchstart', onDocumentPointerDown);
    return () => {
      document.removeEventListener('mousedown', onDocumentPointerDown);
      document.removeEventListener('touchstart', onDocumentPointerDown);
    };
  }, [open]);

  if (!definition) return <>{children}</>;

  const show = () => {
    const rect = triggerRef.current && triggerRef.current.getBoundingClientRect
      ? triggerRef.current.getBoundingClientRect()
      : null;
    if (rect) {
      const viewportWidth = typeof window !== 'undefined' ? window.innerWidth : 1024;
      const spaceLeft = rect.left;
      const spaceRight = viewportWidth - rect.right;
      if (spaceLeft < 140) setPlacement('left');
      else if (spaceRight < 140) setPlacement('right');
      else setPlacement('center');
    }
    setOpen(true);
  };

  const hide = () => {
    if (!pinned) setOpen(false);
  };

  const close = () => {
    setPinned(false);
    setOpen(false);
  };

  const onKeyDown = (event) => {
    if (event.key === 'Escape') {
      event.stopPropagation();
      close();
      return;
    }
    if (event.key === 'Enter' || event.key === ' ') {
      event.preventDefault();
      if (pinned) {
        close();
      } else {
        setPinned(true);
        setOpen(true);
      }
    }
  };

  const onClick = (event) => {
    event.preventDefault();
    event.stopPropagation();
    if (pinned) {
      close();
    } else {
      setPinned(true);
      setOpen(true);
    }
  };

  const placementClass = placement === 'right'
    ? 'right-0'
    : placement === 'center'
      ? 'left-1/2 -translate-x-1/2'
      : 'left-0';

  return (
    <span ref={rootRef} className="relative inline-block">
      <span
        ref={triggerRef}
        role="button"
        tabIndex={0}
        aria-describedby={open ? tooltipId : undefined}
        aria-expanded={open}
        className="cursor-help border-b border-dotted border-cyan-400/70 text-inherit"
        onMouseEnter={show}
        onMouseLeave={hide}
        onFocus={show}
        onBlur={hide}
        onClick={onClick}
        onKeyDown={onKeyDown}
      >
        {children}
      </span>
      {open && (
        <span
          role="tooltip"
          id={tooltipId}
          className={`absolute z-50 mt-2 w-64 max-w-[calc(100vw-2rem)] rounded-lg border border-slate-700 bg-slate-950 p-3 text-xs leading-relaxed text-slate-200 shadow-2xl ${placementClass}`}
        >
          <strong className="mb-1 block capitalize text-cyan-300">{term}</strong>
          {definition}
        </span>
      )}
    </span>
  );
}
