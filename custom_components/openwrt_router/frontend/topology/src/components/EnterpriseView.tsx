/**
 * EnterpriseView — container for the Enterprise modules. Renders the
 * registered sub-tabs (see enterprise/registry.ts); no data of its own.
 */

import React, { useRef, useState } from 'react';
import { getEnterpriseTabs } from '../enterprise/registry';

export function EnterpriseView() {
  const tabs = getEnterpriseTabs();
  const [selected, setSelected] = useState<string | null>(null);
  const refs = useRef<Record<string, HTMLButtonElement | null>>({});

  if (tabs.length === 0) {
    return (
      <div className="topo-view ent">
        <div className="view-header"><span className="view-title">Enterprise</span></div>
        <div className="view-empty">Noch keine Enterprise-Module installiert.</div>
      </div>
    );
  }

  const active = tabs.find(t => t.id === selected) ?? tabs[0];
  const Content = active.component;

  const onKeyDown = (e: React.KeyboardEvent, index: number) => {
    const last = tabs.length - 1;
    const next =
      e.key === 'ArrowRight' ? (index === last ? 0 : index + 1)
      : e.key === 'ArrowLeft' ? (index === 0 ? last : index - 1)
      : e.key === 'Home' ? 0
      : e.key === 'End' ? last
      : null;
    if (next === null) return;
    e.preventDefault();
    setSelected(tabs[next].id);
    refs.current[tabs[next].id]?.focus();
  };

  return (
    <div className="topo-view ent">
      <div className="view-header"><span className="view-title">Enterprise</span></div>
      <div className="ent-tabs" role="tablist" aria-label="Enterprise-Module">
        {tabs.map((t, i) => (
          <button
            key={t.id}
            ref={el => { refs.current[t.id] = el; }}
            type="button"
            role="tab"
            id={`ent-tab-${t.id}`}
            aria-selected={active.id === t.id}
            aria-controls="ent-panel"
            tabIndex={active.id === t.id ? 0 : -1}
            className={`ent-tab${active.id === t.id ? ' active' : ''}`}
            onClick={() => setSelected(t.id)}
            onKeyDown={e => onKeyDown(e, i)}
          >
            {t.icon && <t.icon size={14} />}
            {t.title}
          </button>
        ))}
      </div>
      <div className="ent-body" role="tabpanel" id="ent-panel" aria-labelledby={`ent-tab-${active.id}`}>
        <Content />
      </div>
    </div>
  );
}
