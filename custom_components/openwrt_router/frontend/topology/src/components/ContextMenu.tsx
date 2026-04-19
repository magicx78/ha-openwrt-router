import React, { useEffect, useRef } from 'react';

export interface ContextMenuItem {
  label: string;
  icon?: string;
  onClick: () => void;
  disabled?: boolean;
}

export type ContextMenuEntry = ContextMenuItem | { separator: true };

interface Props {
  x: number;
  y: number;
  items: ContextMenuEntry[];
  onClose: () => void;
}

export function ContextMenu({ x, y, items, onClose }: Props) {
  const menuRef = useRef<HTMLDivElement>(null);

  // Close on click-away or Escape
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => { if (e.key === 'Escape') onClose(); };
    const onDown = (e: MouseEvent) => {
      if (menuRef.current && !menuRef.current.contains(e.target as Node)) onClose();
    };
    document.addEventListener('keydown', onKey);
    document.addEventListener('pointerdown', onDown);
    return () => {
      document.removeEventListener('keydown', onKey);
      document.removeEventListener('pointerdown', onDown);
    };
  }, [onClose]);

  // Keep menu on screen
  const style: React.CSSProperties = { position: 'fixed', left: x, top: y, zIndex: 999 };

  return (
    <div ref={menuRef} className="ctx-menu" style={style} onPointerDown={e => e.stopPropagation()}>
      {items.map((item, i) => {
        if ('separator' in item) {
          return <div key={i} className="ctx-menu__sep" />;
        }
        return (
          <button
            key={i}
            className="ctx-menu__item"
            disabled={item.disabled}
            onClick={() => { item.onClick(); onClose(); }}
          >
            {item.icon && <span className="ctx-menu__icon">{item.icon}</span>}
            {item.label}
          </button>
        );
      })}
    </div>
  );
}
