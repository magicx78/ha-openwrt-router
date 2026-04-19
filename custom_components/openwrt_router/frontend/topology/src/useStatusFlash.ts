import { useEffect, useRef, useState } from 'react';

/**
 * Returns true for ~600 ms whenever `status` changes value.
 * Used to trigger a one-shot CSS flash animation on status transitions.
 */
export function useStatusFlash(status: string): boolean {
  const prevRef = useRef(status);
  const [flashing, setFlashing] = useState(false);

  useEffect(() => {
    if (prevRef.current === status) return;
    prevRef.current = status;
    setFlashing(true);
    const t = setTimeout(() => setFlashing(false), 650);
    return () => clearTimeout(t);
  }, [status]);

  return flashing;
}
