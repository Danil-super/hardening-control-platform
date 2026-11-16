"use client";

import { useEffect, useRef, type ReactNode } from "react";

export function GuideTopics({ children }: { children: ReactNode }) {
  const root = useRef<HTMLDivElement>(null);
  useEffect(() => {
    const reveal = () => {
      let id: string;
      try { id = decodeURIComponent(window.location.hash.slice(1)); } catch { return; }
      if (!id) return;
      // Search the hydrated guide, not Next's hidden streaming placeholders.
      const target = root.current?.querySelector<HTMLElement>(`#${CSS.escape(id)}`);
      if (!target) return;
      for (let parent = target.parentElement; parent && parent !== root.current; parent = parent.parentElement) {
        if (parent instanceof HTMLDetailsElement) parent.open = true;
      }
      target.scrollIntoView({ block: "start" });
    };
    reveal();
    window.addEventListener("hashchange", reveal);
    return () => window.removeEventListener("hashchange", reveal);
  }, []);
  return <div ref={root} className="space-y-4">{children}</div>;
}
