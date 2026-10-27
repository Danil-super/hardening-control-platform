"use client";

import { useEffect, useRef, useState } from "react";
import { readApiResponse, errorMessage } from "@/lib/client-api";
import { Button } from "@/components/ui/button";
import { needsRussianTranslation } from "@/lib/finding-language";
import type { DescriptionTranslation } from "@/lib/description-translation";

export function FindingDescription({ original, reportId, findingId, expanded, field = "description", inline = false, lazy = false }: { original: string; reportId: string; findingId: string; expanded: boolean; field?: "title" | "description" | "recommendation"; inline?: boolean; lazy?: boolean }) {
  const [translation, setTranslation] = useState<DescriptionTranslation | null>(null);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [attempt, setAttempt] = useState(0);
  const element = useRef<HTMLElement | null>(null);
  const [visible, setVisible] = useState(!lazy);
  const needed = needsRussianTranslation(original);

  useEffect(() => {
    if (!lazy || visible) return;
    const observer = new IntersectionObserver(([entry]) => {
      if (entry.isIntersecting) { setVisible(true); observer.disconnect(); }
    }, { rootMargin: "60px" });
    if (element.current) observer.observe(element.current);
    return () => observer.disconnect();
  }, [lazy, visible]);

  useEffect(() => {
    if (!expanded || !visible || !needed || translation) return;
    let active = true;
    setBusy(true); setError("");
    void (async () => {
      try {
        const response = await fetch(`/api/ansible/reports/${encodeURIComponent(reportId)}/description?findingId=${encodeURIComponent(findingId)}&field=${field}`, { cache: "no-store" });
        const payload = await readApiResponse(response) as { ok?: boolean; translation?: DescriptionTranslation; message?: string };
        if (!payload.ok || !payload.translation) throw new Error(payload.message ?? "Перевод недоступен.");
        if (active) setTranslation(payload.translation);
      } catch (failure) { if (active) setError(errorMessage(failure, "Перевод недоступен. Оригинал сохранён.")); }
      finally { if (active) setBusy(false); }
    })();
    // The server can finish and cache a translation after the row is closed.
    return () => { active = false; };
  }, [expanded, visible, needed, original, reportId, findingId, field, attempt, translation]);

  if (inline) return <span ref={(node) => { element.current = node; }} lang={translation || !needed ? "ru" : "en"} title={error || (translation ? original : undefined)}>{translation?.text ?? original}</span>;
  if (!needed) return <p lang="ru" className="whitespace-pre-line text-slate-300 [overflow-wrap:anywhere]">{original}</p>;
  return <div ref={(node) => { element.current = node; }} className="space-y-3 [overflow-wrap:anywhere]">
    {translation ? <><p className="text-xs text-slate-500">Машинный перевод на русский</p><p lang="ru" className="whitespace-pre-line text-slate-300 [overflow-wrap:anywhere]">{translation.text}</p></> : <p role="status" className="text-sm text-slate-400">{busy ? "Перевожу описание на русский…" : error || "Перевод появится после раскрытия записи."}</p>}
    {error && !busy ? <Button variant="secondary" onClick={() => setAttempt((value) => value + 1)}>Повторить перевод</Button> : null}
    <details open={Boolean(error)}><summary className="cursor-pointer text-xs text-sky-200">Оригинал на английском</summary><p lang="en" className="mt-2 whitespace-pre-line text-sm text-slate-400">{original}</p></details>
  </div>;
}
