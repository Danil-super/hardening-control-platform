"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { RefreshCw } from "lucide-react";
import { Button } from "@/components/ui/button";

export function DependencyTrackResult({ hostAlias, reportId, complete, findingCount }: {
  hostAlias: string; reportId: string; complete: boolean; findingCount: number | null;
}) {
  const router = useRouter();
  const [active, setActive] = useState(false);
  const [message, setMessage] = useState("");
  const [failed, setFailed] = useState(false);

  useEffect(() => {
    if (!active) return;
    const controller = new AbortController();
    const started = Date.now();
    let timer: ReturnType<typeof setTimeout> | undefined;
    const deadline = setTimeout(() => {
      controller.abort();
      setMessage("Автоматическое ожидание остановлено через три минуты; результат можно проверить позже.");
      setActive(false);
    }, 180_000);
    async function check() {
      try {
        const response = await fetch("/api/ansible/dependency-track/refresh", { method: "POST", headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ hostAlias, reportId }), signal: controller.signal });
        const result = await response.json();
        if (controller.signal.aborted) return;
        if (!response.ok || !result.ok) throw new Error(result.message || "Не удалось получить результат Dependency-Track.");
        setMessage(result.message);
        if (result.status === "complete" && typeof result.reportId === "string") {
          setActive(false);
          router.push(`/reports/agentless/${encodeURIComponent(result.reportId)}`);
          router.refresh();
          return;
        }
        if (Date.now() - started >= 180_000) {
          setMessage("Анализ ещё не подтверждён. Автоматическое ожидание остановлено через три минуты; результат можно проверить позже.");
          setActive(false);
          return;
        }
        timer = setTimeout(check, 3000);
      } catch (error) {
        if (controller.signal.aborted) return;
        setFailed(true);
        setMessage(error instanceof Error ? error.message : "Не удалось получить результат Dependency-Track.");
        setActive(false);
      }
    }
    void check();
    return () => { controller.abort(); clearTimeout(timer); clearTimeout(deadline); };
  }, [active, hostAlias, reportId, router]);

  return <section className="rounded-xl border border-slate-800 bg-slate-950/70 p-5">
    <h2 className="text-lg font-semibold text-white">Результат Dependency-Track</h2>
    <p className="mt-2 text-sm leading-6 text-slate-300">{complete
      ? `Результат анализа загружен${findingCount === null ? "" : `: ${findingCount} находок`}. Исходная передача и предыдущие результаты сохранены в истории.`
      : "SBOM принят для асинхронного анализа. Проверьте результат, чтобы получить находки по переданным компонентам."}</p>
    <p className="mt-2 text-sm leading-6 text-amber-100">Полнота источников уязвимостей требует отдельной проверки. Нулевой список находок не подтверждает отсутствие CVE.</p>
    <div className="mt-4 flex flex-wrap items-center gap-3">
      <Button type="button" variant="secondary" disabled={active} onClick={() => { setFailed(false); setMessage("Проверяем состояние анализа…"); setActive(true); }}>
        <RefreshCw size={16} className={active ? "animate-spin" : ""} aria-hidden="true" />
        {active ? "Ожидание анализа…" : complete ? "Проверить новый результат" : "Получить результат анализа"}
      </Button>
      {active ? <Button type="button" variant="secondary" onClick={() => { setActive(false); setMessage("Ожидание остановлено. Анализ на сервере Dependency-Track продолжается."); }}>Остановить ожидание</Button> : null}
    </div>
    {message ? <p role={failed ? "alert" : "status"} className={`mt-3 text-sm leading-6 ${failed ? "text-red-200" : "text-slate-300"}`}>{message}</p> : null}
  </section>;
}
