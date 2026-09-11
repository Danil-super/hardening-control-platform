"use client";

import { CheckCircle2, AlertCircle, Info, X } from "lucide-react";
import { createContext, useCallback, useContext, useEffect, useRef, useState, type ReactNode } from "react";

type Tone = "success" | "error" | "warning" | "info";
type Notice = { id: number; message: string; tone: Tone };
type Notify = (message: string, tone?: Tone) => void;
const FeedbackContext = createContext<Notify>(() => {});
const tones = {
  success: "border-emerald-400/40 bg-emerald-950 text-emerald-50",
  error: "border-red-400/40 bg-red-950 text-red-50",
  warning: "border-amber-400/40 bg-amber-950 text-amber-50",
  info: "border-sky-400/40 bg-slate-900 text-sky-50",
};

function Toast({ notice, dismiss }: { notice: Notice; dismiss: (id: number) => void }) {
  const [paused, setPaused] = useState(false);
  useEffect(() => {
    if (paused) return;
    const timer = window.setTimeout(() => dismiss(notice.id), 3000);
    return () => window.clearTimeout(timer);
  }, [notice, dismiss, paused]);
  const Icon = notice.tone === "success" ? CheckCircle2 : notice.tone === "info" ? Info : AlertCircle;
  return (
    <div role={notice.tone === "error" ? "alert" : "status"} aria-atomic="true"
      onMouseEnter={() => setPaused(true)} onMouseLeave={() => setPaused(false)}
      onFocus={() => setPaused(true)} onBlur={() => setPaused(false)}
      className={`pointer-events-auto flex items-start gap-3 rounded-xl border p-4 shadow-2xl ${tones[notice.tone]}`}>
      <Icon size={20} className="mt-0.5 shrink-0" aria-hidden="true" />
      <p className="min-w-0 flex-1 break-words text-sm leading-6">{notice.message}</p>
      <button type="button" onClick={() => dismiss(notice.id)} aria-label="Закрыть уведомление"
        className="shrink-0 rounded-md p-1 opacity-70 hover:opacity-100 focus-visible:outline-2 focus-visible:outline-sky-300">
        <X size={18} aria-hidden="true" />
      </button>
    </div>
  );
}

export function FeedbackProvider({ children }: { children: ReactNode }) {
  const [notices, setNotices] = useState<Notice[]>([]);
  const sequence = useRef(0);
  const dismiss = useCallback((id: number) => setNotices((items) => items.filter((item) => item.id !== id)), []);
  const notify = useCallback<Notify>((message, tone = "info") => {
    if (!message.trim()) return;
    const notice = { id: ++sequence.current, message, tone };
    setNotices((items) => [...items.filter((item) => item.message !== message).slice(-3), notice]);
  }, []);
  return <FeedbackContext.Provider value={notify}>
    {children}
    <div aria-label="Уведомления" className="pointer-events-none fixed inset-x-4 bottom-4 z-50 flex max-h-[70dvh] flex-col gap-3 overflow-y-auto sm:left-auto sm:w-[min(26rem,calc(100vw-2rem))]">
      {notices.map((notice) => <Toast key={notice.id} notice={notice} dismiss={dismiss} />)}
    </div>
  </FeedbackContext.Provider>;
}

export const useNotify = () => useContext(FeedbackContext);

// Keep the detailed result in place and surface every action, including repeated results.
export function useActionResult<T extends { ok?: boolean; partial?: boolean; message?: string }>() {
  const [result, setResult] = useState<T | null>(null);
  const notify = useNotify();
  const update = useCallback((value: T | null) => {
    setResult(value);
    if (value) notify(value.message || (value.ok ? "Готово." : "Не удалось выполнить действие."),
      value.ok ? value.partial ? "warning" : "success" : "error");
  }, [notify]);
  return [result, update] as const;
}

export function useFeedbackMessage() {
  const [message, setMessage] = useState("");
  const notify = useNotify();
  const update = useCallback((value: string, tone: Tone = "error") => {
    setMessage(value);
    if (value) notify(value, tone);
  }, [notify]);
  return [message, update] as const;
}
