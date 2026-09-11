"use client";

import { Eye, EyeOff, LoaderCircle, LockKeyhole, LogIn } from "lucide-react";
import { FormEvent, useState } from "react";
import { Button } from "@/components/ui/button";
import { useFeedbackMessage } from "@/components/ui/feedback";
import { signIn } from "@/lib/client-navigation";

export function LoginForm({ nextPath = "/hosts" }: { nextPath?: string }) {
  const [password, setPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [loading, setLoading] = useState(false);
  const [message, setMessage] = useFeedbackMessage();

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (loading) return;
    setLoading(true);
    setMessage("");

    try {
      await signIn(password, nextPath, {
        request: fetch,
        navigate: (path) => window.location.replace(path),
      });
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "Не удалось выполнить вход.");
      setLoading(false);
    }
  }

  return (
    <form onSubmit={submit} aria-busy={loading} className="rounded-2xl border border-slate-700/70 bg-slate-950/80 p-6 shadow-2xl sm:p-8">
      <div className="flex items-center gap-3">
        <LockKeyhole size={22} className="text-sky-200" aria-hidden="true" />
        <h2 className="text-xl font-semibold text-white">Вход администратора</h2>
      </div>

      <label className="mt-5 block">
        <span className="text-sm font-medium text-slate-300">Пароль</span>
        <span className="relative mt-2 block">
        <input
          type={showPassword ? "text" : "password"}
          name="password"
          required
          autoFocus
          disabled={loading}
          aria-invalid={Boolean(message)}
          aria-describedby={message ? "login-error" : undefined}
          value={password}
          onChange={(event) => setPassword(event.target.value)}
          autoComplete="current-password"
          className="h-12 w-full rounded-lg border border-slate-700 bg-slate-900 pl-3 pr-12 text-base text-slate-100 focus:border-sky-300 focus:outline-none focus:ring-2 focus:ring-sky-300/20"
        />
        <button type="button" onClick={() => setShowPassword((value) => !value)}
          aria-label={showPassword ? "Скрыть пароль" : "Показать пароль"} aria-pressed={showPassword}
          className="absolute inset-y-0 right-0 rounded-lg px-3 text-slate-400 hover:text-white focus-visible:outline-2 focus-visible:outline-sky-300">
          {showPassword ? <EyeOff size={19} aria-hidden="true" /> : <Eye size={19} aria-hidden="true" />}
        </button>
        </span>
      </label>

      {message ? (
        <div id="login-error" className="mt-4 rounded-lg border border-red-400/30 bg-red-500/10 p-3 text-sm leading-6 text-red-100">
          {message}
        </div>
      ) : null}

      <Button type="submit" disabled={loading || !password} className="mt-6 min-h-12 w-full">
        {loading ? <LoaderCircle size={18} className="animate-spin" aria-hidden="true" /> : <LogIn size={18} aria-hidden="true" />}
        {loading ? "Входим…" : "Войти"}
      </Button>
    </form>
  );
}
