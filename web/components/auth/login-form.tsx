"use client";

import { LockKeyhole, LogIn } from "lucide-react";
import { useRouter } from "next/navigation";
import { FormEvent, useState } from "react";
import { Button } from "@/components/ui/button";

export function LoginForm({ nextPath = "/hosts" }: { nextPath?: string }) {
  const router = useRouter();
  const [password, setPassword] = useState("");
  const [loading, setLoading] = useState(false);
  const [message, setMessage] = useState("");

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setLoading(true);
    setMessage("");

    try {
      const response = await fetch("/api/ansible/auth/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ password }),
      });
      const payload = await response.json();
      if (!payload.ok) {
        setMessage(payload.message ?? "Не удалось выполнить вход.");
        return;
      }

      router.replace(nextPath);
      router.refresh();
    } finally {
      setLoading(false);
    }
  }

  return (
    <form onSubmit={submit} className="rounded-md border border-slate-800 bg-slate-950/80 p-5">
      <div className="flex items-center gap-3">
        <LockKeyhole size={22} className="text-sky-200" aria-hidden="true" />
        <h2 className="text-xl font-semibold text-white">Вход администратора</h2>
      </div>

      <label className="mt-5 block">
        <span className="text-xs font-semibold uppercase text-slate-500">Пароль</span>
        <input
          type="password"
          value={password}
          onChange={(event) => setPassword(event.target.value)}
          autoComplete="current-password"
          className="mt-2 h-11 w-full rounded-md border border-slate-700 bg-slate-900 px-3 text-sm text-slate-100"
        />
      </label>

      {message ? (
        <div className="mt-4 rounded-md border border-red-400/30 bg-red-500/10 p-3 text-sm leading-6 text-red-100">
          {message}
        </div>
      ) : null}

      <Button type="submit" disabled={loading || !password} className="mt-5 w-full">
        <LogIn size={16} aria-hidden="true" />
        {loading ? "Проверка..." : "Войти"}
      </Button>
    </form>
  );
}
