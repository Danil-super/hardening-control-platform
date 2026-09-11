"use client";

import { LogOut } from "lucide-react";
import { useState } from "react";
import { Button } from "@/components/ui/button";
import { useNotify } from "@/components/ui/feedback";

export function LogoutButton({ className = "" }: { className?: string }) {
  const [pending, setPending] = useState(false);
  const notify = useNotify();

  async function logout() {
    if (pending) return;
    setPending(true);
    try {
      const response = await fetch("/api/ansible/auth/logout", { method: "POST" });
      if (!response.ok) throw new Error("logout_failed");
      const session = await fetch("/api/ansible/session", { cache: "no-store" });
      if (session.status !== 401) throw new Error("session_not_cleared");
      window.location.replace("/login");
    } catch {
      notify("Не удалось выйти. Проверьте соединение и повторите попытку.", "error");
      setPending(false);
    }
  }

  return (
    <Button type="button" variant="secondary" onClick={logout} disabled={pending} className={className}>
      <LogOut size={16} aria-hidden="true" />
      {pending ? "Выходим…" : "Выйти"}
    </Button>
  );
}
