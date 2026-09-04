"use client";

import { LogOut } from "lucide-react";
import { useRouter } from "next/navigation";
import { Button } from "@/components/ui/button";

export function LogoutButton({ className = "" }: { className?: string }) {
  const router = useRouter();

  async function logout() {
    await fetch("/api/ansible/auth/logout", { method: "POST" });
    router.push("/login");
    router.refresh();
  }

  return (
    <Button type="button" variant="secondary" onClick={logout} className={`w-full ${className}`}>
      <LogOut size={16} aria-hidden="true" />
      Выйти
    </Button>
  );
}
