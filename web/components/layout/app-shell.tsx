"use client";

import { BookOpen, Database, FileText, Server, Shield, SlidersHorizontal } from "lucide-react";
import { usePathname } from "next/navigation";
import Link from "next/link";
import type { ReactNode } from "react";
import { LogoutButton } from "@/components/auth/logout-button";

const navItems = [
  { href: "/hosts", label: "Хосты", icon: Server },
  { href: "/reports", label: "Отчеты", icon: FileText },
  { href: "/data-sources", label: "Источники", icon: Database },
  { href: "/policies", label: "Политики", icon: SlidersHorizontal },
  { href: "/guide", label: "Инструкция", icon: BookOpen },
];

export function AppShell({ children }: { children: ReactNode }) {
  const pathname = usePathname();
  if (pathname === "/login") return <main className="flex min-h-dvh items-center bg-[radial-gradient(ellipse_at_top,#123449_0,#08111f_55%,#050b14_100%)] px-4 py-12">{children}</main>;
  const active = (href: string) => pathname === href || pathname.startsWith(`${href}/`);
  return (
    <div className="min-h-screen bg-[radial-gradient(circle_at_top_left,#164e63_0,#08111f_36%,#050b14_100%)]">
      <aside className="fixed inset-y-0 left-0 hidden w-72 border-r border-slate-800/80 bg-slate-950/90 p-5 backdrop-blur lg:block">
        <Link href="/hosts" className="flex items-center gap-3">
          <span className="flex h-10 w-10 items-center justify-center rounded-md bg-sky-400 text-slate-950">
            <Shield size={22} aria-hidden="true" />
          </span>
          <span>
            <span className="block text-sm font-semibold text-slate-100">Контроль безопасности</span>
            <span className="block text-xs text-slate-400">Linux · Ansible · SSH</span>
          </span>
        </Link>

        <p className="mt-9 px-3 text-xs font-semibold uppercase tracking-wide text-slate-500">Рабочее пространство</p>
        <nav className="mt-2 space-y-1" aria-label="Основная навигация">
          {navItems.map((item) => {
            const Icon = item.icon;
            return (
              <Link
                key={item.href}
                href={item.href}
                aria-current={active(item.href) ? "page" : undefined}
                className={`flex items-center gap-3 rounded-xl px-3 py-3 text-sm transition ${active(item.href) ? "bg-sky-400/10 font-semibold text-sky-200 ring-1 ring-inset ring-sky-400/20" : "text-slate-400 hover:bg-slate-900 hover:text-white"}`}
              >
                <Icon size={18} aria-hidden="true" />
                {item.label}
              </Link>
            );
          })}
        </nav>

        <div className="absolute inset-x-5 bottom-5">
          <LogoutButton className="w-full" />
        </div>
      </aside>

      <div className="lg:pl-72">
        <header className="sticky top-0 z-20 border-b border-slate-800/80 bg-slate-950/80 px-4 py-3 backdrop-blur lg:hidden">
          <div className="flex items-center justify-between gap-3">
            <Link href="/hosts" className="flex items-center gap-2 text-sm font-semibold">
              <Shield size={20} aria-hidden="true" />
              Контроль безопасности
            </Link>
            <LogoutButton className="h-9 px-3 text-xs" />
          </div>
          <nav className="mt-3 grid grid-cols-3 gap-2 sm:grid-cols-5" aria-label="Основная навигация">
            {navItems.map((item) => (
              <Link
                key={item.href}
                href={item.href}
                aria-current={active(item.href) ? "page" : undefined}
                className={`rounded-lg border px-2 py-2 text-center text-xs ${active(item.href) ? "border-sky-400/40 bg-sky-400/10 text-sky-200" : "border-slate-800 bg-slate-900 text-slate-300"}`}
              >
                {item.label}
              </Link>
            ))}
          </nav>
        </header>

        <main className="mx-auto w-full max-w-7xl px-4 py-6 sm:px-6 lg:px-8 lg:py-8">{children}</main>
      </div>
    </div>
  );
}
