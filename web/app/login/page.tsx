import { LoginForm } from "@/components/auth/login-form";
import { normalizeNextPath } from "@/lib/client-navigation";
import { ShieldCheck } from "lucide-react";
import Link from "next/link";

export default async function LoginPage({
  searchParams,
}: {
  searchParams: Promise<{ next?: string }>;
}) {
  const params = await searchParams;
  const nextPath = normalizeNextPath(params.next);

  return (
    <div className="mx-auto w-full max-w-md space-y-7">
      <section className="text-center">
        <span className="mx-auto flex h-14 w-14 items-center justify-center rounded-2xl border border-sky-300/25 bg-sky-400/10 text-sky-300"><ShieldCheck size={30} aria-hidden="true" /></span>
        <h1 className="mt-5 text-3xl font-semibold tracking-tight text-white">Контроль безопасности</h1>
        <p className="mt-3 text-sm leading-6 text-slate-400">
          Аудит Linux-хостов, отчёты и управление изменениями в одном месте.
        </p>
      </section>
      <LoginForm nextPath={nextPath} />
      <p className="text-center text-sm text-slate-400">Нужна помощь? <Link href="/guide" className="text-sky-300 underline-offset-4 hover:underline">Открыть инструкцию</Link></p>
    </div>
  );
}
