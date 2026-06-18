import { LoginForm } from "@/components/auth/login-form";

function normalizeNextPath(value: string | undefined) {
  return value?.startsWith("/") && !value.startsWith("//") ? value : "/hosts";
}

export default async function LoginPage({
  searchParams,
}: {
  searchParams: Promise<{ next?: string }>;
}) {
  const params = await searchParams;
  const nextPath = normalizeNextPath(params.next);

  return (
    <div className="mx-auto grid max-w-5xl gap-6 lg:grid-cols-[minmax(0,1fr)_420px]">
      <section className="rounded-md border border-slate-800 bg-slate-950/70 p-6">
        <p className="text-xs font-semibold uppercase text-sky-200">Локальное управление</p>
        <h1 className="mt-4 text-3xl font-semibold text-white">Защита Ansible-панели</h1>
        <p className="mt-4 text-sm leading-6 text-slate-400">
          Вход нужен для страниц и API, которые управляют inventory, запускают аудит, открывают реальные отчеты и
          выполняют response-playbook'и.
        </p>
        <div className="mt-5 rounded-md border border-slate-800 bg-slate-900/70 p-4">
          <p className="text-sm font-semibold text-white">Первичная настройка</p>
          <p className="mt-2 text-sm leading-6 text-slate-400">
            Создайте `web/.env.local` по примеру `web/.env.example`, задайте `HCP_ADMIN_PASSWORD` и перезапустите
            `npm run dev`.
          </p>
        </div>
      </section>

      <LoginForm nextPath={nextPath} />
    </div>
  );
}
