import { AnsibleControlClient } from "@/components/hosts/ansible-control-client";

export default function HostsPage() {
  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-semibold text-white">Хосты и Ansible</h1>
        <p className="mt-2 max-w-3xl text-slate-400">
          Локальная панель для главного компьютера в сети: проверяйте доступность Linux-хостов, устанавливайте audit-only
          агент и запускайте безопасные playbook'и мониторинга без исправления ОС.
        </p>
      </div>

      <section className="grid gap-4 lg:grid-cols-3">
        <div className="rounded-md border border-slate-800 bg-slate-950/70 p-5">
          <p className="text-xs font-semibold uppercase text-slate-500">Шаг 1</p>
          <h2 className="mt-3 text-lg font-semibold text-white">Создать inventory</h2>
          <code className="mt-3 block rounded-md bg-slate-900 p-3 text-xs text-slate-200">
            cp ansible/inventory.example.ini ansible/inventory.ini
          </code>
        </div>
        <div className="rounded-md border border-slate-800 bg-slate-950/70 p-5">
          <p className="text-xs font-semibold uppercase text-slate-500">Шаг 2</p>
          <h2 className="mt-3 text-lg font-semibold text-white">Проверить SSH</h2>
          <code className="mt-3 block rounded-md bg-slate-900 p-3 text-xs text-slate-200">
            ansible all -i ansible/inventory.ini -m ping
          </code>
        </div>
        <div className="rounded-md border border-slate-800 bg-slate-950/70 p-5">
          <p className="text-xs font-semibold uppercase text-slate-500">Шаг 3</p>
          <h2 className="mt-3 text-lg font-semibold text-white">Запустить сайт локально</h2>
          <code className="mt-3 block rounded-md bg-slate-900 p-3 text-xs text-slate-200">
            cd web && npm run dev:lan
          </code>
        </div>
      </section>

      <AnsibleControlClient />
    </div>
  );
}
