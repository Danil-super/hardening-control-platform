import type { ReactNode } from "react";

export function SummaryCard({
  label,
  value,
  detail,
  icon,
}: {
  label: string;
  value: string | number;
  detail?: string;
  icon?: ReactNode;
}) {
  return (
    <div className="rounded-md border border-slate-800 bg-slate-950/70 p-4 shadow-xl shadow-black/10">
      <div className="flex items-center justify-between gap-3">
        <p className="text-sm text-slate-400">{label}</p>
        {icon ? <span className="text-sky-200">{icon}</span> : null}
      </div>
      <p className="mt-3 text-3xl font-semibold tracking-normal text-white">{value}</p>
      {detail ? <p className="mt-2 text-sm text-slate-400">{detail}</p> : null}
    </div>
  );
}
