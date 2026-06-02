import { Play } from "lucide-react";
import { LinkButton } from "@/components/ui/button";
import type { AuditProfile } from "@/types";

export function ProfileCard({ profile }: { profile: AuditProfile }) {
  return (
    <article className="flex h-full flex-col rounded-md border border-slate-800 bg-slate-950/70 p-5 shadow-xl shadow-black/10">
      <div className="flex items-start justify-between gap-4">
        <div>
          <h2 className="text-xl font-semibold text-white">{profile.title}</h2>
          <p className="mt-2 text-sm leading-6 text-slate-300">{profile.description}</p>
        </div>
        <span className="rounded-md border border-slate-700 bg-slate-900 px-2 py-1 text-xs text-slate-300">
          {profile.rulesCount} правил
        </span>
      </div>

      <div className="mt-4 flex flex-wrap gap-2">
        {profile.categories.map((category) => (
          <span key={category} className="rounded-md bg-slate-900 px-2 py-1 text-xs text-slate-300">
            {category}
          </span>
        ))}
      </div>

      <div className="mt-5 text-xs text-slate-400">{profile.supportedOs.join(" / ")}</div>

      <div className="mt-auto pt-5">
        <LinkButton href={`/audit/${profile.id}`} className="w-full">
          <Play size={16} aria-hidden="true" />
          Запустить аудит
        </LinkButton>
      </div>
    </article>
  );
}
