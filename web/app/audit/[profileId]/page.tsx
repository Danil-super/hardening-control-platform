import { notFound } from "next/navigation";
import { AuditRunner } from "@/components/audit/audit-runner";
import { DemoHostCard } from "@/components/dashboard/demo-host-card";
import { LinkButton } from "@/components/ui/button";
import { getProfile } from "@/data/profiles";

export default async function AuditPage({ params }: { params: Promise<{ profileId: string }> }) {
  const { profileId } = await params;
  const profile = getProfile(profileId);

  if (!profile) {
    notFound();
  }

  return (
    <div className="space-y-6">
      <div className="flex flex-col gap-4 lg:flex-row lg:items-end lg:justify-between">
        <div>
          <h1 className="text-3xl font-semibold text-white">{profile.title}</h1>
          <p className="mt-2 max-w-3xl text-slate-400">{profile.description}</p>
        </div>
        <LinkButton href="/profiles" variant="secondary">Все профили</LinkButton>
      </div>
      <DemoHostCard compact />
      <AuditRunner profileId={profile.id} />
    </div>
  );
}
