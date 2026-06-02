import { RemediationPlanner } from "@/components/remediation/remediation-planner";
import { getProfile } from "@/data/profiles";
import { getAvailableRemediationsForProfile } from "@/lib/demo-audit";

export default async function RemediationPage({
  searchParams,
}: {
  searchParams: Promise<{ profileId?: string }>;
}) {
  const params = await searchParams;
  const profileId = params.profileId ?? "basic_linux";
  const profile = getProfile(profileId) ?? getProfile("basic_linux")!;
  const availableRemediations = getAvailableRemediationsForProfile(profile.id);

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-semibold text-white">Планировщик исправлений</h1>
        <p className="mt-2 max-w-3xl text-slate-400">
          Профиль: {profile.title}. Выберите действия, проверьте риск, затрагиваемые файлы, резервную копию и откат.
        </p>
      </div>
      <RemediationPlanner profileId={profile.id} remediations={availableRemediations} />
    </div>
  );
}
