import { ProfileCard } from "@/components/profiles/profile-card";
import { auditProfiles } from "@/data/profiles";

export default function ProfilesPage() {
  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-semibold text-white">Профили аудита</h1>
        <p className="mt-2 max-w-3xl text-slate-400">
          Выберите профиль, чтобы запустить демонстрационный аудит на заранее подготовленных mock-данных.
        </p>
      </div>
      <div className="grid gap-5 md:grid-cols-2">
        {auditProfiles.map((profile) => <ProfileCard key={profile.id} profile={profile} />)}
      </div>
    </div>
  );
}
