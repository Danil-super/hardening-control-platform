import { NextResponse } from "next/server";
import { getInventoryHost } from "@/lib/inventory";
import { selectAstraOvalPolicy } from "@/lib/astra-oval-policy";
import { selectOpenScapPolicy } from "@/lib/openscap-policy";
import { assertAstraOvalProvenance } from "@/lib/astra-oval-config";
import { ASTRA_BASELINE_DATASTREAM, ASTRA_BASELINE_PROFILE } from "@/lib/scap-presets";
import { listAstraOvalPolicies, listOpenScapPolicies } from "@/lib/state-store";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

type State = "configured" | "missing" | "conflict" | "incomplete";
type SourceStatus = {
  state: State;
  group: string | null;
  message: string;
  // These fields describe the saved, operator-selected scope, NOT verified host applicability.
  declaredRelease?: string | null;
  declaredArchitectures?: string[];
  mode?: "local" | "online" | null;
  sourceReviewRecorded?: boolean;
  profileKind?: "astra-hcp-18" | "custom" | "environment" | null;
};

function errorMessage(error: unknown) {
  return error instanceof Error ? error.message : "Не удалось безопасно сопоставить назначенные источники.";
}

function astraSource(groups: string[]): SourceStatus {
  const policies = listAstraOvalPolicies();
  const specifics = policies.filter((item) => item.groupName !== "linux_hosts" && groups.includes(item.groupName));
  if (specifics.length > 1) return {
    state: "conflict", group: null,
    message: "Несколько конкретных групп назначают разные OVAL-источники. Аудит должен отказать в запуске до устранения конфликта.",
  };
  const candidate = specifics[0] ?? policies.find((item) => item.groupName === "linux_hosts" && groups.includes("linux_hosts"));
  if (!candidate) return {
    state: "missing", group: null,
    message: "Для Astra OVAL-источник не назначен. Если нужен CVE-аудит Astra, настройте базу своего выпуска в «Источниках».",
  };
  try {
    // Use the same production resolver and provenance gate as the audit route.
    const applied = selectAstraOvalPolicy(groups, policies);
    assertAstraOvalProvenance(applied.config);
    return {
      state: "configured", group: applied.groupName, mode: applied.config.mode,
      declaredRelease: applied.config.releasePattern,
      declaredArchitectures: applied.config.architectures,
      sourceReviewRecorded: Boolean(applied.config.sourceReviewedAt),
      message: "Назначение сохранено. Применимость к фактическому выпуску, свежесть, XML, контрольная сумма и происхождение проверяются отдельно; наличие настройки не подтверждает CVE-аудит.",
    };
  } catch (error) {
    return {
      state: "incomplete", group: candidate.groupName,
      message: errorMessage(error),
    };
  }
}

function openScapSource(alias: string, groups: string[]): SourceStatus {
  const policies = listOpenScapPolicies();
  const specifics = policies.filter((item) => item.groupName !== "linux_hosts" && groups.includes(item.groupName));
  if (specifics.length > 1) return {
    state: "conflict", group: null,
    message: "Несколько групп назначают разные профили OpenSCAP. Выберите один профиль для хоста.",
  };
  try {
    // This is the same group precedence as the production OpenSCAP launcher.
    const selected = selectOpenScapPolicy(alias, groups, policies);
    if (selected.policy) return {
      state: "configured", group: selected.policy.groupName,
      profileKind: selected.policy.datastream === ASTRA_BASELINE_DATASTREAM
        && selected.policy.profile === ASTRA_BASELINE_PROFILE ? "astra-hcp-18" : "custom",
      message: "Профиль назначен. Наличие записи не подтверждает доступность OpenSCAP, применимость XCCDF/SCE или успешный запуск на хосте.",
    };
    if (process.env.HCP_OPENSCAP_DATASTREAM?.trim() && process.env.HCP_OPENSCAP_PROFILE?.trim()) return {
      state: "configured", group: null, profileKind: "environment",
      message: "Профиль задан через окружение управляющего узла. Применимость и исполнение на хосте ещё не проверялись.",
    };
    return {
      state: "missing", group: null,
      message: "Профиль OpenSCAP не назначен. Для Astra можно выбрать авторский набор HCP из 18 правил на странице «Политики».",
    };
  } catch (error) {
    return {
      state: "incomplete", group: null, message: errorMessage(error),
    };
  }
}

export async function GET(request: Request) {
  const alias = new URL(request.url).searchParams.get("alias");
  if (!alias || !/^[a-zA-Z0-9_][a-zA-Z0-9_.-]{0,63}$/.test(alias) || ["all", "ungrouped"].includes(alias)) {
    return NextResponse.json({ ok: false, message: "Выберите точный alias подключённого хоста." }, { status: 400 });
  }
  try {
    const host = getInventoryHost(alias);
    if (!host || !host.groups.includes("linux_hosts")) {
      return NextResponse.json({ ok: false, message: "Хост не найден в группе linux_hosts либо имя совпадает с inventory-группой." }, { status: 404 });
    }
    return NextResponse.json({
      ok: true, alias, groups: host.groups,
      assessment: "saved-settings-only",
      astraOval: astraSource(host.groups),
      openScap: openScapSource(alias, host.groups),
      warning: "Это состояние назначений, не проверка ОС, подлинности производителя, свежести базы, выполнения SCAP или полноты CVE. Запуск на целевом хосте не выполнялся.",
    }, { headers: { "Cache-Control": "no-store" } });
  } catch {
    return NextResponse.json({
      ok: false, message: "Не удалось получить сохранённые настройки хоста и источников. Проверьте состояние inventory и базы HCP.",
    }, { status: 503 });
  }
}
