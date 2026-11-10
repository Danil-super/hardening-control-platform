"use client";

import { useState } from "react";
import { Download, LoaderCircle } from "lucide-react";
import { Button } from "@/components/ui/button";
import { useNotify } from "@/components/ui/feedback";
import { readApiResponse } from "@/lib/client-api";

export function AuditPdfDownload({ reportId }: { reportId: string }) {
  const [busy, setBusy] = useState(false);
  const notify = useNotify();
  async function download() {
    setBusy(true);
    try {
      const response = await fetch(`/api/ansible/reports/${encodeURIComponent(reportId)}/pdf`, { cache: "no-store" });
      if (!response.ok) { const failure = await readApiResponse(response); throw new Error(failure.message ?? "Не удалось сформировать PDF."); }
      if (!response.headers.get("content-type")?.startsWith("application/pdf")) throw new Error("Сервер не вернул PDF.");
      const blob = await response.blob();
      const url = URL.createObjectURL(blob);
      const anchor = document.createElement("a");
      anchor.href = url; anchor.download = `${reportId}-hcp.pdf`;
      document.body.appendChild(anchor); anchor.click(); anchor.remove();
      window.setTimeout(() => URL.revokeObjectURL(url), 1000);
    } catch (error) { notify(error instanceof Error ? error.message : "Не удалось скачать PDF.", "error"); }
    finally { setBusy(false); }
  }
  return <Button onClick={() => void download()} disabled={busy}>
    {busy ? <LoaderCircle size={16} className="motion-safe:animate-spin" aria-hidden="true" /> : <Download size={16} aria-hidden="true" />}
    {busy ? "Формирование PDF…" : "Скачать PDF HCP"}
  </Button>;
}
