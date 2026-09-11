"use client";

import { Trash2 } from "lucide-react";
import { useRouter } from "next/navigation";
import { useState } from "react";
import { useNotify } from "@/components/ui/feedback";
import { readApiResponse, errorMessage } from "@/lib/client-api";
import { Button } from "@/components/ui/button";

type DeleteRecordButtonProps = {
  endpoint: string;
  confirmation: string;
  body?: Record<string, string>;
  label?: string;
};

export function DeleteRecordButton({ endpoint, confirmation, body, label = "Удалить" }: DeleteRecordButtonProps) {
  const router = useRouter();
  const notify = useNotify();
  const [pending, setPending] = useState(false);
  const [error, setError] = useState("");

  async function remove() {
    if (!window.confirm(confirmation)) {
      return;
    }
    setPending(true);
    setError("");
    try {
      const response = await fetch(endpoint, {
        method: "DELETE",
        headers: body ? { "Content-Type": "application/json" } : undefined,
        body: body ? JSON.stringify(body) : undefined,
      });
      const payload = await readApiResponse(response);
      if (!response.ok || !payload.ok) {
        throw new Error(payload.message ?? "Не удалось удалить запись.");
      }
      notify(payload.message || "Запись удалена.", "success");
      router.refresh();
    } catch (cause) {
      const message = errorMessage(cause, "Не удалось удалить запись. Проверьте соединение.");
      setError(message);
      notify(message, "error");
    } finally {
      setPending(false);
    }
  }

  return (
    <div className="flex flex-col items-start gap-1">
      <Button type="button" variant="danger" className="h-9 px-3" onClick={remove} disabled={pending}>
        <Trash2 size={15} aria-hidden="true" />
        {pending ? "Удаление…" : label}
      </Button>
      {error ? <p className="max-w-48 text-xs text-red-200">{error}</p> : null}
    </div>
  );
}
