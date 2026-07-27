"use client";

import { Trash2 } from "lucide-react";
import { useRouter } from "next/navigation";
import { useState } from "react";
import { Button } from "@/components/ui/button";

type DeleteRecordButtonProps = {
  endpoint: string;
  confirmation: string;
  body?: Record<string, string>;
  label?: string;
};

export function DeleteRecordButton({ endpoint, confirmation, body, label = "Удалить" }: DeleteRecordButtonProps) {
  const router = useRouter();
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
      const payload = await response.json().catch(() => ({}));
      if (!response.ok || !payload.ok) {
        throw new Error(payload.message ?? "Не удалось удалить запись.");
      }
      router.refresh();
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Не удалось удалить запись.");
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
