import { LoaderCircle } from "lucide-react";

export default function Loading() {
  return <div role="status" className="flex min-h-64 items-center justify-center gap-3 text-slate-300">
    <LoaderCircle size={22} className="animate-spin" aria-hidden="true" /> Загружаем страницу…
  </div>;
}
