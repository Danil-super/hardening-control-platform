import type { Metadata } from "next";
import { AppShell } from "@/components/layout/app-shell";
import { FeedbackProvider } from "@/components/ui/feedback";
import "./globals.css";

export const metadata: Metadata = {
  title: "Контроль безопасности",
  description: "Управление аудитом и безопасными изменениями Linux-хостов через Ansible и SSH.",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="ru" className="h-full antialiased">
      <body className="min-h-full bg-slate-950 text-slate-100">
        <FeedbackProvider><AppShell>{children}</AppShell></FeedbackProvider>
      </body>
    </html>
  );
}
