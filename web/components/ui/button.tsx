import Link from "next/link";
import type { ComponentProps, ReactNode } from "react";

const base =
  "inline-flex min-h-10 shrink-0 items-center justify-center gap-2 rounded-lg px-4 py-2 text-sm font-semibold leading-5 transition active:translate-y-px focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-sky-300 disabled:cursor-not-allowed disabled:opacity-50 disabled:active:translate-y-0 [&>svg]:shrink-0";

const variants = {
  primary: "bg-sky-400 text-slate-950 hover:bg-sky-300",
  secondary: "border border-slate-700 bg-slate-900 text-slate-100 hover:bg-slate-800",
  danger: "border border-red-400/50 bg-red-500/15 text-red-100 hover:bg-red-500/25",
};

type ButtonProps = ComponentProps<"button"> & {
  variant?: keyof typeof variants;
};

export function Button({ className = "", variant = "primary", ...props }: ButtonProps) {
  return <button className={`${base} ${variants[variant]} ${className}`} {...props} />;
}

type LinkButtonProps = ComponentProps<typeof Link> & {
  children: ReactNode;
  variant?: keyof typeof variants;
};

export function LinkButton({ className = "", variant = "primary", ...props }: LinkButtonProps) {
  return <Link className={`${base} ${variants[variant]} ${className}`} {...props} />;
}
