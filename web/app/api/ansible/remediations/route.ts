import { NextResponse } from "next/server";
import { listRemediationTransactions } from "@/lib/state-store";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

export async function GET() {
  return NextResponse.json({ ok: true, transactions: listRemediationTransactions() });
}
