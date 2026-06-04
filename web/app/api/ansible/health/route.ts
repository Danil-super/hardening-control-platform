import { execFile } from "node:child_process";
import { existsSync } from "node:fs";
import path from "node:path";
import { promisify } from "node:util";
import { NextResponse } from "next/server";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

const execFileAsync = promisify(execFile);

function getRepoRoot() {
  return path.resolve(process.cwd(), "..");
}

export async function GET() {
  const repoRoot = getRepoRoot();
  const inventoryPath = path.join(repoRoot, "ansible", "inventory.ini");
  const inventoryExamplePath = path.join(repoRoot, "ansible", "inventory.example.ini");

  try {
    const { stdout } = await execFileAsync("ansible", ["--version"], {
      cwd: repoRoot,
      timeout: 10_000,
      maxBuffer: 1024 * 1024,
    });
    const firstLine = stdout.split("\n")[0] || "ansible установлен";

    return NextResponse.json({
      ansibleInstalled: true,
      version: firstLine,
      inventoryReady: existsSync(inventoryPath),
      inventoryPath,
      inventoryExamplePath,
      message: existsSync(inventoryPath)
        ? "Ansible установлен, inventory.ini найден."
        : "Ansible установлен, но inventory.ini еще не создан. Скопируйте ansible/inventory.example.ini.",
    });
  } catch (error) {
    return NextResponse.json({
      ansibleInstalled: false,
      version: null,
      inventoryReady: existsSync(inventoryPath),
      inventoryPath,
      inventoryExamplePath,
      message: error instanceof Error ? error.message : "Ansible не найден или недоступен.",
    });
  }
}
