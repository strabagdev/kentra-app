import { NextRequest } from "next/server";
import { ensureVaultTable, getPrisma } from "@/lib/prisma";

export const runtime = "nodejs";

function normalizeUser(value: string) {
  return value.trim().toLowerCase().replace(/\s+/g, "-");
}

export async function GET(request: NextRequest) {
  const username = normalizeUser(request.nextUrl.searchParams.get("username") ?? "");

  if (!username) {
    return Response.json({ error: "Username is required." }, { status: 400 });
  }

  await ensureVaultTable();

  const vault = await getPrisma().vault.findUnique({
    where: { username },
  });

  if (!vault) {
    return Response.json({ vault: null });
  }

  return Response.json({ vault: vault.envelope });
}

export async function PUT(request: Request) {
  const body = await request.json();
  const username = normalizeUser(String(body.username ?? ""));
  const envelope = body.envelope;

  if (!username || !envelope || typeof envelope !== "object") {
    return Response.json({ error: "Username and envelope are required." }, { status: 400 });
  }

  await ensureVaultTable();

  const vault = await getPrisma().vault.upsert({
    where: { username },
    create: { username, envelope },
    update: { envelope },
  });

  return Response.json({ vault: vault.envelope });
}
