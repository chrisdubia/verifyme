import { NextResponse } from "next/server";
import { prisma } from "@/lib/db";
import { getSessionUserId } from "@/lib/session";

export const runtime = "nodejs";

export async function POST(req: Request) {
  const userId = await getSessionUserId();
  if (!userId) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });

  const body = await req.json();
  const { deviceKeyId, fileName, mimeType, sha256Hex, signatureB64, metadata } = body;

  if (!deviceKeyId || !fileName || !mimeType || !sha256Hex || !signatureB64) {
    return NextResponse.json({ error: "Missing fields" }, { status: 400 });
  }

  const dk = await prisma.deviceKey.findFirst({ where: { id: deviceKeyId, userId } });
  if (!dk) return NextResponse.json({ error: "Unknown device key" }, { status: 400 });

  const rec = await prisma.provenanceRecord.create({
    data: {
      userId,
      deviceKeyId,
      fileName,
      mimeType,
      sha256Hex,
      signatureB64,
      metadata: metadata ?? null,
    },
  });

  return NextResponse.json({ ok: true, recordId: rec.id });
}
