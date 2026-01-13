import { NextResponse } from "next/server";
import { prisma } from "@/lib/db";
import { getSessionUserId } from "@/lib/session";

export const runtime = "nodejs";

export async function POST(req: Request) {
  const userId = await getSessionUserId();
  if (!userId) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });

  const body = await req.json();
  const publicJwk = body.publicJwk;
  const name = typeof body.name === "string" ? body.name : "My device key";

  if (!publicJwk || typeof publicJwk !== "object") {
    return NextResponse.json({ error: "Missing publicJwk" }, { status: 400 });
  }

  const deviceKey = await prisma.deviceKey.create({
    data: {
      userId,
      name,
      alg: "ECDSA_P256_SHA256",
      publicJwk,
    },
  });

  return NextResponse.json({ ok: true, deviceKeyId: deviceKey.id });
}
