import { NextResponse } from "next/server";
import { prisma } from "@/lib/db";
import { createRegistrationOptions } from "@/lib/webauthn";

export const runtime = "nodejs";

export async function POST(req: Request) {
  const body = await req.json().catch(() => ({}));
  const userName = typeof body.userName === "string" ? body.userName : "user";

  const user = await prisma.user.create({
    data: { label: userName },
  });

  const existing = await prisma.passkeyCredential.findMany({
    where: { userId: user.id },
  });

  const opts = await createRegistrationOptions({
    userId: user.id,
    userName,
    existingCredentialIDs: existing.map((c) => Buffer.from(c.credentialID)),
  });

  return NextResponse.json({ userId: user.id, options: opts });
}
