import { NextResponse } from "next/server";
import { prisma } from "@/lib/db";
import { createAuthOptions } from "@/lib/webauthn";

export const runtime = "nodejs";

export async function POST(req: Request) {
  const body = await req.json();
  const userId = body.userId as string;

  const creds = await prisma.passkeyCredential.findMany({
    where: { userId },
  });
  if (!creds.length) {
    return NextResponse.json({ error: "No passkeys for user" }, { status: 400 });
  }

  const opts = await createAuthOptions({
    userId,
    allowCredentialIDs: creds.map((c: { credentialID: Buffer }) => Buffer.from(c.credentialID)),
  });

  return NextResponse.json({ options: opts });
}
