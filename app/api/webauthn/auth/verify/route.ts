import { NextResponse } from "next/server";
import { prisma } from "@/lib/db";
import { verifyAuth } from "@/lib/webauthn";
import { setSession } from "@/lib/session";

export const runtime = "nodejs";

export async function POST(req: Request) {
  const body = await req.json();
  const userId = body.userId as string;
  const response = body.response;

  const creds = await prisma.passkeyCredential.findMany({
    where: { userId },
  });
  if (!creds.length) return NextResponse.json({ error: "No credential" }, { status: 400 });

  // Find credential by ID if provided
  const matching = creds.find((c) => {
    const idB64Url = response.id as string;
    // We store credentialID as bytes; simplewebauthn browser sends base64url id
    const stored = Buffer.from(c.credentialID).toString("base64url");
    return stored === idB64Url;
  }) ?? creds[0];

  const verification = await verifyAuth({
    userId,
    response,
    credential: {
      credentialID: Buffer.from(matching.credentialID),
      credentialPublicKey: Buffer.from(matching.credentialPublicKey),
      counter: matching.counter,
    },
  });

  const newCounter = verification.authenticationInfo.newCounter;
  await prisma.passkeyCredential.update({
    where: { id: matching.id },
    data: { counter: newCounter },
  });

  await setSession(userId);
  return NextResponse.json({ ok: true });
}
