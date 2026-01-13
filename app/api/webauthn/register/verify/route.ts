import { NextResponse } from "next/server";
import { prisma } from "@/lib/db";
import { verifyRegistration } from "@/lib/webauthn";
import { setSession } from "@/lib/session";

export const runtime = "nodejs";

export async function POST(req: Request) {
  const body = await req.json();
  const userId = body.userId as string;
  const response = body.response;

  const verification = await verifyRegistration({
    userId,
    response,
  });

  const regInfo = verification.registrationInfo;
  if (!regInfo) throw new Error("Missing registrationInfo");

  await prisma.passkeyCredential.create({
    data: {
      userId,
      credentialID: Buffer.from(regInfo.credentialID),
      credentialPublicKey: Buffer.from(regInfo.credentialPublicKey),
      counter: regInfo.counter,
      transports: JSON.stringify(response.response?.transports ?? []),
    },
  });

  await setSession(userId);
  return NextResponse.json({ ok: true });
}
