import { NextResponse } from "next/server";
import { prisma } from "@/lib/db";

export const runtime = "nodejs";

function b64ToBytes(b64: string): Uint8Array {
  const bin = Buffer.from(b64, "base64");
  return new Uint8Array(bin);
}

function hexToBytes(hex: string): Uint8Array {
  const clean = hex.trim().toLowerCase();
  if (!/^[0-9a-f]+$/.test(clean) || clean.length % 2 !== 0) {
    throw new Error("Bad hex");
  }
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

export async function POST(req: Request) {
  const body = await req.json();
  const { recordId, sha256Hex } = body;

  const rec = await prisma.provenanceRecord.findUnique({
    where: { id: recordId },
    include: { user: true },
  });
  if (!rec) return NextResponse.json({ ok: false, error: "Not found" }, { status: 404 });

  const dk = await prisma.deviceKey.findUnique({ where: { id: rec.deviceKeyId } });
  if (!dk) return NextResponse.json({ ok: false, error: "Missing device key" }, { status: 400 });

  const expectedHash = rec.sha256Hex;
  const providedHash = typeof sha256Hex === "string" ? sha256Hex : expectedHash;

  const publicKey = await crypto.subtle.importKey(
    "jwk",
    dk.publicJwk as JsonWebKey,
    { name: "ECDSA", namedCurve: "P-256" },
    true,
    ["verify"]
  );

  const msg = hexToBytes(providedHash);
  const sig = b64ToBytes(rec.signatureB64);

  const signatureValid = await crypto.subtle.verify(
    { name: "ECDSA", hash: "SHA-256" },
    publicKey,
    sig,
    msg
  );

  const hashMatchesRecord = providedHash === expectedHash;

  return NextResponse.json({
    ok: signatureValid && hashMatchesRecord,
    signatureValid,
    hashMatchesRecord,
    record: {
      id: rec.id,
      createdAt: rec.createdAt,
      fileName: rec.fileName,
      mimeType: rec.mimeType,
      sha256Hex: rec.sha256Hex,
      signerUserLabel: rec.user.label ?? rec.user.id,
      deviceKeyId: rec.deviceKeyId,
    },
  });
}
