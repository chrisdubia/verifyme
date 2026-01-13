import { NextResponse } from "next/server";
import { prisma } from "@/lib/db";
import { setSession } from "@/lib/session";

export const runtime = "nodejs";

export async function POST(req: Request) {
  if (process.env.NODE_ENV === "production") {
    return NextResponse.json({ error: "Not available in production" }, { status: 404 });
  }

  const body = await req.json().catch(() => ({}));
  const label = typeof body.label === "string" ? body.label : "Dev User";

  const user = await prisma.user.create({ data: { label } });
  await setSession(user.id);

  return NextResponse.json({ ok: true, userId: user.id });
}
