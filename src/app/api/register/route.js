export const dynamic = 'force-dynamic';

import { NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";
import bcrypt from "bcryptjs";
import { z } from "zod";

const registerSchema = z.object({
  username: z.string().min(4).max(40),
  password: z.string().min(12),
  publicKey: z.string().min(10),
  encryptedPrivateKey: z.string().min(10),
});

export async function POST(req) {
  try {
    let body;
    try {
      body = await req.json();
    } catch {
      return NextResponse.json({ error: "Invalid JSON body" }, { status: 400 });
    }

    const validation = registerSchema.safeParse(body);
    if (!validation.success) {
      return NextResponse.json(
        { error: "Validation failed: " + validation.error.issues.map(i => i.message).join(", ") },
        { status: 400 }
      );
    }

    const { username, password, publicKey, encryptedPrivateKey } = validation.data;

    const existingUser = await prisma.user.findUnique({ where: { username } });
    if (existingUser) {
      return NextResponse.json({ error: "Node explicitly mapped already." }, { status: 409 });
    }

    const passwordHash = await bcrypt.hash(password, 12);

    await prisma.user.create({
      data: { username, passwordHash, publicKey, encryptedPrivateKey },
    });

    return NextResponse.json({ success: true }, { status: 201 });
  } catch (err) {
    // Surface the real error in the response so it's visible without Netlify log access
    const message = err?.message || String(err);
    console.error("[/api/register] Unhandled error:", message);
    return NextResponse.json(
      { error: "Registration failed: " + message },
      { status: 500 }
    );
  }
}
