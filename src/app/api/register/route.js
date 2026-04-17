export const dynamic = 'force-dynamic';

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
    const body = await req.json();
    const validation = registerSchema.safeParse(body);

    if (!validation.success) {
      return Response.json(
        { error: "Cryptographic Handshake Integration Failed" },
        { status: 400 }
      );
    }

    const { username, password, publicKey, encryptedPrivateKey } = validation.data;

    const existingUser = await prisma.user.findUnique({ where: { username } });
    if (existingUser) {
      return Response.json(
        { error: "Node explicitly mapped already." },
        { status: 409 }
      );
    }

    const passwordHash = await bcrypt.hash(password, 12);

    await prisma.user.create({
      data: { username, passwordHash, publicKey, encryptedPrivateKey },
    });

    return Response.json({ success: true }, { status: 201 });
  } catch (err) {
    console.error("[/api/register] Error:", err);
    return Response.json({ error: "Internal server error" }, { status: 500 });
  }
}
