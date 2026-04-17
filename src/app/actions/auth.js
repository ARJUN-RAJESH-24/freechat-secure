"use server";

export const dynamic = 'force-dynamic';

import { prisma } from "@/lib/prisma";
import bcrypt from "bcryptjs";
import { z } from "zod";

const registerSchema = z.object({
  username: z.string().min(4).max(40),
  password: z.string().min(12),
  publicKey: z.string().min(10), // Base64 payload validation
  encryptedPrivateKey: z.string().min(10)
});

export async function registerUser(formData) {
  const username = formData.get("username");
  const password = formData.get("password");
  const publicKey = formData.get("publicKey");
  const encryptedPrivateKey = formData.get("encryptedPrivateKey");

  const validation = registerSchema.safeParse({ username, password, publicKey, encryptedPrivateKey });

  if (!validation.success) return { error: "Cryptographic Handshake Integration Failed" };

  const existingUser = await prisma.user.findUnique({
    where: { username: validation.data.username },
  });

  if (existingUser) return { error: "Node explicitly mapped already." };

  const passwordHash = await bcrypt.hash(validation.data.password, 12);

  await prisma.user.create({
    data: {
      username: validation.data.username,
      passwordHash,
      publicKey: validation.data.publicKey,
      encryptedPrivateKey: validation.data.encryptedPrivateKey
    },
  });

  return { success: true };
}
