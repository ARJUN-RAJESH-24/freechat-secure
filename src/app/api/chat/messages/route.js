export const dynamic = 'force-dynamic';

import { prisma } from "@/lib/prisma";
import { getServerSession } from "next-auth/next";
import { authOptions } from "@/lib/auth";
import { z } from "zod";
import { NextResponse } from "next/server";

const messageSchema = z.object({
  chatId: z.string().uuid(),
  content: z.string().min(1).max(10000),
});

async function getAuthorizedSession(chatId) {
  const session = await getServerSession(authOptions);
  if (!session?.user?.id) return null;

  const participant = await prisma.chatParticipant.findUnique({
    where: { userId_chatId: { userId: session.user.id, chatId } },
  });
  if (!participant) return null;
  return session.user.id;
}

// GET /api/chat/messages?chatId=...
export async function GET(req) {
  try {
    const { searchParams } = new URL(req.url);
    const chatId = searchParams.get("chatId");

    if (!chatId) {
      return NextResponse.json({ error: "Missing chatId" }, { status: 400 });
    }

    const userId = await getAuthorizedSession(chatId);
    if (!userId) {
      return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
    }

    const messages = await prisma.message.findMany({
      where: { chatId },
      include: { sender: { select: { username: true, publicKey: true } } },
      orderBy: { createdAt: "asc" },
      take: 100,
    });

    return NextResponse.json(messages);
  } catch (err) {
    console.error("[GET /api/chat/messages]", err);
    return NextResponse.json({ error: "Internal server error" }, { status: 500 });
  }
}

// POST /api/chat/messages  — send a message
export async function POST(req) {
  try {
    const body = await req.json();
    const validation = messageSchema.safeParse(body);

    if (!validation.success) {
      return NextResponse.json({ error: "Invalid payload" }, { status: 400 });
    }

    const { chatId, content } = validation.data;
    const userId = await getAuthorizedSession(chatId);
    if (!userId) {
      return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
    }

    const msg = await prisma.message.create({
      data: { content, userId, chatId },
      include: { sender: { select: { username: true } } },
    });

    return NextResponse.json(msg, { status: 201 });
  } catch (err) {
    console.error("[POST /api/chat/messages]", err);
    return NextResponse.json({ error: "Internal server error" }, { status: 500 });
  }
}
