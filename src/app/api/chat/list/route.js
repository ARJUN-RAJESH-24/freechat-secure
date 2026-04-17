export const dynamic = 'force-dynamic';

import { prisma } from "@/lib/prisma";
import { getServerSession } from "next-auth/next";
import { authOptions } from "@/lib/auth";
import { NextResponse } from "next/server";

// GET /api/chat/list  — returns all chats for the current user
export async function GET() {
  try {
    const session = await getServerSession(authOptions);
    if (!session?.user?.id) {
      return NextResponse.json([], { status: 200 });
    }

    const chats = await prisma.chatParticipant.findMany({
      where: { userId: session.user.id },
      include: {
        chat: {
          include: {
            participants: {
              include: { user: { select: { username: true, publicKey: true } } },
            },
          },
        },
      },
      orderBy: { joinedAt: "desc" },
    });

    return NextResponse.json(chats.map((c) => c.chat));
  } catch (err) {
    console.error("[GET /api/chat/list]", err);
    return NextResponse.json({ error: "Internal server error" }, { status: 500 });
  }
}

// POST /api/chat/list  — initialize a direct connection with another user
export async function POST(req) {
  try {
    const session = await getServerSession(authOptions);
    if (!session?.user?.id) {
      return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
    }

    const { targetUsername } = await req.json();

    if (!targetUsername || targetUsername === session.user.username) {
      return NextResponse.json({ error: "Cannot connect to self." }, { status: 400 });
    }

    const target = await prisma.user.findUnique({ where: { username: targetUsername } });
    if (!target) {
      return NextResponse.json({ error: "Target node offline or non-existent." }, { status: 404 });
    }

    // Check if a direct chat already exists between the two users
    const existing = await prisma.chat.findFirst({
      where: {
        type: "DIRECT",
        AND: [
          { participants: { some: { userId: session.user.id } } },
          { participants: { some: { userId: target.id } } },
        ],
      },
      include: {
        participants: {
          include: { user: { select: { username: true, publicKey: true } } },
        },
      },
    });

    if (existing) {
      return NextResponse.json(existing);
    }

    const newChat = await prisma.chat.create({
      data: {
        type: "DIRECT",
        participants: {
          create: [
            { userId: session.user.id, role: "ADMIN" },
            { userId: target.id, role: "MEMBER" },
          ],
        },
      },
      include: {
        participants: {
          include: { user: { select: { username: true, publicKey: true } } },
        },
      },
    });

    return NextResponse.json(newChat, { status: 201 });
  } catch (err) {
    console.error("[POST /api/chat/list]", err);
    return NextResponse.json({ error: "Internal server error" }, { status: 500 });
  }
}
