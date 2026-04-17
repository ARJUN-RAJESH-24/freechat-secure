"use server";

import { prisma } from "@/lib/prisma";
import { getServerSession } from "next-auth/next";
import { authOptions } from "@/app/api/auth/[...nextauth]/route";
import { z } from "zod";

const messageSchema = z.object({
  chatId: z.string().uuid(),
  content: z.string().min(1).max(10000), // Updated to support AES-GCM + ECDSA Signature JSON wrappers
});

// Helper to strictly authenticate and authorize user for a chat
async function authorizeChatAccess(chatId) {
  const session = await getServerSession(authOptions);
  if (!session?.user?.id) throw new Error("Unauthorized Access");

  const participant = await prisma.chatParticipant.findUnique({
    where: {
      userId_chatId: {
        userId: session.user.id,
        chatId: chatId,
      },
    },
  });

  if (!participant) throw new Error("IDOR Prevention: Access Denied to Chat Node");
  return session.user.id;
}

export async function getChats() {
  const session = await getServerSession(authOptions);
  if (!session?.user?.id) return [];

  const chats = await prisma.chatParticipant.findMany({
    where: { userId: session.user.id },
    include: {
      chat: {
        include: {
          participants: {
            include: { user: { select: { username: true, publicKey: true } } }
          }
        }
      }
    },
    orderBy: { joinedAt: 'desc' }
  });

  return chats.map(c => c.chat);
}

export async function getMessages(chatId) {
  await authorizeChatAccess(chatId);
  const messages = await prisma.message.findMany({
    where: { chatId },
    include: { sender: { select: { username: true, publicKey: true } } },
    orderBy: { createdAt: 'asc' },
    take: 100 // Prevent memory exhaustion limit
  });
  return messages;
}

export async function sendMessage(chatId, content) {
  const userId = await authorizeChatAccess(chatId);
  
  const validation = messageSchema.safeParse({ chatId, content });
  if (!validation.success) throw new Error("Invalid rigorous payload formatting.");

  const msg = await prisma.message.create({
    data: {
      content: validation.data.content,
      userId,
      chatId,
    },
    include: { sender: { select: { username: true } } }
  });
  
  return msg;
}

export async function initializeDirectConnect(targetUsername) {
  const session = await getServerSession(authOptions);
  if (!session?.user?.id) throw new Error("Unauthorized");
  if (targetUsername === session.user.username) throw new Error("Cannot connect to self.");

  const target = await prisma.user.findUnique({ where: { username: targetUsername }});
  if (!target) throw new Error("Target node offline or non-existent.");

  // Check if DM already exists
  const existingSharedChats = await prisma.chat.findFirst({
    where: {
      type: "DIRECT",
      participants: {
        every: {
          userId: { in: [session.user.id, target.id] }
        }
      }
    }
  });

  if (existingSharedChats) return existingSharedChats;

  // Establish new 1:1 tunnel
  const newChat = await prisma.chat.create({
    data: {
      type: "DIRECT",
      participants: {
        create: [
          { userId: session.user.id, role: "ADMIN" },
          { userId: target.id, role: "MEMBER" }
        ]
      }
    },
    include: {
      participants: {
        include: { user: { select: { username: true, publicKey: true } } }
      }
    }
  });

  return newChat;
}
