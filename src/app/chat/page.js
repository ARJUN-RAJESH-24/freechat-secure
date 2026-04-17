export const dynamic = 'force-dynamic';

import { getServerSession } from "next-auth/next";
import { authOptions } from "@/lib/auth";
import { redirect } from "next/navigation";
import ClientChat from "./ClientChat";
import { prisma } from "@/lib/prisma";

export default async function ChatPage() {
  const session = await getServerSession(authOptions);

  if (!session?.user) {
    redirect("/login");
  }

  // Fetch encrypted private key from DB server-side (avoids passing secrets through cookies)
  const userData = await prisma.user.findUnique({
    where: { id: session.user.id },
    select: { encryptedPrivateKey: true },
  });

  // Fetch initial chats server-side using Prisma directly (no Server Action needed)
  const chatParticipants = await prisma.chatParticipant.findMany({
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

  const initialChats = chatParticipants.map((c) => c.chat);

  return (
    <ClientChat
      initialChats={initialChats}
      currentUser={session.user.username}
      encryptedPrivateKey={userData?.encryptedPrivateKey}
    />
  );
}
