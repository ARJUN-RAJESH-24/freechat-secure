export const dynamic = 'force-dynamic';

import { getServerSession } from "next-auth/next";
import { authOptions } from "@/app/api/auth/[...nextauth]/route";
import { redirect } from "next/navigation";
import { getChats } from "@/app/actions/chat";
import ClientChat from "./ClientChat";
import { prisma } from "@/lib/prisma";

export default async function ChatPage() {
  const session = await getServerSession(authOptions);
  
  if (!session?.user) {
    redirect("/login");
  }

  // Directly extract unbreakable cipher text from storage (Prevents cookie truncation issues)
  const userData = await prisma.user.findUnique({
    where: { id: session.user.id },
    select: { encryptedPrivateKey: true }
  });

  const initialChats = await getChats();

  return (
    <ClientChat 
      initialChats={initialChats} 
      currentUser={session.user.username} 
      encryptedPrivateKey={userData?.encryptedPrivateKey} 
    />
  );
}
