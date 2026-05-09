import { prisma } from "@/lib/prisma";
import { NextResponse } from "next/server";

export async function GET(request) {
  const { searchParams } = new URL(request.url);
  const id = searchParams.get("id");

  try {
    // VULNERABLE CODE: Boolean-based blind injection
    // This query doesn't return data, only checks if something exists
    const sql = `SELECT id FROM "User" WHERE id = '${id}'`;
    
    const users = await prisma.$queryRawUnsafe(sql);

    if (users.length > 0) {
      return NextResponse.json({ exists: true });
    } else {
      return NextResponse.json({ exists: false });
    }
  } catch (error) {
    // We intentionally return a generic error to simulate a blind environment
    return NextResponse.json({ exists: false, error: "Internal error" }, { status: 500 });
  }
}
