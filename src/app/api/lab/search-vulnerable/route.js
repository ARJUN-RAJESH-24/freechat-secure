import { prisma } from "@/lib/prisma";
import { NextResponse } from "next/server";

export async function GET(request) {
  const { searchParams } = new URL(request.url);
  const query = searchParams.get("q");

  try {
    // VULNERABLE CODE: Raw SQL search with string concatenation
    const sql = `SELECT username, "publicKey" FROM "User" WHERE username LIKE '%${query}%'`;
    
    console.log("Executing vulnerable search:", sql);
    
    const results = await prisma.$queryRawUnsafe(sql);

    return NextResponse.json({ success: true, results });
  } catch (error) {
    return NextResponse.json({ 
      success: false, 
      message: "Database error", 
      error: error.message 
    }, { status: 500 });
  }
}
