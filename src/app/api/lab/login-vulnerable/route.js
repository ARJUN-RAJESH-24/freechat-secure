import { prisma } from "@/lib/prisma";
import { NextResponse } from "next/server";

export async function POST(request) {
  try {
    const { username, password } = await request.json();

    // VULNERABLE CODE: Using string interpolation in a raw SQL query
    // This is explicitly for the Cybersecurity Lab demonstration.
    const query = `SELECT * FROM "User" WHERE username = '${username}' AND "passwordHash" = '${password}'`;
    
    console.log("Executing vulnerable query:", query);
    
    const users = await prisma.$queryRawUnsafe(query);

    if (users.length > 0) {
      return NextResponse.json({ 
        success: true, 
        message: "Login successful!", 
        user: { username: users[0].username } 
      });
    } else {
      return NextResponse.json({ 
        success: false, 
        message: "Invalid credentials." 
      }, { status: 401 });
    }
  } catch (error) {
    return NextResponse.json({ 
      success: false, 
      message: "Database error", 
      error: error.message 
    }, { status: 500 });
  }
}
