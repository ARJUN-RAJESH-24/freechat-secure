import { PrismaClient } from "@prisma/client";

// Prisma client initialization with hot-reload check for Next.js
const globalForPrisma = global;
export const prisma = globalForPrisma.prisma || new PrismaClient();

if (process.env.NODE_ENV !== "production") globalForPrisma.prisma = prisma;
