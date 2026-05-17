import { PrismaClient } from "@prisma/client";

const globalForPrisma = globalThis as unknown as {
  prisma?: PrismaClient;
};

export function getPrisma() {
  if (!globalForPrisma.prisma) {
    globalForPrisma.prisma = new PrismaClient();
  }

  return globalForPrisma.prisma;
}

let vaultTableReady: Promise<void> | null = null;

export function ensureVaultTable() {
  if (!vaultTableReady) {
    vaultTableReady = getPrisma().$executeRaw`
      CREATE TABLE IF NOT EXISTS "Vault" (
        "username" TEXT PRIMARY KEY,
        "envelope" JSONB NOT NULL,
        "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
        "updatedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP
      )
    `.then(() => undefined);
  }

  return vaultTableReady;
}
