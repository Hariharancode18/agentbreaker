import { eq } from "drizzle-orm";
import { drizzle } from "drizzle-orm/mysql2";
import { agentbreakerAgents, InsertUser, users } from "../drizzle/schema";
import type { AgentDefinition } from "../shared/agentbreaker";
import { ENV } from './_core/env';

let _db: ReturnType<typeof drizzle> | null = null;

// Lazily create the drizzle instance so local tooling can run without a DB.
export async function getDb() {
  if (!_db && process.env.DATABASE_URL) {
    try {
      _db = drizzle(process.env.DATABASE_URL);
    } catch (error) {
      console.warn("[Database] Failed to connect:", error);
      _db = null;
    }
  }
  return _db;
}

export async function upsertUser(user: InsertUser): Promise<void> {
  if (!user.openId) {
    throw new Error("User openId is required for upsert");
  }

  const db = await getDb();
  if (!db) {
    console.warn("[Database] Cannot upsert user: database not available");
    return;
  }

  try {
    const values: InsertUser = {
      openId: user.openId,
    };
    const updateSet: Record<string, unknown> = {};

    const textFields = ["name", "email", "loginMethod"] as const;
    type TextField = (typeof textFields)[number];

    const assignNullable = (field: TextField) => {
      const value = user[field];
      if (value === undefined) return;
      const normalized = value ?? null;
      values[field] = normalized;
      updateSet[field] = normalized;
    };

    textFields.forEach(assignNullable);

    if (user.lastSignedIn !== undefined) {
      values.lastSignedIn = user.lastSignedIn;
      updateSet.lastSignedIn = user.lastSignedIn;
    }
    if (user.role !== undefined) {
      values.role = user.role;
      updateSet.role = user.role;
    } else if (user.openId === ENV.ownerOpenId) {
      values.role = 'admin';
      updateSet.role = 'admin';
    }

    if (!values.lastSignedIn) {
      values.lastSignedIn = new Date();
    }

    if (Object.keys(updateSet).length === 0) {
      updateSet.lastSignedIn = new Date();
    }

    await db.insert(users).values(values).onDuplicateKeyUpdate({
      set: updateSet,
    });
  } catch (error) {
    console.error("[Database] Failed to upsert user:", error);
    throw error;
  }
}

export async function getUserByOpenId(openId: string) {
  const db = await getDb();
  if (!db) {
    console.warn("[Database] Cannot get user: database not available");
    return undefined;
  }

  const result = await db.select().from(users).where(eq(users.openId, openId)).limit(1);

  return result.length > 0 ? result[0] : undefined;
}

export async function saveAgent(agent: AgentDefinition): Promise<void> {
  const db = await getDb();
  if (!db) return;
  await db.insert(agentbreakerAgents).values({
    id: agent.id,
    name: agent.name,
    description: agent.description,
    agentType: agent.agentType,
    model: agent.model,
    role: agent.role,
    version: agent.version,
    status: agent.status,
    tools: agent.tools,
    policy: agent.policy,
    createdAt: new Date(agent.createdAt),
    lastTested: new Date(agent.lastTested),
  }).onDuplicateKeyUpdate({ set: { name: agent.name, description: agent.description, agentType: agent.agentType, model: agent.model, role: agent.role, version: agent.version, status: agent.status, tools: agent.tools, policy: agent.policy, lastTested: new Date(agent.lastTested) } });
}

export async function listSavedAgents(): Promise<AgentDefinition[]> {
  const db = await getDb();
  if (!db) return [];
  const rows = await db.select().from(agentbreakerAgents);
  return rows.map(row => ({ id: row.id, name: row.name, description: row.description, version: row.version, agentType: row.agentType as AgentDefinition["agentType"], model: row.model, role: row.role, status: row.status as AgentDefinition["status"], tools: row.tools as AgentDefinition["tools"], policy: row.policy as string[], createdAt: row.createdAt.getTime(), lastTested: row.lastTested.getTime() }));
}

// TODO: add feature queries here as your schema grows.
