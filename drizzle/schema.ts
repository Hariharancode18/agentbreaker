import { int, json, mysqlEnum, mysqlTable, text, timestamp, varchar } from "drizzle-orm/mysql-core";

export const users = mysqlTable("users", {
  id: int("id").autoincrement().primaryKey(), openId: varchar("openId", { length: 64 }).notNull().unique(), name: text("name"), email: varchar("email", { length: 320 }), loginMethod: varchar("loginMethod", { length: 64 }), role: mysqlEnum("role", ["user", "admin"]).default("user").notNull(), createdAt: timestamp("createdAt").defaultNow().notNull(), updatedAt: timestamp("updatedAt").defaultNow().onUpdateNow().notNull(), lastSignedIn: timestamp("lastSignedIn").defaultNow().notNull(),
});

export const agentbreakerAgents = mysqlTable("agentbreaker_agents", {
  id: varchar("id", { length: 64 }).primaryKey(), name: varchar("name", { length: 120 }).notNull(), description: text("description").notNull(), agentType: varchar("agentType", { length: 16 }).notNull(), model: varchar("model", { length: 120 }).notNull(), role: varchar("role", { length: 32 }).notNull(), version: varchar("version", { length: 32 }).notNull(), status: varchar("status", { length: 16 }).notNull(), tools: json("tools").notNull(), policy: json("policy").notNull(), createdAt: timestamp("createdAt").defaultNow().notNull(), lastTested: timestamp("lastTested").defaultNow().notNull(),
});
export const agentbreakerAttacks = mysqlTable("agentbreaker_attacks", {
  id: varchar("id", { length: 64 }).primaryKey(), category: varchar("category", { length: 80 }).notNull(), name: varchar("name", { length: 120 }).notNull(), description: text("description").notNull(), payload: text("payload").notNull(), expectedBehavior: text("expectedBehavior").notNull(), detectionConditions: json("detectionConditions").notNull(), baselineSeverity: varchar("baselineSeverity", { length: 16 }).notNull(),
});
export const agentbreakerExecutions = mysqlTable("agentbreaker_executions", {
  id: varchar("id", { length: 64 }).primaryKey(), agentId: varchar("agentId", { length: 64 }).notNull(), attackId: varchar("attackId", { length: 64 }).notNull(), status: varchar("status", { length: 24 }).notNull(), input: text("input").notNull(), response: text("response").notNull(), analysis: json("analysis").notNull(), startedAt: timestamp("startedAt").notNull(), completedAt: timestamp("completedAt").notNull(),
});
export const agentbreakerEvents = mysqlTable("agentbreaker_events", {
  id: varchar("id", { length: 64 }).primaryKey(), executionId: varchar("executionId", { length: 64 }).notNull(), eventType: varchar("eventType", { length: 40 }).notNull(), title: varchar("title", { length: 160 }).notNull(), detail: text("detail").notNull(), payload: json("payload"), timestamp: timestamp("timestamp").notNull(),
});
export const agentbreakerVulnerabilities = mysqlTable("agentbreaker_vulnerabilities", {
  id: varchar("id", { length: 64 }).primaryKey(), executionId: varchar("executionId", { length: 64 }).notNull(), attackId: varchar("attackId", { length: 64 }).notNull(), category: varchar("category", { length: 80 }).notNull(), title: varchar("title", { length: 180 }).notNull(), severity: varchar("severity", { length: 16 }).notNull(), riskScore: int("riskScore").notNull(), evidence: json("evidence").notNull(), recommendation: json("recommendation").notNull(), createdAt: timestamp("createdAt").defaultNow().notNull(),
});

export type User = typeof users.$inferSelect;
export type InsertUser = typeof users.$inferInsert;
