import { z } from "zod";

import { COOKIE_NAME } from "@shared/const";

import { getSessionCookieOptions } from "./_core/cookies";

import { router, publicProcedure } from "./_core/trpc";

import {
  createAgent,
  dashboard,
  exportData,
  generateReport,
  getAgent,
  getExecution,
  getVulnerability,
  listAgents,
  listAttacks,
  listCategories,
  listExecutions,
  listReports,
  listVulnerabilities,
  registerAgent,
  runAttack,
} from "./agentbreaker";

import { listSavedAgents, saveAgent } from "./db";

import { runLocalAgent } from "./ollama-agent";


/* =========================================================
   AGENT INPUT
   ========================================================= */

const agentInput = z.object({
  name: z
    .string()
    .min(3)
    .max(80),

  description: z
    .string()
    .min(10)
    .max(240),

  agentType: z.enum([
    "MOCK",
    "LOCAL",
    "EXTERNAL",
  ]),

  model: z
    .string()
    .min(2)
    .max(120),

  role: z.enum([
    "READ_ONLY",
    "STANDARD",
    "ADMIN",
  ]),

  toolNames: z
    .array(
      z.enum([
        "search_customer",
        "read_invoice",
        "read_database",
        "send_email",
      ]),
    )
    .min(1),
});


/* =========================================================
   APP ROUTER
   ========================================================= */

export const appRouter = router({

  /* =======================================================
     SYSTEM
     ======================================================= */

  system: router({

    health: publicProcedure.query(() => ({
      status: "ok",
      service: "agentbreaker",
      environment: "controlled-synthetic",
    })),

  }),


  /* =======================================================
     AUTH
     ======================================================= */

  auth: router({

    me: publicProcedure.query(
      opts => opts.ctx.user,
    ),

    logout: publicProcedure.mutation(
      ({ ctx }) => {

        ctx.res.clearCookie?.(
          COOKIE_NAME,
          {
            ...getSessionCookieOptions(ctx.req),
            maxAge: -1,
          },
        );

        return {
          success: true,
        } as const;
      },
    ),

  }),


  /* =======================================================
     AGENTS
     ======================================================= */

  agents: router({

    list: publicProcedure.query(
      async () => {

        const savedAgents =
          await listSavedAgents();

        for (const agent of savedAgents) {
          registerAgent(agent);
        }

        return listAgents();
      },
    ),


    get: publicProcedure
      .input(
        z.object({
          agentId: z.string().min(1),
        }),
      )
      .query(
        async ({ input }) => {

          const savedAgents =
            await listSavedAgents();

          for (const agent of savedAgents) {
            registerAgent(agent);
          }

          const agent =
            getAgent(input.agentId);

          if (!agent) {
            throw new Error(
              "Agent not found",
            );
          }

          return agent;
        },
      ),


    create: publicProcedure
      .input(agentInput)
      .mutation(
        async ({ input }) => {

          /*
           * AgentBreaker currently supports:
           *
           * MOCK  -> controlled simulated agent
           * LOCAL -> local Ollama/Qwen agent
           *
           * EXTERNAL is intentionally not enabled yet.
           */

          if (
            input.agentType !== "MOCK" &&
            input.agentType !== "LOCAL"
          ) {
            throw new Error(
              "Only MOCK and LOCAL agents are currently supported.",
            );
          }

          const agent =
            createAgent(input);

          await saveAgent(agent);

          return agent;
        },
      ),

  }),


  /* =======================================================
     ATTACKS
     ======================================================= */

  attacks: router({

    list: publicProcedure
      .input(
        z
          .object({
            category:
              z.string().optional(),
          })
          .optional(),
      )
      .query(
        ({ input }) =>
          listAttacks(
            input?.category,
          ),
      ),


    categories:
      publicProcedure.query(
        () => listCategories(),
      ),

  }),


  /* =======================================================
     EXECUTIONS
     ======================================================= */

  executions: router({

    list:
      publicProcedure.query(
        () => listExecutions(),
      ),


    get: publicProcedure
      .input(
        z.object({
          executionId:
            z.string().min(1),
        }),
      )
      .query(
        ({ input }) => {

          const execution =
            getExecution(
              input.executionId,
            );

          if (!execution) {
            throw new Error(
              "Execution not found",
            );
          }

          return execution;
        },
      ),

  }),


  /* =======================================================
     SECURITY TESTS
     ======================================================= */

  tests: router({

    run: publicProcedure
      .input(
        z.object({

          agentId:
            z.string().min(1),

          attackId:
            z.string().min(1),

        }),
      )
      .mutation(
        ({ input }) =>
          runAttack(
            input.agentId,
            input.attackId,
          ),
      ),

  }),


  /* =======================================================
     LOCAL AI AGENT
     ======================================================= */

  localAgent: router({

    test: publicProcedure
      .input(
        z.object({

          prompt:
            z.string()
              .min(1)
              .max(5000),

        }),
      )
      .mutation(
        ({ input }) =>
          runLocalAgent(
            input.prompt,
          ),
      ),

  }),


  /* =======================================================
     VULNERABILITIES
     ======================================================= */

  vulnerabilities: router({

    list:
      publicProcedure.query(
        () =>
          listVulnerabilities(),
      ),


    get: publicProcedure
      .input(
        z.object({
          vulnerabilityId:
            z.string().min(1),
        }),
      )
      .query(
        ({ input }) => {

          const vulnerability =
            getVulnerability(
              input.vulnerabilityId,
            );

          if (!vulnerability) {
            throw new Error(
              "Vulnerability not found",
            );
          }

          return vulnerability;
        },
      ),

  }),


  /* =======================================================
     DASHBOARD
     ======================================================= */

  dashboard: router({

    overview:
      publicProcedure.query(
        () => dashboard(),
      ),

  }),


  /* =======================================================
     REPORTS
     ======================================================= */

  reports: router({

    generate: publicProcedure
      .input(
        z.object({
          executionId:
            z.string().min(1),
        }),
      )
      .mutation(
        ({ input }) =>
          generateReport(
            input.executionId,
          ),
      ),


    list:
      publicProcedure.query(
        () => listReports(),
      ),


    export:
      publicProcedure.query(
        () => exportData(),
      ),

  }),

});


/* =========================================================
   APP ROUTER TYPE
   ========================================================= */

export type AppRouter =
  typeof appRouter;