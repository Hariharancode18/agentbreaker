import { useMemo, useState } from "react";
import { toast } from "sonner";
import { trpc } from "@/lib/trpc";
import { Button } from "@/components/ui/button";
import { Check, LockKeyhole, Plus, X } from "lucide-react";
import {
  TOOL_CATALOG,
  type AgentDefinition,
  type ToolName,
} from "@shared/agentbreaker";

const defaultTools: ToolName[] = [
  "search_customer",
  "read_invoice",
];

export function AgentRegistrationDialog({
  open,
  onOpenChange,
  onRegistered,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  onRegistered?: (agent: AgentDefinition) => void;
}) {
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");

  const [agentType, setAgentType] =
    useState<AgentDefinition["agentType"]>("MOCK");

  const [model, setModel] = useState(
    "AgentBreaker Mock Agent",
  );

  const [role, setRole] = useState("STANDARD");

  const [tools, setTools] =
    useState<ToolName[]>(defaultTools);

  const utils = trpc.useUtils();

  const create =
    trpc.agents.create.useMutation({
      onSuccess: (agent) => {
        utils.agents.list.invalidate();

        setName("");
        setDescription("");
        setAgentType("MOCK");
        setModel("AgentBreaker Mock Agent");
        setRole("STANDARD");
        setTools(defaultTools);

        onOpenChange(false);

        onRegistered?.(agent);

        toast.success(
          "Agent registered successfully.",
        );
      },

      onError: (error) => {
        toast.error(error.message);
      },
    });

  const selectedDefinitions = useMemo(
    () =>
      TOOL_CATALOG.filter((tool) =>
        tools.includes(tool.name),
      ),
    [tools],
  );

  if (!open) {
    return null;
  }

  const toggleTool = (tool: ToolName) => {
    setTools((current) =>
      current.includes(tool)
        ? current.filter(
            (item) => item !== tool,
          )
        : [...current, tool],
    );
  };

  const invalidTools =
    selectedDefinitions.filter(
      (tool) =>
        !tool.allowedRoles.includes(role),
    );

  const valid =
    name.trim().length >= 3 &&
    name.trim().length <= 80 &&
    description.trim().length >= 10 &&
    description.trim().length <= 240 &&
    tools.length > 0 &&
    invalidTools.length === 0;

  return (
    <div
      className="agent-dialog-backdrop"
      role="presentation"
      onMouseDown={(event) => {
        if (
          event.target ===
          event.currentTarget
        ) {
          onOpenChange(false);
        }
      }}
    >
      <div
        className="agent-dialog"
        role="dialog"
        aria-modal="true"
        aria-labelledby="register-agent-title"
      >
        {/* HEADER */}
        <div className="agent-dialog-head">
          <div>
            <div className="card-kicker">
              TARGET AGENT REGISTRATION
            </div>

            <h2 id="register-agent-title">
              Register target agent
            </h2>

            <p>
              Add a controlled agent profile
              to the security testing registry.
            </p>
          </div>

          <button
            className="icon-close"
            onClick={() =>
              onOpenChange(false)
            }
            aria-label="Close registration dialog"
          >
            <X size={17} />
          </button>
        </div>

        {/* FORM */}
        <div className="agent-form-grid">

          {/* AGENT NAME */}
          <label>
            <span>AGENT NAME</span>

            <input
              value={name}
              onChange={(event) =>
                setName(event.target.value)
              }
              placeholder="Customer Support Agent"
              maxLength={80}
            />

            <small>
              {name.length}/80 · minimum
              3 characters
            </small>
          </label>

          {/* MODEL */}
          <label>
            <span>MODEL</span>

            <input
              value={model}
              onChange={(event) =>
                setModel(event.target.value)
              }
              placeholder="qwen3:4b"
              maxLength={120}
            />
          </label>

          {/* DESCRIPTION */}
          <label className="wide-field">
            <span>DESCRIPTION</span>

            <textarea
              value={description}
              onChange={(event) =>
                setDescription(
                  event.target.value,
                )
              }
              placeholder="Controlled customer support AI agent"
              maxLength={240}
            />

            <small>
              {description.length}/240 ·
              minimum 10 characters
            </small>
          </label>

          {/* AGENT TYPE */}
          <label>
            <span>AGENT TYPE</span>

            <select
              value={agentType}
              onChange={(event) =>
                setAgentType(
                  event.target.value as AgentDefinition["agentType"],
                )
              }
            >
              <option value="MOCK">
                MOCK · supported
              </option>

              {/* LOCAL IS NOW ENABLED */}
              <option value="LOCAL">
                LOCAL · Ollama / Qwen3
              </option>

              {/* EXTERNAL REMAINS DISABLED */}
              <option
                value="EXTERNAL"
                disabled
              >
                EXTERNAL · experimental
              </option>
            </select>
          </label>

          {/* ROLE */}
          <label>
            <span>ROLE</span>

            <select
              value={role}
              onChange={(event) =>
                setRole(event.target.value)
              }
            >
              <option value="READ_ONLY">
                READ_ONLY
              </option>

              <option value="STANDARD">
                STANDARD
              </option>

              <option value="ADMIN">
                ADMIN
              </option>
            </select>
          </label>
        </div>

        {/* TOOLS */}
        <div className="tool-selector">

          <div className="tool-selector-head">
            <div>
              <div className="card-kicker">
                AVAILABLE TOOLS
              </div>

              <strong>
                Configure allowed capabilities
              </strong>
            </div>

            <span>
              {tools.length} selected
            </span>
          </div>

          <div className="tool-selector-grid">
            {TOOL_CATALOG.map((tool) => {
              const selected =
                tools.includes(tool.name);

              const allowed =
                tool.allowedRoles.includes(
                  role,
                );

              return (
                <button
                  type="button"
                  className={`tool-select-row ${
                    selected
                      ? "selected"
                      : ""
                  } ${
                    !allowed
                      ? "incompatible"
                      : ""
                  }`}
                  key={tool.name}
                  onClick={() =>
                    toggleTool(tool.name)
                  }
                >
                  <span className="tool-check">
                    {selected && (
                      <Check size={12} />
                    )}
                  </span>

                  <span className="tool-select-copy">
                    <strong>
                      {tool.name}()
                    </strong>

                    <small>
                      {tool.description}
                    </small>
                  </span>

                  <span className="tool-select-meta">
                    <b>
                      {tool.permission}
                    </b>

                    <small>
                      {allowed
                        ? tool.dataClassification
                        : `Not allowed for ${role}`}
                    </small>
                  </span>
                </button>
              );
            })}
          </div>

          {invalidTools.length > 0 && (
            <div className="form-warning">
              <LockKeyhole size={14} />

              {invalidTools
                .map(
                  (tool) => tool.name,
                )
                .join(", ")}{" "}
              require a different role.
              Remove incompatible tools or
              change the role.
            </div>
          )}
        </div>

        {/* SAFETY */}
        <div className="dialog-safety">
          <LockKeyhole size={14} />

          <span>
            CONTROLLED / SYNTHETIC
          </span>

          <small>
            Registration creates a
            controlled MOCK or LOCAL test
            profile. LOCAL agents run through
            the configured Ollama model.
            No external production systems
            are connected.
          </small>
        </div>

        {/* ACTIONS */}
        <div className="agent-dialog-actions">

          <Button
            className="secondary-btn"
            onClick={() =>
              onOpenChange(false)
            }
          >
            Cancel
          </Button>

          <Button
            className="primary-btn"
            disabled={
              !valid ||
              create.isPending
            }
            onClick={() =>
              create.mutate({
                name: name.trim(),
                description:
                  description.trim(),
                agentType,
                model: model.trim(),
                role: role as
                  | "READ_ONLY"
                  | "STANDARD"
                  | "ADMIN",
                toolNames: tools,
              })
            }
          >
            {create.isPending ? (
              "Registering…"
            ) : (
              <>
                <Plus size={15} />
                Register agent
              </>
            )}
          </Button>
        </div>
      </div>
    </div>
  );
}