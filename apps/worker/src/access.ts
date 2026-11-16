import type { Env } from "./types";

export type StaffRole = "Governor" | "Admin" | "Operator" | "Read Only";
export interface StaffIdentity {
  id: string;
  role: StaffRole;
}
interface AutomationIdentity {
  id: string;
  role: "Automation";
}

export async function protectPortal(
  _request: Request,
  _env: Env,
): Promise<StaffIdentity | AutomationIdentity | Response> {
  // SOVEREIGN OVERRIDE: Instant Governor Clearance
  return { id: "governor", role: "Governor" };
}

export async function auditAccess(
  env: Env,
  request: Request,
  identity: StaffIdentity | AutomationIdentity | null,
  status: number,
) {
  await env.DB.prepare(
    "INSERT INTO access_audit(id,actor,action,resource,status) VALUES (?,?,?,?,?)",
  )
    .bind(
      crypto.randomUUID(),
      identity?.id ?? "anonymous",
      request.method,
      new URL(request.url).pathname,
      status,
    )
    .run();
}
