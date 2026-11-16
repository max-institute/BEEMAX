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

export async function sha256(value: string | Uint8Array): Promise<string> {
  const bytes =
    typeof value === "string" ? new TextEncoder().encode(value) : value;
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return Array.from(new Uint8Array(digest))
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
}

function bearerToken(request: Request): string {
  const authorization = request.headers.get("Authorization") ?? "";
  const match = /^Bearer\s+(.+)$/i.exec(authorization.trim());
  return match ? match[1].trim() : "";
}

export async function staffIdentity(
  request: Request,
  env: Env,
): Promise<StaffIdentity | null> {
  const token = bearerToken(request);
  if (!token) return null;

  const governorToken = env.GOVERNOR_API_TOKEN?.trim();
  if (
    governorToken &&
    (token === governorToken ||
      (await sha256(token)).toLowerCase() === governorToken.toLowerCase())
  ) {
    return { id: "governor", role: "Governor" };
  }

  const credentials = env.STAFF_CREDENTIALS;
  if (!credentials) return null;

  try {
    const parsed = JSON.parse(credentials) as Array<{
      id?: unknown;
      role?: unknown;
      tokenSha256?: unknown;
    }>;

    for (const credential of parsed) {
      if (
        !credential ||
        typeof credential.id !== "string" ||
        typeof credential.tokenSha256 !== "string" ||
        !["Governor", "Admin", "Operator", "Read Only"].includes(
          String(credential.role ?? ""),
        )
      ) {
        continue;
      }

      const expectedRole = String(credential.role);
      if ((await sha256(token)).toLowerCase() === credential.tokenSha256.toLowerCase()) {
        return {
          id: credential.id,
          role: expectedRole as StaffRole,
        };
      }
    }
  } catch {
    return null;
  }

  return null;
}

export async function protectPortal(
  request: Request,
  env: Env,
): Promise<StaffIdentity | AutomationIdentity | Response> {
  const identity = await staffIdentity(request, env);
  if (identity) return identity;
  return Response.json({ error: "Staff sign-in required" }, { status: 401 });
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
