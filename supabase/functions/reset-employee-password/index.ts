// Supabase Edge Function: reset-employee-password
// Deploy via Supabase Dashboard > Edge Functions > Via Editor.
// Keep JWT verification enabled. Never place service-role keys in GitHub or browser code.
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const origin = "https://nvjv8tnmtn-alt.github.io";
const cors = {
  "Access-Control-Allow-Origin": origin,
  "Access-Control-Allow-Headers": "authorization, apikey, content-type, x-client-info",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
  "Content-Type": "application/json",
};
function respond(status: number, data: Record<string, unknown>) {
  return new Response(JSON.stringify(data), { status, headers: cors });
}
Deno.serve(async (req: Request) => {
  if (req.method === "OPTIONS") return new Response(null, { status: 204, headers: cors });
  if (req.method !== "POST") return respond(405, { error: "Methode nicht erlaubt" });
  try {
    const url = Deno.env.get("SUPABASE_URL");
    const anon = Deno.env.get("SUPABASE_ANON_KEY");
    const service = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY");
    if (!url || !anon || !service) return respond(500, { error: "Serverkonfiguration unvollständig" });
    const token = (req.headers.get("Authorization") || "").match(/^Bearer (.+)$/i)?.[1];
    if (!token) return respond(401, { error: "Nicht angemeldet" });
    const publicClient = createClient(url, anon, { auth: { persistSession: false } });
    const { data: identity, error: identityError } = await publicClient.auth.getUser(token);
    if (identityError || !identity.user) return respond(401, { error: "Anmeldung ungültig" });
    const adminClient = createClient(url, service, { auth: { persistSession: false } });
    const { data: actor, error: actorError } = await adminClient
      .from("employee_profiles").select("role,active")
      .eq("user_id", identity.user.id).maybeSingle();
    if (actorError || !actor || actor.role !== "admin" || actor.active !== true)
      return respond(403, { error: "Nur aktive Administratoren dürfen Passwörter zurücksetzen" });
    const body = await req.json().catch(() => null);
    const userId = body?.user_id;
    const password = body?.new_password;
    if (typeof userId !== "string" || !/^[0-9a-f]{8}-[0-9a-f-]{27,}$/i.test(userId))
      return respond(400, { error: "Ungültige Mitarbeiter-ID" });
    if (typeof password !== "string" || password.length < 12 || password.length > 128)
      return respond(400, { error: "Passwort muss 12 bis 128 Zeichen lang sein" });
    if (userId === identity.user.id) return respond(403, { error: "Eigenes Adminpasswort hier nicht änderbar" });
    const { data: target, error: targetError } = await adminClient
      .from("employee_profiles").select("user_id,role,username")
      .eq("user_id", userId).maybeSingle();
    if (targetError || !target || target.role !== "employee")
      return respond(404, { error: "Mitarbeiterkonto nicht gefunden" });
    // Mark as needing password change BEFORE resetting password (fail closed).
    const { error: flagError } = await adminClient.from("employee_profiles")
      .update({ must_change_password: true }).eq("user_id", userId).eq("role", "employee");
    if (flagError) return respond(500, { error: "Passwortpflicht konnte nicht gesetzt werden" });
    const { error: resetError } = await adminClient.auth.admin.updateUserById(userId, { password });
    if (resetError) return respond(500, { error: "Passwort konnte nicht geändert werden: " + resetError.message });
    return respond(200, { ok: true, username: target.username });
  } catch {
    return respond(500, { error: "Interner Fehler beim Zurücksetzen" });
  }
});
