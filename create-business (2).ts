import { createClient } from "npm:@supabase/supabase-js@2.45.4";
const cors = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
};
const j = (b: unknown, s = 200) =>
  new Response(JSON.stringify(b), { status: s, headers: { ...cors, "Content-Type": "application/json" } });
const len = (v: unknown, min: number, max: number) => typeof v === "string" && v.length >= min && v.length <= max;

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: cors });
  if (req.method !== "POST") return j({ error: "Method not allowed" }, 405);

  const url = Deno.env.get("SUPABASE_URL")!;
  let secret = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY");
  if (!secret) { try { secret = JSON.parse(Deno.env.get("SUPABASE_SECRET_KEYS")!)["default"]; } catch { /* none */ } }
  if (!secret) return j({ error: "Server is not configured" }, 500);
  const admin = createClient(url, secret, { auth: { persistSession: false } });

  // 1. Who is calling? Must be a signed-in HOLDING admin.
  const token = (req.headers.get("Authorization") || "").replace(/^Bearer\s+/i, "");
  const { data: u, error: ue } = await admin.auth.getUser(token);
  if (ue || !u?.user) return j({ error: "Not signed in" }, 401);
  const { data: p } = await admin.from("profiles").select("role").eq("user_id", u.user.id).maybeSingle();
  if (!p || p.role !== "holding") return j({ error: "Only the holding admin can register businesses" }, 403);

  // 2. Validate input (same limits as the database).
  let b: Record<string, string>;
  try { b = await req.json(); } catch { return j({ error: "Bad request" }, 400); }
  if (b.action === "delete") {
    if (!/^[a-z0-9-]{2,40}$/.test(b.slug || "")) return j({ error: "Bad business" }, 400);
    const { data: bz } = await admin.from("businesses").select("id").eq("slug", b.slug).maybeSingle();
    if (!bz) return j({ error: "Business not found" }, 404);
    const { data: owners } = await admin.from("profiles").select("user_id").eq("business_id", bz.id).eq("role", "biz");
    const { data: files } = await admin.storage.from("item-photos").list(bz.id, { limit: 1000 });
    if (files?.length) await admin.storage.from("item-photos").remove(files.map((x) => `${bz.id}/${x.name}`));
    const { error: de } = await admin.from("businesses").delete().eq("id", bz.id);
    if (de) return j({ error: "Could not remove the business" }, 500);
    for (const o of owners || []) await admin.auth.admin.deleteUser(o.user_id);
    return j({ ok: true });
  }
  const email = String(b.email || "").toLowerCase();
  if (!/^[^\s@'"]{1,64}@[^\s@'"]{1,190}\.[^\s@'"]{2,}$/.test(email)) return j({ error: "Invalid owner email" }, 400);
  if (!len(b.password, 10, 72)) return j({ error: "Password must be 10-72 characters" }, 400);
  if (!len(b.name, 2, 60) || !len(b.tag, 2, 60) || !len(b.sells, 3, 160) || !len(b.ceo, 2, 80)) return j({ error: "Check name, category, description and CEO" }, 400);
  if (!/^[0-9]{10,15}$/.test(b.wa || "")) return j({ error: "Invalid WhatsApp number" }, 400);
  if (!/^[A-Za-z0-9._]{1,30}$/.test(b.ig || "")) return j({ error: "Invalid Instagram handle" }, 400);
  const slug = b.name.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "").slice(0, 30) || "biz";

  // 3. Create login, business, link. Undo everything if any step fails.
  const { data: cu, error: ce } = await admin.auth.admin.createUser({ email, password: b.password, email_confirm: true, user_metadata: { must_change: true } });
  if (ce || !cu?.user) return j({ error: "That email already has an account or is invalid" }, 400);
  const { data: biz, error: be } = await admin.from("businesses").insert({
    slug, name: b.name, tag: b.tag, sells: b.sells, ceo: b.ceo, loc: (b.loc || "").slice(0, 80),
    hrs: (b.hrs || "").slice(0, 80), since: (b.since || "").slice(0, 10), wa: b.wa, ig: b.ig, sort: 50,
  }).select("id").single();
  if (be || !biz) { await admin.auth.admin.deleteUser(cu.user.id); return j({ error: "Could not create the business (name may already exist)" }, 400); }
  const { error: pe } = await admin.from("profiles").insert({ user_id: cu.user.id, role: "biz", business_id: biz.id });
  if (pe) { await admin.from("businesses").delete().eq("id", biz.id); await admin.auth.admin.deleteUser(cu.user.id); return j({ error: "Could not link the owner" }, 500); }
  return j({ ok: true, slug });
});
