/**
 * SGCIA · R-SIG-AC 01 — Cloudflare Worker
 *
 * Sirve el dashboard (index.html via ASSETS) y expone un API simple para
 * compartir tratamientos, descargas y adjuntos entre todos los usuarios
 * (Natacha, Emilse, Gastón, Mayra, Antonella, Rodrigo) usando KV.
 *
 * Endpoints (todos protegidos por header X-SGCIA-Token):
 *   GET    /api/state                  → { treatments, descargas, attMeta }
 *   PUT    /api/state                  → body: { treatments, descargas }
 *   GET    /api/attachments?key=...    → { files: [...] }
 *   PUT    /api/attachments?key=...    → body: { files: [...] }
 *   DELETE /api/attachments?key=...    → borra esa lista
 *   POST   /api/clear-descargas        → vacía solo la lista de descargas
 *   GET    /api/health                 → { ok:true }
 *
 * Bindings requeridos en wrangler.toml:
 *   - KV namespace:  SGCIA_KV
 *   - Static assets: ASSETS (apuntando a ./public con index.html)
 *   - Variable:      SGCIA_TOKEN  (token compartido — usar `wrangler secret put SGCIA_TOKEN`)
 */

const KEY_STATE = "state";              // { treatments, descargas }
const KEY_ATT_PREFIX = "att:";          // att:sgcia_att_450, att:sgcia_att_trat_450, etc.

// ───────── helpers ──────────────────────────────────────────────────────────
const cors = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET,POST,PUT,DELETE,OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, X-SGCIA-Token",
  "Access-Control-Max-Age": "86400",
};

const json = (obj, status = 200) =>
  new Response(JSON.stringify(obj), {
    status,
    headers: { "Content-Type": "application/json; charset=utf-8", ...cors },
  });

const err = (msg, status = 400) => json({ ok: false, error: msg }, status);

function checkAuth(req, env) {
  // Si no hay token configurado, dejar pasar (deployment para uso interno solamente).
  if (!env.SGCIA_TOKEN) return true;
  const t = req.headers.get("X-SGCIA-Token");
  return t && t === env.SGCIA_TOKEN;
}

// Listar adjuntos: usar KV.list y leer count desde metadata para no descargar todo
async function buildAttMeta(env) {
  const out = {};
  let cursor = undefined;
  for (let i = 0; i < 20; i++) {
    const res = await env.SGCIA_KV.list({ prefix: KEY_ATT_PREFIX, cursor, limit: 1000 });
    for (const k of res.keys) {
      const realKey = k.name.slice(KEY_ATT_PREFIX.length);
      const count = (k.metadata && typeof k.metadata.count === "number") ? k.metadata.count : 0;
      const totalSize = (k.metadata && typeof k.metadata.totalSize === "number") ? k.metadata.totalSize : 0;
      out[realKey] = { count, totalSize };
    }
    if (res.list_complete) break;
    cursor = res.cursor;
  }
  return out;
}

// ───────── handlers ─────────────────────────────────────────────────────────
async function handleState(req, env) {
  if (req.method === "GET") {
    const raw = await env.SGCIA_KV.get(KEY_STATE);
    const state = raw ? JSON.parse(raw) : { treatments: {}, descargas: [] };
    const attMeta = await buildAttMeta(env);
    return json({
      ok: true,
      treatments: state.treatments || {},
      descargas: state.descargas || [],
      attMeta,
      serverTime: new Date().toISOString(),
    });
  }
  if (req.method === "PUT") {
    let body;
    try { body = await req.json(); } catch (e) { return err("body inválido"); }
    const treatments = body.treatments || {};
    const descargas = (body.descargas || []).map(({ blob, ...d }) => d); // sanitizar
    const payload = JSON.stringify({ treatments, descargas });
    if (payload.length > 24 * 1024 * 1024) return err("state demasiado grande", 413);
    await env.SGCIA_KV.put(KEY_STATE, payload);
    return json({ ok: true, savedAt: new Date().toISOString() });
  }
  return err("método no permitido", 405);
}

async function handleAttachments(req, env, url) {
  const key = url.searchParams.get("key");
  if (!key) return err("falta parámetro 'key'");
  if (!/^[a-zA-Z0-9_:-]{1,200}$/.test(key)) return err("key inválida");

  const fullKey = KEY_ATT_PREFIX + key;

  if (req.method === "GET") {
    const raw = await env.SGCIA_KV.get(fullKey);
    const files = raw ? JSON.parse(raw) : [];
    return json({ ok: true, files });
  }
  if (req.method === "PUT") {
    let body;
    try { body = await req.json(); } catch (e) { return err("body inválido"); }
    const files = Array.isArray(body.files) ? body.files : [];
    const payload = JSON.stringify(files);
    if (payload.length > 24 * 1024 * 1024) return err("adjuntos demasiado grandes", 413);
    const totalSize = files.reduce((a, f) => a + (f.size || 0), 0);
    if (files.length === 0) {
      await env.SGCIA_KV.delete(fullKey);
    } else {
      await env.SGCIA_KV.put(fullKey, payload, {
        metadata: { count: files.length, totalSize, updatedAt: Date.now() },
      });
    }
    return json({ ok: true, count: files.length });
  }
  if (req.method === "DELETE") {
    await env.SGCIA_KV.delete(fullKey);
    return json({ ok: true });
  }
  return err("método no permitido", 405);
}

async function handleClearDescargas(req, env) {
  if (req.method !== "POST") return err("método no permitido", 405);
  const raw = await env.SGCIA_KV.get(KEY_STATE);
  const state = raw ? JSON.parse(raw) : { treatments: {}, descargas: [] };
  state.descargas = [];
  await env.SGCIA_KV.put(KEY_STATE, JSON.stringify(state));
  return json({ ok: true });
}

// ───────── entrypoint ───────────────────────────────────────────────────────
export default {
  async fetch(req, env, ctx) {
    const url = new URL(req.url);

    // CORS preflight
    if (req.method === "OPTIONS") return new Response(null, { status: 204, headers: cors });

    // API routes
    if (url.pathname.startsWith("/api/")) {
      if (url.pathname === "/api/health") return json({ ok: true, time: new Date().toISOString() });

      if (!checkAuth(req, env)) return err("no autorizado", 401);

      try {
        if (url.pathname === "/api/state") return await handleState(req, env);
        if (url.pathname === "/api/attachments") return await handleAttachments(req, env, url);
        if (url.pathname === "/api/clear-descargas") return await handleClearDescargas(req, env);
        return err("ruta no encontrada", 404);
      } catch (e) {
        console.error("API error:", e);
        return err("error interno: " + e.message, 500);
      }
    }

    // Estáticos: index.html y demás
    if (env.ASSETS) {
      const r = await env.ASSETS.fetch(req);
      // Asegurar no-cache para el HTML para que los cambios lleguen rápido
      if (url.pathname === "/" || url.pathname.endsWith(".html")) {
        const h = new Headers(r.headers);
        h.set("Cache-Control", "no-store");
        return new Response(r.body, { status: r.status, headers: h });
      }
      return r;
    }

    return new Response("ASSETS no configurado", { status: 500 });
  },
};
