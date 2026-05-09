/**
 * SGCIA Maniagro · API Backend
 * Cloudflare Pages Function — maneja /api/*
 * Archivo: functions/api/[[route]].js
 */

const SESSION_COOKIE = 'sgcia_session';
const SESSION_TTL    = 8 * 3600;
const ENC = new TextEncoder();
const DEC = new TextDecoder();

// ── base64url ─────────────────────────────────────────────────────────────
function b64e(buf) {
  const b = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
  let s = '';
  for (const x of b) s += String.fromCharCode(x);
  return btoa(s).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');
}
function b64d(str) {
  str = str.replace(/-/g,'+').replace(/_/g,'/');
  while (str.length % 4) str += '=';
  const bin = atob(str);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

// ── JWT HS256 ─────────────────────────────────────────────────────────────
async function hmacKey(s) {
  return crypto.subtle.importKey('raw', ENC.encode(s),
    { name:'HMAC', hash:'SHA-256' }, false, ['sign','verify']);
}
async function signJwt(payload, secret) {
  const h = b64e(ENC.encode(JSON.stringify({ alg:'HS256', typ:'JWT' })));
  const p = b64e(ENC.encode(JSON.stringify(payload)));
  const k = await hmacKey(secret);
  const sig = await crypto.subtle.sign('HMAC', k, ENC.encode(`${h}.${p}`));
  return `${h}.${p}.${b64e(sig)}`;
}
async function verifyJwt(token, secret) {
  const [h, p, s] = token.split('.');
  if (!h || !p || !s) return null;
  const k  = await hmacKey(secret);
  const ok = await crypto.subtle.verify('HMAC', k, b64d(s), ENC.encode(`${h}.${p}`));
  if (!ok) return null;
  const pl = JSON.parse(DEC.decode(b64d(p)));
  if (pl.exp && pl.exp < Math.floor(Date.now()/1000)) return null;
  return pl;
}

// ── JWT RS256 Google ──────────────────────────────────────────────────────
let _gkeys = { keys:null, at:0 };
async function googleKeys() {
  if (_gkeys.keys && Date.now()-_gkeys.at < 3600000) return _gkeys.keys;
  const r = await fetch('https://www.googleapis.com/oauth2/v3/certs');
  const j = await r.json();
  _gkeys = { keys:j.keys, at:Date.now() };
  return j.keys;
}
async function verifyGoogleToken(idToken, aud) {
  const [hB, pB, sB] = idToken.split('.');
  if (!hB||!pB||!sB) throw new HttpErr(400,'Token mal formado');
  const header  = JSON.parse(DEC.decode(b64d(hB)));
  const payload = JSON.parse(DEC.decode(b64d(pB)));
  const jwk = (await googleKeys()).find(k => k.kid === header.kid);
  if (!jwk) throw new HttpErr(401,'Clave pública de Google no encontrada');
  const ck = await crypto.subtle.importKey('jwk', jwk,
    { name:'RSASSA-PKCS1-v1_5', hash:'SHA-256' }, false, ['verify']);
  const ok = await crypto.subtle.verify('RSASSA-PKCS1-v1_5', ck, b64d(sB), ENC.encode(`${hB}.${pB}`));
  if (!ok) throw new HttpErr(401,'Firma de Google inválida');
  const now = Math.floor(Date.now()/1000);
  if (payload.exp < now) throw new HttpErr(401,'Token de Google expirado');
  const validIss = ['https://accounts.google.com','accounts.google.com'];
  if (!validIss.includes(payload.iss)) throw new HttpErr(401,'Issuer inválido');
  if (payload.aud !== aud)      throw new HttpErr(401,'Client ID no coincide');
  if (!payload.email_verified)  throw new HttpErr(401,'Email no verificado por Google');
  return payload;
}

// ── Cookies ───────────────────────────────────────────────────────────────
function getCookie(req, name) {
  const m = (req.headers.get('Cookie')||'').match(new RegExp('(?:^|; )'+name+'=([^;]+)'));
  return m ? decodeURIComponent(m[1]) : null;
}
function setCookieStr(name, value, maxAge) {
  return `${name}=${encodeURIComponent(value)}; Max-Age=${maxAge}; Path=/; HttpOnly; Secure; SameSite=Strict`;
}

// ── Sesión ────────────────────────────────────────────────────────────────
async function getSession(req, env) {
  const t = getCookie(req, SESSION_COOKIE);
  if (!t) return null;
  return verifyJwt(t, env.SGCIA_SECRET);
}
async function requireSession(req, env) {
  const s = await getSession(req, env);
  if (!s) throw new HttpErr(401,'Sesión no válida — iniciá sesión');
  return s;
}
async function requireAdmin(req, env) {
  const s = await requireSession(req, env);
  if (!s.isAdmin) throw new HttpErr(403,'Requiere permisos de administrador');
  return s;
}

// ── Respuesta JSON ────────────────────────────────────────────────────────
class HttpErr extends Error { constructor(s,m){super(m);this.status=s;} }
function j(data, status=200, headers={}) {
  return new Response(JSON.stringify(data), {
    status, headers:{ 'Content-Type':'application/json', ...headers }
  });
}

// ── Log append-only ───────────────────────────────────────────────────────
// Clave única por entrada → imposible pisar entradas concurrentes
async function appendLog(env, entry) {
  const ts   = Date.now();
  const rand = Math.random().toString(36).slice(2,10);
  const key  = `log:${String(ts).padStart(15,'0')}:${rand}`;
  const full = { ts: new Date(ts).toISOString(), ...entry };
  await env.SGCIA_KV.put(key, JSON.stringify(full));
  return full;
}
async function listLog(env, limit=500) {
  const out = [];
  let cursor;
  do {
    const r = await env.SGCIA_KV.list({ prefix:'log:', cursor, limit:Math.min(1000,limit-out.length) });
    for (const k of r.keys) {
      const v = await env.SGCIA_KV.get(k.name);
      if (v) { try { out.push(JSON.parse(v)); } catch(e){} }
      if (out.length >= limit) break;
    }
    cursor = r.list_complete ? null : r.cursor;
  } while (cursor && out.length < limit);
  return out.reverse(); // más recientes primero
}

// ── Helpers KV emails ─────────────────────────────────────────────────────
async function getList(env, key) {
  const r = await env.SGCIA_KV.get(key);
  return r ? JSON.parse(r) : [];
}
async function putList(env, key, emails) {
  const c = emails.map(e=>String(e).toLowerCase().trim()).filter(Boolean);
  await env.SGCIA_KV.put(key, JSON.stringify(c));
  return c;
}

// ── Router principal ──────────────────────────────────────────────────────
export async function onRequest(context) {
  const { request:req, env } = context;
  if (req.method === 'OPTIONS') return new Response(null,{status:204});
  const path = new URL(req.url).pathname.replace(/^\/api/,'') || '/';
  const m    = req.method;
  try {
    if (path==='/auth/google'    && m==='POST') return await authGoogle(req,env);
    if (path==='/auth/me'        && m==='GET')  return await authMe(req,env);
    if (path==='/auth/logout'    && m==='POST') return await authLogout(req,env);
    if (path==='/state'          && m==='GET')  return await stateGet(req,env);
    if (path==='/state'          && m==='PUT')  return await statePut(req,env);
    if (path==='/clear-descargas'&& m==='POST') return await clearDescargas(req,env);
    if (path==='/attachments'    && m==='GET')  return await attGet(req,env);
    if (path==='/attachments'    && m==='PUT')  return await attPut(req,env);
    if (path==='/attachments'    && m==='DELETE') return await attDel(req,env);
    if (path==='/log'            && m==='POST') return await logPost(req,env);
    if (path==='/log'            && m==='GET')  return await logGet(req,env);
    if (path==='/allowlist'      && m==='GET')  return await allowlistGet(req,env);
    if (path==='/allowlist'      && m==='PUT')  return await allowlistPut(req,env);
    if (path==='/admins'         && m==='GET')  return await adminsGet(req,env);
    if (path==='/admins'         && m==='PUT')  return await adminsPut(req,env);
    if (path==='/report-lock'    && m==='POST') return await reportLock(req,env);
    return j({error:'Ruta no encontrada'},404);
  } catch(err) {
    if (err instanceof HttpErr) return j({error:err.message},err.status);
    console.error('[SGCIA]',err);
    return j({error:'Error interno del servidor'},500);
  }
}

// ── /api/auth/google ──────────────────────────────────────────────────────
async function authGoogle(req, env) {
  const body = await req.json().catch(()=>({}));
  if (!body.credential) throw new HttpErr(400,'Falta credential de Google');

  const gp    = await verifyGoogleToken(body.credential, env.GOOGLE_CLIENT_ID);
  const email = gp.email.toLowerCase();

  // Admisión: @maniagro.com o allowlist
  const allowlist   = await getList(env,'allowlist');
  const isManiagro  = email.endsWith('@maniagro.com');
  const isException = allowlist.includes(email);

  if (!isManiagro && !isException) {
    await appendLog(env,{
      action:'failed_login', user:email, isAdmin:false,
      details:`Acceso denegado — dominio no autorizado (hd=${gp.hd||'none'})`,
    });
    throw new HttpErr(403,
      `Solo se permiten cuentas @maniagro.com. Tu cuenta (${email}) no está autorizada.`
    );
  }

  // Flag admin desde KV
  const admins  = await getList(env,'admins');
  const isAdmin = admins.includes(email);

  // Sesión propia
  const now = Math.floor(Date.now()/1000);
  const sid = `S-${now.toString(36)}-${Math.random().toString(36).slice(2,8).toUpperCase()}`;
  const payload = {
    email, name:gp.name||email, picture:gp.picture||'',
    isAdmin, iat:now, exp:now+SESSION_TTL, sid,
  };
  const token = await signJwt(payload, env.SGCIA_SECRET);

  await appendLog(env,{
    action:'login', user:email, sessionId:sid, isAdmin,
    details:`OK · ${isException?'allowlist':'@maniagro.com'}${isAdmin?' · ADMIN':''}`,
  });

  return j(
    { ok:true, user:{ email, name:payload.name, picture:payload.picture, isAdmin } },
    200,
    { 'Set-Cookie': setCookieStr(SESSION_COOKIE, token, SESSION_TTL) }
  );
}

// ── /api/auth/me ──────────────────────────────────────────────────────────
async function authMe(req, env) {
  const s = await getSession(req, env);
  if (!s) return j({ authenticated:false });
  return j({ authenticated:true, user:{ email:s.email, name:s.name, picture:s.picture, isAdmin:!!s.isAdmin, sid:s.sid } });
}

// ── /api/auth/logout ──────────────────────────────────────────────────────
async function authLogout(req, env) {
  const s = await getSession(req, env);
  if (s) await appendLog(env,{ action:'logout', user:s.email, sessionId:s.sid, isAdmin:!!s.isAdmin, details:'Cierre de sesión' });
  return j({ ok:true }, 200, { 'Set-Cookie': setCookieStr(SESSION_COOKIE,'',0) });
}

// ── /api/state ────────────────────────────────────────────────────────────
async function stateGet(req, env) {
  await requireSession(req, env);
  const raw   = await env.SGCIA_KV.get('state');
  const state = raw ? JSON.parse(raw) : { treatments:{}, descargas:[] };

  // Metadata de adjuntos para píldoras 📎
  const attMeta = {};
  let cursor;
  do {
    const r = await env.SGCIA_KV.list({ prefix:'att:', cursor });
    for (const k of r.keys) {
      const v = await env.SGCIA_KV.get(k.name);
      if (v) {
        try {
          const arr  = JSON.parse(v);
          const rkey = k.name.slice(4);
          if (Array.isArray(arr))
            attMeta[rkey] = { count:arr.length, totalSize:arr.reduce((a,f)=>a+(f.size||0),0) };
        } catch(e){}
      }
    }
    cursor = r.list_complete ? null : r.cursor;
  } while (cursor);

  return j({ ...state, attMeta });
}

async function statePut(req, env) {
  const s    = await requireSession(req, env);
  const body = await req.json();
  await env.SGCIA_KV.put('state', JSON.stringify({
    treatments: body.treatments||{},
    descargas:  body.descargas||[],
    updatedAt:  new Date().toISOString(),
    updatedBy:  s.email,
  }));
  return j({ ok:true });
}

async function clearDescargas(req, env) {
  await requireSession(req, env);
  const raw   = await env.SGCIA_KV.get('state');
  const state = raw ? JSON.parse(raw) : { treatments:{}, descargas:[] };
  state.descargas = [];
  await env.SGCIA_KV.put('state', JSON.stringify(state));
  return j({ ok:true });
}

// ── /api/attachments ──────────────────────────────────────────────────────
async function attGet(req, env) {
  await requireSession(req, env);
  const key = new URL(req.url).searchParams.get('key');
  if (!key) throw new HttpErr(400,'Falta key');
  const v = await env.SGCIA_KV.get('att:'+key);
  return j({ files: v ? JSON.parse(v) : [] });
}
async function attPut(req, env) {
  await requireSession(req, env);
  const key  = new URL(req.url).searchParams.get('key');
  if (!key) throw new HttpErr(400,'Falta key');
  const body = await req.json();
  await env.SGCIA_KV.put('att:'+key, JSON.stringify(body.files||[]));
  return j({ ok:true });
}
async function attDel(req, env) {
  await requireSession(req, env);
  const key = new URL(req.url).searchParams.get('key');
  if (!key) throw new HttpErr(400,'Falta key');
  await env.SGCIA_KV.delete('att:'+key);
  return j({ ok:true });
}

// ── /api/log ──────────────────────────────────────────────────────────────
async function logPost(req, env) {
  const s    = await requireSession(req, env);
  const body = await req.json();
  // Email siempre viene de la sesión verificada, nunca del body
  const entry = await appendLog(env,{
    action:    body.action||'unknown',
    target:    body.target||'',
    details:   body.details||'',
    user:      s.email,
    sessionId: s.sid,
    isAdmin:   !!s.isAdmin,
  });
  return j({ ok:true, entry });
}
async function logGet(req, env) {
  await requireSession(req, env);
  const limit   = parseInt(new URL(req.url).searchParams.get('limit')||'500',10);
  const entries = await listLog(env, limit);
  return j({ entries });
}

// ── /api/allowlist ────────────────────────────────────────────────────────
async function allowlistGet(req, env) {
  await requireAdmin(req, env);
  return j({ emails: await getList(env,'allowlist') });
}
async function allowlistPut(req, env) {
  const s      = await requireAdmin(req, env);
  const body   = await req.json();
  const emails = await putList(env,'allowlist', body.emails||[]);
  await appendLog(env,{
    action:'admin_modify_allowlist', user:s.email, isAdmin:true, sessionId:s.sid,
    details:`Allowlist actualizada · ${emails.length} email(s): ${emails.join(', ')}`,
  });
  return j({ ok:true, emails });
}

// ── /api/admins ───────────────────────────────────────────────────────────
async function adminsGet(req, env) {
  await requireAdmin(req, env);
  return j({ emails: await getList(env,'admins') });
}
async function adminsPut(req, env) {
  const s      = await requireAdmin(req, env);
  const body   = await req.json();
  const emails = body.emails||[];
  if (!emails.length) throw new HttpErr(400,'La lista de admins no puede estar vacía');
  const saved = await putList(env,'admins', emails);
  await appendLog(env,{
    action:'admin_modify_admins', user:s.email, isAdmin:true, sessionId:s.sid,
    details:`Lista de admins actualizada · ${saved.length} email(s): ${saved.join(', ')}`,
  });
  return j({ ok:true, emails:saved });
}

// ── /api/report-lock ──────────────────────────────────────────────────────
// Lock semanal: solo el primer cliente que lo llame envía el reporte
async function reportLock(req, env) {
  await requireSession(req, env);
  const body   = await req.json();
  const period = body.period||'';
  if (!period) throw new HttpErr(400,'Falta period');
  const lockKey  = 'reportlock:'+period;
  const existing = await env.SGCIA_KV.get(lockKey);
  if (existing) return j({ acquired:false });
  await env.SGCIA_KV.put(lockKey, JSON.stringify({ at:Date.now() }), { expirationTtl: 7*86400 });
  return j({ acquired:true });
}
