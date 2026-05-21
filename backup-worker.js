/**
 * SGCIA · backup-worker.js
 * ─────────────────────────────────────────────────────────────────────────────
 * Worker independiente que corre por Cron Trigger todos los días a las 02:00 UTC
 * y hace dos cosas:
 *   1. Guarda el backup en un segundo KV namespace (BACKUPS_KV), retenido 90 días
 *   2. Sube un archivo JSON al Google Drive de la Service Account,
 *      en la carpeta DRIVE_FOLDER_ID, con nombre: backup_YYYY-MM-DD.json
 *
 * Bindings requeridos en wrangler-backup.toml:
 *   KV:      SGCIA_KV     (lectura del estado actual)
 *   KV:      BACKUPS_KV   (escritura del snapshot diario)
 *   Secret:  SA_KEY       (JSON completo de la Service Account — ver GUIA.md)
 *
 * Variable de entorno (wrangler-backup.toml [vars]):
 *   DRIVE_FOLDER_ID = "1sOli6L1yOof5nKyxgRKMXmRUa5izyBVq"
 */

// ─────────────────────────────────────────────────────────────────────────────
// HELPERS — JWT para Google Service Account (RS256)
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Convierte una clave PEM RSA privada al formato CryptoKey de Web Crypto API.
 * El JSON de la Service Account incluye la clave en formato PKCS8 PEM.
 */
async function importPrivateKey(pemString) {
  const pemBody = pemString
    .replace(/-----BEGIN PRIVATE KEY-----/, '')
    .replace(/-----END PRIVATE KEY-----/, '')
    .replace(/\n/g, '')
    .trim();

  const binaryDer = Uint8Array.from(atob(pemBody), c => c.charCodeAt(0));

  return crypto.subtle.importKey(
    'pkcs8',
    binaryDer.buffer,
    { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
    false,
    ['sign']
  );
}

/**
 * Genera un JWT firmado RS256 para autenticar la Service Account contra Google APIs.
 * Scope requerido: https://www.googleapis.com/auth/drive.file
 */
async function crearJWT(serviceAccountEmail, privateKey, scope) {
  const ahora = Math.floor(Date.now() / 1000);

  const header = { alg: 'RS256', typ: 'JWT' };
  const payload = {
    iss: serviceAccountEmail,
    scope: scope,
    aud: 'https://oauth2.googleapis.com/token',
    exp: ahora + 3600,
    iat: ahora,
  };

  const enc = (obj) => btoa(JSON.stringify(obj))
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

  const headerB64  = enc(header);
  const payloadB64 = enc(payload);
  const input      = `${headerB64}.${payloadB64}`;

  const cryptoKey = await importPrivateKey(privateKey);
  const signature = await crypto.subtle.sign(
    'RSASSA-PKCS1-v1_5',
    cryptoKey,
    new TextEncoder().encode(input)
  );

  const sigB64 = btoa(String.fromCharCode(...new Uint8Array(signature)))
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

  return `${input}.${sigB64}`;
}

/**
 * Obtiene un access token de Google usando OAuth2 con JWT de Service Account.
 */
async function obtenerAccessToken(saEmail, saPrivateKey) {
  const scope = 'https://www.googleapis.com/auth/drive.file';
  const jwt   = await crearJWT(saEmail, saPrivateKey, scope);

  const resp = await fetch('https://oauth2.googleapis.com/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer',
      assertion:  jwt,
    }),
  });

  if (!resp.ok) {
    const error = await resp.text();
    throw new Error(`Error obteniendo token Google: ${resp.status} — ${error}`);
  }

  const data = await resp.json();
  return data.access_token;
}

// ─────────────────────────────────────────────────────────────────────────────
// HELPERS — Recolección de datos desde SGCIA_KV
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Lee todas las claves del KV y arma el objeto de backup completo.
 * Incluye: state (tratamientos), admins, allowlist, y metadata de adjuntos.
 */
async function recolectarDatos(env) {
  const [stateRaw, adminsRaw, allowlistRaw] = await Promise.all([
    env.SGCIA_KV.get('state'),
    env.SGCIA_KV.get('admins'),
    env.SGCIA_KV.get('allowlist'),
  ]);

  // Recolectar claves de adjuntos (prefijo att:)
  const adjuntosKeys = [];
  let cursor;
  do {
    const lista = await env.SGCIA_KV.list({ prefix: 'att:', limit: 1000, cursor });
    adjuntosKeys.push(...lista.keys.map(k => k.name));
    cursor = lista.list_complete ? null : lista.cursor;
  } while (cursor);

  // Contar logs de auditoría sin descargarlos todos (solo el count)
  const logsInfo = await env.SGCIA_KV.list({ prefix: 'log:', limit: 1 });
  let totalLogs = 0;
  let logCursor;
  do {
    const lote = await env.SGCIA_KV.list({ prefix: 'log:', limit: 1000, cursor: logCursor });
    totalLogs += lote.keys.length;
    logCursor = lote.list_complete ? null : lote.cursor;
  } while (logCursor);

  const state = stateRaw ? JSON.parse(stateRaw) : {};
  const treatments = state.treatments || {};
  const cantHallazgos = Object.keys(treatments).length;

  return {
    metadata: {
      timestamp:        new Date().toISOString(),
      version:          '1.0',
      generadoPor:      'SGCIA Backup Worker',
      cantHallazgos,
      cantAdjuntos:     adjuntosKeys.length,
      cantLogsAuditoria: totalLogs,
    },
    state:     stateRaw     ? JSON.parse(stateRaw)     : null,
    admins:    adminsRaw    ? JSON.parse(adminsRaw)    : [],
    allowlist: allowlistRaw ? JSON.parse(allowlistRaw) : [],
    adjuntosKeys, // lista de claves (no el contenido binario — demasiado pesado)
  };
}

// ─────────────────────────────────────────────────────────────────────────────
// PASO 1 — Guardar en BACKUPS_KV
// ─────────────────────────────────────────────────────────────────────────────

async function guardarEnKV(env, fecha, datos) {
  const clave = `backup:${fecha}`;

  await env.BACKUPS_KV.put(
    clave,
    JSON.stringify(datos, null, 2),
    { expirationTtl: 90 * 24 * 60 * 60 } // 90 días
  );

  console.log(`[Backup KV] ✓ Guardado en BACKUPS_KV con clave: ${clave}`);
  return clave;
}

// ─────────────────────────────────────────────────────────────────────────────
// PASO 2 — Subir a Google Drive
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Verifica si ya existe un archivo con ese nombre en la carpeta Drive.
 * Si existe, retorna su ID para sobreescribirlo (evita duplicados).
 */
async function buscarArchivoExistente(accessToken, folderId, nombreArchivo) {
  const query = encodeURIComponent(
    `name='${nombreArchivo}' and '${folderId}' in parents and trashed=false`
  );
  const resp = await fetch(
    `https://www.googleapis.com/drive/v3/files?q=${query}&fields=files(id,name)`,
    { headers: { Authorization: `Bearer ${accessToken}` } }
  );

  if (!resp.ok) return null;
  const data = await resp.json();
  return data.files && data.files.length > 0 ? data.files[0].id : null;
}

/**
 * Sube el archivo JSON a Google Drive usando multipart upload.
 * Si el archivo ya existe (mismo día), lo sobreescribe.
 */
async function subirADrive(accessToken, folderId, nombreArchivo, contenidoJSON) {
  const contenido  = new TextEncoder().encode(contenidoJSON);
  const boundary   = '-------sgcia_backup_boundary';
  const metadatos  = JSON.stringify({ name: nombreArchivo, parents: [folderId] });

  // Verificar si existe para hacer update en vez de create
  const archivoExistenteId = await buscarArchivoExistente(accessToken, folderId, nombreArchivo);

  let url, method;
  if (archivoExistenteId) {
    // PATCH — actualiza el archivo existente
    url    = `https://www.googleapis.com/upload/drive/v3/files/${archivoExistenteId}?uploadType=multipart`;
    method = 'PATCH';
    console.log(`[Backup Drive] Archivo existente encontrado (${archivoExistenteId}), sobreescribiendo...`);
  } else {
    // POST — crea uno nuevo
    url    = 'https://www.googleapis.com/upload/drive/v3/files?uploadType=multipart';
    method = 'POST';
    console.log(`[Backup Drive] Creando nuevo archivo: ${nombreArchivo}`);
  }

  // Construir cuerpo multipart
  const parteMetadatos = `--${boundary}\r\nContent-Type: application/json; charset=UTF-8\r\n\r\n${metadatos}\r\n`;
  const parteContenido = `--${boundary}\r\nContent-Type: application/json\r\n\r\n`;
  const cierre         = `\r\n--${boundary}--`;

  const enc      = new TextEncoder();
  const cuerpo   = new Uint8Array([
    ...enc.encode(parteMetadatos),
    ...enc.encode(parteContenido),
    ...contenido,
    ...enc.encode(cierre),
  ]);

  const resp = await fetch(url, {
    method,
    headers: {
      Authorization:  `Bearer ${accessToken}`,
      'Content-Type': `multipart/related; boundary="${boundary}"`,
    },
    body: cuerpo,
  });

  if (!resp.ok) {
    const error = await resp.text();
    throw new Error(`Error subiendo a Drive: ${resp.status} — ${error}`);
  }

  const resultado = await resp.json();
  console.log(`[Backup Drive] ✓ Archivo subido. ID: ${resultado.id} | Nombre: ${resultado.name}`);
  return resultado.id;
}

// ─────────────────────────────────────────────────────────────────────────────
// HANDLER PRINCIPAL — Cron Trigger
// ─────────────────────────────────────────────────────────────────────────────

async function ejecutarBackup(env) {
  const inicio = Date.now();
  const fecha  = new Date().toISOString().slice(0, 10); // YYYY-MM-DD
  const nombre = `backup_sgcia_${fecha}.json`;

  console.log(`\n═══════════════════════════════════════════`);
  console.log(`[Backup SGCIA] Iniciando — ${new Date().toISOString()}`);
  console.log(`═══════════════════════════════════════════`);

  const errores = [];

  // 1. Recolectar datos
  console.log('[Backup] Recolectando datos del KV...');
  const datos = await recolectarDatos(env);
  const json  = JSON.stringify(datos, null, 2);

  console.log(`[Backup] Datos recolectados:`);
  console.log(`  - Hallazgos: ${datos.metadata.cantHallazgos}`);
  console.log(`  - Adjuntos:  ${datos.metadata.cantAdjuntos}`);
  console.log(`  - Logs:      ${datos.metadata.cantLogsAuditoria}`);

  // 2. Guardar en BACKUPS_KV
  try {
    await guardarEnKV(env, fecha, datos);
  } catch (e) {
    console.error('[Backup KV] ✗ Error:', e.message);
    errores.push(`KV: ${e.message}`);
  }

  // 3. Subir a Google Drive
  try {
    const saKey    = JSON.parse(env.SA_KEY);
    const token    = await obtenerAccessToken(saKey.client_email, saKey.private_key);
    await subirADrive(token, env.DRIVE_FOLDER_ID, nombre, json);
  } catch (e) {
    console.error('[Backup Drive] ✗ Error:', e.message);
    errores.push(`Drive: ${e.message}`);
  }

  const duracion = ((Date.now() - inicio) / 1000).toFixed(2);

  if (errores.length === 0) {
    console.log(`\n[Backup SGCIA] ✅ Completado exitosamente en ${duracion}s`);
  } else {
    console.error(`\n[Backup SGCIA] ⚠️ Completado con errores en ${duracion}s:`);
    errores.forEach(e => console.error(`  - ${e}`));
  }

  return { ok: errores.length === 0, errores, duracion };
}

// ─────────────────────────────────────────────────────────────────────────────
// EXPORT — Cron + HTTP manual (para testear sin esperar el cron)
// ─────────────────────────────────────────────────────────────────────────────

export default {
  // Cron automático: todos los días a las 02:00 UTC
  async scheduled(event, env, ctx) {
    ctx.waitUntil(ejecutarBackup(env));
  },

  // HTTP manual: GET https://sgcia-backup.TU_SUBDOMINIO.workers.dev/run-backup
  // Protegido por el mismo SGCIA_SECRET para que no lo ejecute cualquiera
  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    if (url.pathname === '/run-backup') {
      // Verificar autorización (mismo secret del worker principal)
      const auth = request.headers.get('X-Backup-Token');
      if (!env.BACKUP_RUN_TOKEN || auth !== env.BACKUP_RUN_TOKEN) {
        return new Response(JSON.stringify({ error: 'No autorizado' }), {
          status: 401,
          headers: { 'Content-Type': 'application/json' },
        });
      }

      const resultado = await ejecutarBackup(env);
      return new Response(JSON.stringify(resultado, null, 2), {
        status: resultado.ok ? 200 : 500,
        headers: { 'Content-Type': 'application/json' },
      });
    }

    return new Response(JSON.stringify({ status: 'SGCIA Backup Worker activo' }), {
      headers: { 'Content-Type': 'application/json' },
    });
  },
};
