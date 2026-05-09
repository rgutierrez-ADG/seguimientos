SGCIA — Instrucciones de Deploy
Cloudflare Pages + Google SSO
---
PASO A — Google Cloud (continuación del punto 6)
En "Authorized JavaScript origins" poné:
```
https://sgcia-maniagro.pages.dev
```
(o el nombre que elijas para el proyecto de Pages)
Authorized redirect URIs: dejar vacío (GIS usa postMessage, no redirect).
Copiá el Client ID. Forma: `123456789-xxxx.apps.googleusercontent.com`
---
PASO B — Cloudflare: crear KV namespace
```bash
wrangler login

# Crear el namespace KV
wrangler kv namespace create SGCIA_KV
```
Copiá el `id` que devuelve y pegálo en `wrangler.toml`:
```toml
[[kv_namespaces]]
binding = "SGCIA_KV"
id      = "PEGAR_ID_AQUI"
```
---
PASO C — Reemplazar Client ID en los archivos
En `wrangler.toml`:
```toml
[vars]
GOOGLE_CLIENT_ID = "TU_CLIENT_ID.apps.googleusercontent.com"
```
En `login-block.html` (línea con `const GCI`):
```javascript
const GCI = 'TU_CLIENT_ID.apps.googleusercontent.com';
```
---
PASO D — Crear proyecto en Cloudflare Pages y subir archivos
```bash
# Primera vez: crear el proyecto
wrangler pages project create sgcia-maniagro

# Subir los archivos (desde la carpeta raíz del proyecto)
wrangler pages deploy . --project-name=sgcia-maniagro
```
La URL del proyecto será: `https://sgcia-maniagro.pages.dev`
---
PASO E — Setear secrets en Pages
```bash
# El secret de sesión (cualquier string random, mínimo 32 chars)
openssl rand -hex 64 | wrangler pages secret put SGCIA_SECRET \
  --project-name=sgcia-maniagro
```
O desde el dashboard: Pages → sgcia-maniagro → Settings → Environment Variables → Add variable → marcar como "Secret".
---
PASO F — Bootstrap: definir primer admin
Con Wrangler CLI:
```bash
wrangler kv key put --binding=SGCIA_KV admins \
  '["rgutierrez@maniagro.com","mdip@maniagro.com"]' \
  --namespace-id=TU_KV_ID
```
O via API una vez deployado (solo funciona si ya sos admin — huevo y gallina).
Por eso hacerlo con CLI la primera vez.
Lista inicial de excepciones (vacía por ahora):
```bash
wrangler kv key put --binding=SGCIA_KV allowlist '[]' \
  --namespace-id=TU_KV_ID
```
---
PASO G — Actualizar el HTML del dashboard
Reemplazar el bloque de protección (desde `<!-- 🔒 BLOQUE DE PROTECCIÓN` hasta `FIN DEL BLOQUE DE PROTECCIÓN -->`):
→ Pegar el contenido de `login-block.html`
Reemplazar funciones JS:
→ Aplicar los cambios documentados en `js-patches.js`
→ Las instrucciones están comentadas línea por línea
Eliminar del HTML:
La constante `window.SGCIA_TOKEN`
El objeto `ADMIN_USERS` con hashes
La modal `#adminLoginBg` y su HTML
Las funciones: `doAdminLogin`, `closeAdminLogin`, `_restoreAdminSession`
En el topbar, el botón "Modo Admin" (los admins ya se identifican por email)
Subir el index.html actualizado a la misma carpeta y redesployar:
```bash
   wrangler pages deploy . --project-name=sgcia-maniagro
   ```
---
PASO H — Agregar el origen correcto en Google Cloud
Una vez que tenés la URL real de Pages:
Google Cloud → Credentials → tu OAuth client
Authorized JavaScript origins → Agregar la URL de Pages:
`https://sgcia-maniagro.pages.dev`
Si usás dominio propio (ej: `sgcia.maniagro.com`), agregarlo también.
Guardá y esperá 5 min.
---
Estructura final de archivos
```
sgcia-maniagro/
├── index.html                    ← dashboard con login-block.html integrado
├── wrangler.toml                 ← config de Pages + KV binding
├── _routes.json                  ← routea /api/* a las Functions
└── functions/
    └── api/
        └── [[route]].js          ← el Worker (auth, log, state, etc.)
```
---
Gestión de Admins y Allowlist desde el Dashboard
Una vez deployado, los admins pueden gestionar desde el propio dashboard:
Agregar un admin:
```javascript
// Desde consola del browser (logueado como admin)
await fetch('/api/admins', {
  method: 'PUT',
  credentials: 'include',
  headers: {'Content-Type':'application/json'},
  body: JSON.stringify({ emails: ['admin1@maniagro.com', 'admin2@maniagro.com'] })
});
```
Agregar excepción (auditor externo):
```javascript
await fetch('/api/allowlist', {
  method: 'PUT',
  credentials: 'include',
  headers: {'Content-Type':'application/json'},
  body: JSON.stringify({ emails: ['auditor.externo@brcgs.com'] })
});
```
En la próxima versión esto se puede integrar directamente en la UI del dashboard.
---
Verificación rápida post-deploy
```bash
# Ver logs del Worker en vivo
wrangler pages deployment tail --project-name=sgcia-maniagro

# Ver entradas del KV
wrangler kv key list --binding=SGCIA_KV --namespace-id=TU_KV_ID

# Ver el estado guardado
wrangler kv key get --binding=SGCIA_KV state --namespace-id=TU_KV_ID
```
