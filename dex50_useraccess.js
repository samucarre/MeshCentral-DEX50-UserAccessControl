/*
 * DEX50 User Access Control plugin for MeshCentral
 * Blocks or deletes users on login based on DEX50 backend status.
 *
 * Requires: MeshCentral >= 1.1.80 (plugins enabled)
 */

module.exports = function (parent) {
  const https = require('https');
  const url = require('url');

  const PLUGIN_NAME = 'DEX50-UserAccess';
  const LOG = (...args) => { try { parent.debug(PLUGIN_NAME, ...args); } catch { console.log(`[${PLUGIN_NAME}]`, ...args); } };

  // === CONFIG ===
  // URL de tu backend que ya tienes operativo:
  // Debe devolver JSON: { allow: boolean, reason?: string }
  const CHECK_URL_BASE = process.env.DEX50_CHECK_URL || 'https://backend.dex50.com/api/checkAccess';

  // Estados que causan eliminación del usuario en MeshCentral (opción A)
  // Si tu backend devuelve allow:false para "baja", aquí además lo intentamos borrar del server Mesh.
  const HARD_DELETE_ON_DENY = true;

  // Helpers
  function httpGetJson(targetUrl) {
    return new Promise((resolve, reject) => {
      const u = url.parse(targetUrl);
      const opts = {
        hostname: u.hostname,
        path: u.path,
        protocol: u.protocol,
        method: 'GET',
        port: u.port || (u.protocol === 'https:' ? 443 : 80),
        rejectUnauthorized: false // tu backend usa TLS válido; si no, cámbialo a true cuando tengas certs OK
      };
      const req = https.request(opts, (res) => {
        let body = '';
        res.on('data', (c) => body += c);
        res.on('end', () => {
          try {
            const json = JSON.parse(body);
            resolve({ status: res.statusCode, json });
          } catch (e) {
            reject(new Error(`Invalid JSON from ${targetUrl}: ${e.message} (body="${body.slice(0,200)}")`));
          }
        });
      });
      req.on('error', reject);
      req.end();
    });
  }

  async function checkAccessByEmail(email) {
    const target = `${CHECK_URL_BASE}?email=${encodeURIComponent(email)}`;
    const { status, json } = await httpGetJson(target);
    if (status !== 200 || typeof json !== 'object') {
      throw new Error(`Backend error: HTTP ${status}`);
    }
    // Espera { allow: boolean, reason?: string }
    const allow = !!json.allow;
    const reason = json.reason || (allow ? 'OK' : 'Denied');
    return { allow, reason };
  }

  // Intento de borrado del usuario desde MeshCentral DB.
  // Nota: API interna puede cambiar entre versiones; probamos varias rutas seguras.
  async function tryDeleteMeshUser(user) {
    try {
      // Ruta 1: API oficial de DB si está disponible
      if (parent && parent.db && typeof parent.db.RemoveUser === 'function') {
        await parent.db.RemoveUser(user);
        LOG(`Deleted user via parent.db.RemoveUser: ${user.name || user.email || user._id}`);
        return true;
      }

      // Ruta 2: Acceso genérico a colección "users"
      if (parent && parent.db && typeof parent.db.Remove === 'function') {
        await parent.db.Remove(user._id);
        LOG(`Deleted user via parent.db.Remove (_id): ${user._id}`);
        return true;
      }

      // Ruta 3: Si expone datastore (NeDB/Mongo) directo (no siempre)
      if (parent && parent.db && parent.db.userCollection && typeof parent.db.userCollection.removeOne === 'function') {
        await parent.db.userCollection.removeOne({ _id: user._id });
        LOG(`Deleted user via userCollection.removeOne(_id): ${user._id}`);
        return true;
      }
    } catch (e) {
      LOG(`WARN: Could not delete user (${user.name || user.email || user._id}): ${e.message}`);
      return false;
    }
    LOG(`WARN: No known DB removal method available on this MeshCentral version.`);
    return false;
  }

  // Cierre de sesión forzado y respuesta 403
  function hardDeny(req, res, reason) {
    try {
      if (req && req.session) {
        try { req.session.destroy(() => {}); } catch {}
      }
      if (res && !res.headersSent) {
        res.statusCode = 403;
        res.setHeader('Content-Type', 'text/plain; charset=utf-8');
        res.end(`Access denied by DEX50: ${reason || 'Not allowed'}`);
      }
    } catch {}
  }

  // Hook principal
  const obj = {};

  obj.server_startup = function () {
    LOG('Plugin loaded. Using backend:', CHECK_URL_BASE);
  };

  // Llamado cuando un usuario inicia sesión correctamente en la web de MeshCentral
  // Firma típica: (user, domain, session, req, res)
  obj.hook_userLoggedIn = async function (user, domain, session, req, res) {
    try {
      const email = (user && (user.email || user.name)) || '';
      if (!email) {
        LOG('WARN: user without email/name, allowing by default');
        return;
      }

      LOG(`Login for ${email} → checking DEX50...`);
      const { allow, reason } = await checkAccessByEmail(email);

      if (allow) {
        LOG(`ALLOW ${email}: ${reason}`);
        return;
      }

      LOG(`DENY ${email}: ${reason}`);

      if (HARD_DELETE_ON_DENY) {
        const deleted = await tryDeleteMeshUser(user);
        if (deleted) {
          LOG(`User ${email} removed from MeshCentral (A-policy).`);
        } else {
          LOG(`User ${email} NOT removed (no API or error), still denying access.`);
        }
      }

      hardDeny(req, res, reason);
      // Importante: devolvemos algo (no requerido, pero documentativo)
      return;
    } catch (e) {
      LOG(`ERROR during validation: ${e.message}. Failing closed (deny).`);
      hardDeny(req, res, 'Validation error');
      return;
    }
  };

  return obj;
};
