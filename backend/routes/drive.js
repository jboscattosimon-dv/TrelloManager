const express = require('express');
const router = express.Router();
const { google } = require('googleapis');
const { createClient } = require('@supabase/supabase-js');
const jwt = require('jsonwebtoken');

const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_KEY);

function authMiddleware(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1] || req.query.token;
  if (!token) return res.status(401).json({ error: 'Não autorizado' });
  try { req.user = jwt.verify(token, process.env.JWT_SECRET); next(); }
  catch { res.status(401).json({ error: 'Token inválido' }); }
}

function getRedirectUri(req) {
  return (process.env.GOOGLE_REDIRECT_URI ||
    `${req.protocol}://${req.get('host')}/api/drive/callback`).trim();
}

function makeOAuth2(refreshToken, redirectUri) {
  const client = new google.auth.OAuth2(
    process.env.GOOGLE_CLIENT_ID?.trim(),
    process.env.GOOGLE_CLIENT_SECRET?.trim(),
    redirectUri
  );
  if (refreshToken) client.setCredentials({ refresh_token: refreshToken });
  return client;
}

// Inicia fluxo OAuth — redireciona para o Google
router.get('/authorize', authMiddleware, (req, res) => {
  const redirectUri = getRedirectUri(req);
  const client = makeOAuth2(null, redirectUri);
  const url = client.generateAuthUrl({
    access_type: 'offline',
    prompt: 'consent',
    scope: ['https://www.googleapis.com/auth/drive', 'email', 'openid'],
    state: JSON.stringify({ userId: req.user.id, redirectUri })
  });
  res.redirect(url);
});

// Callback do Google
router.get('/callback', async (req, res) => {
  const { code, state: stateRaw, error } = req.query;
  if (error) return res.redirect('/index.html?drive_error=' + encodeURIComponent(error));
  try {
    const { userId, redirectUri } = JSON.parse(stateRaw);
    const client = makeOAuth2(null, redirectUri);
    const { tokens } = await client.getToken(code);

    let email = null;
    if (tokens.id_token) {
      try {
        const payload = JSON.parse(Buffer.from(tokens.id_token.split('.')[1], 'base64url').toString());
        email = payload.email || null;
      } catch {}
    }

    await supabase.from('users').update({
      google_refresh_token: tokens.refresh_token,
      google_email: email
    }).eq('id', userId);
    res.redirect('/index.html?drive=connected');
  } catch (err) {
    res.redirect('/index.html?drive_error=' + encodeURIComponent(err.message));
  }
});

// Status da conexão
router.get('/status', authMiddleware, async (req, res) => {
  const { data } = await supabase.from('users').select('google_email, google_refresh_token').eq('id', req.user.id).single();
  res.json({ connected: !!data?.google_refresh_token, email: data?.google_email || null });
});

// Desconectar
router.delete('/disconnect', authMiddleware, async (req, res) => {
  await supabase.from('users').update({ google_refresh_token: null, google_email: null }).eq('id', req.user.id);
  res.json({ ok: true });
});

// Listar subpastas dentro de um folder
router.get('/folders', authMiddleware, async (req, res) => {
  const { folderId } = req.query;
  if (!folderId) return res.status(400).json({ error: 'folderId obrigatório' });
  const { data: user } = await supabase.from('users').select('google_refresh_token').eq('id', req.user.id).single();
  if (!user?.google_refresh_token) return res.status(400).json({ error: 'Google Drive não conectado' });
  try {
    const drive = google.drive({ version: 'v3', auth: makeOAuth2(user.google_refresh_token) });
    const { data } = await drive.files.list({
      q: `'${folderId}' in parents and mimeType='application/vnd.google-apps.folder' and trashed=false`,
      fields: 'files(id,name)',
      orderBy: 'name',
      pageSize: 200
    });
    res.json(data.files);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// Info de um folder (nome)
router.get('/folder-info', authMiddleware, async (req, res) => {
  const { folderId } = req.query;
  const { data: user } = await supabase.from('users').select('google_refresh_token').eq('id', req.user.id).single();
  if (!user?.google_refresh_token) return res.status(400).json({ error: 'Google Drive não conectado' });
  try {
    const drive = google.drive({ version: 'v3', auth: makeOAuth2(user.google_refresh_token) });
    const { data } = await drive.files.get({ fileId: folderId, fields: 'id,name' });
    res.json(data);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// Criar pastas
router.post('/folders', authMiddleware, async (req, res) => {
  const { parentId, names } = req.body;
  if (!parentId || !names?.length) return res.status(400).json({ error: 'parentId e names obrigatórios' });
  const { data: user } = await supabase.from('users').select('google_refresh_token').eq('id', req.user.id).single();
  if (!user?.google_refresh_token) return res.status(400).json({ error: 'Google Drive não conectado' });
  try {
    const drive = google.drive({ version: 'v3', auth: makeOAuth2(user.google_refresh_token) });
    const results = [];
    for (const name of names) {
      const safe = name.replace(/'/g, "\\'");
      const { data: existing } = await drive.files.list({
        q: `'${parentId}' in parents and name='${safe}' and mimeType='application/vnd.google-apps.folder' and trashed=false`,
        fields: 'files(id,name)'
      });
      if (existing.files.length) {
        results.push({ name, status: 'exists' });
      } else {
        await drive.files.create({
          requestBody: { name, mimeType: 'application/vnd.google-apps.folder', parents: [parentId] },
          fields: 'id'
        });
        results.push({ name, status: 'created' });
      }
    }
    res.json(results);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

module.exports = router;
