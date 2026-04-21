const express = require('express');
const router = express.Router();
const { google } = require('googleapis');
const { createClient } = require('@supabase/supabase-js');
const jwt = require('jsonwebtoken');

const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_KEY);

function authMiddleware(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Não autorizado' });
  try { req.user = jwt.verify(token, process.env.JWT_SECRET); next(); }
  catch { res.status(401).json({ error: 'Token inválido' }); }
}

function makeOAuth2(refreshToken) {
  const client = new google.auth.OAuth2(
    process.env.GOOGLE_CLIENT_ID,
    process.env.GOOGLE_CLIENT_SECRET,
    process.env.GOOGLE_REDIRECT_URI
  );
  if (refreshToken) client.setCredentials({ refresh_token: refreshToken });
  return client;
}

// Inicia fluxo OAuth — redireciona para o Google
router.get('/authorize', authMiddleware, (req, res) => {
  const client = makeOAuth2();
  const url = client.generateAuthUrl({
    access_type: 'offline',
    prompt: 'consent',
    scope: ['https://www.googleapis.com/auth/drive'],
    state: req.user.id
  });
  res.redirect(url);
});

// Callback do Google
router.get('/callback', async (req, res) => {
  const { code, state: userId, error } = req.query;
  if (error) return res.redirect('/index.html?drive_error=' + encodeURIComponent(error));
  try {
    const client = makeOAuth2();
    const { tokens } = await client.getToken(code);
    client.setCredentials(tokens);
    const { data: gUser } = await google.oauth2({ version: 'v2', auth: client }).userinfo.get();
    await supabase.from('users').update({
      google_refresh_token: tokens.refresh_token,
      google_email: gUser.email
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
