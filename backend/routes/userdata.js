const express = require('express');
const router = express.Router();
const { createClient } = require('@supabase/supabase-js');
const jwt = require('jsonwebtoken');

const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_KEY);

function authMiddleware(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Não autorizado' });
  try { req.user = jwt.verify(token, process.env.JWT_SECRET); next(); }
  catch { res.status(401).json({ error: 'Token inválido' }); }
}

// GET — retorna todos os dados do usuário
router.get('/', authMiddleware, async (req, res) => {
  try {
    const { data } = await supabase
      .from('users').select('user_data').eq('id', req.user.id).single();
    res.json(data?.user_data || {});
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// PATCH — merge shallow: só atualiza as chaves enviadas
router.patch('/', authMiddleware, async (req, res) => {
  try {
    const { data: current } = await supabase
      .from('users').select('user_data').eq('id', req.user.id).single();
    const merged = { ...(current?.user_data || {}), ...req.body };
    await supabase.from('users').update({ user_data: merged }).eq('id', req.user.id);
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

module.exports = router;
