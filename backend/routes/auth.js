const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { createClient } = require('@supabase/supabase-js');

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_KEY
);

const authMiddleware = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Não autorizado' });
  try {
    req.user = jwt.verify(token, process.env.JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'Token inválido' });
  }
};

const adminMiddleware = (req, res, next) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Acesso negado' });
  next();
};

// Login
router.post('/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Email e senha obrigatórios' });

  const { data: user, error } = await supabase
    .from('users')
    .select('*')
    .eq('email', email.toLowerCase())
    .single();

  if (error || !user) return res.status(401).json({ error: 'Email ou senha inválidos' });

  const valid = await bcrypt.compare(password, user.password_hash);
  if (!valid) return res.status(401).json({ error: 'Email ou senha inválidos' });

  const token = jwt.sign(
    { id: user.id, name: user.name, email: user.email, role: user.role,
      trello_api_key: user.trello_api_key, trello_token: user.trello_token },
    process.env.JWT_SECRET,
    { expiresIn: '7d' }
  );

  res.json({ token, user: { id: user.id, name: user.name, email: user.email, role: user.role } });
});

// Listar usuários (admin)
router.get('/users', authMiddleware, adminMiddleware, async (req, res) => {
  const { data, error } = await supabase
    .from('users')
    .select('id, name, email, role, created_at')
    .order('created_at', { ascending: false });
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

// Criar usuário (admin)
router.post('/users', authMiddleware, adminMiddleware, async (req, res) => {
  const { name, email, password, role, trello_api_key, trello_token } = req.body;
  if (!name || !email || !password || !trello_api_key || !trello_token)
    return res.status(400).json({ error: 'Todos os campos são obrigatórios' });

  const password_hash = await bcrypt.hash(password, 10);

  const { data, error } = await supabase.from('users').insert({
    name, email: email.toLowerCase(), password_hash,
    role: role || 'user', trello_api_key, trello_token
  }).select('id, name, email, role, created_at').single();

  if (error) return res.status(400).json({ error: error.message });
  res.json(data);
});

// Deletar usuário (admin)
router.delete('/users/:id', authMiddleware, adminMiddleware, async (req, res) => {
  const { error } = await supabase.from('users').delete().eq('id', req.params.id);
  if (error) return res.status(500).json({ error: error.message });
  res.json({ ok: true });
});

// Atualizar usuário (admin)
router.put('/users/:id', authMiddleware, adminMiddleware, async (req, res) => {
  const { name, email, password, role, trello_api_key, trello_token } = req.body;
  const updates = { name, email: email?.toLowerCase(), role, trello_api_key, trello_token };
  if (password) updates.password_hash = await bcrypt.hash(password, 10);

  const { data, error } = await supabase.from('users')
    .update(updates).eq('id', req.params.id)
    .select('id, name, email, role, created_at').single();
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

module.exports = router;
