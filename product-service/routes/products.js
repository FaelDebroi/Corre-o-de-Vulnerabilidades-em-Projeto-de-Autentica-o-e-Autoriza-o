const express = require('express');
const axios = require('axios');
const db = require('../db');
const router = express.Router();
require('dotenv').config();

// Middleware de autenticação – popula req.user com dados do token
const verifyToken = async (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader) return res.status(401).json({ error: 'Token não fornecido' });
  const token = authHeader.split(' ')[1];
  try {
    const response = await axios.post(`${process.env.AUTH_SERVICE_URL}/auth/verify`, { token });
    if (response.data.valid) {
      req.user = response.data.user;
      next();
    } else {
      res.status(401).json({ error: 'Token inválido' });
    }
  } catch (err) {
    res.status(401).json({ error: 'Falha na verificação do token' });
  }
};

// Middleware de autorização para endpoints administrativos
const checkAdmin = (req, res, next) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Acesso negado' });
  next();
};

// Listar apenas produtos do usuário logado
router.get('/', verifyToken, async (req, res) => {
  try {
    const [rows] = await db.execute('SELECT * FROM products WHERE user_id = ?', [req.user.id]);
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Buscar produto por ID – com verificação de ownership
router.get('/:id', verifyToken, async (req, res) => {
  const { id } = req.params;
  try {
    const [rows] = await db.execute(
      'SELECT * FROM products WHERE id = ? AND user_id = ?',
      [id, req.user.id]
    );
    if (rows.length === 0) return res.status(404).json({ error: 'Produto não encontrado' });
    res.json(rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Criar produto – userId vem exclusivamente do token
router.post('/', verifyToken, async (req, res) => {
  const { name, price } = req.body;
  if (!name || !price) {
    return res.status(400).json({ error: 'name e price são obrigatórios' });
  }
  try {
    const [result] = await db.execute(
      'INSERT INTO products (name, price, user_id) VALUES (?, ?, ?)',
      [name, price, req.user.id]
    );
    res.status(201).json({ id: result.insertId, name, price, userId: req.user.id });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Atualizar produto – verifica ownership
router.put('/:id', verifyToken, async (req, res) => {
  const { id } = req.params;
  const { name, price } = req.body;
  try {
    const [result] = await db.execute(
      'UPDATE products SET name = ?, price = ? WHERE id = ? AND user_id = ?',
      [name, price, id, req.user.id]
    );
    if (result.affectedRows === 0) {
      return res.status(404).json({ error: 'Produto não encontrado ou não pertence ao usuário' });
    }
    res.json({ message: 'Produto atualizado' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Deletar produto – verifica ownership
router.delete('/:id', verifyToken, async (req, res) => {
  const { id } = req.params;
  try {
    const [result] = await db.execute(
      'DELETE FROM products WHERE id = ? AND user_id = ?',
      [id, req.user.id]
    );
    if (result.affectedRows === 0) {
      return res.status(404).json({ error: 'Produto não encontrado ou não pertence ao usuário' });
    }
    res.status(204).send();
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Debug administrativo – requer autenticação + role admin
router.get('/admin/debug', verifyToken, checkAdmin, async (req, res) => {
  const [products] = await db.execute('SELECT id, name, price, user_id FROM products');
  res.json({
    message: 'Debug autorizado',
    total: products.length,
    products
  });
});

module.exports = router;
