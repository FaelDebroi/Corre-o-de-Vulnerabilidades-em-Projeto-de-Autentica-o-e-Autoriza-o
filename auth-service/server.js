require('dotenv').config();
const express = require('express');
const cors = require('cors');
const authRoutes = require('./routes/auth');
const db = require('./db');

const app = express();
const PORT = process.env.PORT || 3001;

app.use(cors());
app.use(express.json());

app.use('/auth', authRoutes);

// Criar tabela users se não existir
(async () => {
  try {
    await db.execute(`
      CREATE TABLE IF NOT EXISTS users (
        id INT AUTO_INCREMENT PRIMARY KEY,
        username VARCHAR(50) UNIQUE NOT NULL,
        password VARCHAR(255) NOT NULL,
        refresh_token TEXT DEFAULT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);
    await db.execute(`
      ALTER TABLE users ADD COLUMN IF NOT EXISTS refresh_token TEXT DEFAULT NULL
    `).catch(() => {});
    console.log('Tabela users verificada/criada');
  } catch (err) {
    console.error('Erro ao criar tabela:', err);
  }
})();

app.listen(PORT, () => {
  console.log(`Auth service rodando na porta ${PORT}`);
});
