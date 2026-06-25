# Autenticação Vulnerável — Correção de Falhas de Segurança

Projeto acadêmico (IFSP) de microsserviços Node.js com vulnerabilidades intencionais baseadas no **OWASP API Security Top 10**, seguido da aplicação das correções correspondentes.

---

## Estrutura do projeto

```
AutenticacaoVulneravel/
├── auth-service/          # Serviço de autenticação (porta 3001)
│   ├── routes/auth.js     # Rotas de registro, login, refresh e verify
│   ├── server.js          # Inicialização e criação das tabelas
│   ├── db.js              # Pool de conexão MySQL
│   └── .env               # Variáveis de ambiente (segredos)
├── product-service/       # Serviço de produtos (porta 3002)
│   ├── routes/products.js # CRUD de produtos com controle de ownership
│   ├── server.js          # Inicialização
│   ├── db.js              # Pool de conexão MySQL
│   └── .env               # Variáveis de ambiente
├── gateway/               # API Gateway (porta 3000)
├── descricao/             # Documentação das falhas e testes originais
└── package.json           # Script concurrently para subir todos os serviços
```

---

## Vulnerabilidades identificadas e corrigidas

### 1. Broken Authentication — `API2 OWASP`

**Arquivo alterado:** `auth-service/routes/auth.js`

#### Antes (código vulnerável)

```js
// Segredo fraco com fallback hardcoded
const JWT_SECRET = process.env.JWT_SECRET || 'jwt_secret_fraca';

// Token sem expiração
const token = jwt.sign(
  { id: user.id, username: user.username },
  JWT_SECRET
  // sem expiresIn
);

// Login retornava apenas um token
res.json({ token });
```

**Problemas:**
- O JWT nunca expirava — um token roubado era válido para sempre.
- O segredo tinha fallback fraco (`'jwt_secret_fraca'`), previsível e quebrável por força bruta.
- Sem refresh token: o único fluxo era logar e guardar o token indefinidamente.
- O endpoint `/verify` não diferenciava tokens expirados de inválidos.

#### Depois (código corrigido)

```js
// Segredo obrigatório, sem fallback fraco
const JWT_SECRET = process.env.JWT_SECRET;
const REFRESH_SECRET = process.env.REFRESH_SECRET || JWT_SECRET;

// Access token com expiração curta
function generateAccessToken(user) {
  return jwt.sign(
    { id: user.id, username: user.username },
    JWT_SECRET,
    { expiresIn: '15m' }
  );
}

// Refresh token com expiração longa, armazenado no banco
function generateRefreshToken(user) {
  return jwt.sign(
    { id: user.id, type: 'refresh' },
    REFRESH_SECRET,
    { expiresIn: '7d' }
  );
}

// Login retorna os dois tokens
res.json({ accessToken, refreshToken });
```

**O que mudou:**

| Ponto | Antes | Depois |
|-------|-------|--------|
| Expiração do token | Sem expiração | 15 minutos |
| Segredo JWT | Fallback fraco hardcoded | Variável de ambiente obrigatória |
| Refresh token | Não existia | Emitido no login, válido por 7 dias |
| Rotação de refresh | Não existia | Cada uso invalida o token anterior |
| `/verify` | Não detectava expiração | Retorna erro com `err.message` se expirado |

**Novo endpoint adicionado — `POST /auth/refresh`:**
- Recebe o `refreshToken` no body.
- Verifica se o token existe no banco vinculado ao usuário.
- Emite novo `accessToken` e novo `refreshToken` (rotação).
- Invalida o refresh token anterior.

---

### 2. BOLA (Broken Object Level Authorization) — `API1 OWASP`

**Arquivo alterado:** `product-service/routes/products.js`

#### Antes (código vulnerável)

```js
// userId aceito do body sem validação
router.post('/', verifyToken, async (req, res) => {
  const { name, price, userId } = req.body;
  // ...
  await db.execute(
    'INSERT INTO products (name, price, user_id) VALUES (?, ?, ?)',
    [name, price, userId] // userId veio do cliente!
  );
});

// GET sem filtro — retorna produtos de todos os usuários
router.get('/', verifyToken, async (req, res) => {
  const [rows] = await db.execute('SELECT * FROM products');
  res.json(rows);
});

// PUT e DELETE sem verificar dono
router.put('/:id', verifyToken, async (req, res) => {
  await db.execute(
    'UPDATE products SET name = ?, price = ? WHERE id = ?',
    [name, price, id] // sem AND user_id = ?
  );
});
```

**Problemas:**
- Um usuário autenticado podia criar produtos em nome de qualquer outro usuário enviando um `userId` diferente no body.
- `GET /` retornava todos os produtos do sistema, de todos os usuários.
- `GET /:id`, `PUT /:id` e `DELETE /:id` não verificavam a propriedade do produto.
- Qualquer usuário podia deletar ou alterar produtos de outros usuários.

#### Depois (código corrigido)

```js
// userId vem exclusivamente do token
router.post('/', verifyToken, async (req, res) => {
  const { name, price } = req.body; // userId removido do body
  await db.execute(
    'INSERT INTO products (name, price, user_id) VALUES (?, ?, ?)',
    [name, price, req.user.id] // vem do token verificado
  );
});

// GET filtra pelo usuário autenticado
router.get('/', verifyToken, async (req, res) => {
  const [rows] = await db.execute(
    'SELECT * FROM products WHERE user_id = ?',
    [req.user.id]
  );
  res.json(rows);
});

// PUT verifica ownership via AND user_id = ?
router.put('/:id', verifyToken, async (req, res) => {
  const [result] = await db.execute(
    'UPDATE products SET name = ?, price = ? WHERE id = ? AND user_id = ?',
    [name, price, id, req.user.id]
  );
  if (result.affectedRows === 0) {
    return res.status(404).json({ error: 'Produto não encontrado ou não pertence ao usuário' });
  }
});
```

**O que mudou:**

| Operação | Antes | Depois |
|----------|-------|--------|
| `POST /` | `userId` do body | `user_id` do token JWT |
| `GET /` | Retorna todos os produtos | Retorna apenas produtos do usuário logado |
| `GET /:id` | Sem filtro de dono | `WHERE id = ? AND user_id = ?` |
| `PUT /:id` | Sem filtro de dono | `WHERE id = ? AND user_id = ?` |
| `DELETE /:id` | Sem filtro de dono | `WHERE id = ? AND user_id = ?` |
| Resposta de acesso negado | 404 revelando existência | 404 genérico (não revela se o produto existe) |

---

### 3. Improper Inventory Management — `API9 OWASP`

**Arquivo alterado:** `product-service/routes/products.js`

#### Antes (código vulnerável)

```js
// Endpoint shadow — sem autenticação, sem documentação
router.get('/internal/debug', async (req, res) => {
  const [products] = await db.execute('SELECT * FROM products');
  res.json({
    message: 'DEBUG ENDPOINT - Não usar em produção',
    total_products: products.length,
    products_sample: users.slice(0, 5),
    server_time: new Date().toISOString()
  });
});
```

**Problemas:**
- Endpoint acessível por qualquer pessoa sem autenticação.
- Expunha volume de dados, amostra de registros e timestamp do servidor.
- Não documentado — um serviço "esquecido" em produção (shadow API).

#### Depois (código corrigido)

```js
// Endpoint /internal/debug REMOVIDO completamente

// Middleware de autorização por role
const checkAdmin = (req, res, next) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Acesso negado' });
  next();
};

// Substituto protegido: exige autenticação + role admin
router.get('/admin/debug', verifyToken, checkAdmin, async (req, res) => {
  const [products] = await db.execute('SELECT id, name, price, user_id FROM products');
  res.json({
    message: 'Debug autorizado',
    total: products.length,
    products
  });
});
```

**O que mudou:**

| Ponto | Antes | Depois |
|-------|-------|--------|
| Rota | `/internal/debug` | `/admin/debug` |
| Autenticação | Nenhuma | `verifyToken` obrigatório |
| Autorização | Nenhuma | `checkAdmin` — exige `role: 'admin'` no token |
| Dados expostos | Todos os produtos + timestamp | Apenas com permissão explícita |

---

### 4. Variáveis de ambiente — `auth-service/.env`

#### Antes

```
JWT_SECRET=jwt_secret_fraca
```

#### Depois

```
JWT_SECRET=7f3e8a9c2b1d4f6e0a3c5b8d2e7f1a4c9b6d3e0f5a8c1b4d7e2f9a6c3b0d8e
REFRESH_SECRET=3a1b9c7d5e2f0a8b4c6d1e3f7a9b2c4d6e8f0a1b3c5d7e9f2a4b6c8d0e2f4a
```

- Segredos longos (64 caracteres hex) gerados aleatoriamente.
- Segredo separado para refresh tokens (`REFRESH_SECRET`).
- O código não possui mais nenhum fallback fraco — se `JWT_SECRET` não estiver definido, a aplicação falha na assinatura do token.

---

### 5. Schema do banco — `auth-service/server.js`

A criação da tabela `users` foi atualizada para incluir a coluna `refresh_token`, necessária para armazenar e validar tokens de renovação:

```js
// Antes
CREATE TABLE IF NOT EXISTS users (
  id INT AUTO_INCREMENT PRIMARY KEY,
  username VARCHAR(50) UNIQUE NOT NULL,
  password VARCHAR(255) NOT NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
)

// Depois
CREATE TABLE IF NOT EXISTS users (
  id INT AUTO_INCREMENT PRIMARY KEY,
  username VARCHAR(50) UNIQUE NOT NULL,
  password VARCHAR(255) NOT NULL,
  refresh_token TEXT DEFAULT NULL,   -- novo
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
)
```

Um `ALTER TABLE ... ADD COLUMN IF NOT EXISTS` é executado em seguida para migrar bancos já existentes sem erro.

---

## Resumo das correções

| Vulnerabilidade (OWASP) | Arquivo alterado | Correção principal |
|-------------------------|------------------|--------------------|
| API2 – Broken Authentication | `auth-service/routes/auth.js` | JWT com expiração de 15min, refresh token rotativo, segredo forte no `.env` |
| API2 – Broken Authentication | `auth-service/.env` | Segredos longos e aleatórios, sem fallback fraco |
| API2 – Broken Authentication | `auth-service/server.js` | Coluna `refresh_token` adicionada à tabela `users` |
| API1 – BOLA | `product-service/routes/products.js` | `userId` removido do body; todas as queries filtram por `AND user_id = ?` |
| API9 – Improper Inventory | `product-service/routes/products.js` | `/internal/debug` removido; substituído por `/admin/debug` com auth + role admin |

---

## Como executar

```bash
# Na raiz do projeto
npm install concurrently -D

# Sobe auth-service, product-service e gateway simultaneamente
npm run start
```

Serviços disponíveis após inicialização:

| Serviço | Porta | Base URL |
|---------|-------|----------|
| auth-service | 3001 | `http://localhost:3001/auth` |
| product-service | 3002 | `http://localhost:3002/products` |
| gateway | 3000 | `http://localhost:3000` |

---

## Fluxo de autenticação corrigido

```
1. POST /auth/register       → cria usuário
2. POST /auth/login          → retorna { accessToken, refreshToken }
3. GET  /products            → Authorization: Bearer <accessToken>
4. POST /auth/refresh        → body: { refreshToken } → novo { accessToken, refreshToken }
5. Token expirado (15min)    → repete passo 4
```
