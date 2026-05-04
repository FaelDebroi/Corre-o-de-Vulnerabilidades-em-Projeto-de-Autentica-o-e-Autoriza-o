# Relatório de Correção de Vulnerabilidades

|---|---|
| **Disciplina** | Desenvolvimento Web III |
| **Aluno** | Rafael Debroi |
| **Atividade** | Quiz 06 — Correção de Vulnerabilidades em Autenticação e Autorização |

---

## Introdução

O projeto é uma aplicação de microsserviços Node.js com três componentes:

| Serviço | Porta | Responsabilidade |
|---|---|---|
| `auth-service` | 3001 | Cadastro, autenticação e emissão de tokens JWT |
| `product-service` | 3002 | CRUD de produtos vinculados a usuários |
| `gateway` | 3000 | Proxy reverso — ponto único de entrada |

Foram identificadas e corrigidas **4 vulnerabilidades** da [OWASP API Security Top 10](https://owasp.org/API-Security/).

---

## Vulnerabilidades e Correções

### API2 — Broken Authentication

**Arquivo:** `auth-service/routes/auth.js`

O token JWT era gerado com um segredo fraco hardcoded e sem prazo de expiração, tornando tokens roubados válidos para sempre e facilmente forjáveis via jwt.io.

**Antes:**
```js
const JWT_SECRET = process.env.JWT_SECRET || 'jwt_secret_fraca';

const token = jwt.sign(
  { id: user.id, username: user.username },
  JWT_SECRET
  // sem expiresIn → token eterno
);
```

**Depois:**
```js
const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET) {
  console.error('FATAL: JWT_SECRET não definido.');
  process.exit(1);
}

const token = jwt.sign(
  { id: user.id, username: user.username },
  JWT_SECRET,
  { expiresIn: '1h' }
);
```

> O `.env` foi atualizado com um segredo aleatório de 64 caracteres.  
> A aplicação agora recusa iniciar se o segredo não estiver definido.  
> O custo do bcrypt foi elevado de `10` para `12` rounds.

---

### API1 — Broken Object Level Authorization (BOLA)

**Arquivo:** `product-service/routes/products.js`

Nenhum endpoint verificava se o produto pertencia ao usuário autenticado. Qualquer token válido dava acesso irrestrito a todos os recursos. No `POST`, o `userId` era aceito livremente pelo body (mass assignment).

| Endpoint | Problema | Correção |
|---|---|---|
| `GET /` | Retornava produtos de todos os usuários | Filtrado por `user_id = req.user.id` |
| `GET /:id` | Qualquer usuário acessava qualquer produto | `AND user_id = req.user.id` no `WHERE` |
| `POST /` | `userId` vinha do body | `user_id` extraído do token; body ignorado |
| `PUT /:id` | Qualquer usuário alterava qualquer produto | `AND user_id = req.user.id` no `WHERE` |
| `DELETE /:id` | Qualquer usuário deletava qualquer produto | `AND user_id = req.user.id` no `WHERE` |

**Exemplo do ataque (antes):**
```http
POST /products
Authorization: Bearer <token_usuario_A>

{ "name": "Produto", "price": 1.00, "userId": 99 }
→ Produto criado em nome do usuário 99
```

**Correção aplicada em todos os endpoints:**
```js
// Listar — só produtos do próprio usuário
db.execute('SELECT * FROM products WHERE user_id = ?', [req.user.id]);

// Buscar, atualizar e deletar — valida o dono antes de agir
db.execute('... WHERE id = ? AND user_id = ?', [id, req.user.id]);

// Criar — user_id sempre vem do token, nunca do body
db.execute('INSERT INTO products (name, price, user_id) VALUES (?, ?, ?)',
  [name, price, req.user.id]);
```

> Validação de `price` também foi adicionada: rejeita valores não numéricos e negativos.

---

### API9 — Improper Inventory Management

**Arquivo:** `product-service/routes/products.js`

Um endpoint de debug estava ativo em produção sem nenhuma autenticação, expondo volume de dados e informações do servidor para qualquer requisição anônima.

**Antes:**
```js
router.get('/internal/debug', async (req, res) => {
  const [products] = await db.execute('SELECT * FROM products');
  res.json({
    total_products: products.length,
    products_sample: products.slice(0, 5),
    server_time: new Date().toISOString()
  });
});
```

> **Correção:** o endpoint foi **removido completamente**.  
> Endpoints de diagnóstico não devem existir em código de produção.

---

### API8 — Security Misconfiguration (CORS)

**Arquivos:** `auth-service/server.js` e `product-service/server.js`

O CORS estava configurado para aceitar requisições de qualquer origem, expondo os serviços internos a chamadas arbitrárias de qualquer domínio externo.

**Antes:**
```js
app.use(cors()); // aceita qualquer origem
```

**Depois:**
```js
app.use(cors({ origin: process.env.ALLOWED_ORIGIN || 'http://localhost:3000' }));
```

> Apenas o gateway pode fazer requisições cross-origin aos serviços internos.

---

## Resumo das Alterações

| Arquivo | O que foi corrigido |
|---|---|
| `auth-service/routes/auth.js` | JWT com expiração de 1h; segredo forte obrigatório; bcrypt custo 12 |
| `auth-service/.env` | Segredo JWT substituído por string aleatória de 64 caracteres |
| `product-service/routes/products.js` | BOLA nos 5 endpoints; mass assignment; endpoint de debug removido; validação de `price` |
| `auth-service/server.js` | CORS restrito ao gateway |
| `product-service/server.js` | CORS restrito ao gateway |

| Risco | Categoria OWASP | Severidade | Status |
|---|---|---|---|
| Tokens sem expiração e segredo fraco | API2 — Broken Authentication | Crítica | Corrigida |
| Acesso irrestrito a recursos alheios | API1 — BOLA | Crítica | Corrigida |
| Endpoint de debug sem autenticação | API9 — Improper Inventory | Alta | Corrigida |
| CORS aberto para qualquer origem | API8 — Security Misconfiguration | Alta | Corrigida |
