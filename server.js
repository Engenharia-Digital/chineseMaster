const express = require('express');
const mysql = require('mysql2/promise');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const { body, validationResult } = require('express-validator');
require('dotenv').config();

console.log('Server.js está sendo inicializado!'); // Adicione esta linha


const app = express();
const PORT = process.env.PORT || 3001;

// Middlewares
app.use(cors({
  origin: [
    'http://localhost:3000',
    'https://chinesemaster-frontend.vercel.app',
    'https://chinesemaster.engdig.com' 
  ],
  credentials: true
}));
app.use(express.json());

// Configuração do banco de dados
const dbConfig = {
  host: process.env.DB_HOST || 'localhost',
  user: process.env.DB_USER || 'root',
  password: process.env.DB_PASSWORD || '',
  database: process.env.DB_NAME || 'chinesemaster',
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0
};

const pool = mysql.createPool(dbConfig);

// Middleware de autenticação
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Token de acesso requerido' });
  }

  jwt.verify(token, process.env.JWT_SECRET || 'chinesemaster_secret', (err, user) => {
    if (err) {
      return res.status(403).json({ error: 'Token inválido' });
    }
    req.user = user;
    next();
  });
};

// ================================
// ROTAS DE AUTENTICAÇÃO
// ================================

// Registro de usuário
app.post('/api/auth/register', [
  body('name').isLength({ min: 2 }).withMessage('Nome deve ter pelo menos 2 caracteres'),
  body('email').isEmail().withMessage('Email inválido'),
  body('password').isLength({ min: 6 }).withMessage('Senha deve ter pelo menos 6 caracteres')
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { name, email, password } = req.body;

    // Verificar se usuário já existe
    const [existingUsers] = await pool.execute(
      'SELECT id FROM users WHERE email = ?',
      [email]
    );

    if (existingUsers.length > 0) {
      return res.status(400).json({ error: 'Email já cadastrado' });
    }

    // Hash da senha
    const saltRounds = 10;
    const hashedPassword = await bcrypt.hash(password, saltRounds);

    // Inserir usuário
    const [result] = await pool.execute(
      'INSERT INTO users (name, email, password, created_at) VALUES (?, ?, ?, NOW())',
      [name, email, hashedPassword]
    );

    // Criar progresso inicial
    await pool.execute(
      'INSERT INTO user_progress (user_id, level, total_points, streak_days, completed_lessons) VALUES (?, 1, 0, 0, 0)',
      [result.insertId]
    );

    // Gerar token JWT
    const token = jwt.sign(
      { userId: result.insertId, email },
      process.env.JWT_SECRET || 'chinesemaster_secret',
      { expiresIn: '24h' }
    );

    res.status(201).json({
      message: 'Usuário criado com sucesso',
      token,
      user: {
        id: result.insertId,
        name,
        email
      }
    });

  } catch (error) {
    console.error('Erro no registro:', error);
    res.status(500).json({ error: 'Erro interno do servidor' });
  }
});

// Login de usuário
app.post('/api/auth/login', [
  body('email').isEmail().withMessage('Email inválido'),
  body('password').isLength({ min: 1 }).withMessage('Senha é obrigatória')
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { email, password } = req.body;

    // Buscar usuário
    const [users] = await pool.execute(
      'SELECT id, name, email, password FROM users WHERE email = ?',
      [email]
    );

    if (users.length === 0) {
      return res.status(401).json({ error: 'Credenciais inválidas' });
    }

    const user = users[0];

    // Verificar senha
    const isValidPassword = await bcrypt.compare(password, user.password);
    if (!isValidPassword) {
      return res.status(401).json({ error: 'Credenciais inválidas' });
    }

    // Gerar token JWT
    const token = jwt.sign(
      { userId: user.id, email: user.email },
      process.env.JWT_SECRET || 'chinesemaster_secret',
      { expiresIn: '24h' }
    );

    res.json({
      message: 'Login realizado com sucesso',
      token,
      user: {
        id: user.id,
        name: user.name,
        email: user.email
      }
    });

  } catch (error) {
    console.error('Erro no login:', error);
    res.status(500).json({ error: 'Erro interno do servidor' });
  }
});

// ================================
// ROTAS DE USUÁRIO
// ================================

// Obter perfil do usuário
app.get('/api/user/profile', authenticateToken, async (req, res) => {
  try {
    const [users] = await pool.execute(
      `SELECT u.id, u.name, u.email, u.created_at,
              p.level, p.total_points, p.streak_days, p.completed_lessons, p.last_study_date
       FROM users u 
       LEFT JOIN user_progress p ON u.id = p.user_id 
       WHERE u.id = ?`,
      [req.user.userId]
    );

    if (users.length === 0) {
      return res.status(404).json({ error: 'Usuário não encontrado' });
    }

    const user = users[0];

    // Buscar badges do usuário
    const [badges] = await pool.execute(
      `SELECT b.name, b.description, b.icon, ub.earned_at
       FROM user_badges ub
       JOIN badges b ON ub.badge_id = b.id
       WHERE ub.user_id = ?`,
      [req.user.userId]
    );

    res.json({
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        created_at: user.created_at
      },
      progress: {
        level: user.level || 1,
        total_points: user.total_points || 0,
        streak_days: user.streak_days || 0,
        completed_lessons: user.completed_lessons || 0,
        last_study_date: user.last_study_date
      },
      badges: badges
    });

  } catch (error) {
    console.error('Erro ao buscar perfil:', error);
    res.status(500).json({ error: 'Erro interno do servidor' });
  }
});

// Atualizar progresso do usuário
app.put('/api/user/progress', authenticateToken, async (req, res) => {
  try {
    const { points_earned, lesson_completed } = req.body;
    const userId = req.user.userId;

    // Buscar progresso atual
    const [currentProgress] = await pool.execute(
      'SELECT * FROM user_progress WHERE user_id = ?',
      [userId]
    );

    if (currentProgress.length === 0) {
      return res.status(404).json({ error: 'Progresso não encontrado' });
    }

    const progress = currentProgress[0];
    const newTotalPoints = progress.total_points + (points_earned || 0);
    const newCompletedLessons = progress.completed_lessons + (lesson_completed ? 1 : 0);

    // Calcular novo nível baseado nos pontos
    const newLevel = Math.floor(newTotalPoints / 100) + 1;

    // Verificar streak
    const today = new Date().toISOString().split('T')[0];
    const lastStudyDate = progress.last_study_date;
    let newStreakDays = progress.streak_days;

    if (lastStudyDate) {
      const lastDate = new Date(lastStudyDate).toISOString().split('T')[0];
      const yesterday = new Date();
      yesterday.setDate(yesterday.getDate() - 1);
      const yesterdayStr = yesterday.toISOString().split('T')[0];

      if (lastDate === yesterdayStr) {
        newStreakDays += 1;
      } else if (lastDate !== today) {
        newStreakDays = 1;
      }
    } else {
      newStreakDays = 1;
    }

    // Atualizar progresso
    await pool.execute(
      `UPDATE user_progress 
       SET total_points = ?, completed_lessons = ?, level = ?, 
           streak_days = ?, last_study_date = CURDATE()
       WHERE user_id = ?`,
      [newTotalPoints, newCompletedLessons, newLevel, newStreakDays, userId]
    );

    res.json({
      message: 'Progresso atualizado com sucesso',
      progress: {
        level: newLevel,
        total_points: newTotalPoints,
        completed_lessons: newCompletedLessons,
        streak_days: newStreakDays
      }
    });

  } catch (error) {
    console.error('Erro ao atualizar progresso:', error);
    res.status(500).json({ error: 'Erro interno do servidor' });
  }
});

// ================================
// ROTAS DE VOCABULÁRIO
// ================================

// Obter palavras do vocabulário
app.get('/api/vocabulary', authenticateToken, async (req, res) => {
  try {
    const { level = 1, category } = req.query;

    let query = 'SELECT * FROM vocabulary WHERE level <= ?';
    let params = [level];

    if (category) {
      query += ' AND category = ?';
      params.push(category);
    }

    query += ' ORDER BY RAND() LIMIT 20';

    const [words] = await pool.execute(query, params);

    res.json({ words });

  } catch (error) {
    console.error('Erro ao buscar vocabulário:', error);
    res.status(500).json({ error: 'Erro interno do servidor' });
  }
});

// Salvar progresso de uma palavra
app.post('/api/vocabulary/progress', authenticateToken, async (req, res) => {
  try {
    const { word_id, is_correct } = req.body;
    const userId = req.user.userId;

    await pool.execute(
      `INSERT INTO user_word_progress (user_id, word_id, correct_count, incorrect_count, last_studied)
       VALUES (?, ?, ?, ?, NOW())
       ON DUPLICATE KEY UPDATE
       correct_count = correct_count + ?,
       incorrect_count = incorrect_count + ?,
       last_studied = NOW()`,
      [
        userId, word_id, 
        is_correct ? 1 : 0, 
        is_correct ? 0 : 1,
        is_correct ? 1 : 0,
        is_correct ? 0 : 1
      ]
    );

    res.json({ message: 'Progresso salvo com sucesso' });

  } catch (error) {
    console.error('Erro ao salvar progresso da palavra:', error);
    res.status(500).json({ error: 'Erro interno do servidor' });
  }
});

// Iniciar servidor
app.listen(PORT, () => {
  console.log(`Servidor rodando na porta ${PORT}`);
});
