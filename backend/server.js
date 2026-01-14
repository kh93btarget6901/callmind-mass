const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { createClient } = require('@supabase/supabase-js');

const app = express();

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Supabase
const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_KEY
);

// ==================== AUTH MIDDLEWARE ====================
function authMiddleware(req, res, next) {
  try {
    const token = req.headers.authorization?.split(' ')[1];
    
    if (!token) {
      return res.status(401).json({ error: 'Требуется авторизация' });
    }
    
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.userId = decoded.userId;
    req.companyId = decoded.companyId;
    req.userEmail = decoded.email;
    
    next();
  } catch (error) {
    return res.status(401).json({ error: 'Невалидный токен' });
  }
}

// ==================== ROUTES ====================

// Главная страница
app.get('/', (req, res) => {
  res.json({ 
    status: 'ok', 
    message: '🚀 CallMind SaaS API работает!',
    version: '1.0.0',
    endpoints: {
      register: 'POST /api/auth/register',
      login: 'POST /api/auth/login',
      me: 'GET /api/auth/me'
    }
  });
});

// РЕГИСТРАЦИЯ
app.post('/api/auth/register', async (req, res) => {
  try {
    const { companyName, email, password, name } = req.body;
    
    console.log('📝 Registration attempt:', { companyName, email });
    
    if (!companyName || !email || !password) {
      return res.status(400).json({ error: 'Заполните все поля' });
    }
    
    if (password.length < 6) {
      return res.status(400).json({ error: 'Пароль минимум 6 символов' });
    }
    
    // Проверка существующего email
    const { data: existingUser } = await supabase
      .from('users')
      .select('id')
      .eq('email', email)
      .single();
    
    if (existingUser) {
      return res.status(400).json({ error: 'Email уже зарегистрирован' });
    }
    
    // Хешируем пароль
    const passwordHash = await bcrypt.hash(password, 10);
    
    // Создаём компанию
    const { data: company, error: companyError } = await supabase
      .from('companies')
      .insert({
        name: companyName,
        email: email,
        status: 'trial',
        trial_ends_at: new Date(Date.now() + 14 * 24 * 60 * 60 * 1000).toISOString(),
        subscription_plan: 'trial',
        minutes_limit: 100,
        managers_limit: 3
      })
      .select()
      .single();
    
    if (companyError) {
      console.error('❌ Company error:', companyError);
      return res.status(500).json({ error: 'Ошибка создания компании: ' + companyError.message });
    }
    
    console.log('✅ Company created:', company.id);
    
    // Создаём пользователя
    const { data: user, error: userError } = await supabase
      .from('users')
      .insert({
        company_id: company.id,
        email: email,
        password_hash: passwordHash,
        name: name || companyName,
        role: 'owner'
      })
      .select()
      .single();
    
    if (userError) {
      console.error('❌ User error:', userError);
      await supabase.from('companies').delete().eq('id', company.id);
      return res.status(500).json({ error: 'Ошибка создания пользователя: ' + userError.message });
    }
    
    console.log('✅ User created:', user.id);
    
    // Создаём токен
    const token = jwt.sign(
      { 
        userId: user.id, 
        companyId: company.id,
        email: user.email,
        role: user.role
      },
      process.env.JWT_SECRET,
      { expiresIn: '30d' }
    );
    
    res.json({
      success: true,
      token,
      user: {
        id: user.id,
        email: user.email,
        name: user.name,
        companyId: company.id,
        companyName: company.name,
        trial_ends_at: company.trial_ends_at
      }
    });
    
  } catch (error) {
    console.error('❌ Registration error:', error);
    res.status(500).json({ error: 'Ошибка сервера: ' + error.message });
  }
});

// ЛОГИН
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    
    console.log('🔐 Login attempt:', email);
    
    if (!email || !password) {
      return res.status(400).json({ error: 'Введите email и пароль' });
    }
    
    const { data: user, error } = await supabase
      .from('users')
      .select('*, company:companies(*)')
      .eq('email', email)
      .single();
    
    if (error || !user) {
      console.log('❌ User not found:', email);
      return res.status(401).json({ error: 'Неверный email или пароль' });
    }
    
    const isValidPassword = await bcrypt.compare(password, user.password_hash);
    
    if (!isValidPassword) {
      console.log('❌ Invalid password for:', email);
      return res.status(401).json({ error: 'Неверный email или пароль' });
    }
    
    const token = jwt.sign(
      { 
        userId: user.id, 
        companyId: user.company_id,
        email: user.email,
        role: user.role
      },
      process.env.JWT_SECRET,
      { expiresIn: '30d' }
    );
    
    console.log('✅ Login successful:', email);
    
    res.json({
      success: true,
      token,
      user: {
        id: user.id,
        email: user.email,
        name: user.name,
        companyId: user.company_id,
        companyName: user.company.name,
        subscription_plan: user.company.subscription_plan,
        minutes_used: user.company.minutes_used,
        minutes_limit: user.company.minutes_limit
      }
    });
    
  } catch (error) {
    console.error('❌ Login error:', error);
    res.status(500).json({ error: 'Ошибка сервера: ' + error.message });
  }
});

// ПРОВЕРКА ТОКЕНА
app.get('/api/auth/me', authMiddleware, async (req, res) => {
  try {
    const { data: user } = await supabase
      .from('users')
      .select('*, company:companies(*)')
      .eq('id', req.userId)
      .single();
    
    if (!user) {
      return res.status(404).json({ error: 'Пользователь не найден' });
    }
    
    res.json({
      user: {
        id: user.id,
        email: user.email,
        name: user.name,
        companyId: user.company_id,
        companyName: user.company.name,
        role: user.role,
        subscription_plan: user.company.subscription_plan,
        trial_ends_at: user.company.trial_ends_at,
        minutes_used: user.company.minutes_used,
        minutes_limit: user.company.minutes_limit,
        bitrix_connected: user.company.bitrix_connected
      }
    });
    
  } catch (error) {
    return res.status(401).json({ error: 'Невалидный токен' });
  }
});

// ==================== ЗАПУСК СЕРВЕРА ====================
const PORT = process.env.PORT || 3000;
app.listen(PORT, '0.0.0.0', () => {
  console.log(`🚀 CallMind SaaS сервер запущен на порту ${PORT}`);
  console.log(`📊 Supabase URL: ${process.env.SUPABASE_URL ? 'Configured ✅' : 'Missing ❌'}`);
  console.log(`🔑 JWT Secret: ${process.env.JWT_SECRET ? 'Configured ✅' : 'Missing ❌'}`);
});
