const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const supabase = require('../config/supabase');
const router = express.Router();

// РЕГИСТРАЦИЯ
router.post('/register', async (req, res) => {
  try {
    const { companyName, email, password, name } = req.body;
    
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
      console.error('Company error:', companyError);
      return res.status(500).json({ error: 'Ошибка создания компании' });
    }
    
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
      console.error('User error:', userError);
      await supabase.from('companies').delete().eq('id', company.id);
      return res.status(500).json({ error: 'Ошибка создания пользователя' });
    }
    
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
    console.error('Registration error:', error);
    res.status(500).json({ error: 'Ошибка сервера' });
  }
});

// ЛОГИН
router.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    
    if (!email || !password) {
      return res.status(400).json({ error: 'Введите email и пароль' });
    }
    
    const { data: user } = await supabase
      .from('users')
      .select('*, company:companies(*)')
      .eq('email', email)
      .single();
    
    if (!user) {
      return res.status(401).json({ error: 'Неверный email или пароль' });
    }
    
    const isValidPassword = await bcrypt.compare(password, user.password_hash);
    
    if (!isValidPassword) {
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
    console.error('Login error:', error);
    res.status(500).json({ error: 'Ошибка сервера' });
  }
});

module.exports = router;
```
