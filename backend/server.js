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

// Serve frontend files
const path = require('path');
app.use(express.static(path.join(__dirname, '../frontend')));

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

// ==================== BITRIX24 INTEGRATION ====================

// Начало авторизации Битрикс (генерация ссылки)
app.post('/api/bitrix/connect', authMiddleware, async (req, res) => {
  try {
    const { bitrixDomain, clientId, clientSecret } = req.body;
    
    if (!bitrixDomain || !clientId || !clientSecret) {
      return res.status(400).json({ error: 'Заполните все поля' });
    }
    
    // Сохраняем данные в компании
    const { error } = await supabase
      .from('companies')
      .update({
        bitrix_domain: bitrixDomain,
        bitrix_client_id: clientId,
        bitrix_client_secret: clientSecret
      })
      .eq('id', req.companyId);
    
    if (error) {
      return res.status(500).json({ error: 'Ошибка сохранения' });
    }
    
    // Генерируем ссылку для авторизации
    const authUrl = `https://${bitrixDomain}/oauth/authorize/?client_id=${clientId}&response_type=code&redirect_uri=https://callmind-mass-production.up.railway.app/api/bitrix/callback`;
    
    res.json({ 
      success: true, 
      authUrl,
      message: 'Перейдите по ссылке для подключения Битрикс24'
    });
    
  } catch (error) {
    console.error('❌ Bitrix connect error:', error);
    res.status(500).json({ error: error.message });
  }
});

// Callback от Битрикс после авторизации
app.get('/api/bitrix/callback', async (req, res) => {
  try {
    const { code, domain } = req.query;
    
    if (!code || !domain) {
      return res.send('<h1>❌ Ошибка: код авторизации не получен</h1>');
    }
    
    console.log('📥 Bitrix callback:', { code: code.substring(0, 20) + '...', domain });
    
    // Находим компанию по домену
    const { data: company } = await supabase
      .from('companies')
      .select('*')
      .eq('bitrix_domain', domain)
      .single();
    
    if (!company) {
      return res.send('<h1>❌ Компания не найдена</h1>');
    }
    
    // Обмениваем код на токены
    const tokenUrl = `https://${domain}/oauth/token/?grant_type=authorization_code&client_id=${company.bitrix_client_id}&client_secret=${company.bitrix_client_secret}&code=${code}`;
    
    const axios = require('axios');
    const tokenResponse = await axios.get(tokenUrl);
    
    // Сохраняем токены
    await supabase
      .from('companies')
      .update({
        bitrix_access_token: tokenResponse.data.access_token,
        bitrix_refresh_token: tokenResponse.data.refresh_token,
        bitrix_connected: true
      })
      .eq('id', company.id);
    
    console.log('✅ Bitrix connected for company:', company.name);
    
    res.send(`
      <html>
        <head>
          <style>
            body { 
              font-family: Arial; 
              text-align: center; 
              padding: 100px;
              background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            }
            .card {
              background: white;
              padding: 50px;
              border-radius: 20px;
              max-width: 500px;
              margin: 0 auto;
              box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            }
            h1 { color: #10b981; }
            p { color: #6b7280; font-size: 18px; }
          </style>
        </head>
        <body>
          <div class="card">
            <h1>✅ Битрикс24 успешно подключён!</h1>
            <p>Компания: <strong>${company.name}</strong></p>
            <p>Домен: <strong>${domain}</strong></p>
            <p style="margin-top: 30px;">Можете закрыть это окно и вернуться в CallMind.</p>
          </div>
        </body>
      </html>
    `);
    
  } catch (error) {
    console.error('❌ Bitrix callback error:', error);
    res.send(`<h1>❌ Ошибка подключения: ${error.message}</h1>`);
  }
});

// Получить статус подключения Битрикс
app.get('/api/bitrix/status', authMiddleware, async (req, res) => {
  try {
    const { data: company } = await supabase
      .from('companies')
      .select('bitrix_domain, bitrix_connected')
      .eq('id', req.companyId)
      .single();
    
    res.json({
      connected: company.bitrix_connected || false,
      domain: company.bitrix_domain || null
    });
    
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Функция для вызова методов Битрикс (вспомогательная)
async function callBitrixMethod(companyId, method, params = {}) {
  const { data: company } = await supabase
    .from('companies')
    .select('bitrix_domain, bitrix_access_token, bitrix_refresh_token, bitrix_client_id, bitrix_client_secret')
    .eq('id', companyId)
    .single();
  
  if (!company || !company.bitrix_access_token) {
    throw new Error('Битрикс не подключён');
  }
  
  const axios = require('axios');
  
  try {
    const url = `https://${company.bitrix_domain}/rest/${method}?auth=${company.bitrix_access_token}`;
    const response = await axios.post(url, params);
    return response.data.result;
  } catch (error) {
    // Если токен истёк — обновляем
    if (error.response?.data?.error === 'expired_token') {
      const tokenUrl = `https://${company.bitrix_domain}/oauth/token/?grant_type=refresh_token&client_id=${company.bitrix_client_id}&client_secret=${company.bitrix_client_secret}&refresh_token=${company.bitrix_refresh_token}`;
      const tokenResponse = await axios.get(tokenUrl);
      
      await supabase
        .from('companies')
        .update({
          bitrix_access_token: tokenResponse.data.access_token,
          bitrix_refresh_token: tokenResponse.data.refresh_token
        })
        .eq('id', companyId);
      
      // Повторяем запрос
      const url = `https://${company.bitrix_domain}/rest/${method}?auth=${tokenResponse.data.access_token}`;
      const response = await axios.post(url, params);
      return response.data.result;
    }
    throw error;
  }
}

// Синхронизация менеджеров из Битрикс
app.post('/api/bitrix/sync-users', authMiddleware, async (req, res) => {
  try {
    const users = await callBitrixMethod(req.companyId, 'user.get', { filter: { ACTIVE: true } });
    
    let synced = 0;
    for (const user of users) {
      const fullName = `${user.NAME} ${user.LAST_NAME}`.trim();
      
      const { error } = await supabase
        .from('managers')
        .upsert({
          company_id: req.companyId,
          bitrix_id: user.ID,
          name: fullName || user.EMAIL
        }, { 
          onConflict: 'company_id,bitrix_id',
          ignoreDuplicates: false 
        });
      
      if (!error) synced++;
    }
    
    res.json({ 
      success: true, 
      synced,
      total: users.length,
      message: `Синхронизировано ${synced} менеджеров` 
    });
    
  } catch (error) {
    console.error('❌ Sync users error:', error);
    res.status(500).json({ error: error.message });
  }
});

// Синхронизация звонков из Битрикс
app.post('/api/bitrix/sync-calls', authMiddleware, async (req, res) => {
  try {
    const calls = await callBitrixMethod(req.companyId, 'voximplant.statistic.get', {
      FILTER: { 
        '>CALL_START_DATE': new Date(Date.now() - 30 * 24 * 60 * 60 * 1000).toISOString() 
      },
      SORT: 'CALL_START_DATE',
      ORDER: 'DESC'
    });
    
    let synced = 0;
    for (const call of calls || []) {
      // Находим менеджера
      const { data: manager } = await supabase
        .from('managers')
        .select('id')
        .eq('company_id', req.companyId)
        .eq('bitrix_id', call.PORTAL_USER_ID)
        .single();
      
      const { error } = await supabase
        .from('calls')
        .upsert({
          company_id: req.companyId,
          bitrix_call_id: call.ID,
          manager_id: manager?.id,
          client_name: call.PHONE_NUMBER,
          phone: call.PHONE_NUMBER,
          duration: parseInt(call.CALL_DURATION) || 0,
          call_date: call.CALL_START_DATE,
          audio_url: call.CALL_RECORD_URL || null,
          crm_link: call.CRM_ENTITY_ID ? `https://${call.PORTAL_URL}/crm/contact/details/${call.CRM_ENTITY_ID}/` : null
        }, { 
          onConflict: 'company_id,bitrix_call_id',
          ignoreDuplicates: false 
        });
      
      if (!error) synced++;
    }
    
    res.json({ 
      success: true, 
      synced,
      total: calls?.length || 0,
      message: `Синхронизировано ${synced} звонков` 
    });
    
  } catch (error) {
    console.error('❌ Sync calls error:', error);
    res.status(500).json({ error: error.message });
  }
});

// Получить менеджеров компании
app.get('/api/managers', authMiddleware, async (req, res) => {
  try {
    const { data, error } = await supabase
      .from('managers')
      .select('*')
      .eq('company_id', req.companyId)
      .order('name');
    
    if (error) throw error;
    
    res.json(data || []);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Получить звонки компании
app.get('/api/calls', authMiddleware, async (req, res) => {
  try {
    const { data: calls, error } = await supabase
      .from('calls')
      .select(`
        *,
        manager:managers(name),
        scores:call_scores(*)
      `)
      .eq('company_id', req.companyId)
      .order('call_date', { ascending: false });
    
    if (error) throw error;
    
    res.json(calls || []);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ==================== ЗАПУСК СЕРВЕРА ====================
const PORT = process.env.PORT || 3000;
app.listen(PORT, '0.0.0.0', () => {
  console.log(`🚀 CallMind SaaS сервер запущен на порту ${PORT}`);
  console.log(`📊 Supabase URL: ${process.env.SUPABASE_URL ? 'Configured ✅' : 'Missing ❌'}`);
  console.log(`🔑 JWT Secret: ${process.env.JWT_SECRET ? 'Configured ✅' : 'Missing ❌'}`);
});
