const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { createClient } = require('@supabase/supabase-js');
const path = require('path');

const app = express();

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, '../frontend')));

const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_KEY);

function authMiddleware(req, res, next) {
  try {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'Требуется авторизация' });
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.userId = decoded.userId;
    req.companyId = decoded.companyId;
    next();
  } catch (error) {
    return res.status(401).json({ error: 'Невалидный токен' });
  }
}

app.post('/api/auth/register', async (req, res) => {
  try {
    const { companyName, email, password, name } = req.body;
    if (!companyName || !email || !password) return res.status(400).json({ error: 'Заполните все поля' });
    
    const passwordHash = await bcrypt.hash(password, 10);
    
    const { data: company } = await supabase.from('companies').insert({
      name: companyName, email, status: 'trial',
      trial_ends_at: new Date(Date.now() + 14 * 24 * 60 * 60 * 1000).toISOString(),
      minutes_limit: 100
    }).select().single();
    
    const { data: user } = await supabase.from('users').insert({
      company_id: company.id, email, password_hash: passwordHash, name: name || companyName, role: 'owner'
    }).select().single();
    
    const token = jwt.sign({ userId: user.id, companyId: company.id }, process.env.JWT_SECRET, { expiresIn: '30d' });
    
    res.json({ success: true, token, user: { id: user.id, email, name: user.name, companyId: company.id, companyName: company.name } });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const { data: user } = await supabase.from('users').select('*, company:companies(*)').eq('email', email).single();
    if (!user || !await bcrypt.compare(password, user.password_hash)) {
      return res.status(401).json({ error: 'Неверный email или пароль' });
    }
    const token = jwt.sign({ userId: user.id, companyId: user.company_id }, process.env.JWT_SECRET, { expiresIn: '30d' });
    res.json({ success: true, token, user: { id: user.id, email, name: user.name, companyId: user.company_id, companyName: user.company.name } });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/bitrix/connect', authMiddleware, async (req, res) => {
  try {
    const { bitrixDomain, clientId, clientSecret } = req.body;
    await supabase.from('companies').update({ bitrix_domain: bitrixDomain, bitrix_client_id: clientId, bitrix_client_secret: clientSecret }).eq('id', req.companyId);
    const authUrl = `https://${bitrixDomain}/oauth/authorize/?client_id=${clientId}&response_type=code&redirect_uri=${process.env.APP_URL || 'https://callmind-mass-production.up.railway.app'}/api/bitrix/callback`;
    res.json({ success: true, authUrl });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/bitrix/callback', async (req, res) => {
  try {
    const { code, domain } = req.query;
    const { data: company } = await supabase.from('companies').select('*').eq('bitrix_domain', domain).single();
    const axios = require('axios');
    const tokenUrl = `https://${domain}/oauth/token/?grant_type=authorization_code&client_id=${company.bitrix_client_id}&client_secret=${company.bitrix_client_secret}&code=${code}`;
    const tokenResponse = await axios.get(tokenUrl);
    await supabase.from('companies').update({ bitrix_access_token: tokenResponse.data.access_token, bitrix_refresh_token: tokenResponse.data.refresh_token, bitrix_connected: true }).eq('id', company.id);
    res.send('<html><body style="font-family:Arial;text-align:center;padding:100px"><h1 style="color:#10b981">✅ Битрикс подключён!</h1><p>Закройте окно</p></body></html>');
  } catch (error) {
    res.send('<h1>Ошибка: ' + error.message + '</h1>');
  }
});

app.get('/api/bitrix/status', authMiddleware, async (req, res) => {
  const { data: company } = await supabase.from('companies').select('bitrix_connected, bitrix_domain').eq('id', req.companyId).single();
  res.json({ connected: company?.bitrix_connected || false, domain: company?.bitrix_domain });
});

async function callBitrixMethod(companyId, method, params = {}) {
  const { data: company } = await supabase.from('companies').select('*').eq('id', companyId).single();
  const axios = require('axios');
  const url = `https://${company.bitrix_domain}/rest/${method}?auth=${company.bitrix_access_token}`;
  const response = await axios.post(url, params);
  return response.data.result;
}

app.post('/api/bitrix/sync-users', authMiddleware, async (req, res) => {
  try {
    const users = await callBitrixMethod(req.companyId, 'user.get', { filter: { ACTIVE: true } });
    for (const user of users) {
      await supabase.from('managers').upsert({ company_id: req.companyId, bitrix_id: user.ID, name: `${user.NAME} ${user.LAST_NAME}`.trim() }, { onConflict: 'company_id,bitrix_id' });
    }
    res.json({ success: true, message: `Синхронизировано ${users.length} менеджеров` });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/bitrix/sync-calls', authMiddleware, async (req, res) => {
  try {
    const calls = await callBitrixMethod(req.companyId, 'voximplant.statistic.get', { FILTER: { '>CALL_START_DATE': new Date(Date.now() - 30 * 24 * 60 * 60 * 1000).toISOString() } });
    for (const call of calls || []) {
      const { data: manager } = await supabase.from('managers').select('id').eq('company_id', req.companyId).eq('bitrix_id', call.PORTAL_USER_ID).single();
      await supabase.from('calls').upsert({ company_id: req.companyId, bitrix_call_id: call.ID, manager_id: manager?.id, client_name: call.PHONE_NUMBER, duration: parseInt(call.CALL_DURATION) || 0, call_date: call.CALL_START_DATE, audio_url: call.CALL_RECORD_URL }, { onConflict: 'company_id,bitrix_call_id' });
    }
    res.json({ success: true, message: `Синхронизировано ${calls?.length || 0} звонков` });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/calls', authMiddleware, async (req, res) => {
  const { data } = await supabase.from('calls').select('*, manager:managers(name), scores:call_scores(*)').eq('company_id', req.companyId).order('call_date', { ascending: false });
  res.json(data || []);
});

app.get('/api/managers', authMiddleware, async (req, res) => {
  const { data } = await supabase.from('managers').select('*').eq('company_id', req.companyId).order('name');
  res.json(data || []);
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`🚀 Server on port ${PORT}`));
