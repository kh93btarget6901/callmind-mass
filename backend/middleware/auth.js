const jwt = require('jsonwebtoken');

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

async function checkLimits(req, res, next) {
  const supabase = require('../config/supabase');
  
  const { data: company } = await supabase
    .from('companies')
    .select('minutes_used, minutes_limit, status')
    .eq('id', req.companyId)
    .single();
  
  if (!company) {
    return res.status(404).json({ error: 'Компания не найдена' });
  }
  
  if (company.status === 'suspended') {
    return res.status(403).json({ error: 'Подписка приостановлена' });
  }
  
  if (company.minutes_used >= company.minutes_limit) {
    return res.status(403).json({ 
      error: 'Лимит минут исчерпан',
      minutes_used: company.minutes_used,
      minutes_limit: company.minutes_limit
    });
  }
  
  next();
}

module.exports = { authMiddleware, checkLimits };
