// server.js — WaBlast Core Server (Supabase REST API — No pg driver)
// This version uses @supabase/supabase-js for ALL database operations
// to avoid IPv6 connection issues on Render

require('dns').setDefaultResultOrder('ipv4first');
require('dotenv').config();

const express = require('express');
const WebSocket = require('ws');
const { createClient } = require('@supabase/supabase-js');
const crypto = require('crypto');
const path = require('path');
const fetch = require('node-fetch');
const FormData = require('form-data');
const multer = require('multer');
const aiChatRouter = require('./src/routes/ai-chat');
const { generateReply, DEFAULT_MODEL: DEFAULT_AI_MODEL } = aiChatRouter;

const app = express();
const PORT = process.env.PORT || 3000;
const SELF_URL = process.env.RENDER_EXTERNAL_URL || `http://localhost:${PORT}`;
const META_API_VERSION = 'v20.0';

// ================================================================
// 1. SUPABASE CLIENT (REST API — bypasses pg/IPv6 entirely)
// ================================================================
const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_KEY, // service_role bypasses RLS
  {
    auth: { autoRefreshToken: false, persistSession: false },
    realtime: { transport: WebSocket }
  }
);

// ================================================================
// 2. CRYPTO — AES-256-GCM for WA token encryption
// ================================================================
function getKey() {
  const keyBase64 = process.env.TOKEN_ENCRYPTION_KEY;
  if (!keyBase64) throw new Error('TOKEN_ENCRYPTION_KEY env var is not set');
  const key = Buffer.from(keyBase64, 'base64');
  if (key.length !== 32) throw new Error('TOKEN_ENCRYPTION_KEY must decode to exactly 32 bytes');
  return key;
}

function encryptToken(plaintext) {
  const key = getKey();
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  let encrypted = cipher.update(plaintext, 'utf8');
  encrypted = Buffer.concat([encrypted, cipher.final()]);
  const authTag = cipher.getAuthTag();
  const combined = Buffer.concat([encrypted, authTag]);
  return `${iv.toString('base64')}:${combined.toString('base64')}`;
}

function decryptToken(stored) {
  const [ivB64, combinedB64] = stored.split(':');
  if (!ivB64 || !combinedB64) throw new Error('Malformed encrypted token');
  const key = getKey();
  const iv = Buffer.from(ivB64, 'base64');
  const combined = Buffer.from(combinedB64, 'base64');
  const authTag = combined.slice(-16);
  const encrypted = combined.slice(0, -16);
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAuthTag(authTag);
  let decrypted = decipher.update(encrypted);
  decrypted = Buffer.concat([decrypted, decipher.final()]);
  return decrypted.toString('utf8');
}

// ================================================================
// 3. MIDDLEWARE
// ================================================================
const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 25 * 1024 * 1024 } });
app.use(express.json({ 
  verify: (req, _res, buf) => { req.rawBody = buf; },
  limit: '10mb' 
}));
app.use(express.static(path.join(__dirname, 'public')));

// Auth middleware — verifies Supabase JWT (works for email + Google + FB)
const verifyUser = async (req, res, next) => {
  const authHeader = req.headers['authorization'] || '';
  let token = authHeader.replace(/^Bearer\s+/i, '').trim();
  if (!token) token = String(req.headers['x-api-key'] || '').trim();
  if (!token) return res.status(401).json({ error: 'Not authenticated' });
  try {
    const { data: { user }, error } = await supabase.auth.getUser(token);
    if (error || !user) return res.status(401).json({ error: 'Invalid or expired token' });
    req.user = user;
    next();
  } catch (err) {
    return res.status(401).json({ error: 'Auth verification failed' });
  }
};

// Admin middleware — protects user creation endpoint
const verifyAdmin = (req, res, next) => {
  const adminSecret = req.headers['x-admin-secret'] || req.body?.admin_secret;
  if (!process.env.ADMIN_SECRET || adminSecret !== process.env.ADMIN_SECRET) {
    return res.status(403).json({ error: 'Forbidden: Invalid Admin Secret' });
  }
  next();
};

// ================================================================
// 4. STATIC & HEALTH
// ================================================================
app.get('/health', (_req, res) => res.json({ status: 'ok' }));

// ================================================================
// 5. ADMIN ROUTES
// ================================================================
app.post('/api/admin/create-user', verifyAdmin, async (req, res) => {
  const { email, password, full_name } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Email and password required' });
  try {
    const { data, error } = await supabase.auth.admin.createUser({
      email, password, email_confirm: true,
      user_metadata: { full_name: full_name || email.split('@')[0] }
    });
    if (error) return res.status(400).json({ error: error.message });
    
    // Create profile + settings rows via REST
    await supabase.from('wb_profiles').upsert({
      id: data.user.id, email, full_name: full_name || email.split('@')[0],
      credits: 50, free_credits_granted: true,
      created_at: new Date().toISOString(), updated_at: new Date().toISOString()
    }, { onConflict: 'id' });
    
    await supabase.from('wb_settings').upsert({
      user_id: data.user.id,
      hour_limit: 1000, day_limit: 5000, min_gap: 5, max_gap: 15,
      created_at: new Date().toISOString(), updated_at: new Date().toISOString()
    }, { onConflict: 'user_id' });
    
    res.json({ success: true, user: data.user });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ================================================================
// 6. PROFILE ROUTES
// ================================================================
app.post('/api/auth/verify', async (req, res) => {
  const authHeader = req.headers['authorization'] || '';
  let token = authHeader.replace(/^Bearer\s+/i, '').trim();
  if (!token) token = String(req.headers['x-api-key'] || '').trim();
  if (!token) return res.status(401).json({ error: 'Not authenticated' });

  try {
    const { data: { user }, error } = await supabase.auth.getUser(token);
    if (error || !user) return res.status(401).json({ error: 'Invalid or expired token' });
    return res.json({ success: true, user: { id: user.id, email: user.email, user_metadata: user.user_metadata } });
  } catch (err) {
    return res.status(401).json({ error: 'Auth verification failed' });
  }
});

app.get('/api/profile', verifyUser, async (req, res) => {
  // Try to get existing profile
  let { data, error } = await supabase
    .from('wb_profiles')
    .select('id, email, full_name')
    .eq('id', req.user.id)
    .single();
  
  // If profile doesn't exist, create it
  if (error || !data) {
    const newProfile = {
      id: req.user.id,
      email: req.user.email || '',
      full_name: req.user.user_metadata?.full_name || req.user.email?.split('@')[0] || 'User',
      credits: 50,
      free_credits_granted: true,
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString()
    };
    
    // Create profile
    await supabase.from('wb_profiles').insert(newProfile);
    
    // Create settings if doesn't exist
    await supabase.from('wb_settings').upsert({
      user_id: req.user.id,
      hour_limit: 1000,
      day_limit: 5000,
      min_gap: 5,
      max_gap: 15,
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString()
    }, { onConflict: 'user_id' });
    
    data = newProfile;
  }
  
  res.json({ success: true, user: data });
});

app.put('/api/profile', verifyUser, async (req, res) => {
  const { full_name, email } = req.body;
  const { error } = await supabase
    .from('wb_profiles')
    .update({ full_name, email, updated_at: new Date().toISOString() })
    .eq('id', req.user.id);
  if (error) return res.status(500).json({ error: error.message });
  res.json({ success: true });
});

// ================================================================
// 7. TEMPLATES ROUTES
// ================================================================
app.get('/api/templates', verifyUser, async (req, res) => {
  const { data, error } = await supabase
    .from('wb_templates')
    .select('*')
    .eq('user_id', req.user.id)
    .order('created_at', { ascending: false });
  if (error) return res.status(500).json({ error: error.message });
  res.json({ success: true, templates: data || [] });
});

app.post('/api/templates', verifyUser, async (req, res) => {
  const { name, body, category, language, footer, buttons, header_type, header_text, header_media_url, header_media_id, placeholders } = req.body;
  if (!name || !body) return res.status(400).json({ error: 'Name and body required' });
  if (!/^[a-z0-9_]+$/.test(name)) return res.status(400).json({ error: 'Name must be lowercase letters, numbers, underscores only' });

  try {
    // Get user's WA account for Meta API call
    const { data: accounts } = await supabase
      .from('wa_accounts')
      .select('access_token, waba_id')
      .eq('user_id', req.user.id)
      .eq('is_active', true)
      .order('created_at', { ascending: false })
      .limit(1);
    
    if (!accounts?.length) return res.status(400).json({ error: 'No WhatsApp account connected' });
    
    const account = accounts[0];
    const plainToken = decryptToken(account.access_token);

    // Build Meta components
    const components = [];
    if (header_type && header_type !== 'NONE') {
      const header = { type: 'HEADER' };
      if (header_type === 'TEXT') {
        header.format = 'TEXT';
        header.text = header_text || '';
      } else {
        header.format = header_type;
        const mediaHandle = header_media_id || header_media_url;
        if (mediaHandle) header.example = { header_handle: [mediaHandle] };
      }
      components.push(header);
    }
    components.push({ type: 'BODY', text: body });
    if (footer?.trim()) components.push({ type: 'FOOTER', text: footer.trim() });
    if (buttons?.length) {
      const buttonComp = { type: 'BUTTONS', buttons: [] };
      for (const btn of buttons) {
        if (btn.type === 'QUICK_REPLY') buttonComp.buttons.push({ type: 'QUICK_REPLY', text: btn.text });
        else if (btn.type === 'URL') buttonComp.buttons.push({ type: 'URL', text: btn.text, url: btn.url });
        else if (btn.type === 'PHONE_NUMBER') buttonComp.buttons.push({ type: 'PHONE_NUMBER', text: btn.text, phone_number: btn.phone });
        else if (btn.type === 'COPY_CODE') buttonComp.buttons.push({ type: 'COPY_CODE', example: [btn.text] });
      }
      if (buttonComp.buttons.length) components.push(buttonComp);
    }

    // Submit to Meta
    const metaRes = await fetch(
      `https://graph.facebook.com/${META_API_VERSION}/${account.waba_id}/message_templates`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${plainToken}` },
        body: JSON.stringify({ name, category: category || 'MARKETING', language: language || 'en_US', components })
      }
    );
    const metaData = await metaRes.json();
    if (!metaRes.ok) return res.status(400).json({ error: metaData.error?.message || 'Meta API error', meta_error: metaData.error });

    // Save to DB
    const { data: inserted, error: insertErr } = await supabase
      .from('wb_templates')
      .insert({
        user_id: req.user.id, name, body,
        category: category || 'MARKETING', language: language || 'en_US',
        status: 'PENDING', header_type: header_type || 'NONE',
        header_text: header_text || null, header_media_url: header_media_url || null,
        footer: footer || null, buttons: buttons || [], placeholders: placeholders || [],
        meta_template_id: metaData.id || null,
        created_at: new Date().toISOString(), updated_at: new Date().toISOString()
      })
      .select()
      .single();
    
    if (insertErr) return res.status(500).json({ error: 'DB save failed: ' + insertErr.message });
    res.json({ success: true, template: inserted, message: 'Template submitted for Meta review.' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.delete('/api/templates/:id', verifyUser, async (req, res) => {
  const { data: tpl } = await supabase
    .from('wb_templates')
    .select('name')
    .eq('id', req.params.id)
    .eq('user_id', req.user.id)
    .single();
  if (!tpl) return res.status(404).json({ error: 'Template not found' });

  // Try to delete from Meta too
  const { data: accounts } = await supabase
    .from('wa_accounts')
    .select('access_token, waba_id')
    .eq('user_id', req.user.id)
    .eq('is_active', true)
    .limit(1);
  
  if (accounts?.length) {
    const plainToken = decryptToken(accounts[0].access_token);
    await fetch(
      `https://graph.facebook.com/${META_API_VERSION}/${accounts[0].waba_id}/message_templates?name=${encodeURIComponent(tpl.name)}`,
      { method: 'DELETE', headers: { 'Authorization': `Bearer ${plainToken}` } }
    );
  }

  const { error } = await supabase
    .from('wb_templates')
    .delete()
    .eq('id', req.params.id)
    .eq('user_id', req.user.id);
  if (error) return res.status(500).json({ error: error.message });
  res.json({ success: true });
});

app.post('/api/templates/media/upload', verifyUser, upload.single('file'), async (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'File upload required' });

  const { data: accounts, error: accountError } = await supabase
    .from('wa_accounts')
    .select('access_token, phone_number_id')
    .eq('user_id', req.user.id)
    .eq('is_active', true)
    .order('created_at', { ascending: false })
    .limit(1);
  if (accountError) return res.status(500).json({ error: accountError.message });
  if (!accounts?.length) return res.status(400).json({ error: 'No WhatsApp account connected' });

  const account = accounts[0];
  const plainToken = decryptToken(account.access_token);
  try {
    const form = new FormData();
    form.append('file', req.file.buffer, {
      filename: req.file.originalname,
      contentType: req.file.mimetype
    });

    const metaRes = await fetch(
      `https://graph.facebook.com/${META_API_VERSION}/${account.phone_number_id}/media`,
      {
        method: 'POST',
        headers: { Authorization: `Bearer ${plainToken}` },
        body: form
      }
    );
    const data = await metaRes.json();
    if (!metaRes.ok) return res.status(metaRes.status).json({ error: data.error?.message || 'Media upload failed', detail: data });

    res.json({ success: true, media_id: data.id, mime_type: data.mime_type, url: data.url || null });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/templates/meta/sync', verifyUser, async (req, res) => {
  const { data: accounts, error: accountError } = await supabase
    .from('wa_accounts')
    .select('access_token, waba_id')
    .eq('user_id', req.user.id)
    .eq('is_active', true)
    .order('created_at', { ascending: false })
    .limit(1);
  if (accountError) return res.status(500).json({ error: accountError.message });
  if (!accounts?.length) return res.status(400).json({ error: 'No WhatsApp account connected' });

  const account = accounts[0];
  const plainToken = decryptToken(account.access_token);

  try {
    const response = await fetch(
      `https://graph.facebook.com/${META_API_VERSION}/${account.waba_id}/message_templates?fields=id,name,status,language,category,components&access_token=${plainToken}`,
      { method: 'GET' }
    );
    if (!response.ok) {
      const errorData = await response.json();
      return res.status(response.status).json({ error: errorData.error?.message || 'Failed to fetch from Meta' });
    }

    const data = await response.json();
    const approvedTemplates = (data.data || []).filter(t => t.status === 'APPROVED');

    const { data: localTemplates, error: localError } = await supabase
      .from('wb_templates')
      .select('id,name,meta_template_id,status')
      .eq('user_id', req.user.id);
    if (localError) return res.status(500).json({ error: localError.message });

    const syncPromises = [];
    for (const tpl of approvedTemplates) {
      const existing = localTemplates?.find(l => l.meta_template_id === tpl.id) || localTemplates?.find(l => l.name === tpl.name);
      const bodyComp = (tpl.components || []).find(c => c.type === 'BODY');
      const footerComp = (tpl.components || []).find(c => c.type === 'FOOTER');
      const headerComp = (tpl.components || []).find(c => c.type === 'HEADER');
      const headerType = headerComp?.format || 'NONE';
      const headerText = headerType === 'TEXT' ? headerComp?.text || null : null;

      if (existing) {
        const updateData = {};
        if (existing.status !== 'APPROVED') updateData.status = 'APPROVED';
        if (!existing.meta_template_id) updateData.meta_template_id = tpl.id;
        if (Object.keys(updateData).length) {
          syncPromises.push(
            supabase.from('wb_templates').update({ ...updateData, updated_at: new Date().toISOString() }).eq('id', existing.id)
          );
        }
      } else {
        syncPromises.push(
          supabase.from('wb_templates').insert({
            user_id: req.user.id,
            name: tpl.name,
            body: bodyComp?.text || '',
            category: tpl.category || 'MARKETING',
            language: tpl.language || 'en_US',
            status: 'APPROVED',
            header_type: headerType,
            header_text: headerText,
            header_media_url: null,
            footer: footerComp?.text || null,
            buttons: [],
            placeholders: [],
            meta_template_id: tpl.id,
            created_at: new Date().toISOString(),
            updated_at: new Date().toISOString()
          })
        );
      }
    }

    await Promise.all(syncPromises);
    res.json({ success: true, templates: approvedTemplates, synced: true });
  } catch (err) {
    res.status(500).json({ error: 'Failed to sync approved templates: ' + err.message });
  }
});

app.get('/api/templates/meta/approved', verifyUser, async (req, res) => {
  // Get user's active WA account
  const { data: accounts } = await supabase
    .from('wa_accounts')
    .select('access_token, waba_id, phone_number_id')
    .eq('user_id', req.user.id)
    .eq('is_active', true)
    .order('created_at', { ascending: false })
    .limit(1);
  
  if (!accounts?.length) {
    return res.status(400).json({ error: 'No WhatsApp account connected' });
  }

  const account = accounts[0];
  const plainToken = decryptToken(account.access_token);

  try {
    // Fetch approved templates from Meta
    const response = await fetch(
      `https://graph.facebook.com/${META_API_VERSION}/${account.waba_id}/message_templates?fields=name,status,language,category,components&access_token=${plainToken}`,
      { method: 'GET' }
    );
    
    if (!response.ok) {
      const errorData = await response.json();
      return res.status(response.status).json({ error: errorData.error?.message || 'Failed to fetch from Meta' });
    }

    const data = await response.json();
    const approvedTemplates = (data.data || []).filter(t => t.status === 'APPROVED');

    res.json({
      success: true,
      templates: approvedTemplates.map(t => ({
        name: t.name,
        status: t.status,
        language: t.language || 'en_US',
        category: t.category || 'MARKETING',
        components: t.components || []
      }))
    });
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch approved templates: ' + err.message });
  }
});

// ================================================================
// 8. CONTACTS ROUTES
// ================================================================
app.get('/api/contacts', verifyUser, async (req, res) => {
  const { data, error } = await supabase
    .from('wb_contacts')
    .select('*')
    .eq('user_id', req.user.id)
    .order('created_at', { ascending: true });
  if (error) return res.status(500).json({ error: error.message });
  res.json({ success: true, contacts: data || [] });
});

app.post('/api/contacts', verifyUser, async (req, res) => {
  const { contacts } = req.body;
  if (!contacts?.length) return res.json({ success: true });
  
  // Delete existing contacts first
  await supabase.from('wb_contacts').delete().eq('user_id', req.user.id);
  
  const rows = contacts.map(c => ({
    user_id: req.user.id,
    name: c.name || c.phone,
    phone: String(c.phone).replace(/\D/g, ''),
    group_name: c.group_name || 'Default',
    message: c.message || null,
    status: 'pending', optin: true,
    created_at: new Date().toISOString(),
    updated_at: new Date().toISOString()
  }));
  
  const { error } = await supabase.from('wb_contacts').insert(rows);
  if (error) return res.status(500).json({ error: error.message });
  
  // Return saved contacts
  const { data } = await supabase
    .from('wb_contacts')
    .select('*')
    .eq('user_id', req.user.id)
    .order('created_at', { ascending: true });
  
  res.json({ success: true, contacts: data || [] });
});

// ================================================================
// 9. SETTINGS ROUTES
// ================================================================
app.get('/api/settings', verifyUser, async (req, res) => {
  const { data } = await supabase
    .from('wb_settings')
    .select('*')
    .eq('user_id', req.user.id)
    .single();
  res.json({ success: true, settings: data || {} });
});

app.post('/api/settings', verifyUser, async (req, res) => {
  const update = { updated_at: new Date().toISOString() };
  if (req.body.hour_limit !== undefined) update.hour_limit = parseInt(req.body.hour_limit) || 0;
  if (req.body.day_limit !== undefined) update.day_limit = parseInt(req.body.day_limit) || 0;
  if (req.body.min_gap !== undefined) update.min_gap = parseInt(req.body.min_gap) || 5;
  if (req.body.max_gap !== undefined) update.max_gap = parseInt(req.body.max_gap) || 15;
  if (req.body.auto_reply !== undefined) update.auto_reply = req.body.auto_reply;
  if (req.body.auto_reply_prompt !== undefined) update.auto_reply_prompt = req.body.auto_reply_prompt;
  if (req.body.auto_reply_model !== undefined) update.auto_reply_model = req.body.auto_reply_model;
  if (req.body.groq_key !== undefined && req.body.groq_key !== '••••••••') update.groq_key = req.body.groq_key;

  const { error } = await supabase
    .from('wb_settings')
    .upsert({ user_id: req.user.id, ...update }, { onConflict: 'user_id' });
  if (error) return res.status(500).json({ error: error.message });
  res.json({ success: true });
});

// ================================================================
// 10. CAMPAIGNS ROUTES
// ================================================================
app.get('/api/campaigns', verifyUser, async (req, res) => {
  const { data, error } = await supabase
    .from('wb_campaigns')
    .select('*')
    .eq('user_id', req.user.id)
    .order('created_at', { ascending: false });
  if (error) return res.status(500).json({ error: error.message });
  res.json({ success: true, campaigns: data || [] });
});

app.post('/api/campaigns', verifyUser, async (req, res) => {
  const { name, template_id, group_name, schedule_at, start_now, placeholder_mapping } = req.body;
  if (!name) return res.status(400).json({ error: 'Campaign name required' });
  if (!template_id) return res.status(400).json({ error: 'template_id required' });

  const scheduledAt = schedule_at ? new Date(schedule_at) : null;
  if (schedule_at && (!scheduledAt || isNaN(scheduledAt.getTime()))) {
    return res.status(400).json({ error: 'Invalid schedule date' });
  }
  if (schedule_at && scheduledAt <= new Date()) {
    return res.status(400).json({ error: 'Scheduled date must be in the future' });
  }
  const isScheduled = scheduledAt && scheduledAt > new Date();
  let status = isScheduled ? 'scheduled' : (start_now ? 'running' : 'draft');

  if (!isScheduled && start_now) {
    const { data: activeCampaign } = await supabase
      .from('wb_campaigns')
      .select('id, name, status')
      .eq('user_id', req.user.id)
      .in('status', ['queued', 'running', 'paused'])
      .limit(1)
      .single();
    if (activeCampaign) {
      return res.status(400).json({ 
        error: `Campaign "${activeCampaign.name}" is already ${activeCampaign.status}. Stop it first.`,
        active_campaign: activeCampaign 
      });
    }
  }

  // Get template
  const { data: tpl, error: tplErr } = await supabase
    .from('wb_templates')
    .select('id, name, status, language')
    .eq('id', template_id)
    .eq('user_id', req.user.id)
    .single();
  if (tplErr || !tpl) return res.status(404).json({ error: 'Template not found' });
  if (tpl.status !== 'APPROVED') return res.status(400).json({ error: 'Template must be APPROVED' });

  // Get contacts
  let contactsQuery = supabase.from('wb_contacts').select('*').eq('user_id', req.user.id);
  if (group_name?.trim()) contactsQuery = contactsQuery.eq('group_name', group_name.trim());
  const { data: contacts } = await contactsQuery;
  if (!contacts?.length) return res.status(400).json({ error: 'No contacts found' });

  // Parse and store placeholder mapping if present
  const insertPayload = {
    user_id: req.user.id,
    name,
    template_id: tpl.id,
    template_name: tpl.name,
    group_name: group_name?.trim() || null,
    status,
    total_contacts: contacts.length,
    queue_total: contacts.length,
    queue_processed: 0,
    queue_failed: 0,
    sent_count: 0,
    failed_count: 0,
    created_at: new Date().toISOString(),
    updated_at: new Date().toISOString()
  };
  if (isScheduled) insertPayload.schedule_at = scheduledAt.toISOString();
  if (placeholder_mapping && typeof placeholder_mapping === 'object' && Object.keys(placeholder_mapping).length) {
    insertPayload.placeholder_mapping = placeholder_mapping;
  }

  const { data: campaign, error: campErr } = await supabase
    .from('wb_campaigns')
    .insert(insertPayload)
    .select()
    .single();
  if (campErr) return res.status(500).json({ error: 'Failed to create campaign: ' + campErr.message });

  const queueItems = contacts.map(c => ({
    campaign_id: campaign.id,
    user_id: req.user.id,
    contact_id: c.id,
    phone: c.phone,
    contact_name: c.name || '',
    template_name: tpl.name,
    template_language: tpl.language || 'en_US',
    status: 'pending',
    attempt_count: 0,
    created_at: new Date().toISOString()
  }));

  const { error: queueErr } = await supabase.from('wb_send_queue').insert(queueItems);
  if (queueErr) {
    await supabase.from('wb_campaigns').delete().eq('id', campaign.id);
    return res.status(500).json({ error: 'Failed to create queue: ' + queueErr.message });
  }

  res.json({ success: true, campaign, total_contacts: contacts.length, message: `Campaign created with ${contacts.length} contacts queued.` });
});

app.post('/api/campaigns/:id/start', verifyUser, async (req, res) => {
  const { error } = await supabase
    .from('wb_campaigns')
    .update({ status: 'running', started_at: new Date().toISOString(), updated_at: new Date().toISOString() })
    .eq('id', req.params.id)
    .eq('user_id', req.user.id);
  if (error) return res.status(500).json({ error: error.message });
  res.json({ success: true, message: 'Campaign started' });
});

app.post('/api/campaigns/:id/pause', verifyUser, async (req, res) => {
  const { error } = await supabase
    .from('wb_campaigns')
    .update({ status: 'paused', updated_at: new Date().toISOString() })
    .eq('id', req.params.id)
    .eq('user_id', req.user.id);
  if (error) return res.status(500).json({ error: error.message });
  res.json({ success: true, message: 'Campaign paused' });
});

app.post('/api/campaigns/:id/stop', verifyUser, async (req, res) => {
  // Count pending items for refund
  const { count: pendingCount } = await supabase
    .from('wb_send_queue')
    .select('*', { count: 'exact', head: true })
    .eq('campaign_id', req.params.id)
    .eq('status', 'pending');

  // Delete pending queue items
  await supabase.from('wb_send_queue').delete().eq('campaign_id', req.params.id).eq('status', 'pending');

  // Reset campaign to draft
  await supabase
    .from('wb_campaigns')
    .update({ status: 'draft', updated_at: new Date().toISOString() })
    .eq('id', req.params.id)
    .eq('user_id', req.user.id);

  res.json({ success: true, message: 'Campaign stopped and reset to draft', refunded: pendingCount || 0 });
});

app.delete('/api/campaigns/:id', verifyUser, async (req, res) => {
  await supabase.from('wb_send_queue').delete().eq('campaign_id', req.params.id);
  await supabase.from('wb_campaign_logs').delete().eq('campaign_id', req.params.id);
  const { error } = await supabase
    .from('wb_campaigns')
    .delete()
    .eq('id', req.params.id)
    .eq('user_id', req.user.id);
  if (error) return res.status(500).json({ error: error.message });
  res.json({ success: true, message: 'Campaign deleted' });
});

app.get('/api/campaigns/active', verifyUser, async (req, res) => {
  // Prefer whichever campaign is actually mid-flight. Ordering purely by
  // created_at could hand back a newer draft/scheduled campaign instead of
  // the one that's actually running, which left the Send tab pointed at the
  // wrong campaign (and stuck at 0/0/0/0) whenever more than one existed.
  const statusPriority = ['running', 'paused', 'queued', 'scheduled', 'draft'];
  const { data: candidates } = await supabase
    .from('wb_campaigns')
    .select('*')
    .eq('user_id', req.user.id)
    .in('status', statusPriority)
    .order('created_at', { ascending: false });

  if (candidates?.length) {
    candidates.sort((a, b) => statusPriority.indexOf(a.status) - statusPriority.indexOf(b.status));
    return res.json({ success: true, campaign: candidates[0] });
  }

  const { data: last } = await supabase
    .from('wb_campaigns')
    .select('*')
    .eq('user_id', req.user.id)
    .eq('status', 'completed')
    .order('completed_at', { ascending: false })
    .limit(1)
    .single();
  res.json({ success: true, campaign: last || null });
});

app.get('/api/campaigns/:id/status', verifyUser, async (req, res) => {
  const { data: campaign, error: campErr } = await supabase
    .from('wb_campaigns')
    .select('id, status, queue_total, queue_processed, queue_failed, sent_count, failed_count, total_contacts, user_id, schedule_at')
    .eq('id', req.params.id)
    .eq('user_id', req.user.id)
    .single();
  if (campErr || !campaign) return res.status(404).json({ error: 'Campaign not found' });

  const { count: pending } = await supabase
    .from('wb_send_queue')
    .select('*', { count: 'exact', head: true })
    .eq('campaign_id', req.params.id)
    .eq('status', 'pending');

  let gap_seconds = 0;
  let next_send_at = null;
  if (campaign.status === 'scheduled' && campaign.schedule_at) {
    next_send_at = campaign.schedule_at;
    const scheduledMs = new Date(campaign.schedule_at).getTime() - Date.now();
    gap_seconds = scheduledMs > 0 ? Math.ceil(scheduledMs / 1000) : 0;
  } else if (campaign.status === 'running' && campaign.sent_count > 0) {
    const { data: settings } = await supabase
      .from('wb_settings')
      .select('max_gap')
      .eq('user_id', req.user.id)
      .single();
    const maxGap = settings?.max_gap || 15;
    const { data: lastSent } = await supabase
      .from('wb_send_queue')
      .select('sent_at')
      .eq('campaign_id', req.params.id)
      .eq('status', 'sent')
      .order('sent_at', { ascending: false })
      .limit(1)
      .single();
    if (lastSent?.sent_at) {
      const secondsSinceLast = (Date.now() - new Date(lastSent.sent_at).getTime()) / 1000;
      if (secondsSinceLast < maxGap) {
        gap_seconds = Math.max(0, Math.ceil(maxGap - secondsSinceLast));
        next_send_at = new Date(Date.now() + gap_seconds * 1000).toISOString();
      }
    }
  }

  res.json({
    success: true, status: campaign.status,
    total: campaign.queue_total || campaign.total_contacts || 0,
    sent: campaign.queue_processed || campaign.sent_count || 0,
    failed: campaign.queue_failed || campaign.failed_count || 0,
    pending: pending || 0, gap_seconds, next_send_at
  });
});

app.get('/api/campaigns/:id/logs', verifyUser, async (req, res) => {
  const { data, error } = await supabase
    .from('wb_send_queue')
    .select('phone, contact_name, status, wa_message_id, error_reason, created_at, delivery_status')
    .eq('campaign_id', req.params.id)
    .eq('user_id', req.user.id)
    .order('created_at', { ascending: true });
  if (error) return res.status(500).json({ error: error.message });
  
  // Enrich with delivery status from logs table
  const logs = data || [];
  for (const log of logs) {
    if (log.wa_message_id) {
      const { data: deliveryLog } = await supabase
        .from('wb_campaign_logs')
        .select('delivery_status, error_reason, delivered_at, read_at')
        .eq('wa_message_id', log.wa_message_id)
        .single();
      if (deliveryLog) {
        log.delivery_status = deliveryLog.delivery_status || log.delivery_status || log.status;
        if (deliveryLog.error_reason) log.error_reason = deliveryLog.error_reason;
      }
    } else if (!log.delivery_status) {
      log.delivery_status = log.status;
    }
  }
  res.json({ success: true, logs });
});

// ================================================================
// 10b. RECEIVED MESSAGES (inbound, via /webhook)
// ================================================================
app.get('/api/messages/received', verifyUser, async (req, res) => {
  const limit = Math.min(parseInt(req.query.limit, 10) || 100, 500);
  const { data, error } = await supabase
    .from('wb_inbound_messages')
    .select('*')
    .eq('user_id', req.user.id)
    .order('created_at', { ascending: false })
    .limit(limit);
  if (error) return res.status(500).json({ error: error.message });

  const { count: unread } = await supabase
    .from('wb_inbound_messages')
    .select('*', { count: 'exact', head: true })
    .eq('user_id', req.user.id)
    .eq('is_read', false);

  res.json({ success: true, messages: data || [], unread: unread || 0 });
});

app.post('/api/messages/received/mark-read', verifyUser, async (req, res) => {
  const { error } = await supabase
    .from('wb_inbound_messages')
    .update({ is_read: true })
    .eq('user_id', req.user.id)
    .eq('is_read', false);
  if (error) return res.status(500).json({ error: error.message });
  res.json({ success: true });
});

// ================================================================
// 11. WA ACCOUNTS ROUTES
// ================================================================
app.get('/api/wa/accounts', verifyUser, async (req, res) => {
  const { data, error } = await supabase
    .from('wa_accounts')
    .select('id, waba_id, phone_number_id, phone_number, display_name, quality_rating, is_active, created_at')
    .eq('user_id', req.user.id)
    .order('created_at', { ascending: false });
  if (error) return res.status(500).json({ error: error.message });
  res.json({ success: true, accounts: data || [] });
});

app.delete('/api/wa/accounts/:id', verifyUser, async (req, res) => {
  const { error } = await supabase
    .from('wa_accounts')
    .update({ is_active: false, updated_at: new Date().toISOString() })
    .eq('id', req.params.id)
    .eq('user_id', req.user.id);
  if (error) return res.status(500).json({ error: error.message });
  res.json({ success: true, message: 'Number disconnected' });
});

app.post('/api/wa/manual/verify', async (req, res) => {
  const { waba_id, access_token } = req.body;
  if (!waba_id || !access_token) return res.status(400).json({ error: 'waba_id and access_token required' });
  try {
    const phoneRes = await fetch(
      `https://graph.facebook.com/${META_API_VERSION}/${waba_id}/phone_numbers?fields=id,display_phone_number,verified_name,quality_rating,code_verification_status`,
      { headers: { 'Authorization': `Bearer ${access_token}` } }
    );
    const phoneData = await phoneRes.json();
    if (phoneData.error) return res.status(400).json({ error: phoneData.error.message });
    const numbers = (phoneData.data || []).map(p => ({
      phone_number_id: p.id, phone_number: p.display_phone_number,
      display_name: p.verified_name, quality_rating: p.quality_rating || 'UNKNOWN',
      verified: p.code_verification_status === 'VERIFIED'
    }));
    if (!numbers.length) return res.status(400).json({ error: 'No phone numbers found under this WABA.' });
    res.json({ success: true, numbers });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/wa/manual/save', verifyUser, async (req, res) => {
  const { waba_id, phone_number_id, access_token } = req.body;
  if (!waba_id || !phone_number_id || !access_token) return res.status(400).json({ error: 'Missing required fields' });
  try {
    // Fetch phone details
    const phoneRes = await fetch(
      `https://graph.facebook.com/${META_API_VERSION}/${phone_number_id}?fields=display_phone_number,verified_name,quality_rating`,
      { headers: { 'Authorization': `Bearer ${access_token}` } }
    );
    const phoneData = await phoneRes.json();
    if (phoneData.error) return res.status(400).json({ error: phoneData.error.message });

    // Subscribe to webhooks
    const subRes = await fetch(
      `https://graph.facebook.com/${META_API_VERSION}/${waba_id}/subscribed_apps`,
      { method: 'POST', headers: { 'Authorization': `Bearer ${access_token}` } }
    );
    const subData = await subRes.json();

    // Encrypt token
    const encryptedToken = encryptToken(access_token);

    // Insert new account
    const { data: inserted, error: insertErr } = await supabase
      .from('wa_accounts')
      .insert({
        user_id: req.user.id, waba_id, phone_number_id,
        phone_number: phoneData.display_phone_number,
        display_name: phoneData.verified_name,
        access_token: encryptedToken,
        quality_rating: phoneData.quality_rating || 'GREEN',
        is_active: true, messages_sent_today: 0,
        last_reset_date: new Date().toISOString().split('T')[0],
        created_at: new Date().toISOString(), updated_at: new Date().toISOString()
      })
      .select('id')
      .single();
    if (insertErr) return res.status(500).json({ error: 'Failed to save account' });

    res.json({
      success: true, account_id: inserted.id,
      phone_number: phoneData.display_phone_number,
      display_name: phoneData.verified_name,
      webhook_subscribed: !subData.error
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ================================================================
// 12. EXTERNAL API (n8n / Zapier)
// ================================================================
app.post('/api/external/send', verifyUser, async (req, res) => {
  const { phone_number_id, to, template_name, language_code } = req.body;
  if (!phone_number_id || !to || !template_name) {
    return res.status(400).json({ error: 'phone_number_id, to, and template_name required' });
  }
  try {
    const { data: acc } = await supabase
      .from('wa_accounts')
      .select('access_token')
      .eq('phone_number_id', phone_number_id)
      .eq('user_id', req.user.id)
      .eq('is_active', true)
      .single();
    if (!acc) return res.status(404).json({ error: 'Phone number not found or inactive' });

    const plainToken = decryptToken(acc.access_token);
    const metaRes = await fetch(
      `https://graph.facebook.com/${META_API_VERSION}/${phone_number_id}/messages`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${plainToken}` },
        body: JSON.stringify({
          messaging_product: 'whatsapp', to,
          type: 'template',
          template: { name: template_name, language: { code: language_code || 'en_US' } }
        })
      }
    );
    const data = await metaRes.json();
    if (metaRes.ok) res.json({ success: true, message_id: data.messages?.[0]?.id });
    else res.status(metaRes.status).json({ error: data.error?.message || 'Meta API error' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ================================================================
// 13. META WEBHOOKS
// ================================================================
app.get('/webhook', (req, res) => {
  const mode = req.query['hub.mode'];
  const token = req.query['hub.verify_token'];
  const challenge = req.query['hub.challenge'];
  if (mode === 'subscribe' && token === process.env.META_WEBHOOK_VERIFY_TOKEN) {
    return res.status(200).send(challenge);
  }
  res.sendStatus(403);
});

app.post('/webhook', async (req, res) => {
  res.sendStatus(200); // Must respond immediately

  // Verify signature
  const sigHeader = req.headers['x-hub-signature-256'] || '';
  if (sigHeader && process.env.META_APP_SECRET) {
    const expected = 'sha256=' + crypto.createHmac('sha256', process.env.META_APP_SECRET).update(req.rawBody).digest('hex');
    try {
      if (!crypto.timingSafeEqual(Buffer.from(sigHeader), Buffer.from(expected))) {
        console.warn('[webhook] signature verification FAILED');
        return;
      }
    } catch (_) { return; }
  }

  const body = req.body;
  if (body.object !== 'whatsapp_business_account') return;

  for (const entry of (body.entry || [])) {
    for (const change of (entry.changes || [])) {
      const field = change.field;
      const value = change.value;

      if (field === 'messages') {
        // Incoming messages from customers (trigger auto-reply if enabled)
        for (const msg of (value?.messages || [])) {
          handleIncomingMessage(value, msg).catch((err) => {
            console.error('[webhook] auto-reply error:', err.message);
          });
        }

        // Delivery statuses
        for (const status of (value?.statuses || [])) {
          if (status.id) {
            const updateData = { delivery_status: status.status };
            if (status.status === 'delivered') updateData.delivered_at = new Date().toISOString();
            if (status.status === 'read') updateData.read_at = new Date().toISOString();
            if (status.errors?.[0]?.title) updateData.error_reason = status.errors[0].title;

            await supabase
              .from('wb_campaign_logs')
              .upsert({
                wa_message_id: status.id, ...updateData,
                updated_at: new Date().toISOString()
              }, { onConflict: 'wa_message_id' });
          }
        }
      } else if (field === 'message_template_status_update') {
        const newStatus = value.event === 'APPROVED' ? 'APPROVED' 
                        : value.event === 'REJECTED' ? 'REJECTED' 
                        : 'PENDING';
        await supabase
          .from('wb_templates')
          .update({ 
            status: newStatus, 
            meta_error: value.reason || null,
            updated_at: new Date().toISOString() 
          })
          .or(`meta_template_id.eq.${value.message_template_id || 'null'},name.eq.${value.message_template_name || 'null'}`);
      }
    }
  }
});

// Pulls a readable preview + type out of any inbound WhatsApp message payload,
// not just text (images, documents, locations, buttons, etc. all show up in
// the Received tab, they just don't trigger the AI auto-reply).
function extractMessagePreview(msg) {
  switch (msg.type) {
    case 'text':
      return { message_type: 'text', message_body: msg.text?.body || '' };
    case 'image':
      return { message_type: 'image', message_body: msg.image?.caption || '📷 Image' };
    case 'video':
      return { message_type: 'video', message_body: msg.video?.caption || '🎥 Video' };
    case 'audio':
      return { message_type: 'audio', message_body: '🎵 Audio message' };
    case 'document':
      return { message_type: 'document', message_body: msg.document?.filename || '📄 Document' };
    case 'sticker':
      return { message_type: 'sticker', message_body: '🩹 Sticker' };
    case 'location':
      return { message_type: 'location', message_body: `📍 Location (${msg.location?.latitude}, ${msg.location?.longitude})` };
    case 'button':
      return { message_type: 'button', message_body: msg.button?.text || 'Button reply' };
    case 'interactive':
      return {
        message_type: 'interactive',
        message_body: msg.interactive?.button_reply?.title || msg.interactive?.list_reply?.title || 'Interactive reply'
      };
    default:
      return { message_type: msg.type || 'unknown', message_body: `[${msg.type || 'unsupported'} message]` };
  }
}

// Handles a single incoming WhatsApp message: logs it (all types, so it shows
// up in the Received tab) and, for plain text only, checks the account's
// auto-reply setting, asks the configured AI model for a reply, and sends it back.
async function handleIncomingMessage(value, msg) {
  const phoneNumberId = value?.metadata?.phone_number_id;
  if (!phoneNumberId) return;

  const { data: waAccount } = await supabase
    .from('wa_accounts')
    .select('*')
    .eq('phone_number_id', phoneNumberId)
    .eq('is_active', true)
    .single();
  if (!waAccount) return;

  // Try to match the sender to a saved contact so the Received tab can show a name.
  let contactName = '';
  try {
    const { data: contact } = await supabase
      .from('wb_contacts')
      .select('name')
      .eq('user_id', waAccount.user_id)
      .eq('phone', msg.from)
      .single();
    if (contact?.name) contactName = contact.name;
  } catch (_) { /* no matching contact, that's fine */ }

  const { message_type, message_body } = extractMessagePreview(msg);

  // Store the inbound message so it shows up in the Received tab.
  try {
    await supabase.from('wb_inbound_messages').insert({
      user_id: waAccount.user_id,
      wa_account_id: waAccount.id,
      phone: msg.from,
      contact_name: contactName,
      message_type,
      message_body,
      wa_message_id: msg.id || null,
      created_at: new Date().toISOString()
    });
  } catch (e) {
    console.error('[webhook] failed to store inbound message:', e.message);
  }

  // Only plain text messages trigger the AI auto-reply.
  if (msg.type !== 'text' || !msg.text?.body) return;

  const { data: settings } = await supabase
    .from('wb_settings')
    .select('auto_reply, auto_reply_prompt, auto_reply_model')
    .eq('user_id', waAccount.user_id)
    .single();
  if (!settings?.auto_reply) return;

  let replyText;
  try {
    replyText = await generateReply({
      model: settings.auto_reply_model || DEFAULT_AI_MODEL,
      systemPrompt: settings.auto_reply_prompt || 'You are a helpful business assistant.',
      userText: msg.text.body,
    });
  } catch (err) {
    console.error('[webhook] AI generation failed:', err.message);
    return;
  }
  if (!replyText) return;

  try {
    const plainToken = decryptToken(waAccount.access_token);
    await fetch(
      `https://graph.facebook.com/${META_API_VERSION}/${waAccount.phone_number_id}/messages`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${plainToken}` },
        body: JSON.stringify({
          messaging_product: 'whatsapp',
          to: msg.from,
          type: 'text',
          text: { body: replyText },
        }),
      }
    );
  } catch (err) {
    console.error('[webhook] failed to send auto-reply:', err.message);
  }
}

// ================================================================
// 14. QUEUE PROCESSOR (Native — runs every 3 seconds)
// ================================================================
async function processQueue() {
  try {
    const nowIso = new Date().toISOString();
    const { data: dueCampaigns } = await supabase
      .from('wb_campaigns')
      .select('id, user_id')
      .eq('status', 'scheduled')
      .lte('schedule_at', nowIso);

    if (dueCampaigns?.length) {
      for (const item of dueCampaigns) {
        const { data: active } = await supabase
          .from('wb_campaigns')
          .select('id')
          .eq('user_id', item.user_id)
          .in('status', ['queued', 'running', 'paused'])
          .limit(1)
          .single();
        if (!active) {
          await supabase
            .from('wb_campaigns')
            .update({ status: 'running', updated_at: nowIso })
            .eq('id', item.id);
        }
      }
    }

    const { data: runningCampaigns } = await supabase
      .from('wb_campaigns')
      .select('id, user_id')
      .eq('status', 'running');

    if (!runningCampaigns?.length) {
      const { data: queuedCampaigns } = await supabase
        .from('wb_campaigns')
        .select('id, user_id')
        .eq('status', 'queued')
        .order('created_at', { ascending: true });

      if (queuedCampaigns?.length) {
        for (const item of queuedCampaigns) {
          const { data: active } = await supabase
            .from('wb_campaigns')
            .select('id')
            .eq('user_id', item.user_id)
            .in('status', ['running', 'paused'])
            .limit(1)
            .single();
          if (!active) {
            await supabase
              .from('wb_campaigns')
              .update({ status: 'running', updated_at: nowIso })
              .eq('id', item.id);
            runningCampaigns.push(item);
            break;
          }
        }
      }
    }

    if (!runningCampaigns?.length) return { processed: 0 };

    const runningIds = runningCampaigns.map(c => c.id);

    // Get one pending queue item
    const { data: pending } = await supabase
      .from('wb_send_queue')
      .select('*')
      .eq('status', 'pending')
      .in('campaign_id', runningIds)
      .order('created_at', { ascending: true })
      .limit(1);
    if (!pending?.length) return { processed: 0 };

    const queueItem = pending[0];

    // Load user settings for gap
    const { data: settings } = await supabase
      .from('wb_settings')
      .select('min_gap, max_gap')
      .eq('user_id', queueItem.user_id)
      .single();
    const minGap = settings?.min_gap || 5;
    const maxGap = settings?.max_gap || 15;
    const randomGap = minGap + Math.random() * (maxGap - minGap);

    // Check last sent time
    const { data: lastSent } = await supabase
      .from('wb_send_queue')
      .select('sent_at')
      .eq('campaign_id', queueItem.campaign_id)
      .eq('status', 'sent')
      .order('sent_at', { ascending: false })
      .limit(1)
      .single();

    if (lastSent?.sent_at) {
      const secondsSinceLast = (Date.now() - new Date(lastSent.sent_at).getTime()) / 1000;
      if (secondsSinceLast < randomGap) {
        return { processed: 0, action: 'gap_wait', wait_seconds: Math.ceil(randomGap - secondsSinceLast) };
      }
    }

    // Get WA account
    const { data: waAccounts } = await supabase
      .from('wa_accounts')
      .select('*')
      .eq('user_id', queueItem.user_id)
      .eq('is_active', true)
      .order('created_at', { ascending: false })
      .limit(1);
    
    if (!waAccounts?.length) {
      await supabase
        .from('wb_send_queue')
        .update({ status: 'failed', error_reason: 'No WhatsApp account connected', processed_at: new Date().toISOString() })
        .eq('id', queueItem.id);
      await updateCampaignProgress(queueItem.campaign_id, false);
      return { processed: 1, failed: 1 };
    }

    const waAccount = waAccounts[0];

    // Mark as processing
    await supabase
      .from('wb_send_queue')
      .update({ status: 'processing', processed_at: new Date().toISOString() })
      .eq('id', queueItem.id);

    // Fetch campaign placeholder mapping for this queue item
    const { data: campaignData } = await supabase
      .from('wb_campaigns')
      .select('placeholder_mapping')
      .eq('id', queueItem.campaign_id)
      .single();

    let templatePayload = { name: queueItem.template_name, language: { code: queueItem.template_language || 'en_US' } };
    if (campaignData?.placeholder_mapping && typeof campaignData.placeholder_mapping === 'object') {
      const params = Object.keys(campaignData.placeholder_mapping)
        .map(key => ({ position: parseInt(key, 10), mapping: campaignData.placeholder_mapping[key] }))
        .filter(item => item.position > 0)
        .sort((a, b) => a.position - b.position)
        .map(item => {
          const map = item.mapping;
          let value = '';
          if (map.type === 'phone') value = queueItem.phone || '';
          else if (map.type === 'name') value = queueItem.contact_name || '';
          else if (map.type === 'custom') value = map.value || '';
          return { type: 'text', text: value };
        });
      if (params.length) {
        templatePayload.components = [ { type: 'BODY', parameters: params } ];
      }
    }

    const payload = {
      messaging_product: 'whatsapp',
      to: queueItem.phone,
      type: 'template',
      template: templatePayload
    };

    let sendSuccess = false;
    let waMessageId = null;
    let errorMsg = null;

    try {
      const plainToken = decryptToken(waAccount.access_token);
      const result = await fetch(
        `https://graph.facebook.com/${META_API_VERSION}/${waAccount.phone_number_id}/messages`,
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${plainToken}` },
          body: JSON.stringify(payload)
        }
      );
      const responseData = await result.json();
      if (result.ok && responseData.messages?.[0]?.id) {
        waMessageId = responseData.messages[0].id;
        sendSuccess = true;
      } else {
        errorMsg = responseData.error?.message || `Meta API ${result.status}`;
      }
    } catch (err) {
      errorMsg = err.message;
    }

    // Update queue item
    await supabase
      .from('wb_send_queue')
      .update({
        status: sendSuccess ? 'sent' : 'failed',
        wa_message_id: waMessageId,
        error_reason: errorMsg,
        sent_at: sendSuccess ? new Date().toISOString() : null,
        attempt_count: (queueItem.attempt_count || 0) + 1
      })
      .eq('id', queueItem.id);

    // Insert log entry if sent
    if (sendSuccess && waMessageId) {
      await supabase
        .from('wb_campaign_logs')
        .upsert({
          campaign_id: queueItem.campaign_id,
          queue_id: queueItem.id,
          wa_message_id: waMessageId,
          delivery_status: 'sent',
          created_at: new Date().toISOString()
        }, { onConflict: 'wa_message_id' });
    }

    await updateCampaignProgress(queueItem.campaign_id, sendSuccess);
    return { processed: 1, sent: sendSuccess ? 1 : 0, failed: sendSuccess ? 0 : 1, phone: queueItem.phone };
  } catch (err) {
    console.error('[queue] processor error:', err.message);
    return { processed: 0, error: err.message };
  }
}

async function updateCampaignProgress(campaignId, sendSuccess) {
  const { data: campaign } = await supabase
    .from('wb_campaigns')
    .select('queue_processed, queue_failed, queue_total, status')
    .eq('id', campaignId)
    .single();
  if (!campaign || campaign.status === 'paused') return;

  const newProcessed = (campaign.queue_processed || 0) + (sendSuccess ? 1 : 0);
  const newFailed = (campaign.queue_failed || 0) + (sendSuccess ? 0 : 1);
  const newStatus = (newProcessed + newFailed) >= campaign.queue_total ? 'completed' : campaign.status;

  await supabase
    .from('wb_campaigns')
    .update({
      queue_processed: newProcessed,
      queue_failed: newFailed,
      status: newStatus,
      sent_count: newProcessed,
      failed_count: newFailed,
      completed_at: newStatus === 'completed' ? new Date().toISOString() : null,
      updated_at: new Date().toISOString()
    })
    .eq('id', campaignId);
}

// ================================================================
// 15. AI CHAT ROUTES (NVIDIA API)
// ================================================================
app.use('/api/ai', aiChatRouter);

// ================================================================
// 16. START SERVER
// ================================================================
app.listen(PORT, () => {
  console.log(`✅ WaBlast server running on ${SELF_URL}`);
  console.log(`   PORT: ${PORT}`);
  console.log(`   ENV: ${process.env.NODE_ENV || 'development'}`);
  console.log(`   DB: Supabase REST API (no pg driver)`);

  // Native Queue Processor — runs every 3 seconds
  let processorBusy = false;
  setTimeout(() => {
    setInterval(async () => {
      if (processorBusy) return;
      processorBusy = true;
      try {
        const data = await processQueue();
        if (data?.processed > 0) {
          console.log('[queue] processed:', { sent: data.sent, failed: data.failed, phone: data.phone });
        }
      } catch (err) {
        console.error('[queue] processor error:', err.message);
      } finally {
        processorBusy = false;
      }
    }, 3000);
  }, 5000);

  // Health check ping (every 14 min to keep Render awake)
  setInterval(async () => {
    try {
      await fetch(`${SELF_URL}/health`);
      console.log('[health] ping sent');
    } catch (_) {}
  }, 14 * 60 * 1000);
});
