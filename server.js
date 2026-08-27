import express from 'express';
import path from 'path';
import fs from 'fs';
import crypto from 'crypto';
import { fileURLToPath } from 'url';
import dotenv from 'dotenv';
import { JWT } from 'google-auth-library';

dotenv.config();

// Also parse .env.example if variables are not set in process.env or if process.env has invalid/short value
function getEnvFallback(key) {
  const envVal = process.env[key];
  if (key === 'GOOGLE_PRIVATE_KEY') {
    if (envVal && !envVal.startsWith('GOCSPX-') && (envVal.includes('BEGIN') || envVal.length > 200)) {
      return envVal;
    }
  } else if (envVal && envVal.trim() && !envVal.startsWith('GOCSPX-')) {
    return envVal;
  }

  try {
    if (fs.existsSync('.env.example')) {
      const content = fs.readFileSync('.env.example', 'utf8');
      const match = content.match(new RegExp(`^${key}=(.*)$`, 'm'));
      if (match && match[1] && match[1].trim()) {
        return match[1].trim();
      }
    }
  } catch {}

  return envVal || '';
}

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = 3000;

app.use(express.json());
app.use(express.static(__dirname));

// CORS headers
app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
  res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization, Cf-Access-Jwt-Assertion');
  if (req.method === 'OPTIONS') {
    return res.sendStatus(200);
  }
  next();
});

// Allowed user emails for authorization
const DEFAULT_ALLOWED_EMAILS = [
  'layymer@gmail.com',
  'murzlik0407@gmail.com'
];

function getAllowedEmails() {
  if (process.env.ALLOWED_EMAILS) {
    return process.env.ALLOWED_EMAILS.split(',').map(e => e.trim().toLowerCase());
  }
  return DEFAULT_ALLOWED_EMAILS.map(e => e.toLowerCase());
}

async function verifyGoogleToken(idToken) {
  if (!idToken) return null;
  try {
    const res = await fetch(`https://oauth2.googleapis.com/tokeninfo?id_token=${idToken}`);
    if (!res.ok) return null;
    const data = await res.json();
    return data.email;
  } catch (err) {
    console.error('Error verifying Google Token:', err);
    return null;
  }
}

function normalizePemKey(raw) {
  if (!raw) return '';
  let str = String(raw).trim();

  // If OAuth client secret was supplied
  if (str.startsWith('GOCSPX-')) {
    throw new Error('GOOGLE_PRIVATE_KEY contains an OAuth Client Secret (GOCSPX-...) instead of a Google Service Account Private Key (-----BEGIN PRIVATE KEY-----). Please provide the Service Account private key.');
  }

  // If JSON object
  if (str.startsWith('{') && str.endsWith('}')) {
    try {
      const parsed = JSON.parse(str);
      if (parsed.private_key) str = parsed.private_key;
    } catch {}
  }

  // Remove surrounding quotes if double-quoted in env
  str = str.replace(/^["']|["']$/g, '').trim();

  // Replace literal '\n', '\r', '\\n', etc. with real newlines
  str = str.replace(/\\r\\n/g, '\n').replace(/\\n/g, '\n').replace(/\\r/g, '\n').replace(/\r\n/g, '\n').replace(/\r/g, '\n');

  // Extract base64 payload
  let base64 = str;
  const match = str.match(/-----BEGIN[^-]+-----([\s\S]*?)-----END[^-]+-----/);
  if (match) {
    base64 = match[1];
  } else {
    base64 = base64.replace(/-----BEGIN[^-]*-----?/g, '').replace(/-----END[^-]*-----?/g, '');
  }

  // Strip ALL non-base64 characters (spaces, linebreaks, tabs, quotes)
  base64 = base64.replace(/[^A-Za-z0-9+/=]/g, '');

  if (!base64 || base64.length < 100) {
    throw new Error(`GOOGLE_PRIVATE_KEY is invalid or too short (${base64.length} chars). A valid RSA private key is typically >1000 base64 characters.`);
  }

  // Format into 64-char lines as required by OpenSSL PEM decoder
  const chunks = base64.match(/.{1,64}/g) || [base64];
  const pem = `-----BEGIN PRIVATE KEY-----\n${chunks.join('\n')}\n-----END PRIVATE KEY-----\n`;

  // Verify that OpenSSL can decode this PEM key
  try {
    crypto.createPrivateKey({ key: pem, format: 'pem' });
  } catch (err) {
    throw new Error(`OpenSSL failed to parse GOOGLE_PRIVATE_KEY: ${err.message}. Please ensure the entire private key starting from '-----BEGIN PRIVATE KEY-----' to '-----END PRIVATE KEY-----' is provided.`);
  }

  return pem;
}

function extractServiceAccountCredentials() {
  let clientEmail = getEnvFallback('GOOGLE_CLIENT_EMAIL');
  let privateKey = getEnvFallback('GOOGLE_PRIVATE_KEY');

  // Check if privateKey or clientEmail is base64 encoded JSON
  for (const candidate of [privateKey, clientEmail]) {
    if (candidate && !candidate.includes('{') && (candidate.startsWith('ey') || candidate.startsWith('eyJ'))) {
      try {
        const decoded = Buffer.from(candidate, 'base64').toString('utf8');
        if (decoded.trim().startsWith('{')) {
          const json = JSON.parse(decoded);
          if (json.client_email) clientEmail = json.client_email;
          if (json.private_key) privateKey = json.private_key;
        }
      } catch {}
    }
  }

  // Check if whole JSON was pasted in GOOGLE_PRIVATE_KEY or GOOGLE_CLIENT_EMAIL
  for (const candidate of [privateKey, clientEmail]) {
    if (candidate && candidate.trim().startsWith('{')) {
      try {
        const json = JSON.parse(candidate.trim());
        if (json.client_email) clientEmail = json.client_email;
        if (json.private_key) privateKey = json.private_key;
      } catch {}
    }
  }

  return {
    clientEmail: String(clientEmail).trim(),
    privateKey: normalizePemKey(privateKey)
  };
}

let jwtClient = null;

async function getGoogleAuthToken() {
  const { clientEmail, privateKey } = extractServiceAccountCredentials();

  if (!clientEmail || !privateKey) {
    throw new Error('GOOGLE_CLIENT_EMAIL and GOOGLE_PRIVATE_KEY must be configured in environment variables');
  }

  if (!jwtClient || jwtClient.email !== clientEmail) {
    jwtClient = new JWT({
      email: clientEmail,
      key: privateKey,
      scopes: ['https://www.googleapis.com/auth/spreadsheets'],
    });
  }

  const tokenResponse = await jwtClient.getAccessToken();
  const token = typeof tokenResponse === 'string' ? tokenResponse : tokenResponse.token;
  if (!token) {
    throw new Error('Failed to acquire access token from Google Auth Library');
  }
  return token;
}

const parseCoord = (val) => {
  if (val === null || val === undefined || val === '') return null;
  const num = parseFloat(String(val).replace(',', '.'));
  return isNaN(num) ? null : num;
};

const buildRowArray = (body) => [
  body.uid || `TRD-${Date.now()}`,
  body.name || '',
  body.entityName || '',
  body.entityId || '',
  body.activityType || 'Роздрібна торгівля',
  body.type || 'Магазин',
  body.openingHours || '',
  (body.availabilityRestriction !== undefined && body.availabilityRestriction !== null && String(body.availabilityRestriction).trim() !== '') ? String(body.availabilityRestriction).trim() : '',
  body.CATUTTC || 'UA53020110010112104',
  body.addressPostCode || '39600',
  'Україна',
  'Полтавська область',
  'Кременчуцький район',
  body.addressAdminUnitL4 || 'Кременчуцька',
  body.addressPostName || 'Кременчук',
  body.addressThoroughfare || '',
  body.addressLocatorDesignator || '',
  body.addressLocatorBuilding || '',
  body.addressDescription || '',
  (body.lat !== null && body.lat !== undefined && body.lat !== '') ? Number(body.lat) : '',
  (body.lon !== null && body.lon !== undefined && body.lon !== '') ? Number(body.lon) : '',
  body.authorityName || 'Виконавчий комітет Кременчуцької міської ради',
  body.authoritytId || '04057287',
  body.permissionNumber || '',
  body.permissionIssued || '',
  body.permissionStatus || 'чинний',
  body.permissionValidFrom || '',
  body.permissionValidThrough || ''
];

async function resolveSheetName(spreadsheetId, token, requestedName) {
  try {
    const metaRes = await fetch(
      `https://sheets.googleapis.com/v4/spreadsheets/${spreadsheetId}?fields=sheets.properties`,
      { headers: { Authorization: `Bearer ${token}` } }
    );
    if (metaRes.ok) {
      const metaData = await metaRes.json();
      const sheets = metaData.sheets || [];
      if (sheets.length > 0) {
        const titles = sheets.map(s => s.properties?.title).filter(Boolean);
        
        // Exact match
        if (requestedName && titles.includes(requestedName)) {
          return requestedName;
        }

        // Case-insensitive / trimmed match
        const found = titles.find(t => t.trim().toLowerCase() === (requestedName || '').trim().toLowerCase());
        if (found) return found;

        // Partial match containing requestedName
        const partial = titles.find(t => t.toLowerCase().includes((requestedName || 'tradepub').toLowerCase()));
        if (partial) return partial;

        // Fallback to the very first sheet in the document
        return titles[0];
      }
    }
  } catch (err) {
    console.warn('Could not fetch spreadsheet metadata:', err);
  }
  return requestedName || 'tradePUB';
}

// Helper to escape range for Google Sheets API
function formatRange(sheetName, range) {
  const safeTitle = sheetName.replace(/'/g, "''");
  return `'${safeTitle}'!${range}`;
}

// Backend API handler
async function handleApiRequest(req, res) {
  const authHeader = req.headers['authorization'] || '';
  const idToken = authHeader.replace(/^Bearer\s+/i, '');

  const userEmail = await verifyGoogleToken(idToken);
  const allowedEmails = getAllowedEmails();

  if (!userEmail || !allowedEmails.includes(userEmail.toLowerCase())) {
    return res.status(403).json({
      error: 'Access denied: Unauthorized identity',
      details: userEmail ? `Email ${userEmail} is not in allowed list` : 'Invalid or missing token'
    });
  }

  const spreadsheetId = getEnvFallback('SPREADSHEET_ID');
  const configuredSheetName = getEnvFallback('SHEET_NAME') || 'tradePUB';

  if (!spreadsheetId) {
    return res.status(400).json({
      error: 'SPREADSHEET_ID is not configured. Please specify the Google Spreadsheet ID in the Settings / environment variables.'
    });
  }

  try {
    const token = await getGoogleAuthToken();
    const sheetName = await resolveSheetName(spreadsheetId, token, configuredSheetName);

    if (req.method === 'GET') {
      const range = encodeURIComponent(formatRange(sheetName, 'A4:AB'));
      const response = await fetch(
        `https://sheets.googleapis.com/v4/spreadsheets/${spreadsheetId}/values/${range}`,
        { headers: { Authorization: `Bearer ${token}` } }
      );
      const data = await response.json();

      if (!response.ok) {
        return res.status(response.status).json({ error: `Google Sheets API Error: ${JSON.stringify(data)}` });
      }

      const items = (data.values || []).map((row, index) => ({
        rowIndex: index + 4,
        uid: row[0] || '',
        name: row[1] || '',
        entityName: row[2] || '',
        entityId: row[3] || '',
        activityType: row[4] || '',
        type: row[5] || '',
        openingHours: row[6] || '',
        availabilityRestriction: row[7] || '',
        CATUTTC: row[8] || '',
        addressPostCode: row[9] || '',
        addressAdminUnitL1: row[10] || 'Україна',
        addressAdminUnitL2: row[11] || 'Полтавська область',
        addressAdminUnitL3: row[12] || 'Кременчуцький район',
        addressAdminUnitL4: row[13] || '',
        addressPostName: row[14] || '',
        addressThoroughfare: row[15] || '',
        addressLocatorDesignator: row[16] || '',
        addressLocatorBuilding: row[17] || '',
        addressDescription: row[18] || '',
        lat: parseCoord(row[19]),
        lon: parseCoord(row[20]),
        authorityName: row[21] || '',
        authoritytId: row[22] || '',
        permissionNumber: row[23] || '',
        permissionIssued: row[24] || '',
        permissionStatus: row[25] || 'чинний',
        permissionValidFrom: row[26] || '',
        permissionValidThrough: row[27] || ''
      }));

      return res.json(items);
    }

    if (req.method === 'POST') {
      const body = req.body || {};
      const rangeA = encodeURIComponent(formatRange(sheetName, 'A:A'));
      const getRes = await fetch(
        `https://sheets.googleapis.com/v4/spreadsheets/${spreadsheetId}/values/${rangeA}`,
        { headers: { Authorization: `Bearer ${token}` } }
      );
      const getData = await getRes.json();
      const nextRowIndex = Math.max((getData.values || []).length + 1, 4);

      const newRow = buildRowArray(body);
      const targetRange = encodeURIComponent(formatRange(sheetName, `A${nextRowIndex}:AB${nextRowIndex}`));

      const gRes = await fetch(
        `https://sheets.googleapis.com/v4/spreadsheets/${spreadsheetId}/values/${targetRange}?valueInputOption=USER_ENTERED`,
        {
          method: 'PUT',
          headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
          body: JSON.stringify({ values: [newRow] })
        }
      );

      if (!gRes.ok) {
        const errData = await gRes.text();
        return res.status(gRes.status).json({ error: `Google API Error: ${errData}` });
      }

      return res.json({ status: 'success', rowIndex: nextRowIndex });
    }

    if (req.method === 'PUT') {
      const body = req.body || {};
      if (!body.rowIndex) {
        return res.status(400).json({ error: 'Missing rowIndex in payload' });
      }

      const updatedRow = buildRowArray(body);
      const targetRange = encodeURIComponent(formatRange(sheetName, `A${body.rowIndex}:AB${body.rowIndex}`));

      const gRes = await fetch(
        `https://sheets.googleapis.com/v4/spreadsheets/${spreadsheetId}/values/${targetRange}?valueInputOption=USER_ENTERED`,
        {
          method: 'PUT',
          headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
          body: JSON.stringify({ values: [updatedRow] })
        }
      );

      if (!gRes.ok) {
        const errData = await gRes.text();
        return res.status(gRes.status).json({ error: `Google API Error: ${errData}` });
      }

      return res.json({ status: 'updated' });
    }

    if (req.method === 'DELETE') {
      const rowIndex = req.query.rowIndex;

      if (!rowIndex) {
        return res.status(400).json({ error: 'Missing rowIndex query parameter' });
      }

      const targetRange = encodeURIComponent(formatRange(sheetName, `Z${rowIndex}`));
      const gRes = await fetch(
        `https://sheets.googleapis.com/v4/spreadsheets/${spreadsheetId}/values/${targetRange}?valueInputOption=USER_ENTERED`,
        {
          method: 'PUT',
          headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
          body: JSON.stringify({ values: [['скасований']] })
        }
      );

      if (!gRes.ok) {
        const errData = await gRes.text();
        return res.status(gRes.status).json({ error: `Google API Error: ${errData}` });
      }

      return res.json({ status: 'deleted' });
    }

    return res.status(405).json({ error: 'Method Not Allowed' });
  } catch (err) {
    console.error('API execution error:', err);
    return res.status(500).json({ error: err.toString() });
  }
}

// API Routes
app.all('/api', handleApiRequest);
app.all('/api/*', handleApiRequest);

// Serve frontend SPA
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

app.listen(PORT, '0.0.0.0', () => {
  console.log(`Server running on http://0.0.0.0:${PORT}`);
});

