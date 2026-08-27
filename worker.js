// Cloudflare Worker & Universal backend handler
// Works seamlessly in Cloudflare Workers and Node.js

function base64UrlEncode(strOrObj) {
  const json = typeof strOrObj === 'string' ? strOrObj : JSON.stringify(strOrObj);
  const b64 = btoa(unescape(encodeURIComponent(json)));
  return b64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function normalizePem(raw) {
  if (!raw) return '';
  let str = String(raw).trim();
  
  if (str.startsWith('{') && str.endsWith('}')) {
    try {
      const parsed = JSON.parse(str);
      if (parsed.private_key) str = parsed.private_key;
    } catch {}
  }

  str = str.replace(/^["']|["']$/g, '').trim();
  str = str.replace(/\\r\\n/g, '\n').replace(/\\n/g, '\n').replace(/\\r/g, '\n').replace(/\r\n/g, '\n');

  let base64 = str;
  const match = str.match(/-----BEGIN[^-]+-----([\s\S]*?)-----END[^-]+-----/);
  if (match) {
    base64 = match[1];
  } else {
    base64 = base64.replace(/-----BEGIN[^-]*-----?/g, '').replace(/-----END[^-]*-----?/g, '');
  }

  base64 = base64.replace(/[^A-Za-z0-9+/=]/g, '');
  const chunks = base64.match(/.{1,64}/g) || [base64];
  return `-----BEGIN PRIVATE KEY-----\n${chunks.join('\n')}\n-----END PRIVATE KEY-----\n`;
}

let cachedToken = null;
let tokenExpiresAt = 0;

async function getGoogleToken(clientEmail, privateKeyPem) {
  const now = Math.floor(Date.now() / 1000);
  if (cachedToken && tokenExpiresAt > now + 60) {
    return cachedToken;
  }

  const cleanPem = normalizePem(privateKeyPem);
  const pemHeader = "-----BEGIN PRIVATE KEY-----";
  const pemFooter = "-----END PRIVATE KEY-----";
  let pemContents = cleanPem;
  if (pemContents.includes(pemHeader)) {
    pemContents = pemContents.substring(
      pemContents.indexOf(pemHeader) + pemHeader.length,
      pemContents.indexOf(pemFooter)
    );
  }
  pemContents = pemContents.replace(/\s+/g, '');
  const binaryDer = Uint8Array.from(atob(pemContents), c => c.charCodeAt(0));

  const cryptoKey = await crypto.subtle.importKey(
    'pkcs8',
    binaryDer.buffer,
    { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
    false,
    ['sign']
  );

  const header = { alg: 'RS256', typ: 'JWT' };
  const claim = {
    iss: clientEmail,
    scope: 'https://www.googleapis.com/auth/spreadsheets',
    aud: 'https://oauth2.googleapis.com/token',
    exp: now + 3600,
    iat: now
  };

  const unsignedToken = `${base64UrlEncode(header)}.${base64UrlEncode(claim)}`;
  const signature = await crypto.subtle.sign(
    'RSASSA-PKCS1-v1_5',
    cryptoKey,
    new TextEncoder().encode(unsignedToken)
  );

  const sigB64 = btoa(String.fromCharCode(...new Uint8Array(signature)))
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

  const signedJwt = `${unsignedToken}.${sigB64}`;

  const tokenRes = await fetch('https://oauth2.googleapis.com/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer',
      assertion: signedJwt
    })
  });

  if (!tokenRes.ok) {
    const errText = await tokenRes.text();
    throw new Error(`Google Auth API failed (${tokenRes.status}): ${errText}`);
  }

  const tokenData = await tokenRes.json();
  cachedToken = tokenData.access_token;
  tokenExpiresAt = now + (tokenData.expires_in || 3600);
  return cachedToken;
}

const parseCoord = (val) => {
  if (val === null || val === undefined || val === '') return null;
  const num = parseFloat(String(val).replace(',', '.'));
  return isNaN(num) ? null : num;
};

function formatRange(sheetName, range) {
  const safeTitle = sheetName.replace(/'/g, "''");
  return `'${safeTitle}'!${range}`;
}

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
        if (requestedName && titles.includes(requestedName)) return requestedName;
        const found = titles.find(t => t.trim().toLowerCase() === (requestedName || '').trim().toLowerCase());
        if (found) return found;
        const partial = titles.find(t => t.toLowerCase().includes((requestedName || 'commercial').toLowerCase()));
        if (partial) return partial;
        return titles[0];
      }
    }
  } catch (err) {
    console.warn('Could not fetch spreadsheet metadata:', err);
  }
  return requestedName || 'commercialObjects';
}

function buildRowArray(body) {
  return [
    body.uid || '',
    body.name || '',
    body.entityName || '',
    body.entityId || '',
    body.type || '',
    body.scheduleStandard || 'Пн-Пт 08:00-17:00',
    body.openingHours || '',
    body.availabilityRestriction || '',
    body.addressCountry || 'UA',
    body.addressRegion || 'Полтавська область',
    body.addressAdminUnit || 'Кременчуцький район',
    body.addressPostCode || '39600',
    body.addressSettlement || 'місто Кременчук',
    body.addressThoroughfare || '',
    body.addressLocatorDesignator || '',
    body.addressLocatorBuilding || '',
    body.addressDescription || '',
    parseCoord(body.lat) !== null ? parseCoord(body.lat) : '',
    parseCoord(body.lon) !== null ? parseCoord(body.lon) : '',
    body.authorityName || 'Виконавчий комітет Кременчуцької міської ради',
    body.authoritytId || '04057287',
    body.permissionNumber || '',
    body.permissionOrderDate || '',
    body.permissionStartDate || '',
    body.permissionExpirationDate || '',
    body.permissionStatus || 'чинний',
    body.permissionValidThrough || ''
  ];
}

const DEFAULT_ALLOWED_EMAILS = [
  'layymer@gmail.com',
  'murzlik0407@gmail.com',
  'kremsupp@gmail.com'
];

async function verifyGoogleToken(idToken) {
  if (!idToken) return null;
  try {
    const res = await fetch(`https://oauth2.googleapis.com/tokeninfo?id_token=${idToken}`);
    if (!res.ok) return null;
    const data = await res.json();
    return data.email;
  } catch {
    return null;
  }
}

function getWorkerVar(env, key, fallback = '') {
  if (env && typeof env[key] !== 'undefined' && env[key] !== null && String(env[key]).trim() !== '') {
    return String(env[key]).trim();
  }
  if (typeof globalThis !== 'undefined' && typeof globalThis[key] !== 'undefined' && globalThis[key] !== null && String(globalThis[key]).trim() !== '') {
    return String(globalThis[key]).trim();
  }
  if (typeof process !== 'undefined' && process.env && typeof process.env[key] !== 'undefined' && process.env[key] !== null && String(process.env[key]).trim() !== '') {
    return String(process.env[key]).trim();
  }
  return fallback;
}

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    // Handle CORS preflight
    if (request.method === 'OPTIONS') {
      return new Response(null, {
        headers: {
          'Access-Control-Allow-Origin': '*',
          'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
          'Access-Control-Allow-Headers': 'Content-Type, Authorization, Cf-Access-Jwt-Assertion'
        }
      });
    }

    // Serve static assets if not /api
    if (!url.pathname.startsWith('/api')) {
      if (env && env.ASSETS) {
        return env.ASSETS.fetch(request);
      }
      return new Response('Not found', { status: 404 });
    }

    const corsHeaders = {
      'Access-Control-Allow-Origin': '*',
      'Content-Type': 'application/json'
    };

    // User authentication verification
    const authHeader = request.headers.get('Authorization') || '';
    const idToken = authHeader.replace(/^Bearer\s+/i, '').trim();
    const cfEmail = request.headers.get('cf-access-authenticated-user-email');

    const allowedEnv = getWorkerVar(env, 'ALLOWED_EMAILS', '');
    const allowedEmails = allowedEnv
      ? allowedEnv.split(',').map(e => e.trim().toLowerCase())
      : DEFAULT_ALLOWED_EMAILS.map(e => e.toLowerCase());

    let userEmail = null;
    if (cfEmail && allowedEmails.includes(cfEmail.toLowerCase())) {
      userEmail = cfEmail.toLowerCase();
    } else if (idToken) {
      userEmail = await verifyGoogleToken(idToken);
    }

    if (!userEmail || !allowedEmails.includes(userEmail.toLowerCase())) {
      return new Response(JSON.stringify({
        error: 'Forbidden: Access restricted to authorized personnel',
        details: userEmail ? `Email ${userEmail} is not allowed` : 'Invalid or expired Google token. Please sign in.'
      }), {
        status: 403,
        headers: corsHeaders
      });
    }

    const spreadsheetId = getWorkerVar(env, 'SPREADSHEET_ID', '19v6n6TXVvfluJStp8i6rNDlF-ZIeMWguAhd9Q4TqWLQ');
    const configuredSheetName = getWorkerVar(env, 'SHEET_NAME', 'commercialObjects');
    const clientEmail = getWorkerVar(env, 'GOOGLE_CLIENT_EMAIL', 'commercialobjects@orbital-clarity-505815-u9.iam.gserviceaccount.com');
    const privateKey = getWorkerVar(env, 'GOOGLE_PRIVATE_KEY', '');

    const missing = [];
    if (!spreadsheetId) missing.push('SPREADSHEET_ID');
    if (!clientEmail) missing.push('GOOGLE_CLIENT_EMAIL');
    if (!privateKey) missing.push('GOOGLE_PRIVATE_KEY');

    if (missing.length > 0) {
      return new Response(JSON.stringify({
        error: `Server configuration incomplete: Missing [${missing.join(', ')}] in Cloudflare Worker environment. Please verify that GOOGLE_PRIVATE_KEY is saved in Cloudflare Dashboard -> Settings -> Variables and Secrets and that a new deployment was triggered.`
      }), {
        status: 500,
        headers: corsHeaders
      });
    }

    try {
      const token = await getGoogleToken(clientEmail, privateKey);
      const sheetName = await resolveSheetName(spreadsheetId, token, configuredSheetName);

      // GET - Fetch rows
      if (request.method === 'GET') {
        const range = encodeURIComponent(formatRange(sheetName, 'A4:AB'));
        const gRes = await fetch(
          `https://sheets.googleapis.com/v4/spreadsheets/${spreadsheetId}/values/${range}`,
          { headers: { Authorization: `Bearer ${token}` } }
        );

        if (!gRes.ok) {
          const errText = await gRes.text();
          return new Response(JSON.stringify({ error: `Google API Error: ${errText}` }), {
            status: gRes.status,
            headers: corsHeaders
          });
        }

        const data = await gRes.json();
        const rows = (data.values || []).map((row, index) => {
          return {
            rowIndex: index + 4,
            uid: row[0] || '',
            name: row[1] || '',
            entityName: row[2] || '',
            entityId: row[3] || '',
            type: row[4] || '',
            scheduleStandard: row[5] || '',
            openingHours: row[6] || '',
            availabilityRestriction: row[7] || '',
            addressCountry: row[8] || 'UA',
            addressRegion: row[9] || 'Полтавська область',
            addressAdminUnit: row[10] || 'Кременчуцький район',
            addressPostCode: row[11] || '39600',
            addressSettlement: row[12] || 'місто Кременчук',
            addressThoroughfare: row[13] || '',
            addressLocatorDesignator: row[14] || '',
            addressLocatorBuilding: row[15] || '',
            addressDescription: row[16] || '',
            lat: parseCoord(row[17]),
            lon: parseCoord(row[18]),
            authorityName: row[19] || '',
            authoritytId: row[20] || '',
            permissionNumber: row[21] || '',
            permissionOrderDate: row[22] || '',
            permissionStartDate: row[23] || '',
            permissionExpirationDate: row[24] || '',
            permissionStatus: row[25] || 'чинний',
            permissionValidThrough: row[26] || ''
          };
        }).filter(item => item.uid || item.name || item.entityName || item.lat || item.lon);

        return new Response(JSON.stringify(rows), {
          status: 200,
          headers: corsHeaders
        });
      }

      // POST - Insert new row
      if (request.method === 'POST') {
        const body = await request.json();
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
          const errText = await gRes.text();
          return new Response(JSON.stringify({ error: `Google API Error: ${errText}` }), {
            status: gRes.status,
            headers: corsHeaders
          });
        }

        return new Response(JSON.stringify({ status: 'success', rowIndex: nextRowIndex }), {
          status: 200,
          headers: corsHeaders
        });
      }

      // PUT - Update row
      if (request.method === 'PUT') {
        const body = await request.json();
        if (!body.rowIndex) {
          return new Response(JSON.stringify({ error: 'Missing rowIndex' }), {
            status: 400,
            headers: corsHeaders
          });
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
          const errText = await gRes.text();
          return new Response(JSON.stringify({ error: `Google API Error: ${errText}` }), {
            status: gRes.status,
            headers: corsHeaders
          });
        }

        return new Response(JSON.stringify({ status: 'updated' }), {
          status: 200,
          headers: corsHeaders
        });
      }

      // DELETE - Cancel permission
      if (request.method === 'DELETE') {
        const rowIndex = url.searchParams.get('rowIndex');
        if (!rowIndex) {
          return new Response(JSON.stringify({ error: 'Missing rowIndex query parameter' }), {
            status: 400,
            headers: corsHeaders
          });
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
          const errText = await gRes.text();
          return new Response(JSON.stringify({ error: `Google API Error: ${errText}` }), {
            status: gRes.status,
            headers: corsHeaders
          });
        }

        return new Response(JSON.stringify({ status: 'deleted' }), {
          status: 200,
          headers: corsHeaders
        });
      }

      return new Response(JSON.stringify({ error: 'Method Not Allowed' }), {
        status: 405,
        headers: corsHeaders
      });
    } catch (err) {
      console.error('Worker API error:', err);
      return new Response(JSON.stringify({ error: err.toString() }), {
        status: 500,
        headers: corsHeaders
      });
    }
  }
};
