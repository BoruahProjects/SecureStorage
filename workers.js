const ALLOWED_ORIGIN = 'https://cloud.domain.com';
const corsHeaders = {
  'Access-Control-Allow-Origin': ALLOWED_ORIGIN,
  'Access-Control-Allow-Methods': 'GET, POST, PATCH, DELETE, HEAD, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, X-File-Key',
  'Access-Control-Allow-Credentials': 'true',
};

const MAX_FILE_SIZE_BYTES = 100 * 1024 * 1024;
const MAX_MANIFEST_SIZE_BYTES = 2 * 1024 * 1024;
const BLOCKED_MIME_TYPES = [
    'text/html',
    'text/javascript',
    'application/javascript',
    'application/x-javascript',
    'image/svg+xml'
];
const TOKEN_EXPIRATION_SECONDS = 24 * 60 * 60;
const IDLE_SESSION_EXPIRATION_SECONDS = 60 * 60;

const MAX_USERNAME_LOGIN_ATTEMPTS = 3;
const USERNAME_LOGIN_ATTEMPT_WINDOW_SECONDS = 10 * 60;
const MAX_IP_LOGIN_ATTEMPTS = 3;
const IP_LOGIN_ATTEMPT_WINDOW_SECONDS = 10 * 60;

const IP_LOCKOUT_DURATIONS_SECONDS = [
    10 * 60,
    30 * 60,
    60 * 60,
    5 * 60 * 60,
    24 * 60 * 60,
    7 * 24 * 60 * 60,
    30 * 24 * 60 * 60,
    365 * 24 * 60 * 60
];

const FILE_MAGIC_BYTES = {
    'image/jpeg': [
        [0xFF, 0xD8, 0xFF, 0xE0],
        [0xFF, 0xD8, 0xFF, 0xE1],
        [0xFF, 0xD8, 0xFF, 0xE2],
        [0xFF, 0xD8, 0xFF, 0xE3],
    ],
    'image/png': [
        [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A],
    ],
    'image/gif': [
        [0x47, 0x49, 0x46, 0x38, 0x37, 0x61],
        [0x47, 0x49, 0x46, 0x38, 0x39, 0x61],
    ],
    'application/pdf': [
        [0x25, 0x50, 0x44, 0x46],
    ],
    'application/zip': [
        [0x50, 0x4B, 0x03, 0x04],
        [0x50, 0x4B, 0x05, 0x06],
        [0x50, 0x4B, 0x07, 0x08],
    ],
};

function startsWithBytes(buffer, pattern) {
    if (buffer.length < pattern.length) {
        return false;
    }
    for (let i = 0; i < pattern.length; i++) {
        if (buffer[i] !== pattern[i]) {
            return false;
        }
    }
    return true;
}

const BASE_PATH = '';

const E2E_META_PREFIX = '_e2e_meta/';
const E2E_SALT_KEY = `${E2E_META_PREFIX}salt`;
const E2E_MANIFEST_KEY = `${E2E_META_PREFIX}manifest.enc`;
const E2E_HINT_KEY = `${E2E_META_PREFIX}hint`;
const E2E_MANIFEST_KEY_STAGING = `${E2E_META_PREFIX}manifest.enc.staging`;
const E2E_VERSION_KEY = `${E2E_META_PREFIX}version`;

const SHARE_STORE_PREFIX = 'share_store:';
const SHARE_LOOKUP_PREFIX = 'share_lookup:';
const SHARE_FILE_MAP_PREFIX = 'share_file_map:';
const ALLOWED_FILE_KEY_REGEX = /^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/;
const ALLOWED_SHARE_ID_REGEX = /^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/;


async function hashString(text) {
    const textEncoder = new TextEncoder();
    const data = textEncoder.encode(text);
    const hashBuffer = await crypto.subtle.digest('SHA-256', data);
    if (!hashBuffer) {
        throw new Error("Hash buffer is null or undefined after digest operation.");
    }
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    const hexHash = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
    return hexHash;
}

function base64ToUint8(base64) {
    const binaryString = atob(base64);
    const len = binaryString.length;
    const bytes = new Uint8Array(len);
    for (let i = 0; i < len; i++) {
        bytes[i] = binaryString.charCodeAt(i);
    }
    return bytes;
}

function uint8ToBase64(bytes) {
    let binary = '';
    const len = bytes.byteLength;
    for (let i = 0; i < len; i++) {
        binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary);
}

async function encrypt(data, key, additionalData) {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const encoder = new TextEncoder();
    const encodedData = typeof data === 'string' ? encoder.encode(data) : data;

    const params = { name: 'AES-GCM', iv: iv };
    if (additionalData) {
        params.additionalData = additionalData;
    }

    const encryptedContent = await crypto.subtle.encrypt(params, key, encodedData);
    const encryptedBytes = new Uint8Array(encryptedContent);
    const result = new Uint8Array(iv.length + encryptedBytes.length);
    result.set(iv);
    result.set(encryptedBytes, iv.length);
    return result;
}

async function decrypt(encryptedData, key, additionalData) {
    const iv = encryptedData.slice(0, 12);
    const data = encryptedData.slice(12);

    const params = { name: 'AES-GCM', iv: iv };
    if (additionalData) {
        params.additionalData = additionalData;
    }

    return crypto.subtle.decrypt(params, key, data);
}

async function decryptText(encryptedData, key, additionalData) {
    try {
        const decryptedBuffer = await decrypt(encryptedData, key, additionalData);
        return new TextDecoder().decode(decryptedBuffer);
    } catch (e) {
        return null;
    }
}

function encodeBase64Url(str) {
    return btoa(str)
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=/g, '');
}

function encodeBase64UrlBytes(bytes) {
    return btoa(String.fromCharCode.apply(null, bytes))
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=/g, '');
}

function decodeBase64Url(str) {
    str = str.replace(/-/g, '+').replace(/_/g, '/');
    while (str.length % 4) {
      str += '=';
    }
    return atob(str);
}

async function computeHmac(data, secret) {
    const key = await crypto.subtle.importKey(
        'raw',
        new TextEncoder().encode(secret),
        { name: 'HMAC', hash: 'SHA-256' },
        false,
        ['sign']
    );
    const signature = await crypto.subtle.sign('HMAC', key, data);
    const hashArray = Array.from(new Uint8Array(signature));
    return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

async function signJwt(payload, privateKeyPem) {
    const header = { alg: 'ES256', typ: 'JWT' };
    const encodedHeader = encodeBase64Url(JSON.stringify(header));
    const encodedPayload = encodeBase64Url(JSON.stringify(payload));
    const data = `${encodedHeader}.${encodedPayload}`;

    const privateKey = await crypto.subtle.importKey(
        'pkcs8',
        pemToBuffer(privateKeyPem),
        { name: 'ECDSA', namedCurve: 'P-256' },
        true,
        ['sign']
    );

    const signature = await crypto.subtle.sign(
        { name: 'ECDSA', hash: { name: 'SHA-256' } },
        privateKey,
        new TextEncoder().encode(data)
    );

    const encodedSignature = encodeBase64UrlBytes(new Uint8Array(signature));
    return `${data}.${encodedSignature}`;
}

async function verifyJwt(token, publicKeyPem) {
    try {
        const [encodedHeader, encodedPayload, encodedSignature] = token.split('.');
        if (!encodedHeader || !encodedPayload || !encodedSignature) return null;

        const header = JSON.parse(decodeBase64Url(encodedHeader));
        if (header.alg !== 'ES256') {
            return null; 
        }

        const data = `${encodedHeader}.${encodedPayload}`;
        const signatureBytes = Uint8Array.from(decodeBase64Url(encodedSignature), c => c.charCodeAt(0));

        const publicKey = await crypto.subtle.importKey(
            'spki',
            pemToBuffer(publicKeyPem),
            { name: 'ECDSA', namedCurve: 'P-256' },
            true,
            ['verify']
        );

        const isValid = await crypto.subtle.verify(
            { name: 'ECDSA', hash: { name: 'SHA-256' } },
            publicKey,
            signatureBytes,
            new TextEncoder().encode(data)
        );

        if (!isValid) return null;

        const payload = JSON.parse(decodeBase64Url(encodedPayload));
        const now = Math.floor(Date.now() / 1000);
        if (payload.exp < now || (payload.nbf && payload.nbf > now)) {
            return null;
        }

        return payload;
    } catch (e) {
        console.error("JWT Verification Error:", e);
        return null;
    }
}

async function authenticate(request, env) {
    const authCookieHeader = request.headers.get('Cookie');
    const authCookie = authCookieHeader?.split('; ').find(row => row.startsWith('auth_token='));
    const requestIp = request.headers.get('CF-Connecting-IP');

    if (!authCookie) {
        return { user: null, token: null };
    }

    const token = authCookie.split('=')[1];
    const payload = await verifyJwt(token, env.JWT_PUBLIC_KEY);

    if (payload) {
        const now = Math.floor(Date.now() / 1000);
        if (now - payload.lastActivity > IDLE_SESSION_EXPIRATION_SECONDS) {
            console.warn('Authentication failed for user ' + payload.sub + ': Idle session timeout');
            return { user: null, token: null };
        }

        if (payload.jti) {
            const isTokenRevoked = await env.KV_TOKEN_DENYLIST.get(payload.jti);
            if (isTokenRevoked) {
                console.warn('Authentication failed for user ' + payload.sub + ': Token is revoked (JTI: ' + payload.jti + ')');
                return { user: null, token: null };
            }
        }

        if (payload.ip !== requestIp) {
            console.warn('Authentication failed for user ' + payload.sub + ': IP mismatch (expected ' + payload.ip + ', got ' + requestIp + ')');
            return { user: null, token: null };
        }

        const currentSessionVersion = await env.KV_SESSIONS.get('admin_session_version');
        if (payload.version !== currentSessionVersion) {
            console.warn('Authentication failed for user ' + payload.sub + ': Session version mismatch');
            return { user: null, token: null };
        }

        if (payload.sub === 'admin') {
            return { user: payload, token: token };
        }
    }

    return { user: null, token: null };
}

async function checkRateLimit(key, kvNamespace, maxAttempts, windowSeconds) {
    let attempts = await kvNamespace.get(key, { type: 'json' });
    if (!attempts) {
        attempts = { count: 0, timestamps: [] };
    }
    const now = Date.now();
    attempts.timestamps = attempts.timestamps.filter(ts => (now - ts) < (windowSeconds * 1000));
    attempts.count = attempts.timestamps.length;

    if (attempts.count >= maxAttempts) {
        const retryAfter = (attempts.timestamps[0] + windowSeconds * 1000 - now) / 1000;
        return { allowed: false, retryAfter };
    }
    return { allowed: true };
}

async function recordRateLimitAttempt(key, kvNamespace, windowSeconds) {
    let attempts = await kvNamespace.get(key, { type: 'json' });
    if (!attempts) {
        attempts = { count: 0, timestamps: [] };
    }
    const now = Date.now();
    attempts.timestamps.push(now);
    attempts.count = attempts.timestamps.length;

    await kvNamespace.put(key, JSON.stringify(attempts), { expirationTtl: windowSeconds + 60 });
}

async function clearRateLimitAttempts(key, kvNamespace) {
    await kvNamespace.delete(key);
}

function timingSafeEqual(a, b) {
  if (a.byteLength !== b.byteLength) {
    return false;
  }

  let diff = 0;
  for (let i = 0; i < a.byteLength; i++) {
    diff |= a[i] ^ b[i];
  }

  return diff === 0;
}

function isValidFilename(name) {
    if (!name || typeof name !== 'string' || !name.trim()) {
        return false;
    }
    const trimmedName = name.trim();
    if (trimmedName.length === 0 || trimmedName.length > 255) {
        return false;
    }
    if (trimmedName.includes('/') || trimmedName.includes('\\')) {
        return false;
    }
    if (trimmedName.includes('..')) {
        return false;
    }
    const controlCharsRegex = /[\x00-\x1F\x7F-\x9F]/;
    if (controlCharsRegex.test(trimmedName)) {
        return false;
    }

    return true;
}

function hexToBytes(hex) {
    const bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < bytes.length; i++) {
        bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
    }
    return bytes;
}

function pemToBuffer(pem) {
    const base64 = pem
        .replace(/-----BEGIN (EC PRIVATE KEY|PUBLIC KEY)-----/, '')
        .replace(/-----END (EC PRIVATE KEY|PUBLIC KEY)-----/, '')
        .replace(/\s/g, '');
    const binaryString = atob(base64);
    const len = binaryString.length;
    const bytes = new Uint8Array(len);
    for (let i = 0; i < len; i++) {
        bytes[i] = binaryString.charCodeAt(i);
    }
    return bytes.buffer;
}

async function verifyOwnership(userId, fileId, env) {
    if (!userId || !fileId) return false;
    const ownershipKey = `${userId}:${fileId}`;
    const result = await env.KV_OWNERSHIP.get(ownershipKey);
    return result !== null;
}

async function handleGetVersion(request, env) {
    const versionMetaString = await env.KV_SESSIONS.get(E2E_VERSION_KEY);
    if (!versionMetaString) {
        return new Response(JSON.stringify({ version: 0 }), {
            headers: { 'Content-Type': 'application/json' }
        });
    }

    const versionMeta = JSON.parse(versionMetaString);
    return new Response(JSON.stringify({ version: versionMeta.version || 0 }), {
        headers: { 'Content-Type': 'application/json' }
    });
}

async function handleUpdateManifest(request, env, params, user) {
    const { manifest, version, baseVersion } = await request.json();

    if (!manifest || typeof version !== 'number' || typeof baseVersion !== 'number') {
        return new Response('Manifest, new version, and base version are required.', { status: 400 });
    }

    const currentVersionMetaString = await env.KV_SESSIONS.get(E2E_VERSION_KEY);
    const currentVersionMeta = JSON.parse(currentVersionMetaString || '{}');
    const currentServerVersion = currentVersionMeta.version || 0;

    if (currentServerVersion !== baseVersion) {
        return new Response(
            JSON.stringify({
                success: false,
                message: 'Update conflict. The data has been modified since you last loaded it. Please refresh and try again.'
            }), {
                status: 409,
                headers: { 'Content-Type': 'application/json' }
            }
        );
    }

    const binaryString = atob(manifest);
    if (binaryString.length > MAX_MANIFEST_SIZE_BYTES) {
        return new Response('Manifest too large.', { status: 413 });
    }
    const len = binaryString.length;
    const bytes = new Uint8Array(len);
    for (let i = 0; i < len; i++) {
        bytes[i] = binaryString.charCodeAt(i);
    }
    const manifestBuffer = bytes.buffer;

    const signature = await computeHmac(manifestBuffer, env.MANIFEST_SECRET);
    const versionData = { version: version, signature: signature };

    await env.R2_BUCKET.put(E2E_MANIFEST_KEY, manifestBuffer);
    await env.KV_SESSIONS.put(E2E_VERSION_KEY, JSON.stringify(versionData));

    return new Response(JSON.stringify({ success: true }), {
         headers: { 'Content-Type': 'application/json' }
    });
}

async function validateFileContent(fileBuffer, expectedMimeType) {
    const uint8Array = new Uint8Array(fileBuffer);

    if (BLOCKED_MIME_TYPES.includes(expectedMimeType)) {
        return false;
    }

    let sniffedType = null;

    for (const type in FILE_MAGIC_BYTES) {
        for (const pattern of FILE_MAGIC_BYTES[type]) {
            if (startsWithBytes(uint8Array, pattern)) {
                sniffedType = type;
                break;
            }
        }
        if (sniffedType) break;
    }

    if (sniffedType) {
        if (BLOCKED_MIME_TYPES.includes(sniffedType)) {
            console.warn(`Content sniffing blocked: ${sniffedType} (disguised as ${expectedMimeType})`);
            return false;
        }

        if (expectedMimeType !== 'application/octet-stream' && expectedMimeType !== sniffedType) {
            if (sniffedType === 'application/zip' && expectedMimeType.startsWith('application/vnd.openxmlformats-officedocument')) {
                return true;
            }
            console.warn(`MIME type mismatch: Expected ${expectedMimeType}, sniffed ${sniffedType}`);
            return false;
        }
        return true;
    }

    if (expectedMimeType.startsWith('text/')) {
        const textDecoder = new TextDecoder('utf-8');
        const textContent = textDecoder.decode(uint8Array.subarray(0, Math.min(uint8Array.length, 4096)));

        if (/<html|<body|<head|<script|<iframe|<object|<embed|<link|<style|<meta/.test(textContent.toLowerCase())) {
            console.warn(`Text content sniffing blocked: Looks like HTML/script (expected ${expectedMimeType})`);
            return false;
        }
        return true;
    }

    console.warn(`File content validation failed: No magic bytes matched for expected ${expectedMimeType} and it's not a recognized text file.`);
    return false;
}

async function handleLogin(request, env) {
    const { username, password } = await request.json();
    const clientIp = request.headers.get('CF-Connecting-IP');

    const ipLockout = await checkIpLockout(clientIp, env);
    if (ipLockout.locked) {
        return new Response(JSON.stringify({ success: false, message: 'Too many login attempts from this IP. Please try again in ' + Math.ceil(ipLockout.retryAfter) + ' seconds.' }), {
            status: 429, headers: { 'Content-Type': 'application/json' }
        });
    }

    const usernameRateLimit = await checkRateLimit('username_login_attempts:' + username, env.KV_LOGIN_ATTEMPTS, MAX_USERNAME_LOGIN_ATTEMPTS, USERNAME_LOGIN_ATTEMPT_WINDOW_SECONDS);
    if (!usernameRateLimit.allowed) {
        return new Response(JSON.stringify({ success: false, message: 'Too many login attempts for this user. Please try again in ' + Math.ceil(usernameRateLimit.retryAfter) + ' seconds.' }), {
            status: 429, headers: { 'Content-Type': 'application/json' }
        });
    }

    let isValidLogin = false;
    if (username && password && env.ADMIN_USERNAME_HASH && env.ADMIN_USERNAME_SALT && env.ADMIN_PASSWORD_HASH && env.ADMIN_PASSWORD_SALT) {

        const computedUsernameHash = await hashString(username + env.ADMIN_USERNAME_SALT);
        const isUsernameValid = timingSafeEqual(hexToBytes(computedUsernameHash), hexToBytes(env.ADMIN_USERNAME_HASH));

        if (isUsernameValid) {
            const salt = hexToBytes(env.ADMIN_PASSWORD_SALT);
            const passwordBuffer = new TextEncoder().encode(password);

            const keyMaterial = await crypto.subtle.importKey(
                'raw', passwordBuffer, { name: 'PBKDF2' }, false, ['deriveKey']
            );

            const derivedKey = await crypto.subtle.deriveKey(
                { name: 'PBKDF2', salt: salt, iterations: 100000, hash: 'SHA-256' },
                keyMaterial,
                { name: 'AES-GCM', length: 256 },
                true,
                ['encrypt']
            );

            const hashBuffer = await crypto.subtle.exportKey('raw', derivedKey);
            const computedPasswordHashBytes = new Uint8Array(hashBuffer);

            isValidLogin = timingSafeEqual(computedPasswordHashBytes, hexToBytes(env.ADMIN_PASSWORD_HASH));
        }
    }

    if (isValidLogin) {
        await clearRateLimitAttempts('username_login_attempts:' + username, env.KV_LOGIN_ATTEMPTS);
        await clearIpLoginAttempts(clientIp, env);

        const sessionVersion = crypto.randomUUID();
        await env.KV_SESSIONS.put('admin_session_version', sessionVersion, { expirationTtl: TOKEN_EXPIRATION_SECONDS });

        const now = Math.floor(Date.now() / 1000);
        const expiration = now + TOKEN_EXPIRATION_SECONDS;

        const payload = {
            sub: 'admin', jti: crypto.randomUUID(), iat: now, nbf: now, exp: expiration,
            version: sessionVersion, ip: clientIp, lastActivity: now
        };
        const token = await signJwt(payload, env.JWT_PRIVATE_KEY);

        const cookieString = `auth_token=${token}; Max-Age=${TOKEN_EXPIRATION_SECONDS}; Path=${BASE_PATH || '/'}; Domain=.domain.com; SameSite=None; Secure; HttpOnly`;

        return new Response(JSON.stringify({ success: true, exp: expiration }), {
            status: 200,
            headers: {
                'Content-Type': 'application/json',
                'Set-Cookie': cookieString
            }
        });
    } else {
        await recordRateLimitAttempt('username_login_attempts:' + username, env.KV_LOGIN_ATTEMPTS, USERNAME_LOGIN_ATTEMPT_WINDOW_SECONDS);
        await recordIpLoginAttempt(clientIp, env);

        return new Response(JSON.stringify({ success: false, message: 'Invalid username or password.' }), {
            status: 401,
            headers: { 'Content-Type': 'application/json' }
        });
    }
}

async function checkIpLockout(ip, env) {
    const lockoutInfo = await env.KV_LOGIN_ATTEMPTS.getWithMetadata(`ip_lockout:${ip}`);

    if (lockoutInfo && lockoutInfo.metadata && lockoutInfo.metadata.expiration) {
        const now = Date.now();
        const expirationTime = lockoutInfo.metadata.expiration * 1000;
        if (now < expirationTime) {
            return {
                locked: true,
                retryAfter: Math.ceil((expirationTime - now) / 1000)
            };
        }
    }
    return { locked: false };
}

async function recordIpLoginAttempt(ip, env) {
    let attempts = await env.KV_LOGIN_ATTEMPTS.get(`ip_attempts:${ip}`, { type: 'json' });
    if (!attempts) {
        attempts = { timestamps: [] };
    }

    const now = Date.now();
    attempts.timestamps.push(now);
    attempts.timestamps = attempts.timestamps.filter(ts => (now - ts) < (IP_LOGIN_ATTEMPT_WINDOW_SECONDS * 1000));

    if (attempts.timestamps.length >= MAX_IP_LOGIN_ATTEMPTS) {
        let levelInfo = await env.KV_LOGIN_ATTEMPTS.get(`ip_lockout_level:${ip}`, { type: 'json' });
        const currentLevel = levelInfo ? levelInfo.level : 0;

        const lockoutDuration = IP_LOCKOUT_DURATIONS_SECONDS[Math.min(currentLevel, IP_LOCKOUT_DURATIONS_SECONDS.length - 1)];

        await env.KV_LOGIN_ATTEMPTS.put(`ip_lockout:${ip}`, 'locked', { expirationTtl: lockoutDuration });

        const nextLevel = currentLevel + 1;
        const oneYearPlusOneDay = (365 * 24 * 60 * 60) + (24 * 60 * 60);
        await env.KV_LOGIN_ATTEMPTS.put(`ip_lockout_level:${ip}`, JSON.stringify({ level: nextLevel }), { expirationTtl: oneYearPlusOneDay });

        await env.KV_LOGIN_ATTEMPTS.delete(`ip_attempts:${ip}`);
    } else {
        await env.KV_LOGIN_ATTEMPTS.put(`ip_attempts:${ip}`, JSON.stringify(attempts), { expirationTtl: IP_LOGIN_ATTEMPT_WINDOW_SECONDS });
    }
}

async function clearIpLoginAttempts(ip, env) {
    await env.KV_LOGIN_ATTEMPTS.delete(`ip_attempts:${ip}`);
    await env.KV_LOGIN_ATTEMPTS.delete(`ip_lockout:${ip}`);
}

async function handleLogout(request, env) {
    const authHeader = request.headers.get('Cookie');
    const cookie = authHeader?.split('; ').find(row => row.startsWith('auth_token='));

    if (cookie) {
        const token = cookie.split('=')[1];
        const payload = await verifyJwt(token, env.JWT_PUBLIC_KEY);
        if (payload && payload.jti && payload.exp) {
            const now = Math.floor(Date.now() / 1000);
            const remainingValidity = payload.exp - now;
            if (remainingValidity > 0) {
                await env.KV_TOKEN_DENYLIST.put(payload.jti, 'revoked', { expirationTtl: remainingValidity });
            }
        }
    }

    await env.KV_SESSIONS.delete('admin_session_version');

    const clearCookieString = `auth_token=; Max-Age=0; Path=${BASE_PATH || '/'}; Domain=.domain.com; SameSite=None; Secure; HttpOnly`;

    return new Response(JSON.stringify({ success: true }), {
        status: 200,
        headers: {
            'Content-Type': 'application/json',
            'Set-Cookie': clearCookieString
        }
    });
}

async function handleGetE2EMeta(request, env) {
    const saltObj = await env.R2_BUCKET.get(E2E_SALT_KEY);
    const hintObj = await env.R2_BUCKET.get(E2E_HINT_KEY);

    if (!saltObj) {
        return new Response(JSON.stringify({ setup: false }), {
            headers: { 'Content-Type': 'application/json' }
        });
    }

    const salt = await saltObj.text();
    let hint = '';
    if (hintObj) {
        const hintEncoder = new TextEncoder();
        const keyMaterial = await crypto.subtle.importKey('raw', hintEncoder.encode(env.TOKEN_SECRET), { name: 'PBKDF2' }, false, ['deriveKey']);
        const hintKey = await crypto.subtle.deriveKey({ name: 'PBKDF2', salt: base64ToUint8(salt), iterations: 100000, hash: 'SHA-256' }, keyMaterial, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);

        try {
            const encryptedHint = base64ToUint8(await hintObj.text());
            hint = await decryptText(encryptedHint, hintKey);
        } catch (e) {
            console.error("Failed to decrypt hint:", e);
            hint = '';
        }
    }

    return new Response(JSON.stringify({ setup: true, salt, hint }), {
        headers: { 'Content-Type': 'application/json' }
    });
}

async function handlePostE2ESetup(request, env) {
    const { salt, hint, manifest } = await request.json();
    if (!salt || !manifest) {
        return new Response('Salt and manifest are required.', { status: 400 });
    }

    try {
        const decodedSalt = atob(salt);
        if (decodedSalt.length !== 32) {
            return new Response('Invalid salt length.', { status: 400 });
        }
    } catch (e) {
        return new Response('Invalid salt format. Must be a valid Base64 string.', { status: 400 });
    }

    const binaryString = atob(manifest);
    const len = binaryString.length;
    const bytes = new Uint8Array(len);
    for (let i = 0; i < len; i++) {
        bytes[i] = binaryString.charCodeAt(i);
    }
    const manifestBuffer = bytes.buffer;

    const hintEncoder = new TextEncoder();
    const keyMaterial = await crypto.subtle.importKey('raw', hintEncoder.encode(env.TOKEN_SECRET), { name: 'PBKDF2' }, false, ['deriveKey']);
    const hintKey = await crypto.subtle.deriveKey({ name: 'PBKDF2', salt: base64ToUint8(salt), iterations: 100000, hash: 'SHA-256' }, keyMaterial, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
    const encryptedHint = await encrypt(hint || '', hintKey);

    const signature = await computeHmac(manifestBuffer, env.MANIFEST_SECRET);
    const versionData = { version: 1, signature: signature };

    await env.R2_BUCKET.put(E2E_SALT_KEY, salt);
    await env.R2_BUCKET.put(E2E_HINT_KEY, uint8ToBase64(encryptedHint));
    await env.R2_BUCKET.put(E2E_MANIFEST_KEY, manifestBuffer);
    await env.KV_SESSIONS.put(E2E_VERSION_KEY, JSON.stringify(versionData));

    return new Response(JSON.stringify({ success: true }), {
        headers: { 'Content-Type': 'application/json' }
    });
}

async function handleGetManifest(request, env) {
    const versionMetaString = await env.KV_SESSIONS.get(E2E_VERSION_KEY);
    if (!versionMetaString) {
        return new Response('Manifest metadata not found.', { status: 404 });
    }

    const versionMeta = JSON.parse(versionMetaString);
    const trustedSignatureHex = versionMeta.signature;

    const manifestObj = await env.R2_BUCKET.get(E2E_MANIFEST_KEY);
    if (!manifestObj) {
        return new Response('Manifest not found.', { status: 404 });
    }

    const manifestBuffer = await manifestObj.arrayBuffer();

    const key = await crypto.subtle.importKey(
        'raw',
        new TextEncoder().encode(env.MANIFEST_SECRET),
        { name: 'HMAC', hash: 'SHA-256' },
        false,
        ['verify']
    );

    const signatureBytes = hexToBytes(trustedSignatureHex);

    const isValid = await crypto.subtle.verify(
        'HMAC',
        key,
        signatureBytes,
        manifestBuffer
    );

    if (!isValid) {
        console.error('CRITICAL: Manifest integrity check failed! The manifest in R2 does not match its signature.');
        return new Response('Server integrity error.', { status: 500 });
    }

    return new Response(manifestBuffer, { headers: { 'Content-Type': 'application/octet-stream' }});
}

async function handleUploadFile(request, env, params, user) {
    const contentType = request.headers.get('Content-Type') || 'application/octet-stream';

    if (BLOCKED_MIME_TYPES.includes(contentType)) {
        return new Response(JSON.stringify({ success: false, message: 'This file type is blocked for security reasons.' }), {
            status: 400,
            headers: { 'Content-Type': 'application/json' }
        });
    }

    const clientIp = request.headers.get('CF-Connecting-IP');
    const rateLimit = await checkRateLimit(`error_attempts:${clientIp}`, env.KV_ERROR_ATTEMPTS, 20, 10 * 60);
    if (!rateLimit.allowed) {
        return new Response('Too many requests.', {
            status: 429,
            headers: { 'Retry-After': String(Math.ceil(rateLimit.retryAfter)) }
        });
    }

    const contentLength = parseInt(request.headers.get('content-length'), 10);
    if (isNaN(contentLength) || contentLength <= 0 || contentLength > MAX_FILE_SIZE_BYTES) {
        return new Response('Invalid file size.', { status: 413 });
    }

    const fileKey = request.headers.get('X-File-Key');
    if (!fileKey || !ALLOWED_FILE_KEY_REGEX.test(fileKey)) {
        return new Response('Invalid file key.', { status: 400 });
    }

    const existingObject = await env.R2_BUCKET.head(fileKey);

    if (existingObject !== null) {
        const isOwner = await verifyOwnership(user.sub, fileKey, env);
        if (!isOwner) {
            return new Response(JSON.stringify({ success: false, message: 'Forbidden' }), {
                status: 403,
                headers: { 'Content-Type': 'application/json' }
            });
        }
    }

    try {
        const fileBodyBuffer = await request.arrayBuffer();
        await env.R2_BUCKET.put(fileKey, fileBodyBuffer, {
            httpMetadata: { contentType },
        });

        await env.KV_OWNERSHIP.put(`${user.sub}:${fileKey}`, 'true', {
            expirationTtl: 31536000
        });

        return new Response(JSON.stringify({ success: true, message: 'File uploaded successfully' }), {
            headers: { 'Content-Type': 'application/json' }
        });
    } catch (e) {
        console.error('Upload Error:', e.message);
        await recordRateLimitAttempt(`error_attempts:${clientIp}`, env.KV_ERROR_ATTEMPTS, 10 * 60);
        return new Response(JSON.stringify({ success: false, message: 'Server failed to store the file.' }), { status: 500 });
    }
}

async function handleDownloadFile(request, env, params, user) {
    if (!user) {
        return new Response('Access denied.', { status: 403 });
    }
    const url = new URL(request.url);
    const fileKey = url.searchParams.get('key');

    if (!fileKey || !ALLOWED_FILE_KEY_REGEX.test(fileKey)) {
        return new Response('Invalid file key', { status: 400 });
    }

    const isOwner = await verifyOwnership(user.sub, fileKey, env);
    if (!isOwner) {
        return new Response('File not found', { status: 404 });
    }

    if (fileKey.startsWith(E2E_META_PREFIX)) {
        return new Response('Access denied.', { status: 403 });
    }

    try {
        const object = await env.R2_BUCKET.get(fileKey);
        if (!object) {
            return new Response('File not found', { status: 404 });
        }
        const headers = new Headers();
        object.writeHttpMetadata(headers);
        headers.set('ETag', object.etag);

        headers.set('Content-Disposition', 'attachment');

        return new Response(object.body, { headers });
    } catch (e) {
        return new Response('An error occurred while retrieving the file.', { status: 500 });
    }
}

async function handleDeleteFile(request, env, params, user) {
    const clientIp = request.headers.get('CF-Connecting-IP');
    const rateLimit = await checkRateLimit(`error_attempts:${clientIp}`, env.KV_ERROR_ATTEMPTS, 20, 10 * 60);
    if (!rateLimit.allowed) {
        return new Response('Too many requests.', { status: 429 });
    }

    const { keys } = await request.json();

    if (!Array.isArray(keys) || keys.length === 0 || !keys.every(key => ALLOWED_FILE_KEY_REGEX.test(key))) {
        return new Response('Invalid file keys provided.', { status: 400 });
    }

    const MAX_DELETES_PER_REQUEST = 1000;
    if (keys.length > MAX_DELETES_PER_REQUEST) {
        return new Response('Deletion request exceeds the maximum limit of ' + MAX_DELETES_PER_REQUEST + ' items.', { status: 400 });
    }

    const sanitizedKeys = keys;

    for (const key of sanitizedKeys) {
        const isOwner = await verifyOwnership(user.sub, key, env);
        if (!isOwner) {
            return new Response('One or more files could not be found or you lack permission.', { status: 404 });
        }
    }

    try {
        for (const fileId of sanitizedKeys) {
            const shareStoreKey = `${SHARE_STORE_PREFIX}${fileId}`;
            const shareStoreEntry = await env.SHARE_STORE.get(shareStoreKey, { type: 'json' });
            if (shareStoreEntry && shareStoreEntry.links) {
                const shareIdsToDelete = Object.keys(shareStoreEntry.links).map(id => `${SHARE_LOOKUP_PREFIX}${id}`);
                if (shareIdsToDelete.length > 0) {
                    await env.SHARE_LOOKUP.delete(shareIdsToDelete);
                }
            }
            await env.SHARE_STORE.delete(shareStoreKey);
        }

        if (sanitizedKeys.length > 0) {
            await env.R2_BUCKET.delete(sanitizedKeys);

            const ownershipKeysToDelete = sanitizedKeys.map(key => `${user.sub}:${key}`);
            for (const key of ownershipKeysToDelete) {
                await env.KV_OWNERSHIP.delete(key);
            }
        }
        return new Response(JSON.stringify({ success: true, message: `Items deleted successfully` }), {
            headers: { 'Content-Type': 'application/json' }
        });
    } catch (e) {
        console.error('Delete Error:', e.message);
        await recordRateLimitAttempt(`error_attempts:${clientIp}`, env.KV_ERROR_ATTEMPTS, 10 * 60);
        return new Response(JSON.stringify({ success: false, message: 'Could not complete the deletion process.' }), { status: 500 });
    }
}


async function handleE2EResetStage(request, env) {
  const contentLength = parseInt(request.headers.get('content-length'), 10);
  if (contentLength > MAX_MANIFEST_SIZE_BYTES) {
    return new Response('Staged manifest is too large.', { status: 413 });
  }

  const manifestBuffer = await request.arrayBuffer();
  if (manifestBuffer.byteLength > MAX_MANIFEST_SIZE_BYTES) {
    return new Response('Staged manifest is too large.', { status: 413 });
  }

  await env.R2_BUCKET.put(E2E_MANIFEST_KEY_STAGING, manifestBuffer);

  return new Response(JSON.stringify({ success: true, message: 'Manifest staged successfully.' }), {
    headers: { 'Content-Type': 'application/json' }
  });
}

async function handleE2EResetCommit(request, env, params, user) {
    const { newSalt, newHint, oldFileKeys, newVersion } = await request.json();

    if (!newSalt || !Array.isArray(oldFileKeys) || typeof newVersion !== 'number') {
        return new Response('Invalid commit request. New salt, old file keys, and new version are required.', { status: 400 });
    }

    try {
        const stagedManifestObj = await env.R2_BUCKET.get(E2E_MANIFEST_KEY_STAGING);
        if (!stagedManifestObj) {
            return new Response(JSON.stringify({ success: false, message: 'Staged manifest not found for commit.' }), { status: 500 });
        }
        const stagedManifestBuffer = await stagedManifestObj.arrayBuffer();
        const signature = await computeHmac(stagedManifestBuffer, env.MANIFEST_SECRET);
        const versionData = { version: newVersion, signature: signature };

        await env.R2_BUCKET.put(E2E_MANIFEST_KEY, stagedManifestBuffer);
        await env.R2_BUCKET.put(E2E_SALT_KEY, newSalt);
        await env.R2_BUCKET.put(E2E_HINT_KEY, newHint || '');
        await env.KV_SESSIONS.put(E2E_VERSION_KEY, JSON.stringify(versionData));

        await env.R2_BUCKET.delete(E2E_MANIFEST_KEY_STAGING);

        if (oldFileKeys.length > 0) {
            const MAX_DELETES = 1000;
            for (let i = 0; i < oldFileKeys.length; i += MAX_DELETES) {
                const batch = oldFileKeys.slice(i, i + MAX_DELETES);
                await env.R2_BUCKET.delete(batch);

                const ownershipKeysToDelete = batch.map(key => `${user.sub}:${key}`);
                for (const key of ownershipKeysToDelete) {
                    await env.KV_OWNERSHIP.delete(key);
                }
            }
        }
        return new Response(JSON.stringify({ success: true, message: 'E2E reset committed successfully.' }), {
            headers: { 'Content-Type': 'application/json' }
        });
    } catch (e) {
        console.error('E2E Reset Commit Error:', e.message);
        await env.R2_BUCKET.delete(E2E_MANIFEST_KEY_STAGING).catch(err => console.error("Failed to cleanup staging key on commit error:", err));
        return new Response(JSON.stringify({
            success: false,
            message: 'A critical error occurred during the commit process. You will be logged out for your security.',
            action: 'force_logout'
        }), {
            status: 500,
            headers: { 'Content-Type': 'application/json' }
        });
    }
}

async function handleHeadRequest(request, env) {
    return new Response(null, { status: 200 });
}

async function handleGetShares(request, env, params, user) {
    const [fileId] = params;
    if (!ALLOWED_FILE_KEY_REGEX.test(fileId)) {
        return new Response('Invalid file ID format.', { status: 400 });
    }

    const isOwner = await verifyOwnership(user.sub, fileId, env);
    if (!isOwner) {
        return new Response('Not Found', { status: 404 });
    }

    const shareData = await env.SHARE_STORE.get(`${SHARE_STORE_PREFIX}${fileId}`, { type: 'json' });
    return new Response(JSON.stringify(shareData || { links: {} }), {
        headers: { 'Content-Type': 'application/json' }
    });
}

async function handleCreateShare(request, env, params, user) {
    const [fileId] = params;
    if (!ALLOWED_FILE_KEY_REGEX.test(fileId)) {
        return new Response('Invalid file ID format.', { status: 400 });
    }

    const isOwner = await verifyOwnership(user.sub, fileId, env);
    if (!isOwner) {
        return new Response('Not Found', { status: 404 });
    }

    const { shareId, expiresAt, hasPassword, fileName, fileSize, encryptedUrl, maxClicks } = await request.json();

    if (!shareId || !ALLOWED_SHARE_ID_REGEX.test(shareId) || typeof hasPassword !== 'boolean' || !fileName || typeof fileSize !== 'number' || !encryptedUrl) {
        return new Response('Missing or invalid share parameters.', { status: 400 });
    }

    const shareStoreKey = `${SHARE_STORE_PREFIX}${fileId}`;
    let shareStoreData = await env.SHARE_STORE.get(shareStoreKey, { type: 'json' }) || { links: {} };

    const parsedMaxClicks = maxClicks ? parseInt(maxClicks, 10) : null;

    shareStoreData.links[shareId] = {
        createdAt: new Date().toISOString(),
        expiresAt: expiresAt || null,
        hasPassword: hasPassword,
        encryptedUrl: encryptedUrl,
        maxClicks: parsedMaxClicks && parsedMaxClicks > 0 ? parsedMaxClicks : null,
        clickCount: 0,
    };

    const publicLookupData = {
        fileName: fileName,
        fileSize: fileSize,
        hasPassword: hasPassword,
        expiresAt: expiresAt || null,
        maxClicks: parsedMaxClicks && parsedMaxClicks > 0 ? parsedMaxClicks : null,
        clickCount: 0,
    };

    const kvOptions = {};
    if (expiresAt) {
        const expiryDate = new Date(expiresAt);
        const now = new Date();
        if (expiryDate > now) {
            kvOptions.expirationTtl = Math.max(60, Math.floor((expiryDate.getTime() - now.getTime()) / 1000));
        } else {
             return new Response('Expiration date must be in the future.', { status: 400 });
        }
    }

    const lookupDataJson = JSON.stringify(publicLookupData);
    const signature = await computeHmac(new TextEncoder().encode(lookupDataJson), env.METADATA_SECRET);
    const signedLookupData = {
        data: uint8ToBase64(new TextEncoder().encode(lookupDataJson)),
        signature: signature
    };

    await env.SHARE_LOOKUP.put(`${SHARE_LOOKUP_PREFIX}${shareId}`, JSON.stringify(signedLookupData), kvOptions);
    await env.SHARE_LOOKUP.put(`${SHARE_FILE_MAP_PREFIX}${shareId}`, fileId, kvOptions);
    await env.SHARE_STORE.put(shareStoreKey, JSON.stringify(shareStoreData));

    return new Response(JSON.stringify({ success: true, shareId: shareId }), {
        status: 201,
        headers: { 'Content-Type': 'application/json' }
    });
}

async function handlePatchShare(request, env, params, user) {
    const [fileId, shareId] = params;
    if (!ALLOWED_FILE_KEY_REGEX.test(fileId) || !ALLOWED_SHARE_ID_REGEX.test(shareId)) {
        return new Response('Invalid ID format.', { status: 400 });
    }

    const isOwner = await verifyOwnership(user.sub, fileId, env);
    if (!isOwner) {
        return new Response('Not Found', { status: 404 });
    }

    const { expiresAt, maxClicks, fileName, fileSize } = await request.json();

    const shareStoreKey = `${SHARE_STORE_PREFIX}${fileId}`;
    let shareStoreData = await env.SHARE_STORE.get(shareStoreKey, { type: 'json' });
    if (!shareStoreData || !shareStoreData.links[shareId]) {
        return new Response('Share link not found.', { status: 404 });
    }

    const parsedMaxClicks = maxClicks ? parseInt(maxClicks, 10) : null;
    shareStoreData.links[shareId].expiresAt = expiresAt !== undefined ? expiresAt : shareStoreData.links[shareId].expiresAt;
    shareStoreData.links[shareId].maxClicks = parsedMaxClicks !== undefined ? parsedMaxClicks : null;
    await env.SHARE_STORE.put(shareStoreKey, JSON.stringify(shareStoreData));

    const shareLookupKey = `${SHARE_LOOKUP_PREFIX}${shareId}`;
    let lookupData;
    const signedLookupData = await env.SHARE_LOOKUP.get(shareLookupKey, { type: 'json' });

    if (signedLookupData && signedLookupData.data && signedLookupData.signature) {
        const lookupDataJsonBytes = base64ToUint8(signedLookupData.data);
        const expectedSignature = await computeHmac(lookupDataJsonBytes, env.METADATA_SECRET);
        if (timingSafeEqual(hexToBytes(expectedSignature), hexToBytes(signedLookupData.signature))) {
            lookupData = JSON.parse(new TextDecoder().decode(lookupDataJsonBytes));
        } else {
             return new Response('Metadata integrity check failed.', { status: 500 });
        }
    } else if (!signedLookupData) { // Handle renewal of expired links
        if (typeof fileName !== 'string' || typeof fileSize !== 'number') {
             return new Response('Missing file metadata required to renew an expired link.', { status: 400 });
        }
        if (!isValidFilename(fileName)) {
            return new Response('Invalid fileName format provided.', { status: 400 });
        }
        lookupData = {
            fileName: fileName,
            fileSize: fileSize,
            hasPassword: shareStoreData.links[shareId].hasPassword,
            clickCount: shareStoreData.links[shareId].clickCount || 0,
        };
    } else {
        return new Response('Corrupt metadata found.', { status: 500 });
    }

    lookupData.expiresAt = expiresAt !== undefined ? expiresAt : lookupData.expiresAt;
    lookupData.maxClicks = parsedMaxClicks !== undefined ? parsedMaxClicks : null;

    const kvOptions = {};
    if (lookupData.expiresAt) {
        const expiryDate = new Date(lookupData.expiresAt);
        const now = new Date();
        if (expiryDate > now) {
            kvOptions.expirationTtl = Math.max(60, Math.floor((expiryDate.getTime() - now.getTime()) / 1000));
        }
    }

    const newLookupDataJson = JSON.stringify(lookupData);
    const newSignature = await computeHmac(new TextEncoder().encode(newLookupDataJson), env.METADATA_SECRET);
    const newSignedLookupData = {
        data: uint8ToBase64(new TextEncoder().encode(newLookupDataJson)),
        signature: newSignature
    };

    await env.SHARE_LOOKUP.put(shareLookupKey, JSON.stringify(newSignedLookupData), kvOptions);
    await env.SHARE_LOOKUP.put(`${SHARE_FILE_MAP_PREFIX}${shareId}`, fileId, kvOptions);
    
    return new Response(JSON.stringify({ success: true }), { headers: { 'Content-Type': 'application/json' } });
}

async function handleDeleteShare(request, env, params, user) {
    const [fileId, shareId] = params;
    if (!ALLOWED_FILE_KEY_REGEX.test(fileId) || !ALLOWED_SHARE_ID_REGEX.test(shareId)) {
        return new Response('Invalid ID format.', { status: 400 });
    }

    const isOwner = await verifyOwnership(user.sub, fileId, env);
    if (!isOwner) {
        return new Response('Not Found', { status: 404 });
    }

    const shareStoreKey = `${SHARE_STORE_PREFIX}${fileId}`;
    let shareStoreData = await env.SHARE_STORE.get(shareStoreKey, { type: 'json' });
    if (shareStoreData && shareStoreData.links[shareId]) {
        delete shareStoreData.links[shareId];
        await env.SHARE_STORE.put(shareStoreKey, JSON.stringify(shareStoreData));
    }

    await env.SHARE_LOOKUP.delete(`${SHARE_LOOKUP_PREFIX}${shareId}`);

    return new Response(null, { status: 204 });
}

async function handleGetPublicShare(request, env, params) {
    const [shareId] = params;
    if (!ALLOWED_SHARE_ID_REGEX.test(shareId)) {
        return new Response('Invalid share ID.', { status: 400 });
    }

    const clientIp = request.headers.get('CF-Connecting-IP');
    const rateLimit = await checkRateLimit(`public_access_attempts:${clientIp}`, env.KV_LOGIN_ATTEMPTS, 30, 60);
    if (!rateLimit.allowed) {
        return new Response('Too many requests.', { status: 429 });
    }
    await recordRateLimitAttempt(`public_access_attempts:${clientIp}`, env.KV_LOGIN_ATTEMPTS, 60);

    const shareLookupKey = `${SHARE_LOOKUP_PREFIX}${shareId}`;
    const signedLookupData = await env.SHARE_LOOKUP.get(shareLookupKey, { type: 'json' });

    if (!signedLookupData || !signedLookupData.data || !signedLookupData.signature) {
        return new Response(JSON.stringify({ error: 'Share link not found or expired.' }), { status: 404, headers: { 'Content-Type': 'application/json' } });
    }

    const lookupDataJsonBytes = base64ToUint8(signedLookupData.data);
    const expectedSignature = await computeHmac(lookupDataJsonBytes, env.METADATA_SECRET);

    if (!timingSafeEqual(hexToBytes(expectedSignature), hexToBytes(signedLookupData.signature))) {
        console.error(`CRITICAL: Share link metadata integrity check failed for shareId: ${shareId}`);
        return new Response(JSON.stringify({ error: 'Server integrity error.' }), { status: 500, headers: { 'Content-Type': 'application/json' } });
    }
    
    let publicData = JSON.parse(new TextDecoder().decode(lookupDataJsonBytes));

    if (publicData.expiresAt && new Date(publicData.expiresAt) < new Date()) {
        return new Response(JSON.stringify({ error: 'This share link has expired.' }), { status: 410, headers: { 'Content-Type': 'application/json' } });
    }

    if (publicData.maxClicks && publicData.clickCount >= publicData.maxClicks) {
        return new Response(JSON.stringify({ error: 'This share link has reached its access limit.' }), { status: 410, headers: { 'Content-Type': 'application/json' } });
    }

    const fileId = await env.SHARE_LOOKUP.get(`${SHARE_FILE_MAP_PREFIX}${shareId}`);
    if (!fileId) {
        return new Response(JSON.stringify({ error: 'File mapping not found for this share link.' }), { status: 500, headers: { 'Content-Type': 'application/json' } });
    }
    
    publicData.fileId = fileId;
    publicData.clickCount = (publicData.clickCount || 0) + 1;
    
    const newLookupDataJson = JSON.stringify(publicData);
    const newSignature = await computeHmac(new TextEncoder().encode(newLookupDataJson), env.METADATA_SECRET);
    const newSignedLookupData = {
        data: uint8ToBase64(new TextEncoder().encode(newLookupDataJson)),
        signature: newSignature
    };
    await env.SHARE_LOOKUP.put(shareLookupKey, JSON.stringify(newSignedLookupData));

    const shareStoreKey = `${SHARE_STORE_PREFIX}${fileId}`;
    let shareStoreData = await env.SHARE_STORE.get(shareStoreKey, { type: 'json' });
    if (shareStoreData && shareStoreData.links[shareId]) {
        shareStoreData.links[shareId].clickCount = publicData.clickCount;
        await env.SHARE_STORE.put(shareStoreKey, JSON.stringify(shareStoreData));
    }

    const headers = {
        'Content-Type': 'application/json',
        'Cache-Control': 'no-store, no-cache, must-revalidate, proxy-revalidate',
        'Pragma': 'no-cache',
        'Expires': '0'
    };

    return new Response(JSON.stringify(publicData), { headers: headers });
}

async function handleDownloadSharedFile(request, env, params) {
    const [shareId] = params;
    if (!ALLOWED_SHARE_ID_REGEX.test(shareId)) {
        return new Response('Invalid share ID.', { status: 400 });
    }

    const clientIp = request.headers.get('CF-Connecting-IP');
    const rateLimit = await checkRateLimit(`public_access_attempts:${clientIp}`, env.KV_LOGIN_ATTEMPTS, 30, 60);
    if (!rateLimit.allowed) {
        return new Response('Too many requests.', { status: 429 });
    }
    
    await recordRateLimitAttempt(`public_access_attempts:${clientIp}`, env.KV_LOGIN_ATTEMPTS, 60);

    const fileId = await env.SHARE_LOOKUP.get(`${SHARE_FILE_MAP_PREFIX}${shareId}`);
    if (!fileId) {
        return new Response('Share link not found or mapping is missing.', { status: 404 });
    }

    const shareLookupKey = `${SHARE_LOOKUP_PREFIX}${shareId}`;
    const signedLookupData = await env.SHARE_LOOKUP.get(shareLookupKey, { type: 'json' });

    if (!signedLookupData || !signedLookupData.data || !signedLookupData.signature) {
        return new Response('Share link metadata not found or is corrupt.', { status: 404 });
    }

    const lookupDataJsonBytes = base64ToUint8(signedLookupData.data);
    const expectedSignature = await computeHmac(lookupDataJsonBytes, env.METADATA_SECRET);

    if (!timingSafeEqual(hexToBytes(expectedSignature), hexToBytes(signedLookupData.signature))) {
        console.error(`CRITICAL: Share link metadata integrity check failed for shareId during download attempt: ${shareId}`);
        return new Response('Server integrity error.', { status: 500 });
    }
    
    const publicData = JSON.parse(new TextDecoder().decode(lookupDataJsonBytes));

    if (publicData.expiresAt && new Date(publicData.expiresAt) < new Date()) {
        return new Response('This share link has expired.', { status: 410 });
    }

    if (publicData.maxClicks && publicData.clickCount >= publicData.maxClicks) {
        return new Response('This share link has reached its access limit.', { status: 410 });
    }

    const object = await env.R2_BUCKET.get(fileId);
    if (!object) {
        return new Response('File not found.', { status: 404 });
    }

    const headers = new Headers();
    object.writeHttpMetadata(headers);
    headers.set('ETag', object.etag);
    headers.set('Content-Disposition', `attachment; filename*=UTF-8''${encodeURIComponent(publicData.fileName)}`);

    return new Response(object.body, { headers });
}

const routes = {
    'POST /api/login': handleLogin,
    'POST /api/logout': handleLogout,
    'HEAD /api/session-check': handleHeadRequest,
    'GET /api/e2e-meta': handleGetE2EMeta,
    'POST /api/e2e-setup': handlePostE2ESetup,
    'GET /api/manifest': handleGetManifest,
    'POST /api/upload': handleUploadFile,
    'GET /api/download': handleDownloadFile,
    'POST /api/delete': handleDeleteFile,
    'POST /api/e2e-reset-stage': handleE2EResetStage,
    'POST /api/e2e-reset-commit': handleE2EResetCommit,
    'GET /api/e2e-version': handleGetVersion,
    'POST /api/manifest-update': handleUpdateManifest,
    'GET|^/api/files/([a-f0-9\\-]+)/shares$|': handleGetShares,
    'POST|^/api/files/([a-f0-9\\-]+)/shares$|': handleCreateShare,
    'PATCH|^/api/files/([a-f0-9\\-]+)/shares/([a-f0-9\\-]+)$|': handlePatchShare,
    'DELETE|^/api/files/([a-f0-9\\-]+)/shares/([a-f0-9\\-]+)$|': handleDeleteShare,
    'GET|^/api/share/public/([a-f0-9\\-]+)$|': handleGetPublicShare,
    'GET|^/api/share/download/([a-f0-9\\-]+)$|': handleDownloadSharedFile,
};

export default {
    async fetch(request, env) {
        if (request.method === 'OPTIONS') {
            return new Response(null, { headers: corsHeaders });
        }

        let response;
        let authResult = {};

        try {
            const requiredSecrets = [
                'ADMIN_USERNAME_HASH', 'ADMIN_USERNAME_SALT', 'ADMIN_PASSWORD_HASH',
                'ADMIN_PASSWORD_SALT', 'TOKEN_SECRET', 'MANIFEST_SECRET', 'JWT_PRIVATE_KEY',
                'JWT_PUBLIC_KEY', 'METADATA_SECRET', 'KV_TOKEN_DENYLIST', 'KV_SESSIONS', 
                'SHARE_STORE', 'SHARE_LOOKUP', 'KV_LOGIN_ATTEMPTS', 'KV_OWNERSHIP'
            ];
            for (const secret of requiredSecrets) {
                if (!env[secret]) {
                    console.error(`FATAL: Secret or binding ${secret} is not configured.`);
                    throw new Error('Server is not configured correctly.');
                }
            }

            const url = new URL(request.url);
            let path = url.pathname;

            if (BASE_PATH && path.startsWith(BASE_PATH)) {
                path = path.substring(BASE_PATH.length) || '/';
            }

            const routeKey = `${request.method} ${path}`;
            let handler;
            let params;
            let routePattern;

            if (routes[routeKey]) {
                handler = routes[routeKey];
                routePattern = routeKey;
            } else {
                for (const pattern in routes) {
                    if (!pattern.includes('|')) continue;
                    const [method, regexStr] = pattern.split('|');
                    if (request.method === method) {
                        const regex = new RegExp(regexStr);
                        const match = path.match(regex);
                        if (match) {
                            handler = routes[pattern];
                            params = match.slice(1);
                            routePattern = pattern;
                            break;
                        }
                    }
                }
            }

            if (handler) {
                const publicRoutes = new Set([
                    'POST /api/login',
                    'POST /api/logout',
                    'GET|^/api/share/public/([a-f0-9\\-]+)$|',
                    'GET|^/api/share/download/([a-f0-9\\-]+)$|'
                ]);

                if (publicRoutes.has(routePattern)) {
                    response = await handler(request, env, params);
                } else {
                    authResult = await authenticate(request, env);
                    if (authResult.user) {
                        response = await handler(request, env, params, authResult.user);
                    } else {
                        response = new Response(JSON.stringify({ error: 'Forbidden' }), { status: 403 });
                    }
                }
            } else {
                response = new Response('Not Found', { status: 404 });
            }

        } catch (e) {
            console.error("Caught unhandled exception:", e);
            response = new Response('An internal server error occurred.', { status: 500 });
        }

        const finalResponse = new Response(response.body, response);
        Object.entries(corsHeaders).forEach(([key, value]) => finalResponse.headers.set(key, value));

        if (response.status === 403) {
             const clearCookieString = `auth_token=; Max-Age=0; Path=${BASE_PATH || '/'}; Domain=.domain.com; SameSite=None; Secure; HttpOnly`;
             finalResponse.headers.set('Set-Cookie', clearCookieString);
        }

        if (authResult.user && response.status >= 200 && response.status < 300) {
            const now = Math.floor(Date.now() / 1000);
            if (now - authResult.user.lastActivity > 60) {
                 const newPayload = { ...authResult.user, iat: now, nbf: now, lastActivity: now, exp: authResult.user.exp };
                 const newToken = await signJwt(newPayload, env.JWT_PRIVATE_KEY);
                 const newCookieString = `auth_token=${newToken}; Max-Age=${TOKEN_EXPIRATION_SECONDS}; Path=${BASE_PATH || '/'}; Domain=.domain.com; SameSite=None; Secure; HttpOnly`;
                 finalResponse.headers.set('Set-Cookie', newCookieString);
            }
        } else if (response.headers.has('Set-Cookie')) {
            finalResponse.headers.set('Set-Cookie', response.headers.get('Set-Cookie'));
        }

        return finalResponse;
    }
};