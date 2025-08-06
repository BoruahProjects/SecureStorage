const BASE_PATH = 'https://files.domain.com';

const MAX_FILE_SIZE_BYTES = 100 * 1024 * 1024;
const MAX_TOTAL_STORAGE_MB = 10240;
const MAX_TOTAL_STORAGE_BYTES = MAX_TOTAL_STORAGE_MB * 1024 * 1024;
const ITEMS_PER_PAGE = 10;
const AUTO_LOGOUT_GRACE_PERIOD_MS = 1000;
const SESSION_CHECK_INTERVAL_MS = 5 * 1000;

const logoutChannel = new BroadcastChannel('logout_channel');

let logoutTimeoutId = null;
let sessionCheckIntervalId = null;
let tokenExpirationTimestamp = null;
let manifestVersion = 0;
let e2eKeys = { manifestKey: null, fileKey: null };
let e2eSalt = null;
let manifest = { items: {} };
let isResetMode = false;
let currentObjectUrl = null;

async function deriveKeysFromPassword(password, salt) {
    const passwordEncoder = new TextEncoder();
    const passwordBuffer = passwordEncoder.encode(password);

    try {
        const keyMaterial = await crypto.subtle.importKey(
            'raw',
            passwordBuffer,
            { name: 'PBKDF2' },
            false,
            ['deriveBits']
        );

        const masterKeyRaw = await crypto.subtle.deriveBits(
            {
                name: 'PBKDF2',
                salt: salt,
                iterations: 1000000,
                hash: 'SHA-256'
            },
            keyMaterial,
            256 
        );

        const ikm = await crypto.subtle.importKey(
            'raw',
            masterKeyRaw,
            'HKDF',
            false,
            ['deriveBits']
        );

        const manifestKeyData = await crypto.subtle.deriveBits(
            {
                name: 'HKDF',
                hash: 'SHA-256',
                salt: new Uint8Array(),
                info: new TextEncoder().encode('manifest-key')
            },
            ikm,
            256
        );

        const fileKeyData = await crypto.subtle.deriveBits(
            {
                name: 'HKDF',
                hash: 'SHA-256',
                salt: new Uint8Array(),
                info: new TextEncoder().encode('file-key')
            },
            ikm,
            256
        );

        const manifestKey = await crypto.subtle.importKey(
            'raw',
            manifestKeyData,
            { name: 'AES-GCM' },
            false, 
            ['encrypt', 'decrypt']
        );
        const fileKey = await crypto.subtle.importKey(
            'raw',
            fileKeyData,
            { name: 'AES-GCM' },
            true, 
            ['encrypt', 'decrypt']
        );

        return { manifestKey, fileKey };

    } finally {
        passwordBuffer.fill(0);
    }
}

function padAndPrefixManifest(encryptedManifest) {
    const blockSize = 4096;
    const originalLength = encryptedManifest.byteLength;
    const paddedLength = Math.ceil((originalLength + 4) / blockSize) * blockSize;

    const finalBuffer = new Uint8Array(paddedLength);
    const view = new DataView(finalBuffer.buffer);

    view.setUint32(0, originalLength, false);

    finalBuffer.set(encryptedManifest, 4);

    if (finalBuffer.length > originalLength + 4) {
        crypto.getRandomValues(finalBuffer.subarray(originalLength + 4));
    }

    return finalBuffer;
}

function unprefixAndUnpadManifest(paddedManifest) {
    if (paddedManifest.byteLength < 4) {
        throw new Error("Invalid padded manifest: too short.");
    }
    const view = new DataView(paddedManifest.buffer);
    const originalLength = view.getUint32(0, false);

    if (4 + originalLength > paddedManifest.byteLength) {
        throw new Error("Invalid padded manifest: length prefix is incorrect.");
    }

    return paddedManifest.subarray(4, 4 + originalLength);
}

function showPage(pageId) {
    document.querySelectorAll('.page').forEach(page => {
        page.classList.add('hidden');
    });
    const page = document.getElementById(pageId);
    const appContainer = document.getElementById('app-container');
    page.classList.remove('hidden');

    if (page.classList.contains('centered-page')) {
        appContainer.classList.add('justify-center', 'items-center');
    } else {
        appContainer.classList.remove('justify-center', 'items-center');
    }
}

function navigateUp() {
    if (currentPath === '') return;

    const trimmedPath = currentPath.slice(0, -1);
    const lastSlashIndex = trimmedPath.lastIndexOf('/');

    currentPath = (lastSlashIndex !== -1) ? trimmedPath.substring(0, lastSlashIndex + 1) : '';

    currentPage = 1;
    renderFiles();
}

function showSpinner(button, text = '') {
    button.disabled = true;
    if (!button.dataset.originalContent) {
        button.dataset.originalContent = button.innerHTML;
    }
    button.innerHTML = '<div class="spinner"></div>' + (text ? '<span class="spinner-text">' + text + '</span>' : '');
}

function hideSpinner(button) {
    if (button.dataset.originalContent) {
        button.innerHTML = button.dataset.originalContent;
    }
    button.disabled = false;
}

function showModal(modalId) {
    document.getElementById(modalId).classList.remove('hidden');
}

function hideModal(modalId) {
    document.getElementById(modalId).classList.add('hidden');
}

function showMessageBox(message, type = 'info', callback = null) {
    const msgBoxOverlay = document.getElementById('message-box-overlay');
    const msgBoxCard = document.getElementById('message-box-card');
    const msgBoxText = document.getElementById('message-box-text');
    const msgBoxCloseBtn = document.getElementById('message-box-close-btn');
    const msgBoxOkBtn = document.getElementById('message-box-ok-btn');

    msgBoxCard.classList.remove('message-box-info', 'message-box-success', 'message-box-error');
    msgBoxCard.classList.add('message-box-' + type);
    msgBoxText.textContent = message;

    msgBoxOverlay.classList.remove('hidden');

    const closeHandler = () => {
        msgBoxOverlay.classList.add('hidden');
        msgBoxCloseBtn.removeEventListener('click', closeHandler);
        msgBoxOkBtn.removeEventListener('click', closeHandler);
        if (callback) callback();
    };

    msgBoxCloseBtn.addEventListener('click', closeHandler);
    msgBoxOkBtn.addEventListener('click', closeHandler);
}

let confirmActionCallback = null;
function showConfirmActionModal(title, message, confirmBtnText = 'Confirm', type = 'primary', onConfirm) {
    const modal = document.getElementById('confirm-action-modal');
    document.getElementById('confirm-action-title').textContent = title;
    document.getElementById('confirm-action-message').textContent = message;
    const confirmButton = document.getElementById('confirm-action-button');
    const cancelButton = document.getElementById('cancel-confirm-action');
    const errorElement = document.getElementById('confirm-action-error');

    confirmButton.classList.remove('primary-button', 'danger-button', 'secondary-button');
    confirmButton.classList.add(type + '-button');
    confirmButton.textContent = confirmBtnText;
    errorElement.classList.add('hidden');
    errorElement.textContent = '';

    confirmActionCallback = onConfirm;

    confirmButton.onclick = async () => {
        showSpinner(confirmButton);
        try {
            await confirmActionCallback();
            hideModal('confirm-action-modal');
        } catch (error) {
            errorElement.textContent = (error && error.message) ? error.message : 'An unknown error occurred.';
            errorElement.classList.remove('hidden');
        } finally {
            hideSpinner(confirmButton);
        }
    };

    cancelButton.onclick = () => {
        hideModal('confirm-action-modal');
        confirmActionCallback = null;
    };

    showModal('confirm-action-modal');
}

function padFileBuffer(buffer, minPadding = 1024, maxPadding = 16384) {
    const paddingLength = Math.floor(Math.random() * (maxPadding - minPadding + 1)) + minPadding;
    const paddedBuffer = new Uint8Array(buffer.byteLength + paddingLength);
    paddedBuffer.set(new Uint8Array(buffer), 0);
    crypto.getRandomValues(paddedBuffer.subarray(buffer.byteLength));
    return { buffer: paddedBuffer, padding: paddingLength };
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

function uint8ToBase64Url(bytes) {
    return btoa(String.fromCharCode.apply(null, bytes))
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=/g, '');
}

function escapeHtml(unsafe) {
    return unsafe
         .replace(/&/g, "&amp;")
         .replace(/</g, "&lt;")
         .replace(/>/g, "&gt;")
         .replace(/"/g, "&quot;")
         .replace(/'/g, "&#039;");
}

async function encrypt(data, key, additionalData) {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const encoder = new TextEncoder();
    const encodedData = typeof data === 'string' ? encoder.encode(data) : data;

    const params = { name: 'AES-GCM', iv: iv };
    if (additionalData) {
        params.additionalData = new TextEncoder().encode(additionalData);
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
        params.additionalData = new TextEncoder().encode(additionalData);
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

async function handleLogin(event) {
    event.preventDefault();
    const usernameInput = document.getElementById('username-input');
    const passwordInput = document.getElementById('password-input');
    const loginError = document.getElementById('login-error');
    const loginButton = document.getElementById('login-button');
    const username = usernameInput.value;
    const password = passwordInput.value;

    loginError.textContent = '';
    showSpinner(loginButton, 'Logging in...');

    try {
        const response = await fetch(BASE_PATH + '/api/login', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, password }),
            credentials: 'include'
        });

        const data = await response.json();

        if (response.ok && data.success) {
            tokenExpirationTimestamp = data.exp * 1000;
            scheduleLogoutTimer(tokenExpirationTimestamp);
            startSessionCheckInterval();
            await checkE2ESetup();
        } else {
            loginError.textContent = data.message || 'Login failed. Please try again.';
        }
    } catch (error) {
        loginError.textContent = 'Network error or server unavailable.';
    } finally {
        hideSpinner(loginButton);
    }
}

function handleClientSideLogout(message = null, broadcast = true) {
    if (broadcast) {
        logoutChannel.postMessage({ command: 'logout' });
    }

    tokenExpirationTimestamp = null;
    if (logoutTimeoutId) {
        clearTimeout(logoutTimeoutId);
        logoutTimeoutId = null;
    }
    if (sessionCheckIntervalId) {
        clearInterval(sessionCheckIntervalId);
        sessionCheckIntervalId = null;
    }

    e2eKeys = { manifestKey: null, fileKey: null };

    if (e2eSalt) {
        e2eSalt.fill(0);
        e2eSalt = null;
    }

    manifest = { items: {} };
    isResetMode = false;

    hideSpinner(document.getElementById('e2e-submit-button'));

    showPage('login-page');
    document.getElementById('username-input').value = '';
    document.getElementById('password-input').value = '';

    if (message) {
        showMessageBox(message, 'info');
    }
}

async function handleLogout() {
    try {
        await fetch(BASE_PATH + '/api/logout', { method: 'POST', credentials: 'include' });
    } catch (error) {
        console.error("Logout failed on server, but logging out client-side anyway.");
    } finally {
        handleClientSideLogout(null);
    }
}

logoutChannel.onmessage = (event) => {
    if (event.data.command === 'logout') {
        handleClientSideLogout('Logged out from another tab.', false);
    }
};

function scheduleLogoutTimer(expiryTimestampMs) {
    if (logoutTimeoutId) clearTimeout(logoutTimeoutId);
    const timeUntilLogout = (expiryTimestampMs + AUTO_LOGOUT_GRACE_PERIOD_MS) - Date.now();
    if (timeUntilLogout > 0) {
        logoutTimeoutId = setTimeout(() => {
            handleClientSideLogout('Your session has expired. Please log in again.');
        }, timeUntilLogout);
    } else {
        handleClientSideLogout('Your session has expired. Please log in again.');
    }
}

function startSessionCheckInterval() {
    if (sessionCheckIntervalId) clearInterval(sessionCheckIntervalId);
    sessionCheckIntervalId = setInterval(checkSessionValidity, SESSION_CHECK_INTERVAL_MS);
}

async function checkSessionValidity() {
    const storedExpiry = tokenExpirationTimestamp;
    if (!storedExpiry || Date.now() > storedExpiry) {
        handleClientSideLogout('Your session has expired. Please log in again.');
        return;
    }
    try {
        const response = await fetch(BASE_PATH + '/api/session-check', { method: 'HEAD', credentials: 'include' });
        if (!response.ok) {
            handleClientSideLogout('Your session is no longer valid. Please log in again.');
        }
    } catch (error) {
         handleClientSideLogout('Network error or session invalid. Please log in again.');
    }
}

async function checkLoginStatus() {
    if (window.location.pathname.endsWith('/share.html')) {
        return;
    }

    const storedExpiry = tokenExpirationTimestamp;

    if (storedExpiry && Date.now() < storedExpiry) {
        try {
            const response = await fetch(BASE_PATH + '/api/session-check', { method: 'HEAD', credentials: 'include' });
            if (response.ok) {
                scheduleLogoutTimer(storedExpiry);
                startSessionCheckInterval();
                await checkE2ESetup();
            } else {
                showPage('login-page');
            }
        } catch (error) {
            showPage('login-page');
        }
    } else {
        showPage('login-page');
    }
    document.body.classList.remove('app-loading');
}

async function checkE2ESetup() {
    try {
        const [metaResponse, versionResponse] = await Promise.all([
            fetch(BASE_PATH + '/api/e2e-meta', { credentials: 'include' }),
            fetch(BASE_PATH + '/api/e2e-version', { credentials: 'include' })
        ]);

        if (!metaResponse.ok || !versionResponse.ok) {
            throw new Error("Failed to fetch encryption metadata from server.");
        }
        const metaData = await metaResponse.json();
        const versionData = await versionResponse.json();

        trustedManifestVersion = versionData.version;

        const e2eTitle = document.getElementById('e2e-title');
        const e2eSubtitle = document.getElementById('e2e-subtitle');
        const e2eConfirmContainer = document.getElementById('e2e-confirm-container');
        const e2eConfirmInput = document.getElementById('e2e-confirm-password-input');
        const e2eHintContainer = document.getElementById('e2e-hint-container');
        const e2eHintDisplay = document.getElementById('e2e-hint-display');
        const e2eOldPasswordContainer = document.getElementById('e2e-old-password-container');
        const e2eActionsContainer = document.getElementById('e2e-actions-container');
        const e2eResetButton = document.getElementById('e2e-reset-button');

        if (metaData.setup) {
            e2eSalt = base64ToUint8(metaData.salt);
            e2eTitle.textContent = 'Unlock Storage';
            e2eSubtitle.textContent = 'Enter your encryption password to continue.';
            e2eConfirmContainer.classList.add('hidden');
            e2eConfirmInput.required = false;
            e2eHintContainer.classList.add('hidden');
            if(metaData.hint) {
                e2eHintDisplay.textContent = 'Hint: ' + metaData.hint;
                e2eHintDisplay.classList.remove('hidden');
            } else {
                e2eHintDisplay.classList.add('hidden');
            }
            e2eResetButton.disabled = false;
            e2eResetButton.classList.remove('hidden');
            e2eResetButton.textContent = 'Reset Password';
            e2eResetButton.classList.add('link-button');
            e2eResetButton.classList.remove('secondary-button');
            e2eActionsContainer.className = 'd-flex flex-col items-center gap-1 mt-1';
        } else {
            e2eTitle.textContent = 'Setup Encryption';
            e2eSubtitle.textContent = 'Create a strong password to encrypt your files. This password cannot be recovered.';
            e2eConfirmContainer.classList.remove('hidden');
            e2eConfirmInput.required = true;
            e2eHintContainer.classList.remove('hidden');
            e2eHintDisplay.classList.add('hidden');
            e2eResetButton.disabled = true;
            e2eResetButton.classList.add('hidden');
            e2eActionsContainer.className = 'd-flex flex-col items-center gap-1 mt-1';
        }
        e2eOldPasswordContainer.classList.add('hidden');
        document.getElementById('e2e-password-input').value = '';
        e2eConfirmInput.value = '';
        document.getElementById('e2e-old-password-input').value = '';
        document.getElementById('e2e-error').textContent = '';
        isResetMode = false;
        showPage('e2e-page');

    } catch (e) {
        showMessageBox('Could not check encryption status. Please try again. ' + e.message, 'error', () => handleLogout());
    }
}

async function handleE2EFormSubmit(e) {
    e.preventDefault();
    const e2eError = document.getElementById('e2e-error');
    const e2eSubmitButton = document.getElementById('e2e-submit-button');
    e2eError.textContent = '';
    showSpinner(e2eSubmitButton);

    if (isResetMode) {
        await handleE2EReset();
    } else if (e2eSalt) {
        await handleE2EUnlock();
    } else {
        await handleE2EInitialSetup();
    }

    hideSpinner(e2eSubmitButton);
}

const enterResetModeHandler = () => {
    isResetMode = true;
    const e2eTitle = document.getElementById('e2e-title');
    const e2eSubtitle = document.getElementById('e2e-subtitle');
    const e2eOldPasswordContainer = document.getElementById('e2e-old-password-container');
    const e2eConfirmContainer = document.getElementById('e2e-confirm-container');
    const e2eConfirmInput = document.getElementById('e2e-confirm-password-input');
    const e2eHintContainer = document.getElementById('e2e-hint-container');
    const e2eHintDisplay = document.getElementById('e2e-hint-display');
    const e2eResetButton = document.getElementById('e2e-reset-button');
    const e2eActionsContainer = document.getElementById('e2e-actions-container');

    e2eTitle.textContent = 'Reset Encryption Password';
    e2eSubtitle.textContent = 'Enter your current and new password. This will re-encrypt all your data.';
    e2eOldPasswordContainer.classList.remove('hidden');
    e2eConfirmContainer.classList.remove('hidden');
    e2eConfirmInput.required = true;
    e2eHintContainer.classList.remove('hidden');
    e2eHintDisplay.classList.add('hidden');

    e2eResetButton.textContent = 'Cancel';
    e2eResetButton.classList.remove('link-button');
    e2eResetButton.classList.add('secondary-button');

    e2eActionsContainer.className = 'd-flex flex-row-reverse justify-center gap-2 mt-1';

    e2eResetButton.removeEventListener('click', enterResetModeHandler);
    e2eResetButton.addEventListener('click', cancelResetModeHandler);
};

const cancelResetModeHandler = (e) => {
    if (e) e.preventDefault();
    const e2eResetButton = document.getElementById('e2e-reset-button');
    checkE2ESetup();
    e2eResetButton.removeEventListener('click', cancelResetModeHandler);
    e2eResetButton.addEventListener('click', enterResetModeHandler);
};

async function handleE2EUnlock() {
    const e2ePasswordInput = document.getElementById('e2e-password-input');
    const e2eError = document.getElementById('e2e-error');
    const e2eSubmitButton = document.getElementById('e2e-submit-button');
    const password = e2ePasswordInput.value;
    if (!password) {
        e2eError.textContent = 'Password is required.';
        return;
    }
    showSpinner(e2eSubmitButton, 'Unlocking...');
    const keys = await deriveKeysFromPassword(password, e2eSalt);

    try {
        const response = await fetch(BASE_PATH + '/api/manifest', { credentials: 'include' });
        if (!response.ok) throw new Error('Could not fetch file manifest.');
        const paddedManifest = new Uint8Array(await response.arrayBuffer());

        const encryptedManifest = unprefixAndUnpadManifest(paddedManifest);

        const decryptedManifestJson = await decryptText(encryptedManifest, keys.manifestKey, e2eSalt);
        if (decryptedManifestJson === null) {
            e2eError.textContent = 'Incorrect password.';
            return;
        }

        let decryptedManifest = JSON.parse(decryptedManifestJson);

        if (decryptedManifest.version < trustedManifestVersion) {
            throw new Error("Manifest version mismatch indicates a potential rollback attack. Logging out for safety.");
        }

        if (typeof decryptedManifest.version === 'undefined' && decryptedManifest.items) {
            decryptedManifest = { version: 1, items: decryptedManifest.items };
        } else if (typeof decryptedManifest.version !== 'number') {
            throw new Error('Manifest is malformed or corrupt (missing version).');
        }

        manifest = decryptedManifest;
        manifestVersion = manifest.version;
        e2eKeys = keys;

        showPage('dashboard-page');
        fetchFiles();

    } catch (err) {
        e2eError.textContent = 'Failed to unlock storage. ' + err.message;
        showMessageBox(err.message, 'error', () => handleLogout());
    }
}

async function handleE2EInitialSetup() {
    const e2ePasswordInput = document.getElementById('e2e-password-input');
    const e2eConfirmInput = document.getElementById('e2e-confirm-password-input');
    const e2eHintInput = document.getElementById('e2e-hint-input');
    const e2eError = document.getElementById('e2e-error');
    const e2eSubmitButton = document.getElementById('e2e-submit-button');

    const password = e2ePasswordInput.value;
    const confirmPassword = e2eConfirmInput.value;
    const hint = e2eHintInput.value;

    if (password.length < 8) {
        e2eError.textContent = 'Password must be at least 8 characters.'; return;
    }
    if (password !== confirmPassword) {
        e2eError.textContent = 'Passwords do not match.'; return;
    }
    showSpinner(e2eSubmitButton, 'Setting up...');
    e2eSalt = crypto.getRandomValues(new Uint8Array(32));
    const keys = await deriveKeysFromPassword(password, e2eSalt);

    const emptyManifest = { version: 1, items: {} };
    const encryptedManifest = await encrypt(JSON.stringify(emptyManifest), keys.manifestKey, e2eSalt);

    const paddedManifest = padAndPrefixManifest(encryptedManifest);

    try {
        const response = await fetch(BASE_PATH + '/api/e2e-setup', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                salt: uint8ToBase64(e2eSalt),
                hint: hint,
                manifest: uint8ToBase64(paddedManifest)
            }),
            credentials: 'include'
        });
        if (!response.ok) throw new Error('Server rejected setup.');

        manifest = emptyManifest;
        manifestVersion = manifest.version;
        e2eKeys = keys;

        showPage('dashboard-page');
        fetchFiles();
    } catch (err) {
        e2eError.textContent = 'Failed to setup encryption. ' + err.message;
    }
}

async function handleE2EReset() {
    const e2eOldPasswordInput = document.getElementById('e2e-old-password-input');
    const e2ePasswordInput = document.getElementById('e2e-password-input');
    const e2eConfirmInput = document.getElementById('e2e-confirm-password-input');
    const e2eHintInput = document.getElementById('e2e-hint-input');
    const e2eError = document.getElementById('e2e-error');
    const e2eSubmitButton = document.getElementById('e2e-submit-button');
    const e2eResetButton = document.getElementById('e2e-reset-button');

    const oldPassword = e2eOldPasswordInput.value;
    const newPassword = e2ePasswordInput.value;
    const confirmPassword = e2eConfirmInput.value;
    const newHint = e2eHintInput.value;

    if (!oldPassword) { e2eError.textContent = 'Current password is required.'; return; }
    if (newPassword.length < 8) { e2eError.textContent = 'New password must be at least 8 characters.'; return; }
    if (newPassword !== confirmPassword) { e2eError.textContent = 'New passwords do not match.'; return; }

    showSpinner(e2eSubmitButton, 'Verifying...');

    const oldKeys = await deriveKeysFromPassword(oldPassword, e2eSalt);
    let currentManifest;

    try {
        const res = await fetch(BASE_PATH + '/api/manifest', { credentials: 'include' });

        if (res.status === 404 || res.headers.get('content-length') === '0') {
            currentManifest = { version: 0, items: {} };
        } else if (!res.ok) {
            throw new Error('Could not fetch manifest (' + res.status + ')');
        } else {
            const paddedManifest = new Uint8Array(await res.arrayBuffer());

            const encryptedManifest = unprefixAndUnpadManifest(paddedManifest);
            const decrypted = await decryptText(encryptedManifest, oldKeys.manifestKey, e2eSalt);

            if (decrypted === null) {
                e2eError.textContent = 'Incorrect current password.';
                hideSpinner(e2eSubmitButton);
                return;
            }
            try {
                currentManifest = JSON.parse(decrypted);
            } catch (jsonError) {
                throw new Error("Manifest is corrupted and could not be read.");
            }
        }
    } catch (err) {
        e2eError.textContent = 'Failed to load current data: ' + err.message;
        hideSpinner(e2eSubmitButton);
        return;
    }

    const newSalt = crypto.getRandomValues(new Uint8Array(32));
    const newKeys = await deriveKeysFromPassword(newPassword, newSalt);

    const filesToReencrypt = [];
    const oldFileKeys = [];
    const newManifestItems = {};

    let commitResponse;

    try {
        for (const id in currentManifest.items) {
            const item = currentManifest.items[id];
            if (!item.encryptedPath) continue;

            const decryptedPath = await decryptText(base64ToUint8(item.encryptedPath), oldKeys.fileKey);
            if (decryptedPath === null) {
                throw new Error('Failed to decrypt path for an item. Manifest may be corrupt.');
            }

            const newFileId = crypto.randomUUID();
            const reencryptedPath = await encrypt(decryptedPath, newKeys.fileKey);

            const newManifestItem = {
                encryptedPath: uint8ToBase64(reencryptedPath),
                size: item.size,
                date: item.date
            };
            if (item.isTrashed) {
                newManifestItem.isTrashed = true;
                newManifestItem.trashedAt = item.trashedAt;
            }
            newManifestItems[newFileId] = newManifestItem;


            if (!decryptedPath.endsWith('/')) {
                filesToReencrypt.push({
                    oldId: id,
                    newId: newFileId,
                });
            }
            oldFileKeys.push(id);
        }

        for (let i = 0; i < filesToReencrypt.length; i++) {
            const fileInfo = filesToReencrypt[i];
            const progressMessage = 'Re-encrypting ' + (i + 1) + '/' + filesToReencrypt.length + '...';
            showSpinner(e2eSubmitButton, progressMessage);

            const downloadResponse = await fetch(BASE_PATH + '/api/download?key=' + fileInfo.oldId, { credentials: 'include' });
            if (!downloadResponse.ok) {
                throw new Error('Failed to download file ID ' + fileInfo.oldId + '.');
            }

            const encryptedContent = new Uint8Array(await downloadResponse.arrayBuffer());
            let decryptedContent;
            try {
                decryptedContent = new Uint8Array(await decrypt(encryptedContent, oldKeys.fileKey, fileInfo.oldId));
                const reencryptedContent = await encrypt(decryptedContent, newKeys.fileKey, fileInfo.newId);

                const uploadResponse = await fetch(BASE_PATH + '/api/upload', {
                    method: 'POST',
                    headers: { 'X-File-Key': fileInfo.newId, 'Content-Type': 'application/octet-stream' },
                    body: reencryptedContent,
                    credentials: 'include'
                });
                if (!uploadResponse.ok) {
                    throw new Error('Failed to re-upload file ID ' + fileInfo.newId + '.');
                }
            } finally {
                if (decryptedContent) {
                    decryptedContent.fill(0);
                }
            }
        }

        showSpinner(e2eSubmitButton, 'Staging changes...');
        const newManifestForUpload = { version: (currentManifest.version || 0) + 1, items: newManifestItems };
        const newEncryptedManifest = await encrypt(JSON.stringify(newManifestForUpload), newKeys.manifestKey, newSalt);

        const paddedManifest = padAndPrefixManifest(newEncryptedManifest);

        const stageResponse = await fetch(BASE_PATH + '/api/e2e-reset-stage', {
            method: 'POST',
            headers: { 'Content-Type': 'application/octet-stream' },
            body: paddedManifest,
            credentials: 'include'
        });
        if (!stageResponse.ok) throw new Error('Server rejected the manifest staging.');

        showSpinner(e2eSubmitButton, 'Finalizing...');
        const newVersionForReset = newManifestForUpload.version;
        commitResponse = await fetch(BASE_PATH + '/api/e2e-reset-commit', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                newSalt: uint8ToBase64(newSalt),
                newHint: newHint,
                oldFileKeys: oldFileKeys,
                newVersion: newVersionForReset
            }),
            credentials: 'include'
        });

        if (!commitResponse.ok) {
            throw new Error('Server failed to commit the changes. Your data is safe with the old password.');
        }

        manifest = newManifestForUpload;
        e2eKeys = newKeys;
        e2eSalt = newSalt;
        manifestVersion = newVersionForReset;
        trustedManifestVersion = newVersionForReset;

        showMessageBox('Password reset successfully! All files have been re-encrypted.', 'success', () => {
            isResetMode = false;
            e2eResetButton.removeEventListener('click', cancelResetModeHandler);
            e2eResetButton.addEventListener('click', enterResetModeHandler);

            showPage('dashboard-page');
            fetchFiles();
        });

    } catch (err) {
        if (commitResponse) {
            try {
                const errorData = await commitResponse.json();
                if (errorData.action === 'force_logout') {
                    showMessageBox(errorData.message, 'error', () => handleLogout());
                    return;
                }
            } catch (jsonError) {
            }
        }

        e2eError.textContent = 'A critical error occurred: ' + err.message;
        showMessageBox('Reset failed: ' + err.message + '. Your data has not been changed.', 'error');

    } finally {
        hideSpinner(e2eSubmitButton);
    }
}

let allDecryptedFiles = [];
let filteredFiles = [];
let currentSort = 'uploaded_at-desc';
let currentSearchTerm = '';
let totalStorageUsed = 0;
let currentPath = '';
let currentPage = 1;
let totalPages = 1;
let selectedItems = new Set();
let selectedTrashItems = new Set();
let trustedManifestVersion = 0;


function formatBytes(bytes, decimals = 2) {
    if (bytes === null || bytes === undefined || isNaN(bytes) || bytes < 0) {
        return '0 Bytes';
    }
    if (bytes === 0) return '0 Bytes';

    const k = 1024;
    const dm = decimals < 0 ? 0 : decimals;
    const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(dm)) + ' ' + sizes[i];
}

function getMimeType(filename) {
    const extension = filename.split('.').pop().toLowerCase();
    const mimeTypes = {
        'jpg': 'image/jpeg',
        'jpeg': 'image/jpeg',
        'png': 'image/png',
        'gif': 'image/gif',
        'webp': 'image/webp',
        'svg': 'image/svg+xml',
        'pdf': 'application/pdf',
        'txt': 'text/plain',
        'md': 'text/markdown',
        'js': 'text/javascript',
        'json': 'application/json',
        'html': 'text/html',
        'css': 'text/css',
    };
    return mimeTypes[extension] || 'application/octet-stream';
}

function sanitizeTextContent(text) {
    const controlChars = /[\x00-\x08\x0B\x0C\x0E-\x1F\x7F-\x9F]/g;
    const invisibleOrBidiChars = /[\u202A-\u202E\u2066-\u2069\u200B-\u200D\uFEFF]/g;

    let sanitizedText = text.replace(controlChars, '');
    sanitizedText = sanitizedText.replace(invisibleOrBidiChars, '');

    return sanitizedText;
}

function isValidFilename(name) {
    if (!name || !name.trim()) return false;
    const trimmedName = name.trim();
    if (trimmedName.length > 255) return false;
    if (trimmedName !== name) return false;
    if (new RegExp('[\\\\/]').test(trimmedName)) return false;
    if (trimmedName.includes('..') || trimmedName.includes('\0')) return false;
    const controlCharsRegex = new RegExp('[\\u0000-\\u001F\\u007F-\\u009F\\u200B-\\u200F\\u202A-\\u202E\\u2060-\\u206F]');
    if (controlCharsRegex.test(trimmedName)) return false;

    return true;
}

function renderBreadcrumbs() {
    const breadcrumbDiv = document.getElementById('breadcrumb');
    breadcrumbDiv.innerHTML = '';
    const pathSegments = currentPath.split('/').filter(segment => segment !== '');

    const homeLink = document.createElement('a');
    homeLink.textContent = 'Home';
    homeLink.addEventListener('click', (e) => {
        e.preventDefault();
        currentPath = '';
        currentPage = 1;
        applyFiltersAndSort();
    });
    breadcrumbDiv.appendChild(homeLink);

    let cumulativePath = '';
    pathSegments.forEach((segment, index) => {
        cumulativePath += segment + '/';
        const span = document.createElement('span');
        span.textContent = '>';
        breadcrumbDiv.appendChild(span);

        if (index === pathSegments.length - 1) {
            const currentFolderSpan = document.createElement('span');
            currentFolderSpan.textContent = escapeHtml(segment);
            currentFolderSpan.classList.add('current-folder');
            breadcrumbDiv.appendChild(currentFolderSpan);
        } else {
            const folderLink = document.createElement('a');
            folderLink.textContent = escapeHtml(segment);
            const pathToGo = cumulativePath;
            folderLink.addEventListener('click', (e) => {
                e.preventDefault();
                currentPath = pathToGo;
                currentPage = 1;
                applyFiltersAndSort();
            });
            breadcrumbDiv.appendChild(folderLink);
        }
    });

    document.getElementById('go-up-button').classList.toggle('hidden', currentPath === '');
}

function renderFiles() {
    const fileListBody = document.getElementById('file-list-body');
    const fileListStatus = document.getElementById('file-list-status');
    const selectAllCheckbox = document.getElementById('select-all-checkbox');
    fileListBody.innerHTML = '';
    renderBreadcrumbs();

    const itemsInCurrentDir = allDecryptedFiles.filter(item => {
        if (item.isTrashed) {
            return false;
        }
        const normalizedItemPath = item.path.endsWith('/') ? item.path.slice(0, -1) : item.path;
        if (normalizedItemPath.startsWith(currentPath)) {
            const relativePath = normalizedItemPath.substring(currentPath.length);
            return !relativePath.includes('/');
        }
        return false;
    });

    let folders = itemsInCurrentDir.filter(item => item.isFolder);
    let files = itemsInCurrentDir.filter(item => !item.isFolder);

    folders.sort((a, b) => a.name.localeCompare(b.name));

    const fileSortFunction = (a, b) => {
        switch (currentSort) {
            case 'name-asc': return a.name.localeCompare(b.name);
            case 'name-desc': return b.name.localeCompare(a.name);
            case 'uploaded_at-asc': return new Date(a.uploaded_at) - new Date(b.uploaded_at);
            case 'uploaded_at-desc': return new Date(b.uploaded_at) - new Date(a.uploaded_at);
            case 'size-asc': return a.size - b.size;
            case 'size-desc': return b.size - a.size;
            default: return 0;
        }
    };
    files.sort(fileSortFunction);

    let sortedItems = [...folders, ...files];

    if (currentSearchTerm) {
        const lowerCaseSearchTerm = currentSearchTerm.toLowerCase();
        sortedItems = sortedItems.filter(item => item.name.toLowerCase().includes(lowerCaseSearchTerm));
    }

    filteredFiles = sortedItems;

    const startIndex = (currentPage - 1) * ITEMS_PER_PAGE;
    const endIndex = startIndex + ITEMS_PER_PAGE;
    const filesToDisplay = filteredFiles.slice(startIndex, endIndex);

    if (filesToDisplay.length === 0) {
        fileListStatus.innerHTML = '<p>No files found.</p>';
        fileListStatus.classList.remove('hidden');
        document.getElementById('pagination-controls').classList.add('hidden');
        selectAllCheckbox.checked = false;
        selectedItems.clear();
        updateBulkActionBar();
        return;
    }
    fileListStatus.classList.add('hidden');

    filesToDisplay.forEach(file => {
        const row = document.createElement('tr');
        if (selectedItems.has(file.id)) {
            row.classList.add('selected');
        }
        const isFolder = file.isFolder;

        const selectCell = document.createElement('td');
        const checkbox = document.createElement('input');
        checkbox.type = 'checkbox';
        checkbox.dataset.id = file.id;
        checkbox.checked = selectedItems.has(file.id);
        checkbox.addEventListener('change', () => {
            if (checkbox.checked) {
                selectedItems.add(file.id);
                row.classList.add('selected');
            } else {
                selectedItems.delete(file.id);
                row.classList.remove('selected');
            }
            updateBulkActionBar();
        });
        selectCell.appendChild(checkbox);

        const nameCell = document.createElement('td');
        const nameDiv = document.createElement('div');
        nameDiv.className = 'flex items-center';

        let iconHtml;
        const iconClass = 'class="file-icon"';

        if (isFolder) {
            nameDiv.style.cursor = 'pointer';
            nameDiv.addEventListener('click', () => navigateToFolder(file.path));
            iconHtml = `<svg ${iconClass} xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#FFC107" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"></path></svg>`;
        } else {
            const extension = file.name.split('.').pop().toLowerCase();
            switch (extension) {
                case 'jpg': case 'jpeg': case 'png': case 'gif': case 'webp': case 'svg': case 'bmp':
                    iconHtml = `<svg ${iconClass} xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#42A5F5" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="3" width="18" height="18" rx="2" ry="2"></rect><circle cx="8.5" cy="8.5" r="1.5"></circle><polyline points="21 15 16 10 5 21"></polyline></svg>`;
                    break;
                case 'zip': case 'rar': case '7z': case 'tar': case 'gz':
                    iconHtml = `<svg ${iconClass} xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#FFA726" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 16V8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16z"></path><polyline points="3.27 6.96 12 12.01 20.73 6.96"></polyline><line x1="12" y1="22.08" x2="12" y2="12"></line></svg>`;
                    break;
                case 'pdf':
                    iconHtml = `<svg ${iconClass} xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#EF5350" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path><polyline points="14 2 14 8 20 8"></polyline><line x1="16" y1="13" x2="8" y2="13"></line><line x1="16" y1="17" x2="8" y2="17"></line><polyline points="10 9 9 9 8 9"></polyline></svg>`;
                    break;
                case 'doc': case 'docx':
                    iconHtml = `<svg ${iconClass} xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#29B6F6" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path><polyline points="14 2 14 8 20 8"></polyline><line x1="16" y1="13" x2="8" y2="13"></line><line x1="16" y1="17" x2="8" y2="17"></line><polyline points="10 9 9 9 8 9"></polyline></svg>`;
                    break;
                default:
                    iconHtml = `<svg ${iconClass} xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#B0B0B0" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M13 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V9z"></path><polyline points="13 2 13 9 20 9"></polyline></svg>`;
                    break;
            }
        }

        nameDiv.innerHTML = iconHtml;

        const textSpan = document.createElement('span');
        textSpan.textContent = file.name;

        nameDiv.appendChild(textSpan);
        nameCell.appendChild(nameDiv);

        const sizeCell = document.createElement('td');
        sizeCell.textContent = isFolder ? '-' : formatBytes(file.size);

        const dateCell = document.createElement('td');
        dateCell.textContent = new Date(file.uploaded_at).toLocaleString('en-US', { year: 'numeric', month: 'short', day: 'numeric', hour: 'numeric', minute: 'numeric', hour12: true });

        const actionsCell = document.createElement('td');
        const actionsDiv = document.createElement('div');
        actionsDiv.className = 'space-x-2';

        const supportedPreviewExtensions = ['jpg', 'jpeg', 'png', 'gif', 'webp', 'txt', 'md', 'json', 'css'];
        const fileExtension = file.name.split('.').pop().toLowerCase();

        if (!isFolder && supportedPreviewExtensions.includes(fileExtension)) {
            const previewBtn = document.createElement('button');
            previewBtn.className = 'icon-button';
            previewBtn.title = 'Preview';
            previewBtn.innerHTML = '<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"></path><circle cx="12" cy="12" r="3"></circle></svg>';
            previewBtn.addEventListener('click', () => handlePreview(file.id));
            actionsDiv.appendChild(previewBtn);
        }

        if (!isFolder) {
            const downloadBtn = document.createElement('button');
            downloadBtn.className = 'icon-button';
            downloadBtn.title = 'Download';
            downloadBtn.innerHTML = '<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"></path><polyline points="7 10 12 15 17 10"></polyline><line x1="12" y1="15" x2="12" y2="3"></line></svg>';
            downloadBtn.addEventListener('click', () => handleDownload(file.id));
            actionsDiv.appendChild(downloadBtn);
        }

        if (!isFolder) {
            const shareBtn = document.createElement('button');
            shareBtn.className = 'icon-button';
            shareBtn.title = 'Share';
            shareBtn.innerHTML = '<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="18" cy="5" r="3" /><circle cx="6" cy="12" r="3" /><circle cx="18" cy="19" r="3" /><line x1="8.59" y1="13.51" x2="15.42" y2="17.49" /><line x1="15.41" y1="6.51" x2="8.59" y2="10.49" /></svg>';
            shareBtn.addEventListener('click', () => openShareModal(file.id, file.name, file.size));
            actionsDiv.appendChild(shareBtn);
        }

        const renameBtn = document.createElement('button');
        renameBtn.className = 'icon-button';
        renameBtn.title = 'Rename';
        renameBtn.innerHTML = '<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"></path><path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"></path></svg>';
        renameBtn.addEventListener('click', () => handleRename(file.id, file.name));
        actionsDiv.appendChild(renameBtn);

        const moveBtn = document.createElement('button');
        moveBtn.className = 'icon-button';
        moveBtn.title = 'Move';
        moveBtn.innerHTML = '<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="6" cy="6" r="3"></circle><circle cx="6" cy="18" r="3"></circle><line x1="8.12" y1="8.12" x2="20" y2="20"></line><line x1="8.12" y1="15.88" x2="20" y2="4"></line></svg>';
        moveBtn.addEventListener('click', () => handleMoveCopy([file.id], 'move'));
        actionsDiv.appendChild(moveBtn);

        const copyBtn = document.createElement('button');
        copyBtn.className = 'icon-button';
        copyBtn.title = 'Copy';
        copyBtn.innerHTML = '<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path></svg>';
        copyBtn.addEventListener('click', () => handleMoveCopy([file.id], 'copy'));
        actionsDiv.appendChild(copyBtn);

        const deleteBtn = document.createElement('button');
        deleteBtn.className = 'icon-button';
        deleteBtn.title = 'Delete';
        deleteBtn.innerHTML = '<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="3 6 5 6 21 6"></polyline><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"></path></svg>';
        deleteBtn.addEventListener('click', () => handleDelete([file.id]));
        actionsDiv.appendChild(deleteBtn);

        actionsCell.appendChild(actionsDiv);

        row.append(selectCell, nameCell, sizeCell, dateCell, actionsCell);
        fileListBody.appendChild(row);
    });

    totalPages = Math.ceil(filteredFiles.length / ITEMS_PER_PAGE);
    const pageInfoSpan = document.getElementById('page-info');
    const prevPageButton = document.getElementById('prev-page-button');
    const nextPageButton = document.getElementById('next-page-button');
    const paginationControls = document.getElementById('pagination-controls');

    pageInfoSpan.textContent = 'Page ' + currentPage + ' of ' + totalPages;
    prevPageButton.disabled = currentPage === 1;
    nextPageButton.disabled = currentPage === totalPages || totalPages === 0;
    paginationControls.classList.toggle('hidden', totalPages <= 1);
    updateBulkActionBar();
}

async function applyFiltersAndSort() {
    currentPage = 1;
    selectedItems.clear();
    await decryptManifest();
    renderFiles();
}

async function decryptManifest() {
    const fileListStatus = document.getElementById('file-list-status');
    const fileListBody = document.getElementById('file-list-body');
    const storageUsageSpan = document.getElementById('storage-usage');

    fileListStatus.innerHTML = '<p>Decrypting file list...</p>';
    fileListStatus.classList.remove('hidden');
    fileListBody.innerHTML = '';

    allDecryptedFiles = [];
    totalStorageUsed = 0;

    try {
        const itemIds = Object.keys(manifest.items);
        for (const id of itemIds) {
            const item = manifest.items[id];
            const encryptedPathBytes = base64ToUint8(item.encryptedPath);
            const path = await decryptText(encryptedPathBytes, e2eKeys.fileKey);
            if (path === null) continue;

            const isFolder = path.endsWith('/');
            const name = isFolder ? path.slice(0, -1).split('/').pop() : path.split('/').pop();

            allDecryptedFiles.push({
                id: id,
                path: path,
                name: name,
                isFolder: isFolder,
                size: item.size || 0,
                uploaded_at: item.date,
                isTrashed: item.isTrashed || false,
                trashedAt: item.trashedAt || null
            });

            if (!item.isTrashed) {
                totalStorageUsed += item.size || 0;
            }
        }
        storageUsageSpan.textContent = 'Usage: ' + formatBytes(totalStorageUsed) + ' / ' + MAX_TOTAL_STORAGE_MB + ' MB';
    } catch (error) {
         fileListStatus.innerHTML = '<p class="error-message">Error processing file list. The manifest may be corrupt.</p>';
         storageUsageSpan.textContent = 'Usage: Error';
    }
}

async function fetchFiles() {
    await applyFiltersAndSort();
}


async function updateAndUploadManifest() {
    try {
        manifest.version = (manifestVersion || 0) + 1;
        const newVersion = manifest.version;

        const encryptedManifest = await encrypt(JSON.stringify(manifest), e2eKeys.manifestKey, e2eSalt);
        const paddedManifest = padAndPrefixManifest(encryptedManifest);

        const response = await fetch(BASE_PATH + '/api/manifest-update', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                manifest: uint8ToBase64(paddedManifest),
                version: newVersion,
                baseVersion: manifestVersion
            }),
            credentials: 'include'
        });

        if (response.status === 409) {
            const errorData = await response.json();
            showMessageBox(errorData.message || 'Update conflict. Please refresh the page and try again.', 'error');
            manifest.version = manifestVersion;
            return false;
        }

        if (!response.ok) {
            throw new Error('Failed to update manifest on server.');
        }

        manifestVersion = newVersion;
        trustedManifestVersion = newVersion;
        return true;

    } catch (error) {
        manifest.version = manifestVersion;
        showMessageBox('Critical error: Could not save changes to the cloud. Please try again. ' + error.message, 'error');
        return false;
    }
}

async function handleFileUpload(event) {
    const files = event.target.files;
    if (files.length === 0) return;

    const uploadButton = document.getElementById('upload-button');
    showSpinner(uploadButton, 'Uploading...');

    const BLOCKED_MIME_TYPES_CLIENT = [
        'text/html',
        'text/javascript',
        'application/javascript',
        'application/x-javascript',
        'image/svg+xml'
    ];

    let successfulUploads = false;

    for (const file of files) {
        if (BLOCKED_MIME_TYPES_CLIENT.includes(file.type)) {
            showMessageBox('Cannot upload "' + file.name + '": This file type is blocked for security reasons.', 'error');
            continue;
        }

        if (file.size > MAX_FILE_SIZE_BYTES) {
            showMessageBox(`Cannot upload "${file.name}": File size exceeds the 100 MB limit.`, 'error');
            continue;
        }

        if (totalStorageUsed + file.size > MAX_TOTAL_STORAGE_BYTES) {
            showMessageBox('Cannot upload "' + file.name + '": Exceeds storage limit.', 'error');
            continue;
        }

        const fileId = crypto.randomUUID();
        const path = currentPath + file.name;

        try {
            const encryptedPath = await encrypt(path, e2eKeys.fileKey);
            const fileContent = await file.arrayBuffer();
            const { buffer: paddedBuffer } = padFileBuffer(fileContent);
            const encryptedContent = await encrypt(paddedBuffer, e2eKeys.fileKey, fileId);

            const uploadResponse = await fetch(BASE_PATH + '/api/upload', {
                method: 'POST',
                headers: {
                    'X-File-Key': fileId,
                    'Content-Type': file.type || 'application/octet-stream'
                },
                body: encryptedContent,
                credentials: 'include'
            });

            if (!uploadResponse.ok) {
                const errorData = await uploadResponse.json();
                throw new Error(errorData.message || 'Server failed to store ' + file.name);
            }

            manifest.items[fileId] = {
                encryptedPath: uint8ToBase64(encryptedPath),
                size: file.size,
                date: new Date(Date.now() - (Math.random() * 60000)).toISOString()
            };

            successfulUploads = true;

        } catch (error) {
            showMessageBox('Failed to upload "' + file.name + '": ' + error.message, 'error');
        }
    }

    if (successfulUploads) {
        if (await updateAndUploadManifest()) {
            showMessageBox('Uploads completed!', 'success');
        }
    }

    event.target.value = '';
    hideSpinner(uploadButton);
    await fetchFiles();
}

async function handleDownload(fileId) {
    let decryptedContent;
    try {
        const item = manifest.items[fileId];
        if (!item) throw new Error('File not found in manifest.');

        const path = await decryptText(base64ToUint8(item.encryptedPath), e2eKeys.fileKey);
        if (!path) throw new Error('Cannot decrypt filename.');
        const originalFileName = path.split('/').pop();

        const response = await fetch(BASE_PATH + '/api/download?key=' + fileId, { credentials: 'include' });
        if (!response.ok) {
            const errorText = await response.text();
            throw new Error('Download failed from server: ' + errorText);
        }

        const encryptedBlob = await response.arrayBuffer();
        decryptedContent = new Uint8Array(await decrypt(new Uint8Array(encryptedBlob), e2eKeys.fileKey, fileId));

        const blob = new Blob([decryptedContent]);
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.style.display = 'none';
        a.href = url;
        a.download = originalFileName;
        document.body.appendChild(a);
        a.click();
        window.URL.revokeObjectURL(url);
        document.body.removeChild(a);

    } catch (error) {
        showMessageBox('Download failed: ' + error.message, 'error');
    } finally {
        if (decryptedContent) {
            decryptedContent.fill(0);
        }
    }
}

function hidePreviewModal() {
    if (currentObjectUrl) {
        URL.revokeObjectURL(currentObjectUrl);
        currentObjectUrl = null;
    }
    document.getElementById('zoom-controls').classList.add('hidden');
    document.getElementById('preview-content-area').innerHTML = '';
    hideModal('preview-modal');
}

async function handlePreview(fileId) {
    const file = allDecryptedFiles.find(f => f.id === fileId);
    if (!file) return;

    const previewContentArea = document.getElementById('preview-content-area');
    const zoomControls = document.getElementById('zoom-controls');
    previewContentArea.classList.remove('is-text-preview');

    let decryptedContent;
    try {
        showModal('preview-modal');
        zoomControls.classList.add('hidden');
        previewContentArea.innerHTML = '';

        const loadingStatus = document.getElementById('preview-loading-status');

        if (loadingStatus) {
            loadingStatus.classList.remove('hidden');
            previewContentArea.appendChild(loadingStatus);
        }

        const response = await fetch(BASE_PATH + '/api/download?key=' + fileId, { credentials: 'include' });
        if (!response.ok) throw new Error('Could not fetch file data (' + response.status + ')');

        const encryptedContent = await response.arrayBuffer();
        decryptedContent = new Uint8Array(await decrypt(new Uint8Array(encryptedContent), e2eKeys.fileKey, fileId));

        const originalContent = decryptedContent.subarray(0, file.size);

        const fileExtension = file.name.split('.').pop().toLowerCase();
        const mimeType = getMimeType(file.name);
        const blob = new Blob([originalContent], { type: mimeType });

        if (currentObjectUrl) URL.revokeObjectURL(currentObjectUrl);
        currentObjectUrl = URL.createObjectURL(blob);

        const previewFileName = document.getElementById('preview-file-name');
        const previewFileSize = document.getElementById('preview-file-size');
        const previewDownloadBtn = document.getElementById('preview-download-button');
        const zoomLevelText = document.getElementById('zoom-level-text');

        previewFileName.textContent = escapeHtml(file.name);
        previewFileName.title = file.name;
        previewFileSize.textContent = 'Size: ' + formatBytes(file.size);
        previewDownloadBtn.onclick = () => handleDownload(file.id);

        previewContentArea.innerHTML = '';
        showModal('preview-modal');

        if (['jpg', 'jpeg', 'png', 'gif', 'webp'].includes(fileExtension)) {
            zoomControls.classList.remove('hidden');
            let zoomLevel = 1;
            const img = document.createElement('img');
            const updateZoom = () => {
                if(img) {
                    img.style.transform = 'scale(' + zoomLevel + ')';
                }
                zoomLevelText.textContent = Math.round(zoomLevel * 100) + '%';
            };
            document.getElementById('zoom-in-btn').onclick = () => { zoomLevel = Math.min(5, zoomLevel + 0.2); updateZoom(); };
            document.getElementById('zoom-out-btn').onclick = () => { zoomLevel = Math.max(0.2, zoomLevel - 0.2); updateZoom(); };
            document.getElementById('zoom-reset-btn').onclick = () => { zoomLevel = 1; updateZoom(); };

            img.src = currentObjectUrl;
            img.style.transition = 'transform 0.2s ease-in-out';
            previewContentArea.appendChild(img);
            updateZoom();

        } else if (['txt', 'md', 'json', 'css'].includes(fileExtension)) {
            previewContentArea.classList.add('is-text-preview');
            zoomControls.classList.add('hidden');
            const text = await new Response(blob).text();
            const pre = document.createElement('pre');
            pre.textContent = sanitizeTextContent(text);
            previewContentArea.appendChild(pre);

        } else {
            zoomControls.classList.add('hidden');
            const p = document.createElement('p');
            p.textContent = 'Preview not available for this file type.';
            previewContentArea.appendChild(p);
        }
    } catch (error) {
        zoomControls.classList.add('hidden');
        previewContentArea.innerHTML = '';
        const p = document.createElement('p');
        p.className = 'error-message';
        p.textContent = 'Error loading preview: ' + error.message;
        previewContentArea.appendChild(p);
    } finally {
        if (decryptedContent) {
            decryptedContent.fill(0);
        }
    }
}

async function handleDelete(itemIds) {
    const message = 'Are you sure you want to move ' + itemIds.length + ' item(s) to the trash?';

    showConfirmActionModal('Move to Trash', message, 'Move to Trash', 'danger', async () => {
        let itemsToTrash = new Set(itemIds);

        for (const itemId of itemIds) {
            const item = allDecryptedFiles.find(f => f.id === itemId);
            if (item && item.isFolder) {
                for (const file of allDecryptedFiles) {
                    if (file.path.startsWith(item.path)) {
                        itemsToTrash.add(file.id);
                    }
                }
            }
        }

        try {
            const trashedAt = new Date().toISOString();
            itemsToTrash.forEach(id => {
                if (manifest.items[id]) {
                    manifest.items[id].isTrashed = true;
                    manifest.items[id].trashedAt = trashedAt;
                }
            });

            if (await updateAndUploadManifest()) {
                 showMessageBox('Items moved to trash successfully.', 'success');
                 selectedItems.clear();
                 await fetchFiles();
            }
        } catch (error) {
            throw new Error('Failed to move items to trash: ' + error.message);
        }
    });
}

async function handleRename(itemId, currentName) {
    const renameInput = document.getElementById('rename-input');
    const confirmBtn = document.getElementById('confirm-rename');
    renameInput.value = currentName;
    showModal('rename-modal');

    confirmBtn.onclick = async () => {
        const newName = renameInput.value;

        if (!isValidFilename(newName)) {
            document.getElementById('rename-error').textContent = 'Invalid name. Max 255 chars, no slashes, control characters, or leading/trailing spaces.';
            return;
        }

        showSpinner(confirmBtn);

        const finalNewName = newName.trim();
        const itemToRename = allDecryptedFiles.find(f => f.id === itemId);
        const oldPath = itemToRename.path;
        const newPath = currentPath + finalNewName + (itemToRename.isFolder ? '/' : '');

        try {
            manifest.items[itemId].encryptedPath = uint8ToBase64(await encrypt(newPath, e2eKeys.fileKey));
            if (itemToRename.isFolder) {
                for (const file of allDecryptedFiles) {
                    if (file.path.startsWith(oldPath) && file.id !== itemId) {
                        const childOldRelativePath = file.path.substring(oldPath.length);
                        const childNewPath = newPath + childOldRelativePath;
                        manifest.items[file.id].encryptedPath = uint8ToBase64(await encrypt(childNewPath, e2eKeys.fileKey));
                    }
                }
            }
            if (await updateAndUploadManifest()) {
                showMessageBox('Item renamed successfully.', 'success');
                hideModal('rename-modal');
                await fetchFiles();
            }
        } catch (error) {
            document.getElementById('rename-error').textContent = 'Failed to rename: ' + error.message;
        } finally {
            hideSpinner(confirmBtn);
        }
    };
}

function navigateToFolder(fullPath) {
    currentPath = fullPath;
    currentPage = 1;
    renderFiles();
}

function updateBulkActionBar() {
    const bulkActionBar = document.getElementById('bulk-action-bar');
    const selectAllCheckbox = document.getElementById('select-all-checkbox');
    const count = selectedItems.size;
    if (count === 0) {
        bulkActionBar.classList.add('hidden');
        selectAllCheckbox.checked = false;
        return;
    }

    bulkActionBar.classList.remove('hidden');

    bulkActionBar.innerHTML = `
        <span>${count} item(s) selected</span>
        <div class="d-flex items-center gap-2">
            <div class="d-flex gap-1">
                <button id="bulk-move-btn" class="icon-button" title="Move"><svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="6" cy="6" r="3"></circle><circle cx="6" cy="18" r="3"></circle><line x1="8.12" y1="8.12" x2="20" y2="20"></line><line x1="8.12" y1="15.88" x2="20" y2="4"></line></svg></button>
                <button id="bulk-copy-btn" class="icon-button" title="Copy"><svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path></svg></button>
                <button id="bulk-delete-btn" class="icon-button" title="Delete"><svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="3 6 5 6 21 6"></polyline><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"></path></svg></button>
            </div>
            <button id="bulk-cancel-btn" class="icon-button" title="Cancel Selection"><svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="18" y1="6" x2="6" y2="18"></line><line x1="6" y1="6" x2="18" y2="18"></line></svg></button>
        </div>`;

    document.getElementById('bulk-move-btn').addEventListener('click', () => handleMoveCopy(Array.from(selectedItems), 'move'));
    document.getElementById('bulk-copy-btn').addEventListener('click', () => handleMoveCopy(Array.from(selectedItems), 'copy'));
    document.getElementById('bulk-delete-btn').addEventListener('click', () => handleDelete(Array.from(selectedItems)));
    document.getElementById('bulk-cancel-btn').addEventListener('click', () => {
        selectedItems.clear();
        renderFiles();
    });
}

async function handleMoveCopy(itemIds, mode) {
    const modal = document.getElementById('move-copy-modal');
    const title = document.getElementById('move-copy-title');
    const browser = document.getElementById('folder-browser');
    const confirmBtn = document.getElementById('confirm-move-copy');
    const errorElement = document.getElementById('move-copy-error');

    errorElement.textContent = '';
    title.textContent = (mode === 'move' ? 'Move' : 'Copy') + ` ${itemIds.length} item(s) to:`;

    let selectedDestination = '';

    const renderFolderTree = (container, parentPath = '') => {
        const folders = allDecryptedFiles.filter(f => {
            if (f.isTrashed || !f.isFolder) return false;

            const normalizedPath = f.path.endsWith('/') ? f.path.slice(0, -1) : f.path;
            const parentSegments = parentPath.split('/').filter(Boolean);
            const childSegments = normalizedPath.split('/');

            if (childSegments.length === parentSegments.length + 1 && f.path.startsWith(parentPath)) {
                return true;
            }
            return false;
        }).sort((a,b) => a.name.localeCompare(b.name));

        folders.forEach(folder => {
            const hasChildren = allDecryptedFiles.some(f => f.isFolder && !f.isTrashed && f.path.startsWith(folder.path) && f.id !== folder.id);

            const li = document.createElement('li');
            li.innerHTML = `
                <div class="tree-item-content" data-path="${folder.path}">
                    <span class="tree-item-toggle ${hasChildren ? '' : 'hidden'}">►</span>
                    <span class="tree-item-icon">📁</span>
                    <span>${escapeHtml(folder.name)}</span>
                </div>
                <ul class="tree-item-children"></ul>
            `;
            container.appendChild(li);

            const contentDiv = li.querySelector('.tree-item-content');
            const toggle = li.querySelector('.tree-item-toggle');
            const childrenUl = li.querySelector('.tree-item-children');

            contentDiv.onclick = (e) => {
                if (e.target === toggle) return;

                browser.querySelectorAll('.tree-item-content').forEach(el => el.classList.remove('selected'));
                contentDiv.classList.add('selected');
                selectedDestination = contentDiv.dataset.path;
            };

            toggle.onclick = (e) => {
                e.stopPropagation();
                const isExpanded = childrenUl.classList.toggle('expanded');
                toggle.classList.toggle('expanded', isExpanded);
                if (isExpanded && childrenUl.children.length === 0) {
                    renderFolderTree(childrenUl, folder.path);
                }
            };
        });
    };

    browser.innerHTML = '';
    const rootUl = document.createElement('ul');
    const rootLi = document.createElement('li');
    rootLi.innerHTML = `
        <div class="tree-item-content selected" data-path="">
            <span class="tree-item-toggle">►</span>
            <span class="tree-item-icon">📁</span>
            <span>Root</span>
        </div>
        <ul class="tree-item-children expanded"></ul>
    `;
    rootUl.appendChild(rootLi);
    browser.appendChild(rootUl);
    selectedDestination = '';

    const rootContent = rootLi.querySelector('.tree-item-content');
    const rootToggle = rootLi.querySelector('.tree-item-toggle');
    const rootChildrenContainer = rootLi.querySelector('.tree-item-children');

    rootContent.onclick = (e) => {
        if (e.target === rootToggle) return;
        browser.querySelectorAll('.tree-item-content').forEach(el => el.classList.remove('selected'));
        rootContent.classList.add('selected');
        selectedDestination = '';
    };

    rootToggle.onclick = (e) => {
        e.stopPropagation();
        rootChildrenContainer.classList.toggle('expanded');
        rootToggle.classList.toggle('expanded');
    };

    renderFolderTree(rootChildrenContainer, '');
    rootToggle.classList.add('expanded');

    showModal('move-copy-modal');

    confirmBtn.onclick = async () => {
        if (selectedDestination === undefined) {
            errorElement.textContent = 'Please select a destination.';
            return;
        }

        showSpinner(confirmBtn);

        try {
            if (mode === 'move') {
                for (const itemId of itemIds) {
                    const item = allDecryptedFiles.find(f => f.id === itemId);
                    const oldPath = item.path;
                    const newPath = selectedDestination + item.name + (item.isFolder ? '/' : '');

                    if (item.isFolder && (newPath.startsWith(oldPath) || oldPath === newPath)) {
                        throw new Error('Cannot move a folder into itself.');
                    }
                     if (allDecryptedFiles.some(f => f.path === newPath && !f.isTrashed)) {
                        throw new Error(`An item named "${item.name}" already exists in the destination.`);
                    }

                    manifest.items[itemId].encryptedPath = uint8ToBase64(await encrypt(newPath, e2eKeys.fileKey));
                    if (item.isFolder) {
                        for (const file of allDecryptedFiles) {
                            if (file.path.startsWith(oldPath) && file.id !== itemId) {
                                const childOldRelativePath = file.path.substring(oldPath.length);
                                const childNewPath = newPath + childOldRelativePath;
                                manifest.items[file.id].encryptedPath = uint8ToBase64(await encrypt(childNewPath, e2eKeys.fileKey));
                            }
                        }
                    }
                }
            } else {
                for (const itemId of itemIds) {
                    const item = allDecryptedFiles.find(f => f.id === itemId);
                    const newId = crypto.randomUUID();
                    const newPath = selectedDestination + item.name + (item.isFolder ? '/' : '');

                     if (allDecryptedFiles.some(f => f.path === newPath && !f.isTrashed)) {
                        throw new Error(`An item named "${item.name}" already exists in the destination.`);
                    }

                    if (item.isFolder) {
                        manifest.items[newId] = {
                            encryptedPath: uint8ToBase64(await encrypt(newPath, e2eKeys.fileKey)),
                            size: 0,
                            date: new Date().toISOString()
                        };
                    } else {
                        const res = await fetch(`${BASE_PATH}/api/download?key=${itemId}`, { credentials: 'include' });
                        if (!res.ok) throw new Error(`Failed to fetch data for ${item.name}`);
                        const encryptedContent = await res.arrayBuffer();
                        const uploadRes = await fetch(`${BASE_PATH}/api/upload`, { method: 'POST', headers: { 'X-File-Key': newId }, body: encryptedContent, credentials: 'include' });
                         if (!uploadRes.ok) throw new Error(`Failed to upload copy of ${item.name}`);
                        manifest.items[newId] = {
                            encryptedPath: uint8ToBase64(await encrypt(newPath, e2eKeys.fileKey)),
                            size: item.size,
                            date: new Date().toISOString()
                        };
                    }
                }
            }

            if (await updateAndUploadManifest()) {
                showMessageBox(`Items ${mode}d successfully.`, 'success');
                hideModal('move-copy-modal');
                selectedItems.clear();
                await fetchFiles();
            }
        } catch(error) {
            errorElement.textContent = `Operation failed: ${error.message}`;
        } finally {
            hideSpinner(confirmBtn);
        }
    };
}

async function openShareModal(fileId, fileName, fileSize) {
    const modal = document.getElementById('share-modal');
    modal.dataset.fileId = fileId;
    modal.dataset.fileName = fileName;
    modal.dataset.fileSize = fileSize;

    document.getElementById('share-modal-title').textContent = `Share "${escapeHtml(fileName)}"`;
    document.getElementById('share-password-input').value = '';
    document.getElementById('share-expiry-input').value = '';
    document.getElementById('share-max-clicks-input').value = '';
    document.getElementById('generated-link-container').classList.add('hidden');
    document.getElementById('share-error').textContent = '';

    showModal('share-modal');
    await fetchAndDisplayShareLinks(fileId);
}

async function fetchAndDisplayShareLinks(fileId) {
    const listElement = document.getElementById('existing-links-list');
    listElement.innerHTML = `<li class="text-center">Loading...</li>`;

    try {
        const response = await fetch(`${BASE_PATH}/api/files/${fileId}/shares`, { credentials: 'include' });
        if (!response.ok) throw new Error('Failed to fetch links.');
        const data = await response.json();

        listElement.innerHTML = '';

        const sortedShareIds = Object.keys(data.links).sort((a, b) => {
            return new Date(data.links[b].createdAt) - new Date(data.links[a].createdAt);
        });

        if (sortedShareIds.length === 0) {
            listElement.innerHTML = `<li class="text-center">No links have been created for this file.</li>`;
            return;
        }

        for (const shareId of sortedShareIds) {
            const link = data.links[shareId];
            const li = document.createElement('li');
            li.className = 'existing-link-item';

            const clickCount = link.clickCount || 0;
            const isExpiredByDate = link.expiresAt && new Date(link.expiresAt) < new Date();
            const isExpiredByClicks = link.maxClicks && clickCount >= link.maxClicks;
            const isExpired = isExpiredByDate || isExpiredByClicks;

            const expiryText = link.expiresAt ? `Expires: ${new Date(link.expiresAt).toLocaleString()}` : 'Expires: Never';

            const lockIcon = link.hasPassword
                ? `<svg class="file-icon" xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"></rect><path d="M7 11V7a5 5 0 0 1 10 0v4"></path></svg>`
                : '';

            const clicksText = link.maxClicks
                ? `Clicks: ${clickCount} / ${link.maxClicks}`
                : `Clicks: ${clickCount}`;

            li.innerHTML = `
                <div class="link-info">
                    <div class="link-id">
                        <svg class="file-icon" xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.72"></path><path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.72-1.72"></path></svg>
                        <span>Link created at ${new Date(link.createdAt).toLocaleString()}</span>
                    </div>
                    <div class="link-details ${isExpired ? 'expired' : ''}">
                        <div class="link-expiry ${isExpiredByDate ? 'expired' : ''}">
                            ${lockIcon}
                            <span>${expiryText}</span>
                        </div>
                        <div class="link-clicks ${isExpiredByClicks ? 'expired' : ''}">
                            <span>${clicksText}</span>
                        </div>
                    </div>
                </div>
                <div class="link-actions">
                    <button class="icon-button copy-share-link-btn" title="Copy Link"><svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path></svg></button>
                    <button class="icon-button edit-share-link-btn" title="Edit Link"><svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"></path><path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"></path></svg></button>
                    <button class="icon-button delete-share-link-btn" title="Delete Link"><svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="3 6 5 6 21 6"></polyline><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"></path></svg></button>
                </div>
            `;
            listElement.appendChild(li);

            const copyBtn = li.querySelector('.copy-share-link-btn');
            const editBtn = li.querySelector('.edit-share-link-btn');
            const deleteBtn = li.querySelector('.delete-share-link-btn');

            if (isExpired) {
                copyBtn.disabled = true;
                copyBtn.classList.add('opacity-50');
            }

            copyBtn.onclick = async () => {
                try {
                    const encryptedUrlBytes = base64ToUint8(link.encryptedUrl);
                    const decryptedUrl = await decryptText(encryptedUrlBytes, e2eKeys.manifestKey, shareId);
                    if (decryptedUrl) {
                        navigator.clipboard.writeText(decryptedUrl).then(() => {
                            showMessageBox('Link copied to clipboard!', 'success');
                        });
                    } else {
                        throw new Error('Decryption failed.');
                    }
                } catch (e) {
                    showMessageBox('Could not copy link. Failed to decrypt stored URL.', 'error');
                }
            };
            editBtn.onclick = () => openEditShareModal(fileId, shareId, link);
            deleteBtn.onclick = () => handleDeleteShare(fileId, shareId);
        }

    } catch (error) {
        listElement.innerHTML = `<li class="text-center">Error: ${error.message}</li>`;
    }
}

async function createShareLink() {
    const modal = document.getElementById('share-modal');
    const fileId = modal.dataset.fileId;
    const fileName = modal.dataset.fileName;
    const fileSize = modal.dataset.fileSize;
    const password = document.getElementById('share-password-input').value;
    const expiry = document.getElementById('share-expiry-input').value;
    const maxClicksInput = document.getElementById('share-max-clicks-input').value;
    const errorElement = document.getElementById('share-error');
    const createBtn = document.getElementById('create-share-link-button');

    errorElement.textContent = '';
    showSpinner(createBtn, 'Creating...');

    try {
        const shareId = crypto.randomUUID();
        const rawFileKey = await crypto.subtle.exportKey('raw', e2eKeys.fileKey);
        let keyMaterial;

        if (password) {
            const salt = crypto.getRandomValues(new Uint8Array(16));
            const passwordEncoder = new TextEncoder();
            const keyMaterialPbkdf2 = await crypto.subtle.importKey('raw', passwordEncoder.encode(password), { name: 'PBKDF2' }, false, ['deriveKey']);

            const derivedKey = await crypto.subtle.deriveKey(
                { name: 'PBKDF2', salt, iterations: 1000000, hash: 'SHA-256' },
                keyMaterialPbkdf2,
                { name: 'AES-GCM', length: 256 },
                false,
                ['encrypt']
            );

            const encryptedFileKey = await encrypt(rawFileKey, derivedKey, shareId);

            const combined = new Uint8Array(salt.length + encryptedFileKey.length);
            combined.set(salt);
            combined.set(encryptedFileKey, salt.length);
            keyMaterial = combined;
        } else {
            keyMaterial = rawFileKey;
        }

        const encodedKeyMaterial = uint8ToBase64Url(new Uint8Array(keyMaterial));
        const shareUrl = `${window.location.origin}/share.html#${shareId}:${encodedKeyMaterial}`;

        const encryptedUrl = uint8ToBase64(await encrypt(shareUrl, e2eKeys.manifestKey, shareId));
        const maxClicks = maxClicksInput ? parseInt(maxClicksInput, 10) : null;

        const response = await fetch(`${BASE_PATH}/api/files/${fileId}/shares`, {
            method: 'POST',
            credentials: 'include',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                shareId,
                expiresAt: expiry ? new Date(expiry).toISOString() : null,
                hasPassword: !!password,
                fileName,
                fileSize: parseInt(fileSize, 10),
                encryptedUrl: encryptedUrl,
                maxClicks: maxClicks,
            })
        });

        if (!response.ok) {
            const errData = await response.json();
            throw new Error(errData.message || 'Server failed to create link.');
        }

        const generatedLinkInput = document.getElementById('generated-link-input');
        generatedLinkInput.value = shareUrl;
        document.getElementById('generated-link-container').classList.remove('hidden');
        document.getElementById('share-password-input').value = '';
        document.getElementById('share-max-clicks-input').value = '';
        document.getElementById('share-expiry-input').value = '';


        await fetchAndDisplayShareLinks(fileId);

    } catch (error) {
        errorElement.textContent = `Error: ${error.message}`;
    } finally {
        hideSpinner(createBtn);
    }
}

async function handleDeleteShare(fileId, shareId) {
    showConfirmActionModal('Delete Link', 'Are you sure you want to permanently delete this share link? This action cannot be undone.', 'Delete', 'danger', async () => {
        try {
            const response = await fetch(`${BASE_PATH}/api/files/${fileId}/shares/${shareId}`, {
                method: 'DELETE',
                credentials: 'include'
            });

            if (!response.ok) {
                 throw new Error('Server failed to delete link.');
            }
            showMessageBox('Link deleted successfully.', 'success');
            await fetchAndDisplayShareLinks(fileId);
        } catch (error) {
             throw new Error(`Deletion failed: ${error.message}`);
        }
    });
}


function openEditShareModal(fileId, shareId, link) {
    const modal = document.getElementById('edit-share-modal');
    const file = allDecryptedFiles.find(f => f.id === fileId);

    modal.dataset.fileId = fileId;
    modal.dataset.shareId = shareId;
    modal.dataset.fileName = file ? file.name : 'Unknown File';
    modal.dataset.fileSize = file ? file.size : 0;

    const expiryInput = document.getElementById('edit-share-expiry-input');
    const maxClicksInput = document.getElementById('edit-share-max-clicks-input');

    if (link.expiresAt && link.expiresAt !== 'null') {
       const localDate = new Date(link.expiresAt);
       const year = localDate.getFullYear();
       const month = (localDate.getMonth() + 1).toString().padStart(2, '0');
       const day = localDate.getDate().toString().padStart(2, '0');
       const hours = localDate.getHours().toString().padStart(2, '0');
       const minutes = localDate.getMinutes().toString().padStart(2, '0');
       expiryInput.value = `${year}-${month}-${day}T${hours}:${minutes}`;
    } else {
       expiryInput.value = '';
    }

    maxClicksInput.value = link.maxClicks || '';
    document.getElementById('edit-share-error').textContent = '';
    showModal('edit-share-modal');
}


async function handleSaveShareSettings() {
    const modal = document.getElementById('edit-share-modal');
    const fileId = modal.dataset.fileId;
    const shareId = modal.dataset.shareId;
    const fileName = modal.dataset.fileName;
    const fileSize = parseInt(modal.dataset.fileSize, 10);

    const newExpiry = document.getElementById('edit-share-expiry-input').value;
    const newMaxClicks = document.getElementById('edit-share-max-clicks-input').value;
    const errorElement = document.getElementById('edit-share-error');
    const saveBtn = document.getElementById('confirm-edit-share');

    errorElement.textContent = '';
    showSpinner(saveBtn);

    try {
        const response = await fetch(`${BASE_PATH}/api/files/${fileId}/shares/${shareId}`, {
            method: 'PATCH',
            credentials: 'include',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                expiresAt: newExpiry ? new Date(newExpiry).toISOString() : null,
                maxClicks: newMaxClicks ? parseInt(newMaxClicks, 10) : null,
                fileName: fileName,
                fileSize: fileSize
            })
        });

        if (!response.ok) throw new Error('Failed to update link settings.');

        hideModal('edit-share-modal');
        showMessageBox('Link settings updated successfully.', 'success');
        await fetchAndDisplayShareLinks(fileId);

    } catch(error) {
        errorElement.textContent = `Error: ${error.message}`;
    } finally {
        hideSpinner(saveBtn);
    }
}

window.addEventListener("beforeunload", () => {
    try {
        logoutChannel.close();
        if (e2eKeys) e2eKeys = { manifestKey: null, fileKey: null };
        if (e2eSalt) e2eSalt.fill(0);
        e2eSalt = null;
        manifest = { items: {} };
        manifestVersion = 1;
    } catch (_) {}
});

function openTrashModal() {
    selectedTrashItems.clear();
    showModal('trash-modal');
    renderTrashList();
}

function updateTrashBulkActionBar() {
    const bulkBar = document.getElementById('trash-bulk-action-bar');
    const selectAllCheckbox = document.getElementById('trash-select-all-checkbox');
    const count = selectedTrashItems.size;

    if (count === 0) {
        bulkBar.classList.add('hidden');
        selectAllCheckbox.checked = false;
        return;
    }

    bulkBar.classList.remove('hidden');
    bulkBar.innerHTML = `
        <span>${count} item(s) selected</span>
        <div class="d-flex gap-1">
            <button id="trash-bulk-restore-btn" class="button secondary-button">Restore</button>
            <button id="trash-bulk-delete-btn" class="button danger-button">Delete Forever</button>
        </div>`;

    document.getElementById('trash-bulk-restore-btn').onclick = (event) => handleRestore(Array.from(selectedTrashItems), event.currentTarget);
    document.getElementById('trash-bulk-delete-btn').onclick = () => handleDeletePermanently(Array.from(selectedTrashItems));
}

function renderTrashList() {
    const tableBody = document.getElementById('trash-table-body');
    const emptyTrashBtn = document.getElementById('empty-trash-button');
    const selectAllCheckbox = document.getElementById('trash-select-all-checkbox');
    tableBody.innerHTML = '';

    const trashedItems = allDecryptedFiles
        .filter(item => item.isTrashed)
        .sort((a, b) => new Date(b.trashedAt) - new Date(a.trashedAt));

    if (trashedItems.length === 0) {
        tableBody.innerHTML = `<tr><td colspan="5" class="text-center">Trash is empty.</td></tr>`;
        emptyTrashBtn.disabled = true;
        selectAllCheckbox.checked = false;
        updateTrashBulkActionBar();
        return;
    }

    emptyTrashBtn.disabled = false;

    trashedItems.forEach(item => {
        const row = document.createElement('tr');
        if (selectedTrashItems.has(item.id)) {
            row.classList.add('selected');
        }

        const iconClass = 'class="file-icon"';
        const iconHtml = item.isFolder
            ? `<svg ${iconClass} xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#FFC107" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"></path></svg>`
            : `<svg ${iconClass} xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#B0B0B0" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M13 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V9z"></path><polyline points="13 2 13 9 20 9"></polyline></svg>`;

        row.innerHTML = `
            <td><input type="checkbox" data-id="${item.id}" ${selectedTrashItems.has(item.id) ? 'checked' : ''}></td>
            <td><div class="d-flex items-center">${iconHtml}<span title="${item.path}">${escapeHtml(item.name)}</span></div></td>
            <td class="text-center">${item.isFolder ? '-' : formatBytes(item.size)}</td>
            <td class="text-center">${new Date(item.trashedAt).toLocaleString()}</td>
            <td>
                <div class="space-x-2">
                    <button class="icon-button restore-btn" title="Restore">
                        <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="1 4 1 10 7 10"></polyline><path d="M3.51 15a9 9 0 1 0 2.13-9.36L1 10"></path></svg>
                    </button>
                    <button class="icon-button delete-perm-btn" title="Delete Forever">
                         <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="#EF5350" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="3 6 5 6 21 6"></polyline><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"></path><line x1="10" y1="11" x2="10" y2="17"></line><line x1="14" y1="11" x2="14" y2="17"></line></svg>
                    </button>
                </div>
            </td>
        `;
        tableBody.appendChild(row);

        const checkbox = row.querySelector('input[type="checkbox"]');
        checkbox.addEventListener('change', () => {
            if (checkbox.checked) {
                selectedTrashItems.add(item.id);
                row.classList.add('selected');
            } else {
                selectedTrashItems.delete(item.id);
                row.classList.remove('selected');
            }
            updateTrashBulkActionBar();
        });
        row.querySelector('.restore-btn').onclick = (event) => handleRestore([item.id], event.currentTarget);
        row.querySelector('.delete-perm-btn').onclick = () => handleDeletePermanently([item.id]);
    });

    selectAllCheckbox.onchange = () => {
        const checkboxes = tableBody.querySelectorAll('input[type="checkbox"]');
        if (selectAllCheckbox.checked) {
            trashedItems.forEach(item => selectedTrashItems.add(item.id));
        } else {
            selectedTrashItems.clear();
        }
        checkboxes.forEach(cb => {
            cb.checked = selectAllCheckbox.checked;
            cb.closest('tr').classList.toggle('selected', selectAllCheckbox.checked);
        });
        updateTrashBulkActionBar();
    };

    updateTrashBulkActionBar();
}

async function handleRestore(itemIds, buttonToSpin = null) {
    const icon = buttonToSpin ? buttonToSpin.querySelector('svg') : null;
    if (buttonToSpin) buttonToSpin.disabled = true;
    if (icon) icon.classList.add('animate-spin');

    try {
        const allItemsToRestore = new Set();
        for (const id of itemIds) {
            allItemsToRestore.add(id);
            const item = allDecryptedFiles.find(f => f.id === id);
            if (item && item.isFolder) {
                allDecryptedFiles.forEach(descendant => {
                    if (descendant.path.startsWith(item.path)) {
                        allItemsToRestore.add(descendant.id);
                    }
                });
            }
        }

        const existingPaths = new Set(allDecryptedFiles.filter(f => !f.isTrashed).map(f => f.path));
        const conflicts = [];

        allItemsToRestore.forEach(id => {
            const itemToRestore = allDecryptedFiles.find(f => f.id === id);
            if (itemToRestore && existingPaths.has(itemToRestore.path)) {
                conflicts.push(itemToRestore.path);
            }
        });

        if (conflicts.length > 0) {
            const conflictMessage = `Cannot restore because the following path(s) already exist: ${[...new Set(conflicts)].join(', ')}. Please move or rename the existing item(s) first.`;
            throw new Error(conflictMessage);
        }

        allItemsToRestore.forEach(id => {
            if (manifest.items[id]) {
                delete manifest.items[id].isTrashed;
                delete manifest.items[id].trashedAt;
            }
        });

        if (await updateAndUploadManifest()) {
            showMessageBox(`${itemIds.length} top-level item(s) and their contents restored successfully.`, 'success');
            await fetchFiles();
            renderTrashList();
            if (selectedTrashItems.size > 0) {
               itemIds.forEach(id => selectedTrashItems.delete(id));
               updateTrashBulkActionBar();
            }
        } else {
            showMessageBox('Failed to restore items.', 'error');
        }
    } catch (error) {
        showMessageBox(`Error restoring items: ${error.message}`, 'error');
    } finally {
        if (icon) icon.classList.remove('animate-spin');
        if (buttonToSpin) buttonToSpin.disabled = false;
    }
}

async function handleDeletePermanently(itemIds) {
    const message = `Are you sure you want to permanently delete ${itemIds.length} item(s)? This action cannot be undone.`;

    showConfirmActionModal('Delete Forever', message, 'Delete', 'danger', async () => {
        let keysToDeleteInR2 = new Set();
        let itemsToDeleteFromManifest = new Set(itemIds);

        for (const itemId of itemIds) {
            const item = allDecryptedFiles.find(f => f.id === itemId);
            if (item) {
                if (item.isFolder) {
                     for (const file of allDecryptedFiles) {
                        if (file.path.startsWith(item.path)) {
                            itemsToDeleteFromManifest.add(file.id);
                            if (!file.isFolder) keysToDeleteInR2.add(file.id);
                        }
                    }
                } else {
                    keysToDeleteInR2.add(item.id);
                }
            }
        }

        try {
            if (keysToDeleteInR2.size > 0) {
                const response = await fetch(`${BASE_PATH}/api/delete`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ keys: Array.from(keysToDeleteInR2) }),
                    credentials: 'include'
                });
                if (!response.ok) {
                    const data = await response.json();
                    throw new Error(data.message || 'Deletion failed on server');
                }
            }

            itemsToDeleteFromManifest.forEach(id => delete manifest.items[id]);

            if (await updateAndUploadManifest()) {
                 showMessageBox('Items permanently deleted.', 'success');
                 await fetchFiles();
                 selectedTrashItems.clear();
                 renderTrashList();
            }
        } catch (error) {
            throw new Error(`Failed to delete: ${error.message}`);
        }
    });
}

function handleCreateFolder() {
    document.getElementById('new-folder-name-input').value = '';
    document.getElementById('create-folder-error').textContent = '';
    showModal('create-folder-modal');
}

async function confirmCreateFolder() {
    const newFolderNameInput = document.getElementById('new-folder-name-input');
    const createFolderError = document.getElementById('create-folder-error');
    const confirmCreateFolderButton = document.getElementById('confirm-create-folder');
    const folderName = newFolderNameInput.value;

    if (!isValidFilename(folderName)) {
        createFolderError.textContent = 'Invalid name. Max 255 chars, no slashes, control characters, or leading/trailing spaces.';
        createFolderError.classList.remove('hidden');
        return;
    }

    showSpinner(confirmCreateFolderButton);
    createFolderError.classList.add('hidden');

    const finalFolderName = folderName.trim();
    const folderId = crypto.randomUUID();
    const path = currentPath + finalFolderName + '/';

    try {
        const encryptedPath = await encrypt(path, e2eKeys.fileKey);
        manifest.items[folderId] = {
            encryptedPath: uint8ToBase64(encryptedPath),
            size: 0,
            date: new Date(Date.now() - (Math.random() * 60000)).toISOString()
        };

        if (await updateAndUploadManifest()) {
            showMessageBox('Folder created successfully!', 'success');
            hideModal('create-folder-modal');
            await fetchFiles();
        }

    } catch(error) {
        createFolderError.textContent = 'Failed to create folder: ' + error.message;
        createFolderError.classList.remove('hidden');
    } finally {
        hideSpinner(confirmCreateFolderButton);
    }
}

document.addEventListener('DOMContentLoaded', () => {
    document.getElementById('current-year').textContent = new Date().getFullYear();
    if (!window.location.pathname.endsWith('/share.html')) {
        checkLoginStatus();
    }

    const loginForm = document.getElementById('login-form');
    const logoutButton = document.getElementById('logout-button');
    const e2eForm = document.getElementById('e2e-form');
    const e2eResetButton = document.getElementById('e2e-reset-button');
    const searchInput = document.getElementById('search-input');
    const sortSelect = document.getElementById('sort-select');
    const uploadButton = document.getElementById('upload-button');
    const fileInput = document.getElementById('file-input');
    const createFolderButton = document.getElementById('create-folder-button');
    const confirmCreateFolderButton = document.getElementById('confirm-create-folder');
    const cancelCreateFolderButton = document.getElementById('cancel-create-folder');
    const newFolderNameInput = document.getElementById('new-folder-name-input');
    const renameInput = document.getElementById('rename-input');
    const confirmRenameButton = document.getElementById('confirm-rename');
    const goUpButton = document.getElementById('go-up-button');
    const prevPageButton = document.getElementById('prev-page-button');
    const nextPageButton = document.getElementById('next-page-button');
    const selectAllCheckbox = document.getElementById('select-all-checkbox');
    const dashboardTitleClickable = document.getElementById('dashboard-title-clickable');

    loginForm.addEventListener('submit', handleLogin);
    logoutButton.addEventListener('click', handleLogout);
    e2eForm.addEventListener('submit', handleE2EFormSubmit);
    e2eResetButton.addEventListener('click', enterResetModeHandler);
    searchInput.addEventListener('input', (e) => { currentSearchTerm = e.target.value; renderFiles(); });
    sortSelect.addEventListener('change', (e) => { currentSort = e.target.value; renderFiles(); });
    uploadButton.addEventListener('click', () => fileInput.click());
    fileInput.addEventListener('change', handleFileUpload);
    createFolderButton.addEventListener('click', handleCreateFolder);
    confirmCreateFolderButton.addEventListener('click', confirmCreateFolder);
    cancelCreateFolderButton.addEventListener('click', () => hideModal('create-folder-modal'));
    document.getElementById('cancel-rename').onclick = () => hideModal('rename-modal');
    document.getElementById('cancel-move-copy').addEventListener('click', () => hideModal('move-copy-modal'));
    goUpButton.addEventListener('click', navigateUp);
    prevPageButton.addEventListener('click', () => { if (currentPage > 1) { currentPage--; renderFiles(); }});
    nextPageButton.addEventListener('click', () => { if (currentPage < totalPages) { currentPage++; renderFiles(); }});
    document.getElementById('close-preview-modal').addEventListener('click', hidePreviewModal);
    document.getElementById('preview-modal').addEventListener('click', (e) => {
        if (e.target.id === 'preview-modal') {
            hidePreviewModal();
        }
    });

    document.getElementById('password-input').addEventListener('keydown', (event) => {
        if (event.key === 'Enter') {
            event.preventDefault();
            document.getElementById('login-button').click();
        }
    });
    newFolderNameInput.addEventListener('keydown', (event) => {
        if (event.key === 'Enter') {
            event.preventDefault();
            confirmCreateFolderButton.click();
        }
    });
    renameInput.addEventListener('keydown', (event) => {
        if (event.key === 'Enter') {
            event.preventDefault();
            confirmRenameButton.click();
        }
    });

    selectAllCheckbox.addEventListener('change', () => {
        const fileListBody = document.getElementById('file-list-body');
        const checkboxes = fileListBody.querySelectorAll('input[type="checkbox"]');
        checkboxes.forEach(checkbox => {
            const id = checkbox.dataset.id;
            const row = checkbox.closest('tr');
            if (selectAllCheckbox.checked) {
                selectedItems.add(id);
                checkbox.checked = true;
                row.classList.add('selected');
            } else {
                selectedItems.delete(id);
                checkbox.checked = false;
                row.classList.remove('selected');
            }
        });
        updateBulkActionBar();
    });

    dashboardTitleClickable.addEventListener('click', () => {
        if (currentPath !== '') {
            currentPath = '';
            currentPage = 1;
            renderFiles();
        }
    });

    document.getElementById('create-share-link-button').addEventListener('click', createShareLink);
    document.getElementById('cancel-share-modal').addEventListener('click', () => hideModal('share-modal'));
    document.getElementById('confirm-edit-share').addEventListener('click', handleSaveShareSettings);
    document.getElementById('cancel-edit-share').addEventListener('click', () => hideModal('edit-share-modal'));
    document.getElementById('copy-generated-link-button').addEventListener('click', () => {
        const input = document.getElementById('generated-link-input');
        input.select();
        document.execCommand('copy');
        showMessageBox('Link copied to clipboard!', 'success');
    });

    document.getElementById('trash-button').addEventListener('click', openTrashModal);
    document.getElementById('close-trash-modal').addEventListener('click', () => hideModal('trash-modal'));
    document.getElementById('empty-trash-button').addEventListener('click', () => {
        const allTrashedIds = allDecryptedFiles
            .filter(item => item.isTrashed)
            .map(item => item.id);
        if (allTrashedIds.length > 0) {
            handleDeletePermanently(allTrashedIds);
        }
    });
});