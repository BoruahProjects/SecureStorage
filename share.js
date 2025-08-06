const BASE_PATH = 'https://files.domain.com';

function getMimeType(filename) {
    const extension = filename.split('.').pop().toLowerCase();
    const mimeTypes = {
        'jpg': 'image/jpeg', 'jpeg': 'image/jpeg', 'png': 'image/png',
        'gif': 'image/gif', 'webp': 'image/webp', 'pdf': 'application/pdf',
        'txt': 'text/plain', 'md': 'text/markdown', 'js': 'text/javascript',
        'json': 'application/json', 'html': 'text/html', 'css': 'text/css',
    };
    return mimeTypes[extension] || 'application/octet-stream';
}

function formatBytes(bytes, decimals = 2) {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const dm = decimals < 0 ? 0 : decimals;
    const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(dm)) + ' ' + sizes[i];
}

function base64UrlToUint8(base64url) {
    let base64 = base64url.replace(/-/g, '+').replace(/_/g, '/');
    const padding = '='.repeat((4 - base64.length % 4) % 4);
    const binaryString = atob(base64 + padding);
    const len = binaryString.length;
    const bytes = new Uint8Array(len);
    for (let i = 0; i < len; i++) {
        bytes[i] = binaryString.charCodeAt(i);
    }
    return bytes;
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

function showSpinner(button, text = '') {
    button.disabled = true;
    const originalContent = button.innerHTML;
    button.dataset.originalContent = originalContent;
    button.innerHTML = '<div class="spinner"></div>' + (text ? `<span class="spinner-text">${text}</span>` : '');
}

function hideSpinner(button) {
    if (button.dataset.originalContent) {
        button.innerHTML = button.dataset.originalContent;
    }
    button.disabled = false;
}

let currentObjectUrl = null;

async function fetchAndDecryptFile(shareId, fileKey, metadata) {
    const response = await fetch(`${BASE_PATH}/api/share/download/${shareId}`);
    if (!response.ok) {
        let errorMessage;
        const errorText = await response.text(); 
        try {
            const errData = JSON.parse(errorText);
            errorMessage = errData.error || errorText;
        } catch (e) {
            errorMessage = errorText;
        }
        throw new Error(errorMessage || 'Download failed.');
    }
    const encryptedBuffer = await response.arrayBuffer();

    const decryptedBufferWithPadding = await decrypt(new Uint8Array(encryptedBuffer), fileKey, metadata.fileId);

    const decryptedBuffer = new Uint8Array(decryptedBufferWithPadding).subarray(0, metadata.fileSize);

    return new Blob([decryptedBuffer], { type: getMimeType(metadata.fileName) });
}

function hidePreviewModal() {
    if (currentObjectUrl) {
        URL.revokeObjectURL(currentObjectUrl);
        currentObjectUrl = null;
    }
    document.getElementById('preview-content-area').innerHTML = '';
    document.getElementById('preview-modal').classList.add('hidden');
}

function handleDownload(metadata, blobToDownload) {
    if (!blobToDownload) {
        document.getElementById('share-error').textContent = 'File data is not available. Please try again.';
        return;
    }
    const url = window.URL.createObjectURL(blobToDownload);
    const a = document.createElement('a');
    a.style.display = 'none';
    a.href = url;
    a.download = metadata.fileName;
    document.body.appendChild(a);
    a.click();
    window.URL.revokeObjectURL(url);
    document.body.removeChild(a);
}

async function handlePreview(shareId, finalFileKey, metadata) {
    const previewBtn = document.getElementById('preview-button');
    const modal = document.getElementById('preview-modal');
    const contentArea = document.getElementById('preview-content-area');

    contentArea.classList.remove('is-text-preview');
    modal.classList.remove('hidden');
    contentArea.innerHTML = `<div id="preview-loading-status" class="d-block text-center"><div class="spinner spinner-centered"></div><p>Loading and decrypting...</p></div>`;

    showSpinner(previewBtn, 'Downloading...');
    try {
        const blob = await fetchAndDecryptFile(shareId, finalFileKey, metadata);

        if (!blob) {
            hidePreviewModal();
            return;
        }

        const fileExtension = metadata.fileName.split('.').pop().toLowerCase();

        if (currentObjectUrl) URL.revokeObjectURL(currentObjectUrl);
        currentObjectUrl = URL.createObjectURL(blob);

        document.getElementById('preview-file-name').textContent = metadata.fileName;
        document.getElementById('preview-file-size').textContent = 'Size: ' + formatBytes(metadata.fileSize);
        document.getElementById('preview-download-button').onclick = () => handleDownload(metadata, blob);

        contentArea.innerHTML = '';

        if (['jpg', 'jpeg', 'png', 'gif', 'webp'].includes(fileExtension)) {
            const img = document.createElement('img');
            img.src = currentObjectUrl;
            contentArea.appendChild(img);
        } else if (['txt', 'md', 'js', 'json', 'html', 'css'].includes(fileExtension)) {
            contentArea.classList.add('is-text-preview');
            const text = await blob.text();
            const pre = document.createElement('pre');
            pre.textContent = text;
            contentArea.appendChild(pre);
        } else {
            const p = document.createElement('p');
            p.textContent = 'Preview not available for this file type.';
            contentArea.appendChild(p);
        }
    } catch (error) {
        document.getElementById('share-error').textContent = `Preview failed: ${error.message}`;
        hidePreviewModal();
    } finally {
        hideSpinner(previewBtn);
    }
}


document.addEventListener('DOMContentLoaded', async () => {
    document.body.classList.remove('app-loading');

    const statusEl = document.getElementById('share-status');
    const errorEl = document.getElementById('share-error');
    const actionContainer = document.getElementById('action-container');
    const downloadBtn = document.getElementById('download-button');
    const previewBtn = document.getElementById('preview-button');
    const passwordPrompt = document.getElementById('password-prompt');
    const passwordInput = document.getElementById('share-password-input');
    const passwordSubmitBtn = document.getElementById('password-submit-button');
    const fileDetailsEl = document.getElementById('file-details');
    const fileNameEl = document.getElementById('file-name');
    const fileSizeEl = document.getElementById('file-size');

    let finalFileKey = null;

    const fragment = window.location.hash.substring(1);
    if (!fragment || !fragment.includes(':')) {
        statusEl.textContent = 'This share link is invalid or incomplete.';
        errorEl.textContent = 'Error: Missing share ID or key material in the URL.';
        return;
    }

    const [shareId, keyMaterialEncoded] = fragment.split(':');

    if (!shareId || !keyMaterialEncoded) {
        statusEl.textContent = 'This share link is invalid or incomplete.';
        errorEl.textContent = 'Error: Malformed share link.';
        return;
    }

    let metadata;
    try {
        const response = await fetch(`${BASE_PATH}/api/share/public/${shareId}?v=${Date.now()}`);
        metadata = await response.json();
        if (!response.ok) {
            throw new Error(metadata.error || 'Could not retrieve file information.');
        }
    } catch (error) {
        statusEl.textContent = 'This link is no longer valid.';
        errorEl.textContent = `Error: ${error.message}`;
        return;
    }

    statusEl.classList.add('hidden');
    actionContainer.classList.remove('hidden');
    fileNameEl.textContent = metadata.fileName;
    fileSizeEl.textContent = formatBytes(metadata.fileSize);
    fileDetailsEl.classList.remove('hidden');

    const keyMaterial = base64UrlToUint8(keyMaterialEncoded);

    const supportedPreviewExtensions = ['jpg', 'jpeg', 'png', 'gif', 'webp', 'txt', 'md', 'js', 'json', 'html', 'css'];
    const fileExtension = metadata.fileName.split('.').pop().toLowerCase();
    const isPreviewable = supportedPreviewExtensions.includes(fileExtension);

    previewBtn.classList.toggle('hidden', !isPreviewable);

    const onKeyReady = (key) => {
        finalFileKey = key;
        downloadBtn.disabled = false;
        if (isPreviewable) {
            previewBtn.disabled = false;
        }
    };

    if (metadata.hasPassword) {
        passwordPrompt.classList.remove('hidden');
        passwordPrompt.addEventListener('submit', async (e) => {
            e.preventDefault();
            const password = passwordInput.value;
            if (!password) {
                errorEl.textContent = 'Password cannot be empty.';
                return;
            }
            showSpinner(passwordSubmitBtn, 'Unlocking...');
            errorEl.textContent = '';

            try {
                const salt = keyMaterial.slice(0, 16);
                const encryptedKey = keyMaterial.slice(16);

                const passwordEncoder = new TextEncoder();
                const keyMaterialPbkdf2 = await crypto.subtle.importKey('raw', passwordEncoder.encode(password), { name: 'PBKDF2' }, false, ['deriveKey']);
                const derivedKey = await crypto.subtle.deriveKey({ name: 'PBKDF2', salt, iterations: 1000000, hash: 'SHA-256' }, keyMaterialPbkdf2, { name: 'AES-GCM', length: 256 }, false, ['decrypt']);

                const decryptedFileKey = await decrypt(encryptedKey, derivedKey, shareId);
                const importedKey = await crypto.subtle.importKey('raw', decryptedFileKey, { name: 'AES-GCM' }, false, ['decrypt']);

                passwordPrompt.classList.add('hidden');
                onKeyReady(importedKey);

            } catch (err) {
                errorEl.textContent = 'Incorrect password or tampered link.';
            } finally {
                hideSpinner(passwordSubmitBtn);
            }
        });
    } else {
        try {
            const importedKey = await crypto.subtle.importKey('raw', keyMaterial, { name: 'AES-GCM' }, false, ['decrypt']);
            onKeyReady(importedKey);
        } catch (e) {
             statusEl.textContent = 'Could not process file key.';
             errorEl.textContent = 'The key material in the link appears to be corrupt.';
             return;
        }
    }

    downloadBtn.addEventListener('click', async () => {
        if (!finalFileKey) return;

        showSpinner(downloadBtn, 'Downloading...');
        try {
            const blob = await fetchAndDecryptFile(shareId, finalFileKey, metadata);
            if (blob) {
                handleDownload(metadata, blob);
            }
        } catch (error) {
            document.getElementById('share-error').textContent = `Download failed: ${error.message}`;
        } finally {
            hideSpinner(downloadBtn);
        }
    });

    previewBtn.addEventListener('click', () => {
        if (!finalFileKey) return;
        handlePreview(shareId, finalFileKey, metadata);
    });

    document.getElementById('close-preview-modal').addEventListener('click', hidePreviewModal);
    document.getElementById('preview-modal').addEventListener('click', (e) => {
        if (e.target.id === 'preview-modal') hidePreviewModal();
    });
});