# Secure Storage

## Project Description

**Secure Storage** is a self-hostable, end-to-end encrypted cloud storage solution designed for personal use. Leveraging **Cloudflare Workers** and **R2**, it provides a robust and secure platform for storing your files with client-side encryption, ensuring your data remains private.  
It features a user-friendly web interface, file management capabilities (upload, download, rename, move, copy, trash), and secure shareable links.

---

## Features

- **End-to-End Encryption (E2EE):**  
  All files are encrypted in your browser before being uploaded. Your encryption keys never leave your device.

- **Self-Hostable:**  
  Easily deployable on Cloudflare Workers and R2, giving you full control over your storage infrastructure.

- **File Management:**  
  Intuitive interface to upload, download, rename, move, copy, and delete files and folders.

- **Secure Sharing:**  
  Generate password-protected and time-limited share links for individual files.

- **Trash Bin:**  
  Recover accidentally deleted files from the trash.

- **Responsive Design:**  
  Accessible and usable across desktop, tablet, and mobile.

- **Authentication:**  
  Secure login system for access control.

---

## Technologies Used

- **Frontend:** HTML, CSS, JavaScript
- **Backend/Cloud:** Cloudflare Workers, Cloudflare R2 (object storage), Cloudflare KV (metadata and rate limiting)
- **Cryptography:** Web Crypto API (AES-GCM, PBKDF2, HKDF, ECDSA for JWTs)

---

## Getting Started

These instructions will get you a copy of the project up and running on your local machine for development and testing, and guide you through deploying it to Cloudflare.

### Prerequisites

- A Cloudflare account
- Node.js and npm (or yarn) installed
- Cloudflare Wrangler CLI (`npm install -g wrangler`)
- Basic understanding of JavaScript, HTML, and CSS

### Installation and Deployment

1. **Clone the repository:**
    ```sh
    git clone https://github.com/your-username/secure-storage.git
    cd secure-storage
    ```

2. **Configure Cloudflare:**

    - **R2 Bucket:** Create an R2 bucket for file storage. Note its name.
    - **KV Namespaces:** Create the following KV namespaces:
      - KV_TOKEN_DENYLIST
      - KV_SESSIONS
      - KV_ERROR_ATTEMPTS
      - KV_LOGIN_ATTEMPTS
      - KV_OWNERSHIP
      - SHARE_STORE
      - SHARE_LOOKUP

    - **Secrets:** Set up the following secrets in your Cloudflare Workers environment using `wrangler secret put [SECRET_NAME]`:
      - `ADMIN_USERNAME_HASH`: Hashed admin username.
      - `ADMIN_USERNAME_SALT`: Salt used for hashing admin username.
      - `ADMIN_PASSWORD_HASH`: Hashed admin password.
      - `ADMIN_PASSWORD_SALT`: Salt used for hashing admin password.
      - `TOKEN_SECRET`: A strong, random string for token encryption.
      - `MANIFEST_SECRET`: A strong, random string for manifest HMAC.
      - `JWT_PRIVATE_KEY`: Your ECDSA P-256 private key in PKCS#8 PEM format (e.g., `-----BEGIN EC PRIVATE KEY----- ... -----END EC PRIVATE KEY-----`)
      - `JWT_PUBLIC_KEY`: Your ECDSA P-256 public key in SPKI PEM format (e.g., `-----BEGIN PUBLIC KEY----- ... -----END PUBLIC KEY-----`)
      - `METADATA_SECRET`: A strong, random string for share link metadata HMAC.
      - `R2_BUCKET`: The name of your R2 bucket.
      - KV namespace IDs as created above.

    - **Generate Keys:**  
      You can generate ECDSA P-256 keys using OpenSSL:
      ```sh
      openssl ecparam -name prime256v1 -genkey -noout -out private_key.pem
      openssl ec -in private_key.pem -pubout -out public_key.pem
      ```
      Convert them to PKCS#8 and SPKI formats if necessary.

    - **Generate Hashes for Admin Credentials:**  
      Example in Node.js:
      ```js
      const crypto = require('crypto');
      async function hashPassword(password, salt) {
          const keyMaterial = await crypto.subtle.importKey(
              'raw',
              new TextEncoder().encode(password),
              { name: 'PBKDF2' },
              false,
              ['deriveKey']
          );
          const derivedKey = await crypto.subtle.deriveKey(
              { name: 'PBKDF2', salt: salt, iterations: 100000, hash: 'SHA-256' },
              keyMaterial,
              { name: 'AES-GCM', length: 256 },
              true,
              ['encrypt']
          );
          const hashBuffer = await crypto.subtle.exportKey('raw', derivedKey);
          return Buffer.from(hashBuffer).toString('hex');
      }

      async function hashUsername(username, salt) {
          const hashBuffer = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(username + salt));
          return Buffer.from(hashBuffer).toString('hex');
      }

      (async () => {
          const usernameSalt = crypto.randomBytes(16);
          const passwordSalt = crypto.randomBytes(16);

          const adminUsername = 'your_admin_username';
          const adminPassword = 'your_admin_password';

          const hashedUsername = await hashUsername(adminUsername, usernameSalt.toString('hex'));
          const hashedPassword = await hashPassword(adminPassword, passwordSalt);

          console.log('ADMIN_USERNAME_HASH:', hashedUsername);
          console.log('ADMIN_USERNAME_SALT:', usernameSalt.toString('hex'));
          console.log('ADMIN_PASSWORD_HASH:', hashedPassword);
          console.log('ADMIN_PASSWORD_SALT:', passwordSalt.toString('hex'));
      })();
      ```

3. **Deploy the Worker:**

    Create a `wrangler.toml` file in your project root:
    ```toml
    name = "secure-storage-worker"
    main = "workers.js"
    compatibility_date = "2024-01-01"

    [vars]
    ALLOWED_ORIGIN = "https://your-frontend-domain.com"

    [r2_buckets]
    binding = "R2_BUCKET"
    bucket_name = "your-r2-bucket-name"

    [kv_namespaces]
    binding = "KV_TOKEN_DENYLIST"
    id = "YOUR_KV_TOKEN_DENYLIST_ID"
    binding = "KV_SESSIONS"
    id = "YOUR_KV_SESSIONS_ID"
    binding = "KV_LOGIN_ATTEMPTS"
    id = "YOUR_KV_LOGIN_ATTEMPTS_ID"
    binding = "KV_OWNERSHIP"
    id = "YOUR_KV_OWNERSHIP_ID"
    binding = "SHARE_STORE"
    id = "YOUR_SHARE_STORE_ID"
    binding = "SHARE_LOOKUP"
    id = "YOUR_SHARE_LOOKUP_ID"
    ```

    Deploy your worker:
    ```sh
    wrangler deploy
    ```

4. **Deploy the Frontend:**

    - Host `index.html`, `share.html`, `main.js`, `share.js`, `style.css`, and `_headers` on Cloudflare Pages, GitHub Pages, or any static hosting service.
    - **Cloudflare Pages** is recommended.
    - Create a new Cloudflare Pages project and connect it to your GitHub repository.
    - Set the build command and output directory to empty (static site).
    - Ensure your `_headers` file is in the root.
    - **Important:**  
      - Update `BASE_PATH` in `main.js` and `share.js` to your Worker URL.
      - Update `ALLOWED_ORIGIN` in `workers.js` to your frontend domain.

---

## Usage

- **Access your deployed frontend URL.**
- **Login:** Use the admin credentials you configured as secrets.
- **Set Encryption Password:** On first login, you'll set an E2EE password. **Remember this!** It cannot be recovered.
- **Manage Files:** Upload, download, create folders, rename, move, copy, and share your encrypted files.

---

## Security Considerations

- **Encryption Keys:**  
  Derived from your E2E password; never leave your browser. Server stores only encrypted blobs.
- **Password Strength:**  
  Use a strong, unique E2E password.
- **Cloudflare Infrastructure:**  
  Robust, but security depends on your E2E password and secrets configuration.
- **MIME Type Blocking:**  
  Certain MIME types are blocked to prevent malicious uploads.

---

## Contributing

Contributions are welcome! If you find a bug or have a feature request, please open an issue. If you'd like to contribute code, please fork the repository and submit a pull request.

---

## License

This project is licensed under a custom license. Please refer to the `LICENSE` file for details.
