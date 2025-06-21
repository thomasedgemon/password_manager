# 🔐 Stateless Password Manager

A local-only, session-based password manager that prioritizes ephemeral access and strong encryption.

---

## ✅ Features

- One-password-at-a-time decryption model for enhanced security.
- Master password **never saved** — can be forcibly removed from session memory at any time.
- Passwords decrypted in-session have a **limited lifespan**.
- UI displays:
  - ✅ Whether master password is in session memory
  - 📝 A running log of the last 5 actions
- Simple dropdown UI to select from stored labels.

---

## 📦 Current Capabilities (as of 6/20/25)

1. OS-agnostic: config file location is hardcoded but dynamically determined per platform.
2. Forces user to define a filepath for the encrypted CSV at setup.
3. If no valid file is defined, the app exits.
4. Encryption uses:
   - `AES-256-CBC`
   - Salted PBKDF2 with **600,000 iterations**
5. Saved labels appear in a dropdown for easy selection.

---

## 🚧 Roadmap / TODO

- [ ] Finalize **decryption display** and auto-clear logic
- [ ] Add functionality to **store new passwords**
- [ ] Add ability to **remove existing passwords**
- [ ] Add password **generator**
  - User-specified length
  - Enforces alphanumeric + special characters
  - Uses `os.urandom()` for high entropy
- [ ] Add functionality to **import/export from flash drive** for use on other machines

---

## 🛡️ Philosophy

> This manager is built to avoid long-term persistence. Nothing sensitive is stored unencrypted, and decrypted secrets vanish quickly after viewing. No external services, no database, no tracking — just you and your keys.


   
