#Stateless Password Manager

A local-only, session-based password manager that prioritizes ephemeral access and strong encryption.

---

## Current Capabilities (as of 6/20/25)

1. OS-agnostic: config file location is hardcoded but dynamically determined per platform.
2. Forces user to define a filepath for the encrypted CSV at setup.
3. If no valid file is defined, the app exits.
4. Encryption uses:
   - `AES-256-CBC`
   - Salted PBKDF2 with **600,000 iterations**
   - os.urandom for RNG
5. Saved labels appear in a dropdown for easy selection.
6. Per-password decryption
7. Master password cleared from session memory automatically after every action
8. Running log of the last five actions
9. Dropdown UI for encrypted labels
10. Time-based auto clearing of decrypted passwords

---

## Roadmap / TODO

- [ ] Finalize **decryption display** and auto-clear logic
- [ ] Add ability to **remove existing passwords**
- [ ] Add password **generator**
  - User-specified length
  - Enforces alphanumeric + special characters
  - Uses `os.urandom()` for high entropy
- [ ] Add functionality to **import/export from flash drive** for use on other machines

---

##  Philosophy

> This manager is built to avoid long-term persistence. Nothing sensitive is stored unencrypted, and decrypted secrets vanish quickly after viewing. No external services, no database, no tracking — just you and your keys.


   
