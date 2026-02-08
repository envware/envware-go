# 🌸 envware-go

[![License](https://img.shields.io/badge/License-BSL%201.1-orange.svg?style=flat-square)](LICENSE.md)
[![Go Version](https://img.shields.io/badge/Go-1.21+-blue?style=flat-square&logo=go)](https://go.dev)

**Securely sync encrypted secrets across your devices and team with zero-trust security.**

`envware-go` is the high-performance, Go-powered engine for Envware. It focuses on absolute security, speed, and a simplified developer experience for managing environment variables.

## Why Envware?

Stop sharing `.env` files via Slack, DMs, or insecure notes. Envware ensures your secrets never touch the cloud in plain text.

- **🔒 Zero-Trust Architecture:** Your secrets are encrypted **locally** using AES-256-GCM. The server never sees your plain text data.
- **🔑 SSH Identity:** Authorization is tied to your local SSH keys. Every command is digitally signed and verified by the server.
- **🏢 Multi-tenant Teams:** Organize projects by teams with granular access control.
- **🛡️ Secure Key Exchange:** Access is granted by encrypting a Project Key directly for a user's verified public key.
- **✨ Fingerprint Verification:** Verify collaborator identities using SHA256 fingerprints, making it immune to server-side tampering.

## Core Commands

- **`request <team> <project> <ROLE>`**: Request access to a project or create it (if you are the OWNER).
- **`push <team> <project> [env-file]`**: Encrypt and upload your local secrets.
- **`pull <team> <project> [env-file]`**: Download and decrypt secrets for your project.
- **`accept`**: List pending access requests.
- **`accept <id>`**: Securely approve an access request and share the project key.
- **`projects <team>`**: List all projects in a specific team.
- **`envs <team> <project>`**: List all environments available in a project.
- **`secrets <team> <project> [env-file]`**: List secret keys (names only) in an environment.
- **`status <team> [project]`**: Check team and project details.

## Installation

The quickest way to install Envware 2.0 is via our installation script:

```bash
curl -sSL https://www.envware.dev/install.sh | bash
```

### Other options

#### Via Go
```bash
go install github.com/envware/envware-go@latest
```
*Note: Make sure your `$GOPATH/bin` is in your PATH.*

### 2. Or Build from Source
```bash
go build -o envw main.go
# Move to your local bin to use it globally:
sudo mv envw /usr/local/bin/
```

### 3. Request Access or Create Project
```bash
envw request team1 project1 OWNER
```

### 4. Push Secrets
```bash
# Uploads .env by default
envw push team1 project1
```

### 5. Pull Secrets
```bash
# Downloads and decrypts
envw pull team1 project1
```

## Security Model (The "Master Key" Logic)

Envware uses a **dual-key E2EE architecture** to ensure that plain text secrets never touch our infrastructure.

### 1. The Project Key (The Master Code)
When a project is initialized, a unique **Project Key** (AES-256) is generated locally on your machine. This is the "Master Code" that locks and unlocks your `.env` files.

### 2. Secure Envelopes (RSA-OAEP)
To store this Project Key on our server without us ever seeing it, we use your **SSH Public Key** to create a "Secure Envelope" around it.
*   **The Server** only sees a sealed envelope.
*   **Only Your Private SSH Key** can open that envelope to retrieve the Master Code.

### 3. How Teams Share Access
When you approve a new member (`envw accept`):
1.  Your CLI downloads **your** envelope and opens it using your private key.
2.  It retrieves the **Master Code** (locally, in memory).
3.  It creates a **new envelope** using the **new member's public key**.
4.  The server now stores a second envelope. Same Master Code, but different lock.

**Result:** Every team member has their own "copy" of the Master Code, but each copy is locked with their unique SSH identity. If the server is compromised, the attacker only finds millions of sealed envelopes they cannot open. 🛡️🌸

## Advanced Security Features

### 🛡️ Local Mode (E2EE for Git)
With **Local Mode**, you can store your secrets directly in your Git repository without exposing them.
- **`encrypt <team> <project> [env-file]`**: Creates a secure `.env.crypto` file.
- **`decrypt <team> <project> [file]`**: Decrypts it back to your environment.

### 🧂 Environment Salting & RBAC
Envware adds an extra layer of security by using the environment name (e.g., `production`, `development`) as a **cryptographic salt**. 
- **How it works:** When you run `encrypt`, the environment name is embedded in the metadata.
- **Protection:** If a file contains "prod" or "production" in its environment name, the backend will strictly deny decryption keys to users with the `DEVELOPER` role.
- **Deterministic:** Even if a developer has the Master Project Key, the mathematical salt (based on the environment name) ensures they cannot derive the final decryption key for production files.

> **Note:** Always name your production-sensitive files using "prod" or "production" (e.g., `.env.production`) to trigger the automatic RBAC protection. 🛡️🌸

### 🛡️ AES-256-GCM Implementation
We use Authenticated Encryption (GCM) to ensure both **privacy** and **integrity**:
- **`iv` (Initialization Vector)**: A unique, random "nonce" for every encryption operation. This ensures that the same secret encrypted twice results in different ciphertexts, preventing pattern analysis.
- **`tag` (Authentication Tag)**: A cryptographic checksum that proves the data hasn't been tampered with. If even a single bit is modified in your `.env.crypto`, the decryption will fail.

---

**Website:** [https://www.envware.dev](https://www.envware.dev)  
**Documentation:** [https://www.envware.dev/docs](https://www.envware.dev) 🌸🚀
