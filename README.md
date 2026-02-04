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

## Security Model

Envware uses a dual-key E2EE system:
1. **User Identity:** Derived from your local SSH public key (`~/.ssh/id_rsa`).
2. **Project Key:** A unique AES-256 key generated for each project.
3. **Storage:** The server only stores "encrypted blobs". The Project Key is stored encrypted with your SSH Public Key.

### Challenge-Response Auth
Unlike traditional CLIs using long-lived JWTs, `envware-go` uses a challenge-response mechanism for every sensitive operation. The server issues a unique challenge, and the CLI signs it using your private SSH key.

---

**Website:** [https://www.envware.dev](https://www.envware.dev)  
**Documentation:** [https://www.envware.dev/docs](https://www.envware.dev) 🌸🚀
