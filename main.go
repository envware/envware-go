package main

import (
	"bufio"
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/fatih/color"
	"golang.org/x/crypto/scrypt"
)

// --- LLM Documentation ---

const llmsTxt = `# Envware

> Secure environment variable manager with end-to-end encryption (E2EE) using SSH keys.

Envware encrypts secrets locally before syncing. The server never sees plaintext data.

## Quick Start

` + "```" + `bash
# Install
curl -sSL https://www.envware.dev/install.sh | bash

# Request access (or create project as OWNER)
envw request <team> <project> <ROLE>

# Push secrets (encrypts .env locally, uploads ciphertext)
envw push <team> <project> [env-file]

# Pull secrets (downloads and decrypts)
envw pull <team> <project> [env-file]
` + "```" + `

## Core Commands

| Command | Description |
|---------|-------------|
| envw request <team> <project> <ROLE> | Request access or create project |
| envw push <team> <project> [.env] | Encrypt and upload secrets |
| envw pull <team> <project> [.env] | Download and decrypt secrets |
| envw status <team> [project] | Show team/project info |
| envw projects <team> | List projects in a team |
| envw envs <team> <project> | List environments |
| envw secrets <team> <project> [env] | List secret keys (names only) |
| envw accept | List pending access requests |
| envw accept <id> | Approve access request |
| envw purchase teams | Buy extra team slot |
| envw purchase projects <team> | Buy +5 project slots |
| envw purchase users <team> <project> | Buy +10 user slots |

## Roles

- OWNER: Full control, billing, can approve requests
- ADMIN: Push, pull, approve access
- DEV: Pull only
- CI: Show individual secrets (for pipelines)

## Security Model

- Secrets encrypted with AES-256-GCM using a Project Key
- Project Key is RSA-encrypted for each user's SSH public key
- Server only stores encrypted envelopes, never plaintext
- Access approval re-encrypts Project Key for new member's public key

## Links

- Website: https://www.envware.dev
- Docs: https://www.envware.dev/docs
- Install: curl -sSL https://www.envware.dev/install.sh | bash
`

const llmsFullTxt = `# Envware - Complete LLM Reference

> Secure environment variable manager with end-to-end encryption (E2EE) using SSH keys.

Envware encrypts secrets locally using your SSH identity before syncing. The server never sees plaintext data.

## Installation

` + "```" + `bash
# Quick install (recommended)
curl -sSL https://www.envware.dev/install.sh | bash

# Via Go
go install github.com/envware/envware-go@latest
` + "```" + `

## Architecture

Hierarchy: User (SSH Identity) -> Teams -> Projects -> Environments -> Secrets

Security Model:
1. Project Key: Each project has a unique AES-256 key generated locally
2. Secure Envelopes: Project Key is RSA-OAEP encrypted for each user's SSH public key
3. Zero-Knowledge Server: Server only stores encrypted envelopes and ciphertext
4. Fingerprint Verification: SHA256 fingerprints verify user identity

## Commands Reference

### envw request <team> <project> <ROLE>
Request access to a project or create it (becomes OWNER if first).
Roles: OWNER, ADMIN, DEV, CI

### envw push <team> <project> [env-file]
Encrypt and upload secrets. Default: .env
Examples: envw push myteam myapp .env.production

### envw pull <team> <project> [env-file]
Download and decrypt secrets. Default: .env
Examples: envw pull myteam myapp .env.production

### envw status <team> [project]
Show team details or project users/environments.

### envw projects <team>
List all projects in a team.

### envw envs <team> <project>
List all environments in a project.

### envw secrets <team> <project> [env-file]
List secret keys (names only, not values).

### envw accept
List pending access requests.

### envw accept <request-id>
Approve access request (re-encrypts Project Key for new member).
IMPORTANT: Verify fingerprint out-of-band before approving!

### envw purchase teams
Buy +1 team slot ($10/month)

### envw purchase projects <team>
Buy +5 project slots for a team ($10/month)

### envw purchase users <team> <project>
Buy +10 user slots for a project ($10/month)

## Free Tier Limits

- Teams: 1
- Projects per Team: 3
- Users per Project: 5

## Common Workflows

New Project:
  envw request myteam myapp OWNER
  envw push myteam myapp

Grant Access:
  # Teammate runs: envw request myteam myapp DEV
  # You run: envw accept
  # Verify fingerprint, then: envw accept <id>

Multiple Environments:
  envw push myteam myapp .env.development
  envw push myteam myapp .env.staging
  envw push myteam myapp .env.production

## Links

- Website: https://www.envware.dev
- Docs: https://www.envware.dev/docs
- GitHub: https://github.com/envware/envware-go
`

// --- Estruturas de Dados ---

type ChallengeRequest struct{ PublicKey string `json:"publicKey"` }
type ChallengeResponse struct{ Challenge string `json:"challenge"` }

type AccessRequest struct {
	PublicKey   string `json:"publicKey"`
	Signature   string `json:"signature"`
	TeamSlug    string `json:"teamSlug"`
	ProjectSlug string `json:"projectSlug"`
	Role        string `json:"role"`
	UserName    string `json:"userName"`
	DeviceAlias string `json:"deviceAlias"`
}

type StatusRequest struct {
	PublicKey   string `json:"publicKey"`
	Signature   string `json:"signature"`
	TeamSlug    string `json:"teamSlug"`
	ProjectSlug string `json:"projectSlug,omitempty"`
}

type Secret struct {
	Key   string `json:"key"`
	Value string `json:"value"`
	Iv    string `json:"iv"`
	Tag   string `json:"tag"`
}

type PushRequest struct {
	PublicKey           string   `json:"publicKey"`
	Signature           string   `json:"signature"`
	TeamSlug            string   `json:"teamSlug"`
	ProjectSlug         string   `json:"projectSlug"`
	Environment         string   `json:"environment"`
	Secrets             []Secret `json:"secrets"`
	EncryptedProjectKey string   `json:"encryptedProjectKey,omitempty"`
}

type PullRequest struct {
	PublicKey   string   `json:"publicKey"`
	Signature   string   `json:"signature"`
	TeamSlug    string   `json:"teamSlug"`
	ProjectSlug string   `json:"projectSlug"`
	Environment string   `json:"environment"`
}

type ApproveRequest struct {
	PublicKey           string `json:"publicKey"`
	Signature           string `json:"signature"`
	RequestId           string `json:"requestId,omitempty"`
	EncryptedProjectKey string `json:"encryptedProjectKey"`
	TeamSlug            string `json:"teamSlug,omitempty"`
	ProjectSlug         string `json:"projectSlug,omitempty"`
}

type EnvInfo struct {
	Name  string `json:"name"`
	Count int    `json:"count"`
}

type ProjectListItem struct {
	Name         string `json:"name"`
	Slug         string `json:"slug"`
	SecretsCount int    `json:"secretsCount"`
}

type TeamSummary struct {
	Name          string `json:"name"`
	Slug          string `json:"slug"`
	ProjectsCount int    `json:"projectsCount"`
	Role          string `json:"role"`
}

type UserStats struct {
	Name  string        `json:"name"`
	Email string        `json:"email"`
	Teams []TeamSummary `json:"teams"`
}

type CommonResponse struct {
	Success             bool              `json:"success"`
	Message             string            `json:"message"`
	Secrets             []Secret          `json:"secrets"`
	Envs                []EnvInfo         `json:"envs,omitempty"`
	Projects            []ProjectListItem `json:"projects,omitempty"`
	EncryptedProjectKey string            `json:"encryptedProjectKey,omitempty"`
	Team                *TeamInfo         `json:"team,omitempty"`
	Project             *ProjectInfo      `json:"project,omitempty"`
	User                *UserStats        `json:"user,omitempty"`
	Requests            []PendingRequest  `json:"requests,omitempty"`
	Error               string            `json:"error,omitempty"`
}

type PendingRequest struct {
	Id          string `json:"id"`
	UserName    string `json:"userName"`
	UserEmail   string `json:"userEmail"`
	PublicKey   string `json:"publicKey"`
	Role        string `json:"role"`
	ProjectSlug string `json:"projectSlug"`
	TeamSlug    string `json:"teamSlug"`
	DeviceAlias string `json:"deviceAlias"`
}

type TeamInfo struct {
	Name               string            `json:"name"`
	Slug               string            `json:"slug"`
	IsPremium          bool              `json:"isPremium"`
	IsVerified         bool              `json:"isVerified"`
	MaxProjects        int               `json:"maxProjects"`
	ProjectsCount      int               `json:"projectsCount"`
	MaxUsersPerProject int               `json:"maxUsersPerProject"`
	OwnerEmail         string            `json:"ownerEmail"`
	Projects           []TeamProjectInfo `json:"projects"`
}

type TeamProjectInfo struct {
	Name       string `json:"name"`
	Slug       string `json:"slug"`
	UsersCount int    `json:"usersCount"`
}

type ProjectInfo struct {
	Name      string     `json:"name"`
	Slug      string     `json:"slug"`
	UsersUsed int        `json:"usersUsed"`
	MaxUsers  int        `json:"maxUsers"`
	Users     []UserInfo `json:"users"`
}

type UserInfo struct {
	Name        string `json:"name"`
	Email       string `json:"email"`
	Device      string `json:"device"`
	Fingerprint string `json:"fingerprint"`
	Role        string `json:"role"`
	IsCurrent   bool   `json:"isCurrent"`
}

// --- Serviços ---

type EnvwareService struct {
	HomeDir string
	BaseURL string
}

func NewEnvwareService() *EnvwareService {
	home, _ := os.UserHomeDir()
	baseUrl := "https://www.envware.dev/api/v2"
	if os.Getenv("ENVW_LOCAL") == "true" {
		baseUrl = "http://localhost:3000/api/v2"
	}
	return &EnvwareService{HomeDir: home, BaseURL: baseUrl}
}

func (s *EnvwareService) GetSSHKeys() (string, string, error) {
	privPath := filepath.Join(s.HomeDir, ".ssh", "id_rsa")
	privBytes, err := os.ReadFile(privPath)
	if err != nil {
		return "", "", err
	}
	pubBytes, _ := os.ReadFile(privPath + ".pub")
	return string(privBytes), string(pubBytes), nil
}

func (s *EnvwareService) GetFingerprint(publicKey string) string {
	parts := strings.Split(strings.TrimSpace(publicKey), " ")
	keyData := parts[0]
	if len(parts) > 1 {
		keyData = parts[1]
	}
	der, _ := base64.StdEncoding.DecodeString(keyData)
	hash := sha256.Sum256(der)
	return base64.StdEncoding.EncodeToString(hash[:])
}

// deriveKey usa scrypt para derivar a chave AES igual ao Node.js
func (s *EnvwareService) deriveKey(projectKey string) ([]byte, error) {
	return scrypt.Key([]byte(projectKey), []byte("envware-salt"), 16384, 8, 1, 32)
}

func (s *EnvwareService) EncryptSecret(text string, projectKey string) (Secret, error) {
	key, err := s.deriveKey(projectKey)
	if err != nil {
		return Secret{}, err
	}

	block, _ := aes.NewCipher(key)
	gcm, _ := cipher.NewGCM(block)
	iv := make([]byte, gcm.NonceSize())
	io.ReadFull(rand.Reader, iv)
	sealed := gcm.Seal(nil, iv, []byte(text), nil)
	tagSize := gcm.Overhead()
	return Secret{
		Value: hex.EncodeToString(sealed[:len(sealed)-tagSize]),
		Iv:    hex.EncodeToString(iv),
		Tag:   hex.EncodeToString(sealed[len(sealed)-tagSize:]),
	}, nil
}

func (s *EnvwareService) DecryptSecret(enc Secret, projectKey string) (string, error) {
	key, err := s.deriveKey(projectKey)
	if err != nil {
		return "", err
	}

	block, _ := aes.NewCipher(key)
	gcm, _ := cipher.NewGCM(block)
	iv, _ := hex.DecodeString(enc.Iv)
	val, _ := hex.DecodeString(enc.Value)
	tag, _ := hex.DecodeString(enc.Tag)
	plaintext, err := gcm.Open(nil, iv, append(val, tag...), nil)
	return string(plaintext), err
}

func (s *EnvwareService) RSADecrypt(encStr string, privKey *rsa.PrivateKey) ([]byte, error) {
	data, err := base64.StdEncoding.DecodeString(encStr)
	if err != nil {
		return nil, err
	}
	return rsa.DecryptOAEP(sha256.New(), rand.Reader, privKey, data, nil)
}

// getAuthChallenge solicita um desafio fresco e gera a assinatura
func (s *EnvwareService) getAuthChallenge(pubStr string, privKey *rsa.PrivateKey) (string, error) {
	challReq, _ := json.Marshal(ChallengeRequest{PublicKey: pubStr})
	resp, err := http.Post(s.BaseURL+"/auth/challenge", "application/json", bytes.NewBuffer(challReq))
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("server returned %d", resp.StatusCode)
	}

	var challResp ChallengeResponse
	if err := json.NewDecoder(resp.Body).Decode(&challResp); err != nil {
		return "", err
	}

	if challResp.Challenge == "" {
		return "", fmt.Errorf("empty challenge")
	}

	hashed := sha256.Sum256([]byte(challResp.Challenge))
	sig, err := rsa.SignPKCS1v15(rand.Reader, privKey, crypto.SHA256, hashed[:])
	if err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(sig), nil
}

func openInBrowser(url string) error {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "linux":
		cmd = exec.Command("xdg-open", url)
	case "darwin":
		cmd = exec.Command("open", url)
	case "windows":
		cmd = exec.Command("cmd", "/c", "start", url)
	default:
		return fmt.Errorf("unsupported platform")
	}
	return cmd.Start()
}

func main() {
	color.New(color.FgCyan, color.Bold).Println("🌸 envware-go ENGINE v2.0.7")
	if len(os.Args) < 2 {
		fmt.Println("Usage: envw <command> [args...]")
		return
	}

	action := os.Args[1]
	service := NewEnvwareService()
	privStr, pubStr, err := service.GetSSHKeys()
	if err != nil {
		color.Red("Error loading keys: %v", err)
		return
	}

	pemBlock, _ := pem.Decode([]byte(privStr))
	var privKey *rsa.PrivateKey
	if key, err := x509.ParsePKCS1PrivateKey(pemBlock.Bytes); err == nil {
		privKey = key
	} else {
		pk8, _ := x509.ParsePKCS8PrivateKey(pemBlock.Bytes)
		privKey = pk8.(*rsa.PrivateKey)
	}

	switch action {
	case "push":
		if len(os.Args) < 4 {
			fmt.Println("Usage: push <team> <project> [env-file]")
			return
		}
		team, project := os.Args[2], os.Args[3]
		environment := ".env"
		if len(os.Args) >= 5 {
			environment = os.Args[4]
		}

		fmt.Print("🔐 Auth... ")
		signature, err := service.getAuthChallenge(pubStr, privKey)
		if err != nil {
			color.Red("Fail: %v", err)
			return
		}
		color.Green("OK!")

		pullReq, _ := json.Marshal(PullRequest{PublicKey: pubStr, Signature: signature, TeamSlug: team, ProjectSlug: project, Environment: environment})
		respPull, err := http.Post(service.BaseURL+"/pull-secrets", "application/json", bytes.NewBuffer(pullReq))
		if err != nil {
			color.Red("Server Offline")
			return
		}
		var pullResp CommonResponse
		json.NewDecoder(respPull.Body).Decode(&pullResp)
		respPull.Body.Close()

		if !pullResp.Success {
			color.Red("Error: %s 🌸", pullResp.Error)
			return
		}

		var projectKey string
		if pullResp.EncryptedProjectKey != "" {
			projectKeyBytes, err := service.RSADecrypt(pullResp.EncryptedProjectKey, privKey)
			if err != nil {
				color.Red("Error decrypting project key: %v. 🌸", err)
				return
			}
			projectKey = string(projectKeyBytes)
		} else {
			color.Yellow("Project not initialized. Initializing E2EE... 🛡️")

			fmt.Print("🔐 Re-Auth for Key Init... ")
			signature2, err := service.getAuthChallenge(pubStr, privKey)
			if err != nil {
				color.Red("Fail: %v", err)
				return
			}
			color.Green("OK!")

			keyInitReq, _ := json.Marshal(ApproveRequest{
				PublicKey: pubStr, Signature: signature2, TeamSlug: team, ProjectSlug: project,
			})
			respInit, err := http.Post(service.BaseURL+"/projects/keys", "application/json", bytes.NewBuffer(keyInitReq))
			if err != nil {
				color.Red("Server Offline")
				return
			}
			var keyResp CommonResponse
			json.NewDecoder(respInit.Body).Decode(&keyResp)
			respInit.Body.Close()

			if keyResp.Success && keyResp.EncryptedProjectKey != "" {
				projectKeyBytes, err := service.RSADecrypt(keyResp.EncryptedProjectKey, privKey)
				if err != nil {
					color.Red("Failed to decrypt newly initialized key: %v", err)
					return
				}
				projectKey = string(projectKeyBytes)
				color.Green("✔ Project initialized! 🛡️")
			} else {
				color.Red("Failed to initialize project: %s.", keyResp.Error)
				return
			}
		}

		secretsMap, _ := parseEnvFile(environment)
		var secrets []Secret
		for k, v := range secretsMap {
			s, _ := service.EncryptSecret(v, projectKey)
			s.Key = k
			secrets = append(secrets, s)
		}

		fmt.Print("🔐 Finalizing Push... ")
		signature3, err := service.getAuthChallenge(pubStr, privKey)
		if err != nil {
			color.Red("Fail: %v", err)
			return
		}
		color.Green("OK!")

		pushReq := PushRequest{
			PublicKey: pubStr, Signature: signature3, TeamSlug: team, ProjectSlug: project,
			Environment: environment, Secrets: secrets,
		}
		reqBody, _ := json.Marshal(pushReq)
		respPush, err := http.Post(service.BaseURL+"/secrets/push", "application/json", bytes.NewBuffer(reqBody))
		if err != nil {
			color.Red("Server Offline")
			return
		}
		body, _ := io.ReadAll(respPush.Body)
		var finalResp CommonResponse
		json.Unmarshal(body, &finalResp)
		respPush.Body.Close()
		if finalResp.Success {
			color.Green("✔ Secrets pushed successfully to %s/%s! 🌸🚀", team, project)
		} else {
			color.Red("❌ Push failed: %s", finalResp.Error)
		}

	case "pull":
		if len(os.Args) < 4 {
			fmt.Println("Usage: pull <team> <project> [env-file]")
			return
		}
		team, project := os.Args[2], os.Args[3]
		environment := ".env"
		if len(os.Args) >= 5 {
			environment = os.Args[4]
		}

		fmt.Print("🔐 Auth... ")
		signature, err := service.getAuthChallenge(pubStr, privKey)
		if err != nil {
			color.Red("Fail: %v", err)
			return
		}
		color.Green("OK!")

		pullReq, _ := json.Marshal(PullRequest{PublicKey: pubStr, Signature: signature, TeamSlug: team, ProjectSlug: project, Environment: environment})
		resp, err := http.Post(service.BaseURL+"/pull-secrets", "application/json", bytes.NewBuffer(pullReq))
		if err != nil {
			color.Red("Server Offline")
			return
		}
		var pullResp CommonResponse
		json.NewDecoder(resp.Body).Decode(&pullResp)
		resp.Body.Close()

		if !pullResp.Success || (len(pullResp.Secrets) == 0 && pullResp.EncryptedProjectKey == "") {
			color.Red("Error: %s 🌸", pullResp.Error)
			return
		}

		projectKeyBytes, err := service.RSADecrypt(pullResp.EncryptedProjectKey, privKey)
		if err != nil {
			color.Red("Error decrypting: %v", err)
			return
		}
		projectKey := string(projectKeyBytes)

		var envContent string
		for _, s := range pullResp.Secrets {
			val, err := service.DecryptSecret(s, projectKey)
			if err != nil {
				color.Red("Error decrypting secret %s: %v", s.Key, err)
				continue
			}
			envContent += fmt.Sprintf("%s=%s\n", s.Key, val)
		}

		os.WriteFile(environment, []byte(envContent), 0644)
		color.Green("✔ %s updated! 💎", environment)

		// Check if the pulled file is in .gitignore
		checkGitIgnore(environment)

	case "status":
		teamSlug := ""
		if len(os.Args) >= 3 {
			teamSlug = os.Args[2]
		}
		projectSlug := ""
		if len(os.Args) >= 4 {
			projectSlug = os.Args[3]
		}

		fmt.Print("🔐 Auth... ")
		signature, err := service.getAuthChallenge(pubStr, privKey)
		if err != nil {
			color.Red("Fail: %v", err)
			return
		}
		color.Green("OK!")

		statReq, _ := json.Marshal(StatusRequest{PublicKey: pubStr, Signature: signature, TeamSlug: teamSlug, ProjectSlug: projectSlug})
		resp, err := http.Post(service.BaseURL+"/team-stats", "application/json", bytes.NewBuffer(statReq))
		if err != nil {
			color.Red("Fail: %v", err)
			return
		}
		var finalResp CommonResponse
		json.NewDecoder(resp.Body).Decode(&finalResp)
		resp.Body.Close()
		if finalResp.Success {
			if finalResp.Message != "" {
				color.Yellow("\n%s\n", finalResp.Message)
			}
			if finalResp.User != nil {
				fmt.Printf("\n👤 USER: %s (%s)\n", finalResp.User.Name, finalResp.User.Email)
				if len(finalResp.User.Teams) == 0 {
					color.Yellow("  No teams found for this user.")
				} else {
					fmt.Println("🏢 TEAMS:")
					for _, t := range finalResp.User.Teams {
						fmt.Printf("  - %s (%s) | %d projects | Role: %s\n", t.Name, t.Slug, t.ProjectsCount, t.Role)
					}
				}
				fmt.Println("\nRun \"envw status <team-slug>\" for more info. 🌸")
			}
			if finalResp.Team != nil {
				fmt.Printf("\n🏢 TEAM: %s", finalResp.Team.Name)
				if !finalResp.Team.IsVerified {
					color.Yellow(" [UNDER VERIFICATION]")
				}
				fmt.Println()
				for _, p := range finalResp.Team.Projects {
					fmt.Printf("  - %s (%s)\n", p.Name, p.Slug)
				}
			}
			if finalResp.Project != nil {
				fmt.Printf("\n🚀 PROJECT: %s\n", finalResp.Project.Name)
				for _, u := range finalResp.Project.Users {
					fmt.Printf("  👤 %s (%s)\n", u.Email, u.Role)
				}
			}
		}

	case "request":
		if len(os.Args) < 5 {
			return
		}
		team, project, role := os.Args[2], os.Args[3], os.Args[4]
		reader := bufio.NewReader(os.Stdin)
		fmt.Print("👤 Name: ")
		userName, _ := reader.ReadString('\n')
		hostname, _ := os.Hostname()

		fmt.Print("🔐 Auth... ")
		signature, err := service.getAuthChallenge(pubStr, privKey)
		if err != nil {
			color.Red("Fail: %v", err)
			return
		}
		color.Green("OK!")

		reqData, _ := json.Marshal(AccessRequest{
			PublicKey: pubStr, Signature: signature, TeamSlug: team, ProjectSlug: project, Role: role,
			UserName: strings.TrimSpace(userName), DeviceAlias: hostname,
		})
		respReq, err := http.Post(service.BaseURL+"/request-access", "application/json", bytes.NewBuffer(reqData))
		if err != nil {
			color.Red("Server Offline")
			return
		}
		var res CommonResponse
		json.NewDecoder(respReq.Body).Decode(&res)
		respReq.Body.Close()
		if res.Success {
			color.Green("✨ %s", res.Message)
		} else {
			color.Red("Fail: %s", res.Error)
		}

	case "envs":
		if len(os.Args) < 4 {
			fmt.Println("Usage: envs <team> <project>")
			return
		}
		team, project := os.Args[2], os.Args[3]

		fmt.Print("🔐 Auth... ")
		signature, err := service.getAuthChallenge(pubStr, privKey)
		if err != nil {
			color.Red("Fail: %v", err)
			return
		}
		color.Green("OK!")

		envReq, _ := json.Marshal(StatusRequest{PublicKey: pubStr, Signature: signature, TeamSlug: team, ProjectSlug: project})
		respEnvs, err := http.Post(service.BaseURL+"/projects/envs", "application/json", bytes.NewBuffer(envReq))
		if err != nil {
			color.Red("Server Offline")
			return
		}
		var finalResp CommonResponse
		json.NewDecoder(respEnvs.Body).Decode(&finalResp)
		respEnvs.Body.Close()

		if finalResp.Success {
			fmt.Printf("\n📂 Environments for %s/%s:\n", team, project)
			if len(finalResp.Envs) == 0 {
				color.Yellow("  No environments found.")
			} else {
				for _, env := range finalResp.Envs {
					fmt.Printf("  - %s | %d secrets\n", env.Name, env.Count)
				}
			}
			fmt.Println()
		} else {
			color.Red("❌ Error: %s", finalResp.Error)
		}

	case "projects":
		if len(os.Args) < 3 {
			fmt.Println("Usage: projects <team>")
			return
		}
		team := os.Args[2]

		fmt.Print("🔐 Auth... ")
		signature, err := service.getAuthChallenge(pubStr, privKey)
		if err != nil {
			color.Red("Fail: %v", err)
			return
		}
		color.Green("OK!")

		projListReq, _ := json.Marshal(StatusRequest{PublicKey: pubStr, Signature: signature, TeamSlug: team})
		respList, err := http.Post(service.BaseURL+"/projects", "application/json", bytes.NewBuffer(projListReq))
		if err != nil {
			color.Red("Server Offline")
			return
		}
		var finalResp CommonResponse
		json.NewDecoder(respList.Body).Decode(&finalResp)
		respList.Body.Close()

		if finalResp.Success {
			fmt.Printf("\n🚀 Projects in team %s:\n", team)
			if len(finalResp.Projects) == 0 {
				color.Yellow("  No projects found in this team.")
			} else {
				for _, p := range finalResp.Projects {
					fmt.Printf("  - %s (%s) | %d secrets\n", p.Name, p.Slug, p.SecretsCount)
				}
			}
			fmt.Println()
		} else {
			color.Red("❌ Error: %s", finalResp.Error)
		}

	case "secrets":
		if len(os.Args) < 4 {
			fmt.Println("Usage: secrets <team> <project> [env-file]")
			return
		}
		team, project := os.Args[2], os.Args[3]
		environment := ".env"
		if len(os.Args) >= 5 {
			environment = os.Args[4]
		}

		fmt.Print("🔐 Auth... ")
		signature, err := service.getAuthChallenge(pubStr, privKey)
		if err != nil {
			color.Red("Fail: %v", err)
			return
		}
		color.Green("OK!")

		pullReq, _ := json.Marshal(PullRequest{PublicKey: pubStr, Signature: signature, TeamSlug: team, ProjectSlug: project, Environment: environment})
		respP, err := http.Post(service.BaseURL+"/pull-secrets", "application/json", bytes.NewBuffer(pullReq))
		if err != nil {
			color.Red("Server Offline")
			return
		}
		var pullResp CommonResponse
		json.NewDecoder(respP.Body).Decode(&pullResp)
		respP.Body.Close()

		if !pullResp.Success || len(pullResp.Secrets) == 0 {
			color.Red("Error: No secrets found or Access denied. 🌸")
			return
		}

		fmt.Printf("\n🔑 Keys in %s/%s (%s):\n", team, project, environment)
		for _, s := range pullResp.Secrets {
			fmt.Printf("  - %s\n", s.Key)
		}
		fmt.Println()

	case "accept":
		if len(os.Args) < 2 {
			return
		}

		if len(os.Args) == 2 {
			fmt.Print("🔐 Auth... ")
			signature, err := service.getAuthChallenge(pubStr, privKey)
			if err != nil {
				color.Red("Fail: %v", err)
				return
			}
			color.Green("OK!")

			listReq, _ := json.Marshal(StatusRequest{PublicKey: pubStr, Signature: signature})
			respL, err := http.Post(service.BaseURL+"/projects/requests/pending", "application/json", bytes.NewBuffer(listReq))
			if err != nil {
				color.Red("Server Offline")
				return
			}
			var listResp CommonResponse
			json.NewDecoder(respL.Body).Decode(&listResp)
			respL.Body.Close()

			if len(listResp.Requests) == 0 {
				color.Yellow("\nNo pending access requests. 🌸")
				return
			}

			fmt.Printf("\n📋 Pending Access Requests:\n")
			for _, req := range listResp.Requests {
				fingerprint := service.GetFingerprint(req.PublicKey)
				fmt.Printf("\n🆔 ID: %s\n", req.Id)
				fmt.Printf("👤 User: %s (%s)\n", req.UserName, req.UserEmail)
				fmt.Printf("💻 Device: %s\n", req.DeviceAlias)
				fmt.Printf("🚀 Project: %s/%s (%s)\n", req.TeamSlug, req.ProjectSlug, req.Role)
				fmt.Printf("🛡️  Fingerprint: SHA256:%s\n", fingerprint)
			}
			fmt.Printf("\nRun \"envw accept <id>\" to grant access. 🌸\n")
		} else {
			requestId := os.Args[2]

			fmt.Print("🔐 Auth... ")
			signatureA, err := service.getAuthChallenge(pubStr, privKey)
			if err != nil {
				color.Red("Fail: %v", err)
				return
			}
			color.Green("OK!")

			fmt.Print("🔍 Checking request details... ")
			listReq, _ := json.Marshal(StatusRequest{PublicKey: pubStr, Signature: signatureA})
			respL, _ := http.Post(service.BaseURL+"/projects/requests/pending", "application/json", bytes.NewBuffer(listReq))
			var listResp CommonResponse
			json.NewDecoder(respL.Body).Decode(&listResp)
			respL.Body.Close()
			color.Green("OK!")

			var targetRequest *PendingRequest
			for _, r := range listResp.Requests {
				if r.Id == requestId {
					targetRequest = &r
					break
				}
			}

			if targetRequest == nil {
				color.Red("Request ID not found. 🌸")
				return
			}

			fmt.Printf("📥 Fetching project key for %s/%s... ", targetRequest.TeamSlug, targetRequest.ProjectSlug)

			signatureP2, err := service.getAuthChallenge(pubStr, privKey)
			if err != nil {
				color.Red("Fail (Auth): %v", err)
				return
			}

			pullReq, _ := json.Marshal(PullRequest{
				PublicKey: pubStr, Signature: signatureP2,
				TeamSlug: targetRequest.TeamSlug, ProjectSlug: targetRequest.ProjectSlug,
				Environment: ".env",
			})
			respP, _ := http.Post(service.BaseURL+"/pull-secrets", "application/json", bytes.NewBuffer(pullReq))
			var pullResp CommonResponse
			json.NewDecoder(respP.Body).Decode(&pullResp)
			respP.Body.Close()

			if !pullResp.Success || pullResp.EncryptedProjectKey == "" {
				color.Red("FAIL!")
				color.Red("Error: You don't have the project key to share. Push first. 🌸")
				return
			}
			color.Green("OK!")

			projectKeyBytes, _ := service.RSADecrypt(pullResp.EncryptedProjectKey, privKey)
			projectKey := string(projectKeyBytes)

			fmt.Print("🛡️  Encrypting key for recipient... ")
			encryptBody, _ := json.Marshal(map[string]string{
				"publicKey": targetRequest.PublicKey,
				"plainText": projectKey,
			})

			reqE, _ := http.NewRequest("PUT", service.BaseURL+"/auth/verify-go", bytes.NewBuffer(encryptBody))
			reqE.Header.Set("Content-Type", "application/json")
			client := &http.Client{}
			respE, err := client.Do(reqE)
			if err != nil {
				color.Red("Server Offline")
				return
			}
			var encData struct {
				Success       bool
				EncryptedData string
			}
			json.NewDecoder(respE.Body).Decode(&encData)
			respE.Body.Close()

			if !encData.Success {
				color.Red("Failed to encrypt for recipient. 🌸")
				return
			}
			color.Green("OK!")

			fmt.Print("🚀 Sending approval... ")
			signatureApp, err := service.getAuthChallenge(pubStr, privKey)
			if err != nil {
				color.Red("Fail (Auth): %v", err)
				return
			}

			approveReq, _ := json.Marshal(ApproveRequest{
				PublicKey: pubStr, Signature: signatureApp, RequestId: requestId, EncryptedProjectKey: encData.EncryptedData,
			})
			respApp, _ := http.Post(service.BaseURL+"/projects/requests/approve", "application/json", bytes.NewBuffer(approveReq))
			var finalResp CommonResponse
			json.NewDecoder(respApp.Body).Decode(&finalResp)
			respApp.Body.Close()

			if finalResp.Success {
				color.Green("OK!")
				color.Green("\n✔ Approved! %s now has access to %s/%s. 🌸🚀", targetRequest.UserName, targetRequest.TeamSlug, targetRequest.ProjectSlug)
			} else {
				color.Red("FAIL!")
				color.Red("\nApproval failed: %s", finalResp.Error)
			}
		}

	case "purchase":
		if len(os.Args) < 3 {
			fmt.Println("Usage: purchase <category> <team-slug> [project-slug/action] [action]")
			fmt.Println("Categories: users, projects")
			fmt.Println("Actions: add, sub (default: add)")
			fmt.Println("\nExamples:")
			fmt.Println("  envw purchase users myteam myproject")
			fmt.Println("  envw purchase projects myteam")
			fmt.Println("  envw purchase projects myteam sub")
			return
		}
		category, teamSlug := os.Args[2], os.Args[3]
		projectSlug := ""
		action := "add"

		if category == "users" {
			if len(os.Args) < 5 {
				fmt.Println("Usage for users: purchase users <team-slug> <project-slug> [action]")
				return
			}
			projectSlug = os.Args[4]
			if len(os.Args) >= 6 {
				action = os.Args[5]
			}
		} else {
			if len(os.Args) >= 5 {
				action = os.Args[4]
			}
		}

		fmt.Print("🔐 Auth... ")
		signature, err := service.getAuthChallenge(pubStr, privKey)
		if err != nil {
			color.Red("Fail: %v", err)
			return
		}
		color.Green("OK!")

		purReq, _ := json.Marshal(map[string]string{
			"publicKey":   pubStr,
			"signature":   signature,
			"category":    category,
			"action":      action,
			"teamSlug":    teamSlug,
			"projectSlug": projectSlug,
		})

		resp, err := http.Post(service.BaseURL+"/purchase", "application/json", bytes.NewBuffer(purReq))
		if err != nil {
			color.Red("Server Offline")
			return
		}
		defer resp.Body.Close()

		var res struct {
			Success    bool   `json:"success"`
			PaymentUrl string `json:"paymentUrl"`
			Message    string `json:"message"`
			Error      string `json:"error"`
		}
		json.NewDecoder(resp.Body).Decode(&res)

		if res.Success {
			color.Green("✨ %s", res.Message)
			if res.PaymentUrl != "" {
				fmt.Printf("\nPlease complete your payment at:\n%s\n", res.PaymentUrl)
				fmt.Println("Opening browser to complete payment...")
				openInBrowser(res.PaymentUrl)
			}
		} else {
			color.Red("Fail: %s", res.Error)
		}

	case "docs":
		llmFlag := false
		fullFlag := false
		for _, arg := range os.Args[2:] {
			if arg == "--llm" || arg == "-l" {
				llmFlag = true
			}
			if arg == "--full" || arg == "-f" {
				fullFlag = true
			}
		}

		if llmFlag {
			if fullFlag {
				fmt.Println(llmsFullTxt)
			} else {
				fmt.Println(llmsTxt)
			}
		} else {
			fmt.Println("📚 Envware Documentation")
			fmt.Println("")
			fmt.Println("  Website:  https://www.envware.dev")
			fmt.Println("  Docs:     https://www.envware.dev/docs")
			fmt.Println("  GitHub:   https://github.com/envware/envware-go")
			fmt.Println("")
			fmt.Println("Options:")
			fmt.Println("  --llm, -l       Print LLM-friendly documentation (llms.txt)")
			fmt.Println("  --full, -f      Print full LLM documentation (use with --llm)")
			fmt.Println("")
			fmt.Println("Examples:")
			fmt.Println("  envw docs --llm          # Quick reference for AI assistants")
			fmt.Println("  envw docs --llm --full   # Complete CLI reference")
		}

	case "set-email":
		if len(os.Args) < 3 {
			fmt.Println("Usage: set-email <your-email-address>")
			return
		}
		newEmail := os.Args[2]

		fmt.Print("🔐 Auth... ")
		signature, err := service.getAuthChallenge(pubStr, privKey)
		if err != nil {
			color.Red("Fail: %v", err)
			return
		}
		color.Green("OK!")

		updateReq, _ := json.Marshal(map[string]string{
			"publicKey":   pubStr,
			"signature":   signature,
			"newEmail":    newEmail,
		})
		
		req, err := http.NewRequest("PUT", service.BaseURL+"/user/email", bytes.NewBuffer(updateReq))
		if err != nil {
			color.Red("Error creating request: %v", err)
			return
		}
		req.Header.Set("Content-Type", "application/json")
		
		client := &http.Client{}
		resp, err := client.Do(req)
		if err != nil {
			color.Red("Server Offline")
			return
		}
		defer resp.Body.Close()

		var res struct {
			Success bool   `json:"success"`
			Message string `json:"message"`
			Error   string `json:"error"`
		}
		json.NewDecoder(resp.Body).Decode(&res)

		if res.Success {
			color.Green("✨ %s", res.Message)
		} else {
			color.Red("Fail: %s", res.Error)
		}

	case "fingerprint":
		fingerprint := service.GetFingerprint(pubStr)
		fmt.Printf("\n💻 Your Fingerprint: SHA256:%s\n", fingerprint)
		fmt.Println("Share this with your team OWNER/ADMIN to verify your identity. 🛡️ 🌸")

	case "version":
		fmt.Printf("envware-go version 2.0.7 🌸\n")

	case "help":
		showUsage()

	default:
		if action != "" && action != "-h" && action != "--help" {
			color.Yellow("Unknown command: %s", action)
		}
		showUsage()
	}
}

func showUsage() {
	fmt.Println("\nUsage: envw <command> [args...]")
	fmt.Println("\nCore Commands:")
	fmt.Println("  push <team> <project> [env]    Encrypt and upload secrets")
	fmt.Println("  pull <team> <project> [env]    Download and decrypt secrets")
	fmt.Println("  request <team> <project> <role> Request access or create project")
	fmt.Println("  accept [id]                    List or approve access requests")
	fmt.Println("\nInfo Commands:")
	fmt.Println("  status [team] [project]        Show info about user, team or project")
	fmt.Println("  projects <team>                List projects in a team")
	fmt.Println("  envs <team> <project>          List environments in a project")
	fmt.Println("  secrets <team> <project> [env] List secret keys (names only)")
	fmt.Println("  fingerprint                    Show your machine's fingerprint")
	fmt.Println("  version                        Show current version")
	fmt.Println("\nBilling Commands:")
	fmt.Println("  purchase teams                 Buy extra team slot ($10/mo)")
	fmt.Println("  purchase projects <team>       Buy +5 project slots ($10/mo)")
	fmt.Println("  purchase users <t> <p>         Buy +10 user slots ($10/mo)")
	fmt.Println("\nOther:")
	fmt.Println("  set-email <email>              Set your account email")
	fmt.Println("  docs [--llm]                   Show documentation")
	fmt.Println()
}

func checkGitIgnore(envFile string) {
	// 1. Check if .gitignore exists
	if _, err := os.Stat(".gitignore"); os.IsNotExist(err) {
		return
	}

	// 2. Use 'git check-ignore' to see if the file is ignored
	cmd := exec.Command("git", "check-ignore", "-q", envFile)
	err := cmd.Run()

	// If exit code is 0, the file is ignored.
	// If exit code is 1, the file is NOT ignored.
	if err == nil {
		return // Already ignored
	}

	// 3. If not ignored, ask the user
	color.Yellow("\n⚠️  Warning: %s is not in your .gitignore!", envFile)
	fmt.Print("Do you want to add it to .gitignore? (y/N): ")

	var response string
	fmt.Scanln(&response)
	response = strings.ToLower(strings.TrimSpace(response))

	if response == "y" || response == "yes" {
		f, err := os.OpenFile(".gitignore", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			color.Red("Error opening .gitignore: %v", err)
			return
		}
		defer f.Close()

		// Add a newline before if needed
		info, _ := f.Stat()
		if info.Size() > 0 {
			// Check if file ends with newline
			content, _ := os.ReadFile(".gitignore")
			if len(content) > 0 && content[len(content)-1] != '\n' {
				f.WriteString("\n")
			}
		}

		if _, err := f.WriteString(envFile + "\n"); err != nil {
			color.Red("Error writing to .gitignore: %v", err)
		} else {
			color.Green("✔ Added %s to .gitignore! 🌸", envFile)
		}
	}
}

func parseEnvFile(path string) (map[string]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	res := make(map[string]string)
	sc := bufio.NewScanner(file)
	for sc.Scan() {
		ln := sc.Text()
		if ln == "" || strings.HasPrefix(ln, "#") {
			continue
		}
		parts := strings.SplitN(ln, "=", 2)
		if len(parts) == 2 {
			res[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
		}
	}
	return res, nil
}
