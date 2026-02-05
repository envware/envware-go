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
	"path/filepath"
	"strings"

	"github.com/fatih/color"
	"golang.org/x/crypto/scrypt"
)

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

func main() {
	color.New(color.FgCyan, color.Bold).Println("🌸 envware-go ENGINE v2.0.3")
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
			fmt.Println("Usage: purchase <category> <team-slug> [action]")
			fmt.Println("Categories: users, projects")
			fmt.Println("Actions: add, sub (default: add)")
			return
		}
		category, teamSlug := os.Args[2], os.Args[3]
		action := "add"
		if len(os.Args) >= 5 {
			action = os.Args[4]
		}

		fmt.Print("🔐 Auth... ")
		signature, err := service.getAuthChallenge(pubStr, privKey)
		if err != nil {
			color.Red("Fail: %v", err)
			return
		}
		color.Green("OK!")

		purReq, _ := json.Marshal(map[string]string{
			"publicKey": pubStr,
			"signature": signature,
			"category":  category,
			"action":    action,
			"teamSlug":  teamSlug,
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
			}
		} else {
			color.Red("Fail: %s", res.Error)
		}

	default:
		color.Yellow("Unknown command: %s", action)
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
