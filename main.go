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
	PublicKey   string `json:"publicKey"`
	Signature   string `json:"signature"`
	TeamSlug    string `json:"teamSlug"`
	ProjectSlug string `json:"projectSlug"`
	Environment string `json:"environment"`
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

type CommonResponse struct {
	Success             bool              `json:"success"`
	Message             string            `json:"message"`
	Secrets             []Secret          `json:"secrets"`
	Envs                []EnvInfo         `json:"envs,omitempty"`
	Projects            []ProjectListItem `json:"projects,omitempty"`
	EncryptedProjectKey string            `json:"encryptedProjectKey,omitempty"`
	Team                *TeamInfo         `json:"team,omitempty"`
	Project             *ProjectInfo      `json:"project,omitempty"`
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

func main() {
	color.New(color.FgCyan, color.Bold).Println("🌸 envware-go ENGINE v2.0.0-alpha")
	if len(os.Args) < 2 {
		fmt.Println("Usage: ./envw-go <command> [args...]")
		return
	}

	action := os.Args[1]
	service := NewEnvwareService()
	privStr, pubStr, err := service.GetSSHKeys()
	if err != nil {
		color.Red("Error loading keys: %v", err)
		return
	}

	// --- 1. Preparar Chaves (Sem Auth Global) ---
	pemBlock, _ := pem.Decode([]byte(privStr))
	var privKey *rsa.PrivateKey
	if key, err := x509.ParsePKCS1PrivateKey(pemBlock.Bytes); err == nil {
		privKey = key
	} else {
		pk8, _ := x509.ParsePKCS8PrivateKey(pemBlock.Bytes)
		privKey = pk8.(*rsa.PrivateKey)
	}

	// --- 2. Lógica de Comandos ---

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

		// --- Re-Auth para novo Challenge (evitar Expired) ---
		fmt.Print("🔐 Auth... ")
		challReqP, _ := json.Marshal(ChallengeRequest{PublicKey: pubStr})
		respP, _ := http.Post(service.BaseURL+"/auth/challenge", "application/json", bytes.NewBuffer(challReqP))
		var challRespP ChallengeResponse
		json.NewDecoder(respP.Body).Decode(&challRespP)
		respP.Body.Close()

		hashedP := sha256.Sum256([]byte(challRespP.Challenge))
		sigP, _ := rsa.SignPKCS1v15(rand.Reader, privKey, crypto.SHA256, hashedP[:])
		signaturePush := base64.StdEncoding.EncodeToString(sigP)
		color.Green("OK!")

		pullReq, _ := json.Marshal(PullRequest{PublicKey: pubStr, Signature: signaturePush, TeamSlug: team, ProjectSlug: project, Environment: environment})
		respPull, _ := http.Post(service.BaseURL+"/pull-secrets", "application/json", bytes.NewBuffer(pullReq))
		var pullResp CommonResponse
		json.NewDecoder(respPull.Body).Decode(&pullResp)
		respPull.Body.Close()

		if !pullResp.Success {
			color.Red("Error: You don't have access to this project. 🌸")
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

			// --- Re-Auth para novo Challenge (evitar Expired) ---
			fmt.Print("🔐 Re-Auth for Key Init... ")
			challReq, _ := json.Marshal(ChallengeRequest{PublicKey: pubStr})
			resp, _ := http.Post(service.BaseURL+"/auth/challenge", "application/json", bytes.NewBuffer(challReq))
			var challResp2 ChallengeResponse
			json.NewDecoder(resp.Body).Decode(&challResp2)
			resp.Body.Close()

			hashed2 := sha256.Sum256([]byte(challResp2.Challenge))
			sig2, _ := rsa.SignPKCS1v15(rand.Reader, privKey, crypto.SHA256, hashed2[:])
			signature2 := base64.StdEncoding.EncodeToString(sig2)
			color.Green("OK!")

			keyInitReq, _ := json.Marshal(ApproveRequest{
				PublicKey: pubStr, Signature: signature2, TeamSlug: team, ProjectSlug: project,
			})
			respInit, _ := http.Post(service.BaseURL+"/projects/keys", "application/json", bytes.NewBuffer(keyInitReq))
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

		// --- Re-Auth para novo Challenge (evitar Expired no push final) ---
		fmt.Print("🔐 Finalizing Push... ")
		challReq3, _ := json.Marshal(ChallengeRequest{PublicKey: pubStr})
		resp3, _ := http.Post(service.BaseURL+"/auth/challenge", "application/json", bytes.NewBuffer(challReq3))
		var challResp3 ChallengeResponse
		json.NewDecoder(resp3.Body).Decode(&challResp3)
		resp3.Body.Close()

		hashed3 := sha256.Sum256([]byte(challResp3.Challenge))
		sig3, _ := rsa.SignPKCS1v15(rand.Reader, privKey, crypto.SHA256, hashed3[:])
		signature3 := base64.StdEncoding.EncodeToString(sig3)
		color.Green("OK!")

		pushReq := PushRequest{
			PublicKey: pubStr, Signature: signature3, TeamSlug: team, ProjectSlug: project,
			Environment: environment, Secrets: secrets,
		}
		reqBody, _ := json.Marshal(pushReq)
		respPush, _ := http.Post(service.BaseURL+"/secrets/push", "application/json", bytes.NewBuffer(reqBody))

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

		// --- Re-Auth para novo Challenge (evitar Expired) ---
		fmt.Print("🔐 Auth... ")
		challReq, _ := json.Marshal(ChallengeRequest{PublicKey: pubStr})
		resp, _ := http.Post(service.BaseURL+"/auth/challenge", "application/json", bytes.NewBuffer(challReq))
		var challResp ChallengeResponse
		json.NewDecoder(resp.Body).Decode(&challResp)
		resp.Body.Close()

		hashed := sha256.Sum256([]byte(challResp.Challenge))
		sig, _ := rsa.SignPKCS1v15(rand.Reader, privKey, crypto.SHA256, hashed[:])
		signaturePull := base64.StdEncoding.EncodeToString(sig)
		color.Green("OK!")

		pullReq, _ := json.Marshal(PullRequest{PublicKey: pubStr, Signature: signaturePull, TeamSlug: team, ProjectSlug: project, Environment: environment})
		resp, _ = http.Post(service.BaseURL+"/pull-secrets", "application/json", bytes.NewBuffer(pullReq))
		var pullResp CommonResponse
		json.NewDecoder(resp.Body).Decode(&pullResp)
		resp.Body.Close()

		if !pullResp.Success || len(pullResp.Secrets) == 0 {
			color.Red("Error: No secrets found for %s/%s in environment %s. 🌸", team, project, environment)
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
		if len(os.Args) < 3 {
			return
		}
		teamSlug := os.Args[2]
		projectSlug := ""
		if len(os.Args) >= 4 {
			projectSlug = os.Args[3]
		}

		// --- Auth Fresco para Status ---
		fmt.Print("🔐 Auth... ")
		challReqS, _ := json.Marshal(ChallengeRequest{PublicKey: pubStr})
		respS, _ := http.Post(service.BaseURL+"/auth/challenge", "application/json", bytes.NewBuffer(challReqS))
		var challRespS ChallengeResponse
		json.NewDecoder(respS.Body).Decode(&challRespS)
		respS.Body.Close()

		hashedS := sha256.Sum256([]byte(challRespS.Challenge))
		sigS, _ := rsa.SignPKCS1v15(rand.Reader, privKey, crypto.SHA256, hashedS[:])
		signatureStatus := base64.StdEncoding.EncodeToString(sigS)
		color.Green("OK!")

		statReq, _ := json.Marshal(StatusRequest{PublicKey: pubStr, Signature: signatureStatus, TeamSlug: teamSlug, ProjectSlug: projectSlug})
		resp, err := http.Post(service.BaseURL+"/team-stats", "application/json", bytes.NewBuffer(statReq))
		if err != nil {
			color.Red("Fail: %v", err)
			return
		}
		var finalResp CommonResponse
		json.NewDecoder(resp.Body).Decode(&finalResp)
		resp.Body.Close()
		if finalResp.Success {
			if finalResp.Team != nil {
				fmt.Printf("\n🏢 TEAM: %s\n", finalResp.Team.Name)
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

		// --- Auth Fresco para Request ---
		fmt.Print("🔐 Auth... ")
		challReqR, _ := json.Marshal(ChallengeRequest{PublicKey: pubStr})
		respAuth, err := http.Post(service.BaseURL+"/auth/challenge", "application/json", bytes.NewBuffer(challReqR))
		if err != nil {
			color.Red("Fail: API Offline")
			return
		}
		var challRespR ChallengeResponse
		json.NewDecoder(respAuth.Body).Decode(&challRespR)
		respAuth.Body.Close()

		if challRespR.Challenge == "" {
			color.Red("Fail: Could not get challenge from server")
			return
		}

		hashedR := sha256.Sum256([]byte(challRespR.Challenge))
		sigR, _ := rsa.SignPKCS1v15(rand.Reader, privKey, crypto.SHA256, hashedR[:])
		signatureRequest := base64.StdEncoding.EncodeToString(sigR)
		color.Green("OK!")

		reqData, _ := json.Marshal(AccessRequest{
			PublicKey: pubStr, Signature: signatureRequest, TeamSlug: team, ProjectSlug: project, Role: role,
			UserName: strings.TrimSpace(userName), DeviceAlias: hostname,
		})
		respReq, _ := http.Post(service.BaseURL+"/request-access", "application/json", bytes.NewBuffer(reqData))
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

		// --- Auth Fresco para Envs ---
		fmt.Print("🔐 Auth... ")
		challReqE, _ := json.Marshal(ChallengeRequest{PublicKey: pubStr})
		respE, _ := http.Post(service.BaseURL+"/auth/challenge", "application/json", bytes.NewBuffer(challReqE))
		var challRespE ChallengeResponse
		json.NewDecoder(respE.Body).Decode(&challRespE)
		respE.Body.Close()

		hashedE := sha256.Sum256([]byte(challRespE.Challenge))
		sigE, _ := rsa.SignPKCS1v15(rand.Reader, privKey, crypto.SHA256, hashedE[:])
		signatureEnvs := base64.StdEncoding.EncodeToString(sigE)
		color.Green("OK!")

		envReq, _ := json.Marshal(StatusRequest{PublicKey: pubStr, Signature: signatureEnvs, TeamSlug: team, ProjectSlug: project})
		respEnvs, _ := http.Post(service.BaseURL+"/projects/envs", "application/json", bytes.NewBuffer(envReq))
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

		// --- Auth Fresco para Projects ---
		fmt.Print("🔐 Auth... ")
		challReqProj, _ := json.Marshal(ChallengeRequest{PublicKey: pubStr})
		respProj, _ := http.Post(service.BaseURL+"/auth/challenge", "application/json", bytes.NewBuffer(challReqProj))
		var challRespProj ChallengeResponse
		json.NewDecoder(respProj.Body).Decode(&challRespProj)
		respProj.Body.Close()

		hashedProj := sha256.Sum256([]byte(challRespProj.Challenge))
		sigProj, _ := rsa.SignPKCS1v15(rand.Reader, privKey, crypto.SHA256, hashedProj[:])
		signatureProjects := base64.StdEncoding.EncodeToString(sigProj)
		color.Green("OK!")

		projListReq, _ := json.Marshal(StatusRequest{PublicKey: pubStr, Signature: signatureProjects, TeamSlug: team})
		respList, _ := http.Post(service.BaseURL+"/projects", "application/json", bytes.NewBuffer(projListReq))
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

		// --- Auth Fresco para Secrets ---
		fmt.Print("🔐 Auth... ")
		challReqSec, _ := json.Marshal(ChallengeRequest{PublicKey: pubStr})
		respSec, _ := http.Post(service.BaseURL+"/auth/challenge", "application/json", bytes.NewBuffer(challReqSec))
		var challRespSec ChallengeResponse
		json.NewDecoder(respSec.Body).Decode(&challRespSec)
		respSec.Body.Close()

		hashedSec := sha256.Sum256([]byte(challRespSec.Challenge))
		sigSec, _ := rsa.SignPKCS1v15(rand.Reader, privKey, crypto.SHA256, hashedSec[:])
		signatureSecrets := base64.StdEncoding.EncodeToString(sigSec)
		color.Green("OK!")

		pullReq, _ := json.Marshal(PullRequest{PublicKey: pubStr, Signature: signatureSecrets, TeamSlug: team, ProjectSlug: project, Environment: environment})
		respP, _ := http.Post(service.BaseURL+"/pull-secrets", "application/json", bytes.NewBuffer(pullReq))
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

		// --- Auth Fresco ---
		fmt.Print("🔐 Auth... ")
		challReqA, _ := json.Marshal(ChallengeRequest{PublicKey: pubStr})
		respA, _ := http.Post(service.BaseURL+"/auth/challenge", "application/json", bytes.NewBuffer(challReqA))
		var challRespA ChallengeResponse
		json.NewDecoder(respA.Body).Decode(&challRespA)
		respA.Body.Close()

		hashedA := sha256.Sum256([]byte(challRespA.Challenge))
		sigA, _ := rsa.SignPKCS1v15(rand.Reader, privKey, crypto.SHA256, hashedA[:])
		signatureA := base64.StdEncoding.EncodeToString(sigA)
		color.Green("OK!")

		if len(os.Args) == 2 {
			// Listar pedidos pendentes
			listReq, _ := json.Marshal(StatusRequest{PublicKey: pubStr, Signature: signatureA})
			respL, _ := http.Post(service.BaseURL+"/projects/requests/pending", "application/json", bytes.NewBuffer(listReq))
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
			fmt.Printf("\nRun \"./envw-go accept <id>\" to grant access. 🌸\n")
		} else {
			// Aprovar um pedido específico
			requestId := os.Args[2]

			// 1. Buscar detalhes do request
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

			// 2. Pegar a ProjectKey local
			fmt.Printf("📥 Fetching project key for %s/%s... ", targetRequest.TeamSlug, targetRequest.ProjectSlug)

			// --- Re-Auth para novo Challenge (PULL) ---
			challReqP2, _ := json.Marshal(ChallengeRequest{PublicKey: pubStr})
			respP2, _ := http.Post(service.BaseURL+"/auth/challenge", "application/json", bytes.NewBuffer(challReqP2))
			var challRespP2 ChallengeResponse
			json.NewDecoder(respP2.Body).Decode(&challRespP2)
			respP2.Body.Close()

			hashedP2 := sha256.Sum256([]byte(challRespP2.Challenge))
			sigP2, _ := rsa.SignPKCS1v15(rand.Reader, privKey, crypto.SHA256, hashedP2[:])
			signatureP2 := base64.StdEncoding.EncodeToString(sigP2)

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
				fmt.Printf("Debug Server Response: Success=%v, Error=%s, KeyEmpty=%v\n", pullResp.Success, pullResp.Error, pullResp.EncryptedProjectKey == "")
				return
			}
			color.Green("OK!")

			projectKeyBytes, _ := service.RSADecrypt(pullResp.EncryptedProjectKey, privKey)
			projectKey := string(projectKeyBytes)

			// 3. Encriptar a chave para o destinatário
			fmt.Print("🛡️  Encrypting key for recipient... ")
			encryptBody, _ := json.Marshal(map[string]string{
				"publicKey": targetRequest.PublicKey,
				"plainText": projectKey,
			})

			// Nota: O PUT em verify-go não exige challenge (ponte interna segura)
			reqE, _ := http.NewRequest("PUT", service.BaseURL+"/auth/verify-go", bytes.NewBuffer(encryptBody))
			reqE.Header.Set("Content-Type", "application/json")
			client := &http.Client{}
			respE, _ := client.Do(reqE)
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

			// 4. Enviar aprovação
			fmt.Print("🚀 Sending approval... ")
			// --- Re-Auth para novo Challenge (APPROVE) ---
			challReqApp, _ := json.Marshal(ChallengeRequest{PublicKey: pubStr})
			respCApp, _ := http.Post(service.BaseURL+"/auth/challenge", "application/json", bytes.NewBuffer(challReqApp))
			var challRespApp ChallengeResponse
			json.NewDecoder(respCApp.Body).Decode(&challRespApp)
			respCApp.Body.Close()

			hashedApp := sha256.Sum256([]byte(challRespApp.Challenge))
			sigApp, _ := rsa.SignPKCS1v15(rand.Reader, privKey, crypto.SHA256, hashedApp[:])
			signatureApp := base64.StdEncoding.EncodeToString(sigApp)

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
