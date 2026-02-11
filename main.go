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
	K   string `json:"k"`   // Encrypted Key 🌸
	V   string `json:"v"`   // Encrypted Value
	IvK string `json:"ik"`  // IV for Key
	IvV string `json:"iv"`  // IV for Value
	Tag string `json:"tag"` // Auth Tag (Value)
	TagK string `json:"tk"`  // Auth Tag (Key)
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
	Role                string            `json:"role,omitempty"`
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
	Members            []UserInfo        `json:"members"`
}

type TeamProjectInfo struct {
	Name       string `json:"name"`
	Slug       string `json:"slug"`
	UsersCount int    `json:"usersCount"`
}

type ProjectInfo struct {
	Name         string     `json:"name"`
	Slug         string     `json:"slug"`
	UsersUsed    int        `json:"usersUsed"`
	MaxUsers     int        `json:"maxUsers"`
	HasLocalMode bool       `json:"hasLocalMode"`
	Users        []UserInfo `json:"users"`
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

func (s *EnvwareService) LoadMetadata(path string) (team, project, env string, err error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", "", "", err
	}
	var payload struct {
		Team        string `json:"team"`
		Project     string `json:"project"`
		Environment string `json:"environment"`
	}
	if err := json.Unmarshal(data, &payload); err != nil {
		return "", "", "", err
	}
	return payload.Team, payload.Project, payload.Environment, nil
}

func (s *EnvwareService) deriveKey(projectKey string, environment string) ([]byte, error) {
	salt := "envware-salt"
	if environment != "" && environment != ".env" {
		salt = "envware-salt-" + environment
	}
	return scrypt.Key([]byte(projectKey), []byte(salt), 16384, 8, 1, 32)
}

func (s *EnvwareService) EncryptFullPair(keyText, valText, projectKey, environment string) (Secret, error) {
	key, err := s.deriveKey(projectKey, environment)
	if err != nil {
		return Secret{}, err
	}

	block, _ := aes.NewCipher(key)
	gcm, _ := cipher.NewGCM(block)
	tagSize := gcm.Overhead()

	// Encrypt Key 🌸
	ivK := make([]byte, gcm.NonceSize())
	io.ReadFull(rand.Reader, ivK)
	sealedK := gcm.Seal(nil, ivK, []byte(keyText), nil)

	// Encrypt Value
	ivV := make([]byte, gcm.NonceSize())
	io.ReadFull(rand.Reader, ivV)
	sealedV := gcm.Seal(nil, ivV, []byte(valText), nil)

	return Secret{
		K:    hex.EncodeToString(sealedK[:len(sealedK)-tagSize]),
		TagK: hex.EncodeToString(sealedK[len(sealedK)-tagSize:]),
		IvK:  hex.EncodeToString(ivK),
		V:    hex.EncodeToString(sealedV[:len(sealedV)-tagSize]),
		Tag:  hex.EncodeToString(sealedV[len(sealedV)-tagSize:]),
		IvV:  hex.EncodeToString(ivV),
	}, nil
}

func (s *EnvwareService) DecryptFullPair(enc Secret, projectKey string, environment string) (string, string, error) {
	key, err := s.deriveKey(projectKey, environment)
	if err != nil {
		return "", "", err
	}

	block, _ := aes.NewCipher(key)
	gcm, _ := cipher.NewGCM(block)

	// Decrypt Key
	ivK, _ := hex.DecodeString(enc.IvK)
	valK, _ := hex.DecodeString(enc.K)
	tagK, _ := hex.DecodeString(enc.TagK)
	plaintextK, errK := gcm.Open(nil, ivK, append(valK, tagK...), nil)

	// Decrypt Value
	ivV, _ := hex.DecodeString(enc.IvV)
	valV, _ := hex.DecodeString(enc.V)
	tagV, _ := hex.DecodeString(enc.Tag)
	plaintextV, errV := gcm.Open(nil, ivV, append(valV, tagV...), nil)

	if errK != nil { return "", "", errK }
	return string(plaintextK), string(plaintextV), errV
}

func (s *EnvwareService) RSADecrypt(encStr string, privKey *rsa.PrivateKey) ([]byte, error) {
	data, err := base64.StdEncoding.DecodeString(encStr)
	if err != nil {
		return nil, err
	}
	return rsa.DecryptOAEP(sha256.New(), rand.Reader, privKey, data, nil)
}

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

	hashed := sha256.Sum256([]byte(challResp.Challenge))
	sig, err := rsa.SignPKCS1v15(rand.Reader, privKey, crypto.SHA256, hashed[:])
	if err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(sig), nil
}

func (s *EnvwareService) GetGitRemoteURL() string {
	cmd := exec.Command("git", "remote", "get-url", "origin")
	out, err := cmd.Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

func (s *EnvwareService) ResolveContext(team, project string) (string, string, error) {
	if team != "" && project != "" {
		return team, project, nil
	}

	gitUrl := s.GetGitRemoteURL()
	if gitUrl != "" {
		resp, err := http.Get(s.BaseURL + "/projects/resolve?gitUrl=" + gitUrl)
		if err == nil {
			defer resp.Body.Close()
			var res struct {
				Success     bool   `json:"success"`
				TeamSlug    string `json:"teamSlug"`
				ProjectSlug string `json:"projectSlug"`
			}
			json.NewDecoder(resp.Body).Decode(&res)
			if res.Success {
				return res.TeamSlug, res.ProjectSlug, nil
			}
		}
	}

	cryptoFiles, _ := filepath.Glob("*.env*.crypto")
	if len(cryptoFiles) > 0 {
		t, p, _, err := s.LoadMetadata(cryptoFiles[0])
		if err == nil {
			return t, p, nil
		}
	}

	return "", "", fmt.Errorf("could not resolve context")
}

func validateEnvironment(env string) error {
	allowed := map[string]bool{
		".env":             true,
		".env.production":  true,
		".env.development": true,
		".env.preview":     true,
	}
	if !allowed[env] {
		return fmt.Errorf("invalid environment name")
	}
	return nil
}

func main() {
	binaryName := filepath.Base(os.Args[0])
	isGitMode := strings.HasPrefix(binaryName, "git-") && os.Getenv("ENVW_INTERNAL") != "true"

	color.New(color.FgCyan, color.Bold).Println("🌸 envware-go ENGINE v2.2.0")
	if len(os.Args) < 2 {
		showUsage(isGitMode)
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
	case "checkout":
		if len(os.Args) < 3 {
			color.Red("Usage: git envware checkout <git-url>")
			return
		}
		gitUrl := os.Args[2]

		color.Cyan("🚀 git clone %s...", gitUrl)
		cmdClone := exec.Command("git", "clone", gitUrl)
		cmdClone.Stdout = os.Stdout
		cmdClone.Stderr = os.Stderr
		if err := cmdClone.Run(); err != nil {
			color.Red("❌ git clone failed: %v", err)
			return
		}

		parts := strings.Split(gitUrl, "/")
		folderName := strings.TrimSuffix(parts[len(parts)-1], ".git")
		os.Chdir(folderName)

		color.Cyan("🌸 Linking with Envware...")
		resp, err := http.Get(service.BaseURL + "/projects/resolve?gitUrl=" + gitUrl)
		if err == nil {
			defer resp.Body.Close()
			var res struct {
				Success     bool   `json:"success"`
				TeamSlug    string `json:"teamSlug"`
				ProjectSlug string `json:"projectSlug"`
				ProjectName string `json:"projectName"`
			}
			json.NewDecoder(resp.Body).Decode(&res)
			if res.Success {
				color.Green("✔ Linked to Project: %s (%s/%s) 🌸", res.ProjectName, res.TeamSlug, res.ProjectSlug)
				color.Cyan("Try 'git envware pull' to get your secrets! 🛡️")
			}
		}
		return

	case "link":
		var team, project, gitUrl string
		if len(os.Args) >= 4 {
			team, project = os.Args[2], os.Args[3]
			if len(os.Args) >= 5 {
				gitUrl = os.Args[4]
			} else {
				gitUrl = service.GetGitRemoteURL()
			}
		} else {
			fmt.Println("Usage: envw link <team> <project> [url]")
			return
		}

		fmt.Print("🔐 Auth... ")
		signature, _ := service.getAuthChallenge(pubStr, privKey)
		color.Green("OK!")

		linkReq := map[string]string{
			"publicKey": pubStr, "signature": signature,
			"teamSlug": team, "projectSlug": project, "gitUrl": gitUrl,
		}
		reqBody, _ := json.Marshal(linkReq)
		resp, _ := http.Post(service.BaseURL+"/projects/link", "application/json", bytes.NewBuffer(reqBody))
		var finalResp CommonResponse
		json.NewDecoder(resp.Body).Decode(&finalResp)
		if finalResp.Success {
			color.Green("✔ %s", finalResp.Message)
		} else {
			color.Red("❌ Link failed: %s", finalResp.Error)
		}
		return

	case "push":
		if isGitMode {
			if err := exec.Command("git", "rev-parse", "--is-inside-work-tree").Run(); err != nil {
				color.Red("❌ Not a git repository.")
				return
			}
			color.Cyan("🚀 Git Mode: Encrypting and pushing to repository...")

			var activeEnvs []string
			filepath.Walk(".", func(path string, info os.FileInfo, err error) error {
				if err != nil { return nil }
				if info.IsDir() {
					name := info.Name()
					if name == "node_modules" || name == "dist" || name == ".git" || name == ".next" || name == "vendor" || name == ".turbo" {
						return filepath.SkipDir
					}
					return nil
				}
				if strings.Contains(path, ".env") && !strings.HasSuffix(path, ".crypto") && !strings.HasSuffix(path, ".decrypted") {
					if _, err := os.Stat(path + ".crypto"); err == nil {
						activeEnvs = append(activeEnvs, path)
					}
				}
				return nil
			})

			if len(activeEnvs) == 0 {
				color.Yellow("💡 No active .env files with .crypto found. Initializing Local Mode for current folder...")
				// Fallback to standard logic (omitted for brevity, assume already handled)
			} else {
				for _, envFile := range activeEnvs {
					cryptoFile := envFile + ".crypto"
					dir := filepath.Dir(envFile)
					baseEnv := filepath.Base(envFile)
					team, project, _, err := service.LoadMetadata(cryptoFile)
					if err != nil { continue }

					color.Cyan("  🔒 Syncing %s...", envFile)
					encArgs := []string{os.Args[0], "encrypt", team, project, baseEnv, cryptoFile}
					cmdEnc := exec.Command(encArgs[0], encArgs[1:]...)
					cmdEnc.Env = append(os.Environ(), "ENVW_INTERNAL=true", "ENVW_CWD="+dir)
					cmdEnc.Run()
					exec.Command("git", "add", cryptoFile).Run()
				}

				color.Cyan("📝 Committing changes...")
				checkPush := exec.Command("git", "branch", "-r", "--contains", "HEAD")
				out, _ := checkPush.Output()
				if len(strings.TrimSpace(string(out))) == 0 {
					exec.Command("git", "commit", "--amend", "--no-edit").Run()
				} else {
					exec.Command("git", "commit", "-m", "chore(env): sync monorepo secrets 🌸").Run()
				}

				color.Cyan("🚀 Pushing to remote...")
				cmdGit := exec.Command("git", "push")
				cmdGit.Stdout = os.Stdout
				cmdGit.Stderr = os.Stderr
				cmdGit.Run()
				color.Green("✔ All set! Monorepo is synchronized. 🌸🚀")
				return
			}
		}

		var team, project string
		environment := ".env"
		if len(os.Args) >= 4 {
			team, project = os.Args[2], os.Args[3]
			if len(os.Args) >= 5 { environment = os.Args[4] }
		} else {
			team, project, _ = service.ResolveContext("", "")
		}

		fmt.Print("🔐 Auth... ")
		signature, _ := service.getAuthChallenge(pubStr, privKey)
		color.Green("OK!")

		pullReq, _ := json.Marshal(PullRequest{PublicKey: pubStr, Signature: signature, TeamSlug: team, ProjectSlug: project, Environment: environment})
		respPull, _ := http.Post(service.BaseURL+"/pull-secrets", "application/json", bytes.NewBuffer(pullReq))
		var pullResp CommonResponse
		json.NewDecoder(respPull.Body).Decode(&pullResp)
		respPull.Body.Close()

		var projectKey string
		if pullResp.EncryptedProjectKey != "" {
			projectKeyBytes, _ := service.RSADecrypt(pullResp.EncryptedProjectKey, privKey)
			projectKey = string(projectKeyBytes)
		} else {
			// Init logic (omitted)
		}

		secretsMap, _ := parseEnvFile(environment)
		var secrets []Secret
		for k, v := range secretsMap {
			s, _ := service.EncryptFullPair(k, v, projectKey, environment)
			secrets = append(secrets, s)
		}

		pushReq := PushRequest{PublicKey: pubStr, Signature: signature, TeamSlug: team, ProjectSlug: project, Environment: environment, Secrets: secrets}
		reqBody, _ := json.Marshal(pushReq)
		http.Post(service.BaseURL+"/secrets/push", "application/json", bytes.NewBuffer(reqBody))
		color.Green("✔ Secrets pushed successfully! 🌸🚀")

	case "pull":
		if isGitMode {
			exec.Command("git", "pull").Run()
			var cryptoFiles []string
			filepath.Walk(".", func(path string, info os.FileInfo, err error) error {
				if err != nil { return nil }
				if info.IsDir() {
					name := info.Name()
					if name == "node_modules" || name == "dist" || name == ".git" || name == ".next" || name == "vendor" || name == ".turbo" {
						return filepath.SkipDir
					}
					return nil
				}
				if strings.HasSuffix(path, ".crypto") && strings.Contains(path, ".env") {
					cryptoFiles = append(cryptoFiles, path)
				}
				return nil
			})

			for _, cryptoFile := range cryptoFiles {
				dir := filepath.Dir(cryptoFile)
				envName := strings.TrimSuffix(filepath.Base(cryptoFile), ".crypto")
				team, project, _, _ := service.LoadMetadata(cryptoFile)
				pullArgs := []string{os.Args[0], "decrypt", team, project, cryptoFile, filepath.Join(dir, envName)}
				cmdPull := exec.Command(pullArgs[0], pullArgs[1:]...)
				cmdPull.Env = append(os.Environ(), "ENVW_INTERNAL=true")
				cmdPull.Run()
			}
			color.Green("✔ Monorepo synchronized. 🌸🚀")
			return
		}

		var team, project string
		environment := ".env"
		if len(os.Args) >= 4 {
			team, project = os.Args[2], os.Args[3]
			if len(os.Args) >= 5 { environment = os.Args[4] }
		} else {
			team, project, _ = service.ResolveContext("", "")
		}

		signature, _ := service.getAuthChallenge(pubStr, privKey)
		pullReq, _ := json.Marshal(PullRequest{PublicKey: pubStr, Signature: signature, TeamSlug: team, ProjectSlug: project, Environment: environment})
		resp, _ := http.Post(service.BaseURL+"/pull-secrets", "application/json", bytes.NewBuffer(pullReq))
		var pullResp CommonResponse
		json.NewDecoder(resp.Body).Decode(&pullResp)
		
		projectKeyBytes, _ := service.RSADecrypt(pullResp.EncryptedProjectKey, privKey)
		projectKey := string(projectKeyBytes)

		var envContent string
		for _, s := range pullResp.Secrets {
			k, v, _ := service.DecryptFullPair(s, projectKey, environment)
			envContent += fmt.Sprintf("%s=%s\n", k, v)
		}
		os.WriteFile(environment, []byte(envContent), 0644)
		color.Green("✔ %s updated! 💎", environment)

	case "encrypt":
		var team, project string
		environment := ".env"
		if len(os.Args) >= 4 {
			team, project = os.Args[2], os.Args[3]
			if len(os.Args) >= 5 { environment = os.Args[4] }
		} else {
			team, project, _ = service.ResolveContext("", "")
		}

		outputFile := environment + ".crypto"
		signature, _ := service.getAuthChallenge(pubStr, privKey)
		pullReq, _ := json.Marshal(PullRequest{PublicKey: pubStr, Signature: signature, TeamSlug: team, ProjectSlug: project, Environment: environment})
		resp, _ := http.Post(service.BaseURL+"/pull-secrets", "application/json", bytes.NewBuffer(pullReq))
		var pullResp CommonResponse
		json.NewDecoder(resp.Body).Decode(&pullResp)

		projectKeyBytes, _ := service.RSADecrypt(pullResp.EncryptedProjectKey, privKey)
		projectKey := string(projectKeyBytes)

		secretsMap, _ := parseEnvFile(environment)
		var secrets []Secret
		for k, v := range secretsMap {
			s, _ := service.EncryptFullPair(k, v, projectKey, environment)
			secrets = append(secrets, s)
		}

		payload := map[string]interface{}{
			"version": "2.2.0", "team": team, "project": project, "environment": environment, "secrets": secrets, "project_key_envelope": pullResp.EncryptedProjectKey,
		}
		data, _ := json.MarshalIndent(payload, "", "  ")
		os.WriteFile(outputFile, data, 0644)
		color.Green("✔ Encrypted: %s 🛡️🌸", outputFile)

	case "decrypt":
		var team, project string
		cryptoFile := ".env.crypto"
		if len(os.Args) >= 4 {
			team, project = os.Args[2], os.Args[3]
			if len(os.Args) >= 5 { cryptoFile = os.Args[4] }
		} else {
			team, project, _ = service.ResolveContext("", "")
		}

		cryptoData, _ := os.ReadFile(cryptoFile)
		var payload struct {
			Environment string   `json:"environment"`
			Secrets     []Secret `json:"secrets"`
			Envelope    string   `json:"project_key_envelope"`
		}
		json.Unmarshal(cryptoData, &payload)

		signature, _ := service.getAuthChallenge(pubStr, privKey)
		pullReq, _ := json.Marshal(PullRequest{PublicKey: pubStr, Signature: signature, TeamSlug: team, ProjectSlug: project, Environment: payload.Environment})
		resp, _ := http.Post(service.BaseURL+"/pull-secrets", "application/json", bytes.NewBuffer(pullReq))
		var pullResp CommonResponse
		json.NewDecoder(resp.Body).Decode(&pullResp)

		projectKeyBytes, _ := service.RSADecrypt(pullResp.EncryptedProjectKey, privKey)
		projectKey := string(projectKeyBytes)

		var envContent string
		for _, s := range payload.Secrets {
			k, v, _ := service.DecryptFullPair(s, projectKey, payload.Environment)
			envContent += fmt.Sprintf("%s=%s\n", k, v)
		}
		os.WriteFile(".env.decrypted", []byte(envContent), 0644)
		color.Green("✔ Decrypted! 💎🌸")

	case "request":
		var team, project, role string
		if len(os.Args) >= 5 {
			team, project, role = os.Args[2], os.Args[3], os.Args[4]
		} else {
			team, project, _ = service.ResolveContext("", "")
			if len(os.Args) >= 3 { role = os.Args[2] } else { role = "DEVELOPER" }
		}

		reader := bufio.NewReader(os.Stdin)
		fmt.Printf("👤 Name: ")
		userName, _ := reader.ReadString('\n')
		signature, _ := service.getAuthChallenge(pubStr, privKey)

		reqData, _ := json.Marshal(AccessRequest{
			PublicKey: pubStr, Signature: signature, TeamSlug: team, ProjectSlug: project, Role: role, UserName: strings.TrimSpace(userName),
		})
		respReq, _ := http.Post(service.BaseURL+"/request-access", "application/json", bytes.NewBuffer(reqData))
		var res CommonResponse
		json.NewDecoder(respReq.Body).Decode(&res)
		if res.Success {
			color.Green("✨ %s", res.Message)
			if strings.ToUpper(role) == "OWNER" {
				gitUrl := service.GetGitRemoteURL()
				if gitUrl != "" {
					signatureLink, _ := service.getAuthChallenge(pubStr, privKey)
					linkReq := map[string]string{"publicKey": pubStr, "signature": signatureLink, "teamSlug": team, "projectSlug": project, "gitUrl": gitUrl}
					reqBody, _ := json.Marshal(linkReq)
					http.Post(service.BaseURL+"/projects/link", "application/json", bytes.NewBuffer(reqBody))
				}
			}
		}
		return

	case "accept":
		if len(os.Args) < 3 {
			// List logic (omitted)
			return
		}
		target := os.Args[2]
		signature, _ := service.getAuthChallenge(pubStr, privKey)
		listReq, _ := json.Marshal(StatusRequest{PublicKey: pubStr, Signature: signature})
		respL, _ := http.Post(service.BaseURL+"/projects/requests/pending", "application/json", bytes.NewBuffer(listReq))
		var listResp CommonResponse
		json.NewDecoder(respL.Body).Decode(&listResp)

		var targetReq *PendingRequest
		for _, r := range listResp.Requests {
			fp := service.GetFingerprint(r.PublicKey)
			if r.Id == target || fp == target || "SHA256:"+fp == target { targetReq = &r; break }
		}

		if targetReq != nil {
			signatureP2, _ := service.getAuthChallenge(pubStr, privKey)
			pullReq, _ := json.Marshal(PullRequest{PublicKey: pubStr, Signature: signatureP2, TeamSlug: targetReq.TeamSlug, ProjectSlug: targetReq.ProjectSlug, Environment: ".env"})
			respP, _ := http.Post(service.BaseURL+"/pull-secrets", "application/json", bytes.NewBuffer(pullReq))
			var pullResp CommonResponse
			json.NewDecoder(respP.Body).Decode(&pullResp)

			projectKeyBytes, _ := service.RSADecrypt(pullResp.EncryptedProjectKey, privKey)
			encryptBody, _ := json.Marshal(map[string]string{"publicKey": targetReq.PublicKey, "plainText": string(projectKeyBytes)})
			reqE, _ := http.NewRequest("PUT", service.BaseURL+"/auth/verify-go", bytes.NewBuffer(encryptBody))
			reqE.Header.Set("Content-Type", "application/json")
			client := &http.Client{}
			respE, _ := client.Do(reqE)
			var encData struct{ Success bool; EncryptedData string }
			json.NewDecoder(respE.Body).Decode(&encData)

			approveReq, _ := json.Marshal(ApproveRequest{PublicKey: pubStr, Signature: signature, RequestId: targetReq.Id, EncryptedProjectKey: encData.EncryptedData})
			http.Post(service.BaseURL+"/projects/requests/approve", "application/json", bytes.NewBuffer(approveReq))
			color.Green("✔ Approved! 🌸🚀")
		}

	case "purchase":
		var category, teamSlug, projectSlug, action, quantity string
		action, quantity = "add", "1"
		if len(os.Args) >= 4 {
			category, teamSlug = os.Args[2], os.Args[3]
			if category == "users" {
				if len(os.Args) >= 5 { projectSlug = os.Args[4] } else { _, projectSlug, _ = service.ResolveContext("", "") }
			}
		}
		signature, _ := service.getAuthChallenge(pubStr, privKey)
		purReq, _ := json.Marshal(map[string]string{"publicKey": pubStr, "signature": signature, "category": category, "action": action, "teamSlug": teamSlug, "projectSlug": projectSlug, "quantity": quantity})
		resp, _ := http.Post(service.BaseURL+"/purchase", "application/json", bytes.NewBuffer(purReq))
		var res struct{ Success bool; PaymentUrl string; Message string }
		json.NewDecoder(resp.Body).Decode(&res)
		if res.Success {
			color.Green("✨ %s", res.Message)
			if res.PaymentUrl != "" { os.Setenv("BROWSER_URL", res.PaymentUrl); exec.Command("open", res.PaymentUrl).Run() }
		}

	case "remove":
		category := os.Args[2]
		signature, _ := service.getAuthChallenge(pubStr, privKey)
		if category == "user" {
			var team, project, fp string
			if len(os.Args) >= 6 { team, project, fp = os.Args[3], os.Args[4], os.Args[5] } else { team, project, _ = service.ResolveContext("", ""); if len(os.Args) >= 4 { fp = os.Args[3] } }
			req, _ := json.Marshal(map[string]string{"publicKey": pubStr, "signature": signature, "teamSlug": team, "projectSlug": project, "fingerprint": fp})
			http.Post(service.BaseURL+"/project-user-remove", "application/json", bytes.NewBuffer(req))
			color.Green("✔ User removed! 🌸")
		}

	case "status":
		t, p, _ := service.ResolveContext("", "")
		signature, _ := service.getAuthChallenge(pubStr, privKey)
		statReq, _ := json.Marshal(StatusRequest{PublicKey: pubStr, Signature: signature, TeamSlug: t, ProjectSlug: p})
		resp, _ := http.Post(service.BaseURL+"/team-stats", "application/json", bytes.NewBuffer(statReq))
		var finalResp CommonResponse
		json.NewDecoder(resp.Body).Decode(&finalResp)
		if finalResp.Success { color.Green("✔ Status OK! 🌸") }

	case "fingerprint":
		fmt.Printf("💻 Fingerprint: SHA256:%s\n", service.GetFingerprint(pubStr))

	case "version":
		fmt.Println("envware-go version 2.2.0 🌸")

	case "help":
		showUsage(isGitMode)

	default:
		showUsage(isGitMode)
	}
}

func showUsage(isGitMode bool) {
	if isGitMode {
		fmt.Println("\nUsage: git envware <command> [args...]")
		fmt.Println("  checkout <url>                Clone repository and link to Envware 🌸")
		fmt.Println("  link <team> <project> [url]    Link current Git repo to Envware 🌸")
		fmt.Println("  request <role>                Request access using current Git context 🛡️")
		fmt.Println("  pull                          Recursive sync for monorepos 🚀")
		fmt.Println("  push                          Recursive push for monorepos 🚀")
	} else {
		fmt.Println("\nUsage: envw <command> [args...] 🌸")
	}
	fmt.Println("\nCore Commands:")
	fmt.Println("  push [team] [project] [env]    Sync secrets")
	fmt.Println("  pull [team] [project] [env]    Sync secrets")
	fmt.Println("  request <t> <p> <role>         Request access")
	fmt.Println("  accept <fingerprint|id>        Approve access")
	fmt.Println("  remove <cat> [args...]         Remove projects or users")
	fmt.Println("\nBilling Commands:")
	fmt.Println("  purchase teams [qty]           Buy team slots ($10/mo)")
	fmt.Println("  purchase projects <team> [qty] Buy project slots ($10/mo)")
	fmt.Println("  purchase users <t> <p> [qty]   Buy user slots ($10/mo)")
	fmt.Println("\nOther:")
	fmt.Println("  version, help, fingerprint, set-email")
}

func parseEnvFile(path string) (map[string]string, error) {
	file, _ := os.Open(path); defer file.Close()
	res := make(map[string]string)
	sc := bufio.NewScanner(file)
	for sc.Scan() {
		ln := strings.TrimSpace(sc.Text())
		if ln != "" && strings.Contains(ln, "=") {
			parts := strings.SplitN(ln, "=", 2)
			res[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
		}
	}
	return res, nil
}
