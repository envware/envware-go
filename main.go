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
	"net/url"
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

func mustBeGitInvoked() {
	if strings.HasPrefix(filepath.Base(os.Args[0]), "git-") {
		return
	}
	color.Red("Use apenas via Git: git envw <comando> (instale o binário como git-envw no PATH)")
	os.Exit(1)
}

func requireGitWorktree() error {
	if err := exec.Command("git", "rev-parse", "--is-inside-work-tree").Run(); err != nil {
		return fmt.Errorf("não é um repositório Git")
	}
	return nil
}

func requireGitRemote(s *EnvwareService) error {
	if s.GetGitRemoteURL() == "" {
		return fmt.Errorf("defina o remote origin (git remote add origin <url>)")
	}
	return nil
}

// OriginResolveResult resultado de GET/POST /projects/resolve (com membership se publicKey enviado).
type OriginResolveResult struct {
	ProjectRegistered bool
	Member            bool
	MembershipKnown   bool
	TeamSlug          string
	ProjectSlug       string
	ProjectName       string
}

// FetchOriginResolve consulta o projeto pelo URL Git; com publicKey verifica se o utilizador é membro do team.
func (s *EnvwareService) FetchOriginResolve(gitURL, pubStr string) (*OriginResolveResult, error) {
	if gitURL == "" {
		return nil, fmt.Errorf("git remote origin não configurado")
	}
	payload := map[string]string{"gitUrl": gitURL}
	if strings.TrimSpace(pubStr) != "" {
		payload["publicKey"] = pubStr
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	resp, err := http.Post(s.BaseURL+"/projects/resolve", "application/json", bytes.NewBuffer(body))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var raw struct {
		Success     bool   `json:"success"`
		TeamSlug    string `json:"teamSlug"`
		ProjectSlug string `json:"projectSlug"`
		ProjectName string `json:"projectName"`
		Member      *bool  `json:"member,omitempty"`
		Error       string `json:"error"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		return nil, err
	}
	out := &OriginResolveResult{}
	if !raw.Success {
		return out, nil
	}
	out.ProjectRegistered = true
	out.TeamSlug = raw.TeamSlug
	out.ProjectSlug = raw.ProjectSlug
	out.ProjectName = raw.ProjectName
	if raw.Member != nil {
		out.MembershipKnown = true
		out.Member = *raw.Member
	}
	return out, nil
}

func runAccessRequest(service *EnvwareService, pubStr string, privKey *rsa.PrivateKey, team, project, role string) {
	reader := bufio.NewReader(os.Stdin)
	fmt.Printf("👤 Nome: ")
	userName, _ := reader.ReadString('\n')
	signature, err := service.getAuthChallenge(pubStr, privKey)
	if err != nil {
		color.Red("❌ Auth: %v", err)
		return
	}
	reqData, _ := json.Marshal(AccessRequest{
		PublicKey: pubStr, Signature: signature, TeamSlug: team, ProjectSlug: project, Role: role, UserName: strings.TrimSpace(userName),
	})
	respReq, err := http.Post(service.BaseURL+"/request-access", "application/json", bytes.NewBuffer(reqData))
	if err != nil {
		color.Red("❌ %v", err)
		return
	}
	var res CommonResponse
	json.NewDecoder(respReq.Body).Decode(&res)
	if res.Success {
		color.Green("✨ %s", res.Message)
		if strings.ToUpper(role) == "OWNER" {
			gitURL := service.GetGitRemoteURL()
			if gitURL != "" {
				signatureLink, _ := service.getAuthChallenge(pubStr, privKey)
				linkReq := map[string]string{"publicKey": pubStr, "signature": signatureLink, "teamSlug": team, "projectSlug": project, "gitUrl": gitURL}
				reqBody, _ := json.Marshal(linkReq)
				http.Post(service.BaseURL+"/projects/link", "application/json", bytes.NewBuffer(reqBody))
			}
		}
	} else if res.Error != "" {
		color.Red("❌ %s", res.Error)
	}
}

func ensureTeamProjectAccess(service *EnvwareService, pubStr string, privKey *rsa.PrivateKey) (team, project string, ok bool) {
	gitURL := service.GetGitRemoteURL()
	if gitURL == "" {
		color.Red("❌ defina o remote origin (git remote add origin <url>)")
		return "", "", false
	}
	res, err := service.FetchOriginResolve(gitURL, pubStr)
	if err != nil {
		color.Red("❌ Envware: %v", err)
		return "", "", false
	}
	if !res.ProjectRegistered {
		color.Yellow("Este repositório não usa Envware — o remote origin não está registado na plataforma.")
		return "", "", false
	}
	if !res.MembershipKnown {
		color.Yellow("Não foi possível verificar se pertences ao team (resposta incompleta do servidor).")
		return "", "", false
	}
	if !res.Member {
		color.Yellow("A tua chave SSH ainda não faz parte do team deste projeto no Envware.")
		fmt.Print("Queres enviar um pedido de acesso como DEVELOPER? [s/N]: ")
		var ans string
		fmt.Scanln(&ans)
		ans = strings.TrimSpace(strings.ToLower(ans))
		if ans == "s" || ans == "sim" || ans == "y" || ans == "yes" {
			runAccessRequest(service, pubStr, privKey, res.TeamSlug, res.ProjectSlug, "DEVELOPER")
		}
		color.Cyan("Sem acesso ao projeto até um administrador aprovar o pedido.")
		return "", "", false
	}
	return res.TeamSlug, res.ProjectSlug, true
}

func postPullSecrets(s *EnvwareService, pubStr string, privKey *rsa.PrivateKey, teamSlug, projectSlug, environment string) (CommonResponse, int, error) {
	sig, err := s.getAuthChallenge(pubStr, privKey)
	if err != nil {
		return CommonResponse{}, 0, err
	}
	body, err := json.Marshal(PullRequest{
		PublicKey: pubStr, Signature: sig,
		TeamSlug: teamSlug, ProjectSlug: projectSlug, Environment: environment,
	})
	if err != nil {
		return CommonResponse{}, 0, err
	}
	resp, err := http.Post(s.BaseURL+"/pull-secrets", "application/json", bytes.NewBuffer(body))
	if err != nil {
		return CommonResponse{}, 0, err
	}
	defer resp.Body.Close()
	var out CommonResponse
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return out, resp.StatusCode, nil
}

func isSkippableDir(name string) bool {
	switch name {
	case "node_modules", "dist", ".git", ".next", "vendor", ".turbo", "build", "coverage", ".vercel":
		return true
	}
	return false
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
	color.New(color.FgCyan, color.Bold).Println("🌸 envware-go ENGINE v2.2.0")
	if len(os.Args) < 2 {
		showUsage()
		return
	}

	action := os.Args[1]

	if action == "version" {
		fmt.Println("envware-go version 2.2.0 🌸")
		return
	}
	if action == "help" {
		showUsage()
		return
	}

	mustBeGitInvoked()

	if action == "clone" {
		service := NewEnvwareService()
		if len(os.Args) < 3 {
			color.Red("Uso: git envw clone <url>")
			return
		}
		gitURL := os.Args[2]
		color.Cyan("🚀 git clone %s...", gitURL)
		cmdClone := exec.Command("git", "clone", gitURL)
		cmdClone.Stdout = os.Stdout
		cmdClone.Stderr = os.Stderr
		if err := cmdClone.Run(); err != nil {
			color.Red("❌ git clone falhou: %v", err)
			return
		}
		parts := strings.Split(gitURL, "/")
		folderName := strings.TrimSuffix(parts[len(parts)-1], ".git")
		_ = os.Chdir(folderName)

		privStr, pubStr, keyErr := service.GetSSHKeys()
		pubForResolve := ""
		var privKey *rsa.PrivateKey
		if keyErr == nil {
			pubForResolve = pubStr
			pemBlock, _ := pem.Decode([]byte(privStr))
			if pemBlock != nil {
				if key, err := x509.ParsePKCS1PrivateKey(pemBlock.Bytes); err == nil {
					privKey = key
				} else if pk8, err := x509.ParsePKCS8PrivateKey(pemBlock.Bytes); err == nil {
					privKey = pk8.(*rsa.PrivateKey)
				}
			}
		}

		color.Cyan("🌸 A consultar Envware…")
		res, err := service.FetchOriginResolve(gitURL, pubForResolve)
		if err != nil {
			color.Red("❌ Envware: %v", err)
			return
		}
		if !res.ProjectRegistered {
			color.Yellow("Este projeto não usa Envware — este URL Git não está registado na plataforma.")
			return
		}
		if keyErr != nil || !res.MembershipKnown {
			color.Green("✔ Projeto registado no Envware: %s (%s/%s) 🌸", res.ProjectName, res.TeamSlug, res.ProjectSlug)
			color.Cyan("Configura chaves SSH em ~/.ssh para verificares o teu acesso ao team.")
			return
		}
		if res.Member {
			color.Green("✔ Projeto: %s (%s/%s) 🌸", res.ProjectName, res.TeamSlug, res.ProjectSlug)
			color.Cyan("Corre `git envw pull` para obter secrets. 🛡️")
			return
		}
		color.Yellow("A tua chave SSH ainda não faz parte do team deste projeto no Envware.")
		fmt.Print("Queres enviar um pedido de acesso como DEVELOPER? [s/N]: ")
		var ans string
		fmt.Scanln(&ans)
		ans = strings.TrimSpace(strings.ToLower(ans))
		if (ans == "s" || ans == "sim" || ans == "y" || ans == "yes") && privKey != nil {
			runAccessRequest(service, pubStr, privKey, res.TeamSlug, res.ProjectSlug, "DEVELOPER")
			color.Cyan("Quando o pedido for aprovado, corre `git envw pull`.")
		} else if (ans == "s" || ans == "sim" || ans == "y" || ans == "yes") && privKey == nil {
			color.Yellow("Não foi possível assinar o pedido (chave privada inválida).")
		}
		return
	}

	service := NewEnvwareService()
	privStr, pubStr, err := service.GetSSHKeys()
	if err != nil {
		color.Red("Erro ao carregar chaves SSH: %v", err)
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
	case "link":
		if err := requireGitWorktree(); err != nil {
			color.Red("❌ %v", err)
			return
		}
		if err := requireGitRemote(service); err != nil {
			color.Red("❌ %v", err)
			return
		}
		var team, project, gitUrl string
		if len(os.Args) >= 4 {
			team, project = os.Args[2], os.Args[3]
			if len(os.Args) >= 5 {
				gitUrl = os.Args[4]
			} else {
				gitUrl = service.GetGitRemoteURL()
			}
		} else {
			color.Red("Uso: git envw link <team> <project> [url]")
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
		if err := requireGitWorktree(); err != nil {
			color.Red("❌ %v", err)
			return
		}
		if err := requireGitRemote(service); err != nil {
			color.Red("❌ %v", err)
			return
		}
		team, project, ok := ensureTeamProjectAccess(service, pubStr, privKey)
		if !ok {
			return
		}

		color.Cyan("🔒 Encriptar secrets (origin → %s/%s)…", team, project)

		var envFiles []string
		filepath.Walk(".", func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return nil
			}
			if info.IsDir() {
				if isSkippableDir(info.Name()) {
					return filepath.SkipDir
				}
				return nil
			}
			base := filepath.Base(path)
			if !strings.Contains(base, ".env") {
				return nil
			}
			if strings.HasSuffix(path, ".crypto") || strings.HasSuffix(path, ".decrypted") {
				return nil
			}
			envFiles = append(envFiles, path)
			return nil
		})

		if len(envFiles) == 0 {
			color.Yellow("Nenhum ficheiro .env encontrado no repositório.")
			return
		}

		var toAdd []string
		for _, envFile := range envFiles {
			environment := filepath.Base(envFile)
			if err := validateEnvironment(environment); err != nil {
				color.Yellow("Ignorado (ambiente inválido): %s", envFile)
				continue
			}
			pullResp, st, err := postPullSecrets(service, pubStr, privKey, team, project, environment)
			if err != nil {
				color.Yellow("Erro API %s: %v", envFile, err)
				continue
			}
			if st != http.StatusOK || pullResp.EncryptedProjectKey == "" {
				msg := pullResp.Error
				if msg == "" {
					msg = fmt.Sprintf("HTTP %d", st)
				}
				color.Yellow("Sem acesso ou sem chave — ignorado: %s (%s)", envFile, msg)
				continue
			}
			pkb, err := service.RSADecrypt(pullResp.EncryptedProjectKey, privKey)
			if err != nil {
				color.Yellow("Erro ao desencriptar chave do projeto: %s", envFile)
				continue
			}
			projectKey := string(pkb)

			secretsMap, err := parseEnvFile(envFile)
			if err != nil || len(secretsMap) == 0 {
				color.Yellow("Ficheiro vazio ou ilegível: %s", envFile)
				continue
			}
			var secrets []Secret
			for k, v := range secretsMap {
				s, err := service.EncryptFullPair(k, v, projectKey, environment)
				if err != nil {
					continue
				}
				secrets = append(secrets, s)
			}
			outPath := envFile + ".crypto"
			payload := map[string]interface{}{
				"version":              "2.2.0",
				"team":                 team,
				"project":              project,
				"environment":          environment,
				"secrets":              secrets,
				"project_key_envelope": pullResp.EncryptedProjectKey,
			}
			data, err := json.MarshalIndent(payload, "", "  ")
			if err != nil {
				color.Red("Erro JSON %s: %v", envFile, err)
				continue
			}
			if err := os.WriteFile(outPath, data, 0644); err != nil {
				color.Red("Erro ao gravar %s: %v", outPath, err)
				continue
			}
			toAdd = append(toAdd, outPath)
			color.Green("✔ %s → %s", envFile, outPath)
		}

		for _, p := range toAdd {
			exec.Command("git", "add", p).Run()
		}
		if len(toAdd) > 0 {
			color.Cyan("📝 git commit…")
			checkPush := exec.Command("git", "branch", "-r", "--contains", "HEAD")
			out, _ := checkPush.Output()
			if len(strings.TrimSpace(string(out))) == 0 {
				exec.Command("git", "commit", "--amend", "--no-edit").Run()
			} else {
				exec.Command("git", "commit", "-m", "chore(env): sync secrets 🌸").Run()
			}
			color.Cyan("🚀 git push…")
			cmdGit := exec.Command("git", "push")
			cmdGit.Stdout = os.Stdout
			cmdGit.Stderr = os.Stderr
			_ = cmdGit.Run()
			color.Green("✔ Repositório atualizado. 🌸🚀")
		}

	case "pull":
		if err := requireGitWorktree(); err != nil {
			color.Red("❌ %v", err)
			return
		}
		if err := requireGitRemote(service); err != nil {
			color.Red("❌ %v", err)
			return
		}
		team, project, ok := ensureTeamProjectAccess(service, pubStr, privKey)
		if !ok {
			return
		}

		color.Cyan("📥 git pull…")
		_ = exec.Command("git", "pull").Run()

		var cryptoFiles []string
		filepath.Walk(".", func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return nil
			}
			if info.IsDir() {
				if isSkippableDir(info.Name()) {
					return filepath.SkipDir
				}
				return nil
			}
			if strings.HasSuffix(path, ".crypto") && strings.Contains(filepath.Base(path), ".env") {
				cryptoFiles = append(cryptoFiles, path)
			}
			return nil
		})

		for _, cryptoFile := range cryptoFiles {
			data, err := os.ReadFile(cryptoFile)
			if err != nil {
				color.Yellow("Ignorado (leitura): %s", cryptoFile)
				continue
			}
			var meta struct {
				Environment string   `json:"environment"`
				Secrets     []Secret `json:"secrets"`
			}
			if err := json.Unmarshal(data, &meta); err != nil || meta.Environment == "" || len(meta.Secrets) == 0 {
				color.Yellow("Ignorado (metadata inválida): %s", cryptoFile)
				continue
			}

			pullResp, st, err := postPullSecrets(service, pubStr, privKey, team, project, meta.Environment)
			if err != nil {
				color.Yellow("Erro API %s: %v", cryptoFile, err)
				continue
			}
			if st != http.StatusOK || pullResp.EncryptedProjectKey == "" {
				msg := pullResp.Error
				if msg == "" {
					msg = fmt.Sprintf("HTTP %d", st)
				}
				color.Yellow("Sem permissão para %s — ignorado (%s)", meta.Environment, msg)
				continue
			}

			pkb, err := service.RSADecrypt(pullResp.EncryptedProjectKey, privKey)
			if err != nil {
				color.Yellow("Chave do projeto: %s", cryptoFile)
				continue
			}
			projectKey := string(pkb)

			dir := filepath.Dir(cryptoFile)
			base := filepath.Base(cryptoFile)
			envName := strings.TrimSuffix(base, ".crypto")
			outPath := filepath.Join(dir, envName)

			var envContent string
			for _, sec := range meta.Secrets {
				k, v, err := service.DecryptFullPair(sec, projectKey, meta.Environment)
				if err != nil {
					color.Yellow("Erro ao desencriptar entrada em %s", cryptoFile)
					continue
				}
				envContent += fmt.Sprintf("%s=%s\n", k, v)
			}
			if err := os.WriteFile(outPath, []byte(envContent), 0644); err != nil {
				color.Red("Erro ao gravar %s: %v", outPath, err)
				continue
			}
			color.Green("✔ %s", outPath)
		}
		color.Green("✔ Pull concluído. 🌸🚀")

	case "encrypt":
		if err := requireGitWorktree(); err != nil {
			color.Red("❌ %v", err)
			return
		}
		if err := requireGitRemote(service); err != nil {
			color.Red("❌ %v", err)
			return
		}
		team, project, ok := ensureTeamProjectAccess(service, pubStr, privKey)
		if !ok {
			return
		}
		environment := ".env"
		if len(os.Args) >= 3 {
			environment = os.Args[2]
		}
		if err := validateEnvironment(environment); err != nil {
			color.Red("❌ %v", err)
			return
		}

		outputFile := environment + ".crypto"
		pullResp, st, err := postPullSecrets(service, pubStr, privKey, team, project, environment)
		if err != nil || st != http.StatusOK || pullResp.EncryptedProjectKey == "" {
			color.Red("❌ Não foi possível obter a chave do projeto (verifica acesso ao ambiente).")
			return
		}

		projectKeyBytes, _ := service.RSADecrypt(pullResp.EncryptedProjectKey, privKey)
		projectKey := string(projectKeyBytes)

		secretsMap, err := parseEnvFile(environment)
		if err != nil || len(secretsMap) == 0 {
			color.Red("❌ Ficheiro %s vazio ou inexistente.", environment)
			return
		}
		var secrets []Secret
		for k, v := range secretsMap {
			s, err := service.EncryptFullPair(k, v, projectKey, environment)
			if err != nil {
				continue
			}
			secrets = append(secrets, s)
		}

		payload := map[string]interface{}{
			"version": "2.2.0", "team": team, "project": project, "environment": environment, "secrets": secrets, "project_key_envelope": pullResp.EncryptedProjectKey,
		}
		data, _ := json.MarshalIndent(payload, "", "  ")
		os.WriteFile(outputFile, data, 0644)
		color.Green("✔ Encrypted: %s 🛡️🌸", outputFile)

	case "decrypt":
		if err := requireGitWorktree(); err != nil {
			color.Red("❌ %v", err)
			return
		}
		if err := requireGitRemote(service); err != nil {
			color.Red("❌ %v", err)
			return
		}
		team, project, ok := ensureTeamProjectAccess(service, pubStr, privKey)
		if !ok {
			return
		}
		cryptoFile := ".env.crypto"
		if len(os.Args) >= 3 {
			cryptoFile = os.Args[2]
		}

		cryptoData, err := os.ReadFile(cryptoFile)
		if err != nil {
			color.Red("❌ %v", err)
			return
		}
		var filePayload struct {
			Environment string   `json:"environment"`
			Secrets     []Secret `json:"secrets"`
		}
		json.Unmarshal(cryptoData, &filePayload)

		pullResp, st, err := postPullSecrets(service, pubStr, privKey, team, project, filePayload.Environment)
		if err != nil || st != http.StatusOK || pullResp.EncryptedProjectKey == "" {
			color.Red("❌ Sem permissão ou chave indisponível para este ambiente.")
			return
		}

		projectKeyBytes, _ := service.RSADecrypt(pullResp.EncryptedProjectKey, privKey)
		projectKey := string(projectKeyBytes)

		dir := filepath.Dir(cryptoFile)
		base := filepath.Base(cryptoFile)
		outName := strings.TrimSuffix(base, ".crypto")
		outPath := filepath.Join(dir, outName)

		var envContent string
		for _, s := range filePayload.Secrets {
			k, v, err := service.DecryptFullPair(s, projectKey, filePayload.Environment)
			if err != nil {
				continue
			}
			envContent += fmt.Sprintf("%s=%s\n", k, v)
		}
		os.WriteFile(outPath, []byte(envContent), 0644)
		color.Green("✔ Decrypted: %s 💎🌸", outPath)

	case "request":
		if err := requireGitWorktree(); err != nil {
			color.Red("❌ %v", err)
			return
		}
		if err := requireGitRemote(service); err != nil {
			color.Red("❌ %v", err)
			return
		}
		gitURL := service.GetGitRemoteURL()
		res, err := service.FetchOriginResolve(gitURL, pubStr)
		if err != nil {
			color.Red("❌ %v", err)
			return
		}
		var team, project, role string
		if res.ProjectRegistered {
			if res.MembershipKnown && res.Member {
				color.Yellow("Já tens acesso a este projeto no Envware como membro do team.")
				return
			}
			team, project = res.TeamSlug, res.ProjectSlug
			role = "DEVELOPER"
			if len(os.Args) >= 3 {
				role = os.Args[2]
			}
		} else {
			if len(os.Args) >= 5 {
				team, project, role = os.Args[2], os.Args[3], os.Args[4]
			} else {
				color.Yellow("Este repositório não usa Envware no origin — indica: git envw request <team> <project> <role>")
				return
			}
		}
		runAccessRequest(service, pubStr, privKey, team, project, role)
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
		if err := requireGitWorktree(); err != nil {
			color.Red("❌ %v", err)
			return
		}
		if err := requireGitRemote(service); err != nil {
			color.Red("❌ %v", err)
			return
		}
		tOrig, pOrig, ok := ensureTeamProjectAccess(service, pubStr, privKey)
		if !ok {
			return
		}
		var category, teamSlug, projectSlug, action, quantity string
		action, quantity = "add", "1"
		if len(os.Args) >= 4 {
			category, teamSlug = os.Args[2], os.Args[3]
			if category == "users" {
				if len(os.Args) >= 5 {
					projectSlug = os.Args[4]
				} else {
					projectSlug = pOrig
				}
			}
		} else if len(os.Args) >= 3 {
			category = os.Args[2]
			teamSlug = tOrig
			if category == "users" {
				projectSlug = pOrig
			}
		}
		if category == "" {
			color.Red("Uso: git envw purchase <teams|projects|users> …")
			return
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
		if len(os.Args) < 3 {
			color.Red("Uso: git envw remove user [team] [project] <fingerprint>")
			return
		}
		if err := requireGitWorktree(); err != nil {
			color.Red("❌ %v", err)
			return
		}
		if err := requireGitRemote(service); err != nil {
			color.Red("❌ %v", err)
			return
		}
		category := os.Args[2]
		signature, _ := service.getAuthChallenge(pubStr, privKey)
		if category == "user" {
			var team, project, fp string
			if len(os.Args) >= 6 {
				team, project, fp = os.Args[3], os.Args[4], os.Args[5]
			} else {
				if len(os.Args) < 4 {
					color.Red("Uso: git envw remove user <fingerprint>")
					return
				}
				t, p, ok := ensureTeamProjectAccess(service, pubStr, privKey)
				if !ok {
					return
				}
				team, project = t, p
				fp = os.Args[3]
			}
			req, _ := json.Marshal(map[string]string{"publicKey": pubStr, "signature": signature, "teamSlug": team, "projectSlug": project, "fingerprint": fp})
			http.Post(service.BaseURL+"/project-user-remove", "application/json", bytes.NewBuffer(req))
			color.Green("✔ User removed! 🌸")
		}

	case "status":
		if err := requireGitWorktree(); err != nil {
			color.Red("❌ %v", err)
			return
		}
		if err := requireGitRemote(service); err != nil {
			color.Red("❌ %v", err)
			return
		}
		t, p, ok := ensureTeamProjectAccess(service, pubStr, privKey)
		if !ok {
			return
		}
		signature, _ := service.getAuthChallenge(pubStr, privKey)
		statReq, _ := json.Marshal(StatusRequest{PublicKey: pubStr, Signature: signature, TeamSlug: t, ProjectSlug: p})
		resp, _ := http.Post(service.BaseURL+"/team-stats", "application/json", bytes.NewBuffer(statReq))
		var finalResp CommonResponse
		json.NewDecoder(resp.Body).Decode(&finalResp)
		if finalResp.Success { color.Green("✔ Status OK! 🌸") }

	case "fingerprint":
		fmt.Printf("💻 Fingerprint: SHA256:%s\n", service.GetFingerprint(pubStr))

	case "help":
		showUsage()

	default:
		showUsage()
	}
}

func showUsage() {
	fmt.Println("\nUso: git envw <comando>  (binário: git-envw)")
	fmt.Println("  clone <url>                     git clone + resolver projeto no Envware")
	fmt.Println("  link <team> <project> [url]    Liga este repo (origin) ao projeto")
	fmt.Println("  push                            Encripta todos os .env permitidos → .crypto + commit/push")
	fmt.Println("  pull                            git pull + desencripta .crypto com permissão")
	fmt.Println("  request [role]                  Pedido de acesso (origin resolve team/projeto)")
	fmt.Println("  request <team> <project> <role> Primeiro pedido se o origin ainda não está registado")
	fmt.Println("\nOutros:")
	fmt.Println("  encrypt [.env…]                 Um ambiente → .crypto (usa origin)")
	fmt.Println("  decrypt [ficheiro.crypto]       Desencripta um .crypto")
	fmt.Println("  accept <id|fingerprint>         Aprovar pedido")
	fmt.Println("  remove user …                   Remover utilizador do projeto")
	fmt.Println("  purchase …                      Pacotes (equipa verifica API)")
	fmt.Println("  status | fingerprint | version | help")
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
