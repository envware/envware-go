package main

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"

	"golang.org/x/crypto/ssh"
)

type VerifyRequest struct {
	PublicKey string `json:"publicKey"`
	Signature string `json:"signature"`
	Challenge string `json:"challenge"`
}

type VerifyResponse struct {
	Verified bool   `json:"verified"`
	Error    string `json:"error"`
}

func verifyHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req VerifyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	pubKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(req.PublicKey))
	if err != nil {
		json.NewEncoder(w).Encode(VerifyResponse{Verified: false, Error: "Invalid public key format"})
		return
	}

	cryptoPubKey := pubKey.(ssh.CryptoPublicKey).CryptoPublicKey()
	rsaPubKey := cryptoPubKey.(*rsa.PublicKey)

	sigBytes, err := base64.StdEncoding.DecodeString(req.Signature)
	if err != nil {
		json.NewEncoder(w).Encode(VerifyResponse{Verified: false, Error: "Invalid signature base64"})
		return
	}

	hashed := sha256.Sum256([]byte(req.Challenge))
	err = rsa.VerifyPKCS1v15(rsaPubKey, crypto.SHA256, hashed[:], sigBytes)

	if err != nil {
		json.NewEncoder(w).Encode(VerifyResponse{Verified: false, Error: err.Error()})
		return
	}

	json.NewEncoder(w).Encode(VerifyResponse{Verified: true})
}

func main() {
	http.HandleFunc("/verify", verifyHandler)
	fmt.Println("🌸 Go Verify Microservice rodando na porta 8080...")
	http.ListenAndServe(":8080", nil)
}
