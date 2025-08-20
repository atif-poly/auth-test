package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type v1PasskeySimple struct {
	CredentialID string    `json:"credentialId"`
	CreatedAt    time.Time `json:"createdAt"`
	LastUsed     time.Time `json:"lastUsed"`
}

// iOS expected models
type ResponseMFAChallenge struct {
	Challenge string `json:"challenge"`
	ExpiresAt string `json:"expiresAt"`
}

type ResponseMFAMethod struct {
	Type              string  `json:"type"`
	IsEnabled         bool    `json:"isEnabled"`
	IsSetup           bool    `json:"isSetup"`
	SetupTimestamp    *string `json:"setupTimestamp,omitempty"`
	LastUsedTimestamp *string `json:"lastUsedTimestamp,omitempty"`
}

// Request bodies
type bodyPasskeyRegister struct {
	CredentialID      string  `json:"credentialId"`
	PublicKey         string  `json:"publicKey"`
	AttestationObject *string `json:"attestationObject,omitempty"`
	AuthenticatorData *string `json:"authenticatorData,omitempty"`
	UserID            string  `json:"userId"`
}

type bodyPasskeyAuthenticate struct {
	CredentialID      string `json:"credentialId"`
	AuthenticatorData string `json:"authenticatorData"`
	Signature         string `json:"signature"`
	UserHandle        string `json:"userHandle"`
	UserID            string `json:"userId"`
	Challenge         string `json:"challenge"`
}

// In-memory store
type userPasskeysStore struct {
	mu       sync.RWMutex
	byUserID map[string]map[string]v1PasskeySimple // userID -> credentialId -> passkey
}

func newUserPasskeysStore() *userPasskeysStore {
	return &userPasskeysStore{byUserID: make(map[string]map[string]v1PasskeySimple)}
}

func (s *userPasskeysStore) upsert(userID string, cred v1PasskeySimple) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.byUserID[userID]; !ok {
		s.byUserID[userID] = make(map[string]v1PasskeySimple)
	}
	s.byUserID[userID][cred.CredentialID] = cred
}

func (s *userPasskeysStore) get(userID, credentialID string) (v1PasskeySimple, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	userMap, ok := s.byUserID[userID]
	if !ok {
		return v1PasskeySimple{}, false
	}
	cred, ok := userMap[credentialID]
	return cred, ok
}

func (s *userPasskeysStore) list(userID string) []v1PasskeySimple {
	s.mu.RLock()
	defer s.mu.RUnlock()
	userMap, ok := s.byUserID[userID]
	if !ok {
		return []v1PasskeySimple{}
	}
	result := make([]v1PasskeySimple, 0, len(userMap))
	for _, v := range userMap {
		result = append(result, v)
	}
	return result
}

func (s *userPasskeysStore) deleteAll(userID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.byUserID, userID)
}

var store = newUserPasskeysStore()
var dataFilePath string

func main() {
	// Determine persistence path and load data
	dataFilePath = os.Getenv("MFA_STORE_PATH")
	if strings.TrimSpace(dataFilePath) == "" {
		dataFilePath = filepath.Join(".", "mfa-data.json")
	}
	if err := store.loadFromFile(dataFilePath); err != nil {
		log.Printf("warning: failed to load data file %s: %v", dataFilePath, err)
	} else {
		log.Printf("loaded data from %s", dataFilePath)
	}
	http.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})

	// iOS-consumed endpoints
	http.HandleFunc("/v1/mfa/passkey/challenge", handleGetChallenge)
	http.HandleFunc("/v1/mfa/passkey/register", handleRegisterPasskey)
	http.HandleFunc("/v1/mfa/passkey/authenticate", handleAuthenticatePasskey)
	http.HandleFunc("/v1/mfa/status/", handleGetMFAStatusByPath)
	http.HandleFunc("/v1/mfa/disable/", handleDisableMFA)

	port := os.Getenv("PORT")
	if strings.TrimSpace(port) == "" {
		port = "8080"
	}
	addr := ":" + port
	log.Printf("MFA test server listening on %s", addr)
	log.Fatal(http.ListenAndServe(addr, nil))
}

func handleRegisterPasskey(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	var req bodyPasskeyRegister
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "invalid JSON body"})
		return
	}
	if strings.TrimSpace(req.CredentialID) == "" || strings.TrimSpace(req.PublicKey) == "" {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "credentialId and publicKey are required"})
		return
	}
	if strings.TrimSpace(req.UserID) == "" {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "userId is required"})
		return
	}
	userID := strings.TrimSpace(req.UserID)
	log.Printf("POST /v1/mfa/passkey/register user=%s credentialId=%s", userID, req.CredentialID)
	now := time.Now().UTC()
	if existing, ok := store.get(userID, req.CredentialID); ok {
		existing.LastUsed = now
		store.upsert(userID, existing)
		_ = store.saveToFile(dataFilePath)
		log.Printf("register: passkey already existed; updated lastUsed user=%s credentialId=%s", userID, req.CredentialID)
		writeJSON(w, http.StatusOK, buildMethodForUser(userID))
		return
	}
	store.upsert(userID, v1PasskeySimple{
		CredentialID: req.CredentialID,
		CreatedAt:    now,
		LastUsed:     now,
	})
	_ = store.saveToFile(dataFilePath)
	log.Printf("register: created new passkey user=%s credentialId=%s", userID, req.CredentialID)
	writeJSON(w, http.StatusOK, buildMethodForUser(userID))
}

// POST /v1/mfa/passkey/authenticate
func handleAuthenticatePasskey(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	var body bodyPasskeyAuthenticate
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "invalid JSON body"})
		return
	}
	userID := strings.TrimSpace(body.UserID)
	if userID == "" {
		userID = strings.TrimSpace(body.UserHandle)
	}
	if userID == "" {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "userId is required"})
		return
	}
	log.Printf("POST /v1/mfa/passkey/authenticate user=%s credentialId=%s", userID, body.CredentialID)
	cred, ok := store.get(userID, body.CredentialID)
	if !ok {
		log.Printf("authenticate: credential not found user=%s credentialId=%s", userID, body.CredentialID)
		method := ResponseMFAMethod{Type: "PASSKEY", IsEnabled: false, IsSetup: false}
		writeJSON(w, http.StatusOK, method)
		return
	}
	// Minimal verification: require non-empty essential fields
	if strings.TrimSpace(body.AuthenticatorData) == "" || strings.TrimSpace(body.Signature) == "" || strings.TrimSpace(body.Challenge) == "" {
		log.Printf("authenticate: missing fields user=%s credentialId=%s", userID, body.CredentialID)
		method := ResponseMFAMethod{Type: "PASSKEY", IsEnabled: false, IsSetup: true}
		writeJSON(w, http.StatusOK, method)
		return
	}
	cred.LastUsed = time.Now().UTC()
	store.upsert(userID, cred)
	_ = store.saveToFile(dataFilePath)
	method := buildMethodForUser(userID)
	log.Printf("authenticate: success user=%s credentialId=%s lastUsed=%s", userID, body.CredentialID, cred.LastUsed.Format(time.RFC3339Nano))
	writeJSON(w, http.StatusOK, method)
}

// GET /v1/mfa/passkey/challenge
func handleGetChallenge(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	log.Printf("GET /v1/mfa/passkey/challenge")
	ch, _ := generateChallenge()
	expires := time.Now().UTC().Add(2 * time.Minute).Format(time.RFC3339Nano)
	writeJSON(w, http.StatusOK, ResponseMFAChallenge{Challenge: ch, ExpiresAt: expires})
}

// GET /v1/mfa/status/{userID}
func handleGetMFAStatusByPath(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	// Path prefix is /v1/mfa/status/
	path := r.URL.Path
	prefix := "/v1/mfa/status/"
	if !strings.HasPrefix(path, prefix) || len(path) <= len(prefix) {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	targetUserID := path[len(prefix):]
	log.Printf("GET /v1/mfa/status/{userID} targetUser=%s", targetUserID)
	method := buildMethodForUser(targetUserID)
	writeJSON(w, http.StatusOK, []ResponseMFAMethod{method})
}

// DELETE /v1/mfa/disable/{type}
func handleDisableMFA(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	// Extract type from path: /v1/mfa/disable/{type}?userID=...
	path := r.URL.Path
	prefix := "/v1/mfa/disable/"
	if !strings.HasPrefix(path, prefix) || len(path) <= len(prefix) {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	methodType := path[len(prefix):]
	
	// Get userID from query param
	q := r.URL.Query()
	userID := q.Get("userID")
	if userID == "" {
		userID = q.Get("userId")
	}
	if strings.TrimSpace(userID) == "" {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "userID query param is required"})
		return
	}
	
	if strings.EqualFold(methodType, "PASSKEY") {
		log.Printf("DELETE /v1/mfa/disable/PASSKEY user=%s", userID)
		store.deleteAll(userID)
		_ = store.saveToFile(dataFilePath)
		w.WriteHeader(http.StatusNoContent)
		return
	}
	log.Printf("DELETE /v1/mfa/disable unknown-type=%s -> 404", methodType)
	w.WriteHeader(http.StatusNotFound)
}

func generateChallenge() (string, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(b[:]), nil
}

// Helpers
func buildMethodForUser(userID string) ResponseMFAMethod {
	passkeys := store.list(userID)
	if len(passkeys) == 0 {
		return ResponseMFAMethod{Type: "PASSKEY", IsEnabled: false, IsSetup: false}
	}
	earliest := passkeys[0].CreatedAt
	latest := passkeys[0].LastUsed
	for _, pk := range passkeys[1:] {
		if pk.CreatedAt.Before(earliest) {
			earliest = pk.CreatedAt
		}
		if pk.LastUsed.After(latest) {
			latest = pk.LastUsed
		}
	}
	setup := earliest.UTC().Format(time.RFC3339Nano)
	last := latest.UTC().Format(time.RFC3339Nano)
	return ResponseMFAMethod{
		Type:              "PASSKEY",
		IsEnabled:         true,
		IsSetup:           true,
		SetupTimestamp:    &setup,
		LastUsedTimestamp: &last,
	}
}

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// Persistence helpers
func (s *userPasskeysStore) loadFromFile(path string) error {
	b, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	var decoded map[string]map[string]v1PasskeySimple
	if err := json.Unmarshal(b, &decoded); err != nil {
		return err
	}
	s.mu.Lock()
	s.byUserID = decoded
	s.mu.Unlock()
	return nil
}

func (s *userPasskeysStore) saveToFile(path string) error {
	// Create a snapshot under read lock
	s.mu.RLock()
	snapshot := make(map[string]map[string]v1PasskeySimple, len(s.byUserID))
	for userID, creds := range s.byUserID {
		inner := make(map[string]v1PasskeySimple, len(creds))
		for credID, passkey := range creds {
			inner[credID] = passkey
		}
		snapshot[userID] = inner
	}
	s.mu.RUnlock()

	// Marshal outside the lock
	data, err := json.MarshalIndent(snapshot, "", "  ")
	if err != nil {
		return err
	}

	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	tmpFile, err := os.CreateTemp(filepath.Dir(path), ".mfa-data-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmpFile.Name()
	if _, err := tmpFile.Write(data); err != nil {
		tmpFile.Close()
		os.Remove(tmpName)
		return err
	}
	if err := tmpFile.Sync(); err != nil {
		tmpFile.Close()
		os.Remove(tmpName)
		return err
	}
	if err := tmpFile.Close(); err != nil {
		os.Remove(tmpName)
		return err
	}
	return os.Rename(tmpName, path)
}