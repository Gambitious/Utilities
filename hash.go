package utilities

import (
	"crypto"
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"hash"
	"strings"

	"github.com/xdg-go/pbkdf2"

	"golang.org/x/crypto/md4"
)

// Hash hashes input using SHA256 and returns the result as a hex string
func Hash(input string, hasher hash.Hash) string {
	hasher.Write([]byte(input))
	return hex.EncodeToString(hasher.Sum(nil))
}

// Hmac creates an HMAC with SHA256, optionally base64 encoded
func HMAC(key, input string, hashType crypto.Hash, b64 bool) string {
	var h hash.Hash
	switch hashType {
	case crypto.SHA256:
		h = hmac.New(sha256.New, []byte(key))
	case crypto.SHA512:
		h = hmac.New(sha512.New, []byte(key))
	case crypto.MD4:
		h = hmac.New(md4.New, []byte(key))
	case crypto.MD5:
		h = hmac.New(md5.New, []byte(key))
	case crypto.SHA1:
		h = hmac.New(sha1.New, []byte(key))
	// case crypto.SHA224:
	// 	h = hmac.New(sha224.New, []byte(key))
	default:
		return "error"
	}
	h.Write([]byte(input))
	if b64 {
		return base64.StdEncoding.EncodeToString(h.Sum(nil))
	}
	return hex.EncodeToString(h.Sum(nil))
}

func DoubleSha256(data []byte) []byte {
	firstHash := sha256.Sum256(data)
	secondHash := sha256.Sum256(firstHash[:])
	return secondHash[:]
}

// FromBufferToB64 converts a byte slice to a base64 string.
func FromBufferToB64(data []byte) string {
	return base64.StdEncoding.EncodeToString(data)
}

// PBKDF2 derives a key using PBKDF2 with specified parameters.
func PBKDF2(password, salt []byte, algorithm string, iterations int) []byte {
	keyLen := 32
	if algorithm == "sha256" {
		keyLen = 32
	} else if algorithm == "sha512" {
		keyLen = 64
	}
	return pbkdf2.Key(password, salt, iterations, keyLen, sha256.New)
}

// FromUtf8ToBytes converts a UTF-8 string to a byte slice.
func FromUtf8ToBytes(str string) []byte {
	return []byte(str)
}

// DeriveKeyFromPassword derives a master key from password and email using PBKDF2.
func DeriveKeyFromPassword(password, email string, kdfConfig map[string]int) []byte {
	iterations := kdfConfig["iterations"]
	if iterations == 0 {
		iterations = 100000 // Default for PBKDF2
	}
	return PBKDF2(FromUtf8ToBytes(password), FromUtf8ToBytes(email), "sha256", iterations)
}

// MakeMasterKey creates a master key using password and email.
func MakeMasterKey(password, email string, kdfConfig map[string]int) []byte {
	return DeriveKeyFromPassword(password, email, kdfConfig)
}

// MakePreloginKey makes a pre-login key using the user's master password and email.
func MakePreloginKey(masterPassword, email string, iterations int) []byte {
	trimmedEmail := strings.TrimSpace(strings.ToLower(email))
	kdfConfig := map[string]int{"iterations": iterations} // Example configuration
	return MakeMasterKey(masterPassword, trimmedEmail, kdfConfig)
}

// HashMasterKey hashes a master key using PBKDF2 and a specified purpose.
func HashMasterKey(password string, key []byte) string {
	iterations := 1
	hash := PBKDF2(key, FromUtf8ToBytes(password), "sha256", iterations)
	return FromBufferToB64(hash)
}

// LogIn performs login by deriving and hashing keys based on user credentials.
func PBKDF2Hash(credentials map[string]string, iterations int) string {
	email := credentials["email"]
	masterPassword := credentials["masterPassword"]

	// Step 1: Create the master key
	masterKey := MakePreloginKey(masterPassword, email, iterations)

	// Step 2: Create local and server hashes
	// localMasterKeyHash := HashMasterKey(masterPassword, masterKey, "LocalAuthorization")
	serverMasterKeyHash := HashMasterKey(masterPassword, masterKey)

	// fmt.Println("Local Master Key Hash:", localMasterKeyHash)
	// fmt.Println("Server Master Key Hash:", serverMasterKeyHash)

	return serverMasterKeyHash
}
