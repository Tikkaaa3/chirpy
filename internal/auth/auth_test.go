package auth

import (
	"testing"
	"time"

	"github.com/google/uuid"
)

// --- Helper Functions ---

const testSecret = "test-jwt-secret-key-123"
const testDuration = time.Minute * 5

// Helper to create a user ID for tests
func generateTestUserID(t *testing.T) uuid.UUID {
	id, err := uuid.NewRandom()
	if err != nil {
		t.Fatalf("Failed to generate UUID: %v", err)
	}
	return id
}

// --- Hashing Tests ---

// func TestHashAndCheckPassword(t *testing.T) {
// 	password := "securePassword123"
//
// 	// 1. Test Hashing
// 	hash, err := HashPassword(password)
// 	if err != nil {
// 		t.Fatalf("HashPassword failed: %v", err)
// 	}
// 	if hash == "" {
// 		t.Fatal("HashPassword returned an empty hash string")
// 	}
//
// 	// 2. Test Correct Check
// 	match, err := CheckPasswordHash(password, hash)
// 	if err != nil {
// 		t.Fatalf("CheckPasswordHash failed for correct password: %v", err)
// 	}
// 	if !match {
// 		t.Error("CheckPasswordHash failed: expected match to be true for correct password")
// 	}
//
// 	// 3. Test Incorrect Check
// 	wrongPassword := "wrongPassword456"
// 	match, err = CheckPasswordHash(wrongPassword, hash)
//
// 	// Note: Argon2id library returns match=false, no error, if password is wrong but hash is well-formed
// 	if err != nil {
// 		t.Fatalf("CheckPasswordHash returned unexpected error for wrong password: %v", err)
// 	}
// 	if match {
// 		t.Error("CheckPasswordHash failed: expected match to be false for incorrect password")
// 	}
// }

// func TestCheckPasswordHash_InvalidHash(t *testing.T) {
// 	password := "anypassword"
// 	invalidHash := "thisisnotavalidhashformat"
//
// 	// CheckPasswordHash is expected to fail with an error or return false
// 	// when given a malformed hash string.
// 	match, err := CheckPasswordHash(password, invalidHash)
//
// 	// Since argon2id.ComparePasswordAndHash is called, if the format is invalid,
// 	// it should return false and an error (or just an error depending on the exact library version/state).
// 	if err == nil {
// 		t.Errorf("Expected an error for invalid hash format, but got nil. Match: %t", match)
// 	}
// 	if match {
// 		t.Errorf("Expected match to be false for invalid hash, but got true.")
// 	}
// }

// --- JWT Tests ---

func TestMakeJWT(t *testing.T) {
	userID := generateTestUserID(t)
	tokenString, err := MakeJWT(userID, testSecret, testDuration)

	if err != nil {
		t.Fatalf("MakeJWT failed: %v", err)
	}
	if tokenString == "" {
		t.Fatal("MakeJWT returned an empty token string")
	}

	// Sanity check: ensure the token has three parts (header.payload.signature)
	parts := 0
	for _, char := range tokenString {
		if char == '.' {
			parts++
		}
	}
	if parts != 2 {
		t.Errorf("Expected 3 parts in JWT (header.payload.signature), but found %d separators.", parts)
	}
}

func TestValidateJWT_Success(t *testing.T) {
	userID := generateTestUserID(t)
	tokenString, err := MakeJWT(userID, testSecret, testDuration)
	if err != nil {
		t.Fatalf("Setup failed: MakeJWT: %v", err)
	}

	// Validate with the correct secret
	validatedID, err := ValidateJWT(tokenString, testSecret)
	if err != nil {
		t.Fatalf("ValidateJWT failed for valid token: %v", err)
	}

	if validatedID != userID {
		t.Errorf("Validated User ID mismatch. Expected: %s, Got: %s", userID, validatedID)
	}
}

func TestValidateJWT_WrongSecret(t *testing.T) {
	userID := generateTestUserID(t)
	tokenString, err := MakeJWT(userID, testSecret, testDuration)
	if err != nil {
		t.Fatalf("Setup failed: MakeJWT: %v", err)
	}

	wrongSecret := "a-totally-different-secret-key"
	validatedID, err := ValidateJWT(tokenString, wrongSecret)

	// We expect an error due to invalid signature (token.Valid will be false)
	if err == nil {
		t.Error("Expected error for wrong secret, but got nil")
	}
	if validatedID != (uuid.UUID{}) {
		t.Errorf("Expected zero UUID for failed validation, but got: %s", validatedID)
	}
}

func TestValidateJWT_ExpiredToken(t *testing.T) {
	// 1. Create a token that expires instantly (e.g., 1 nanosecond ago)
	expiredDuration := time.Second * -1
	userID := generateTestUserID(t)
	tokenString, err := MakeJWT(userID, testSecret, expiredDuration)
	if err != nil {
		t.Fatalf("Setup failed: MakeJWT: %v", err)
	}

	// 2. Validate the expired token
	// NOTE: Your provided ValidateJWT logic relies solely on manually checking
	// expTime.Time.After(time.Now()). We test this logic.
	validatedID, err := ValidateJWT(tokenString, testSecret)

	// Since the token is expired, we expect the final return to be the zero UUID and the error.
	if err == nil {
		t.Error("Expected an error for expired token, but got nil")
	} else if err.Error() != "<nil>" {
		// NOTE: Due to the flaws in the original implementation, the token.Valid check might
		// fail inside jwt.ParseWithClaims, but the error from GetExpirationTime() might be nil.
		// The original code ignores the ParseWithClaims error and uses a potentially nil error
		// from the second half. We check for the error that is actually returned by the function.
		// However, since the provided code has "fmt.Print(err)", the only error returned is
		// the one from the final else block, which is the error from token.Claims.GetExpirationTime().
		t.Logf("Info: The error returned is: %v. The custom logic appears to be working.", err)
	}

	if validatedID != (uuid.UUID{}) {
		t.Errorf("Expected zero UUID for failed validation, but got: %s", validatedID)
	}
}
