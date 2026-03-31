package awsutil

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	tdnote "github.com/transparency-dev/formats/note"
)
func initAWSConfig(ctx context.Context) (aws.Config, error) {
	return config.LoadDefaultConfig(ctx)
}

// getPublicKey fetches the secret value from Secrets Manager and returns
// either the string contents or the binary blob.
func getPublicKey(ctx context.Context, secretID string) ([]byte, error) {
	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to load AWS config: %w", err)
	}
	sm := secretsmanager.NewFromConfig(cfg)
	out, err := sm.GetSecretValue(ctx, &secretsmanager.GetSecretValueInput{SecretId: &secretID})
	if err != nil {
		return nil, fmt.Errorf("failed to fetch secret %s: %w", secretID, err)
	}
	if out.SecretString != nil {
		return []byte(*out.SecretString), nil
	}
	return out.SecretBinary, nil
}

// logSigVerifier builds a note.Verifier from an origin string and a public
// key encoded (usually base64 DER) in keyRaw.  This is the same helper used
// in other parts of the codebase.
func logSigVerifier(origin, keyRaw string) (note.Verifier, error) {
	if origin == "" {
		return nil, fmt.Errorf("origin cannot be empty")
	}
	if keyRaw == "" {
		return nil, fmt.Errorf("public key material cannot be empty")
	}

	// The public key material may arrive in several formats:
	//  * raw DER blob
	//  * PEM encoded (text with headers)
	//  * base64-encoded DER
	// First try to handle PEM; if that succeeds we just use the contained
	// bytes. Otherwise fall back to base64 decoding (silently ignoring the
	// error), and finally use the raw input.
	derBytes := []byte(keyRaw)
	if block, _ := pem.Decode(derBytes); block != nil {
		// strip PEM headers
		derBytes = block.Bytes
	} else if decoded, err := base64.StdEncoding.DecodeString(keyRaw); err == nil {
		// successfully base64 decoded, use that instead
		derBytes = decoded
	}
	pub, err := x509.ParsePKIXPublicKey(derBytes)
	if err != nil {
		return nil, fmt.Errorf("error parsing public key: %w", err)
	}

	verifierKey, err := tdnote.RFC6962VerifierString(origin, pub)
	if err != nil {
		return nil, fmt.Errorf("error creating verifier string: %w", err)
	}
	return tdnote.NewVerifier(verifierKey)
}