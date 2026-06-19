// gcp_client.go
//
// TEST HARNESS: This file intentionally contains a hardcoded GCP service account
// key for secrets detection tool benchmarking. This key is FAKE.
// See secrets-manifest.csv for ground truth.

package config

import (
	"context"
	"encoding/json"

	"google.golang.org/api/option"
	"google.golang.org/api/storage/v1"
)

// --- MANIFEST ID 33 ---
// GCP Service Account Key JSON (real format — contains private_key, client_email, etc.)
// Tools should detect: the private_key field, client_email, and/or the whole JSON blob
const GCPServiceAccountKeyJSON = `{
  "type": "service_account",
  "project_id": "my-project-prod",
  "private_key_id": "abc123def456ghi789jkl012mno345pqr678stu",
  "private_key": "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEAFAKEPRIVATEKEYDATAFORTESTINGPURPOSES0123456789\nABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789\nFAKELINE2ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz\nFAKELINE3ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz\n-----END RSA PRIVATE KEY-----\n",
  "client_email": "my-service-account@my-project-prod.iam.gserviceaccount.com",
  "client_id": "123456789012345678901",
  "auth_uri": "https://accounts.google.com/o/oauth2/auth",
  "token_uri": "https://oauth2.googleapis.com/token",
  "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
  "client_x509_cert_url": "https://www.googleapis.com/robot/v1/metadata/x509/my-service-account%40my-project-prod.iam.gserviceaccount.com"
}`

// --- MANIFEST ID 34 ---
// GCP API Key (format: AIza[A-Za-z0-9\-_]{35})
const GCPAPIKey = "AIzaFakeGCPApiKeyABCDEFGHIJKLMNOPQRSTUVWXYZ"

func NewStorageClient(ctx context.Context) (*storage.Service, error) {
	var keyData map[string]interface{}
	if err := json.Unmarshal([]byte(GCPServiceAccountKeyJSON), &keyData); err != nil {
		return nil, err
	}
	return storage.NewService(ctx, option.WithCredentialsJSON([]byte(GCPServiceAccountKeyJSON)))
}
