/*
 *  Copyright 2023 gematik GmbH
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package internal

import (
	"crypto"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

const (
	sessionSigPrk1Path = "../e2e-tests/secrets/session-sign-key1.pem"
	sessionSigPrk2Path = "../e2e-tests/secrets/session-sign-key2.pem"
	sessionJwksPath    = "../e2e-tests/secrets/session-verify-jwks.json"
	invalidKeyPem      = `-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIFsIDzK9t0/6rxoRPbiHKUiOGO+Fo1leQmFNnsV7ioMGoAoGCCqGSM49
AwEHoUQDQgAEtTzXSKqhCEnaUSZ65pQ3zvPDOrvF4k2KX05dGYDCcq8XMbZgbefX
0QWpZf51ncusULt9VhaGKU44nYt1QtwVbw==
-----END EC PRIVATE KEY-----`
)

func parseKeyPEMOrPanic(pemBytes []byte) jwk.Key {
	key, err := ParseKeyFromPemBytes(pemBytes)
	if err != nil {
		panic(err)
	}
	return key
}

func loadKeyPEMOrPanic(path string) jwk.Key {
	// read bytes from file
	keyPem, err := os.ReadFile(path)
	if err != nil {
		panic(err)
	}
	return parseKeyPEMOrPanic(keyPem)
}

func publicKeyOrPanic(key jwk.Key, usage string) jwk.Key {
	puk, err := key.PublicKey()
	if err != nil {
		panic(err)
	}
	t, err := puk.Thumbprint(crypto.SHA256)
	if err != nil {
		panic(err)
	}
	puk.Set(jwk.KeyIDKey, base64.StdEncoding.EncodeToString(t))
	puk.Set(jwk.KeyUsageKey, usage)
	puk.Set(jwk.AlgorithmKey, jwa.ES256)
	return puk
}

func loadJwksOrPanic(path string) jwk.Set {
	data, err := os.ReadFile(path)
	if err != nil {
		panic(err)
	}
	jwks, err := jwk.Parse(data)
	if err != nil {
		panic(err)
	}
	return jwks
}

func TestKeys(t *testing.T) {
	prk1 := loadKeyPEMOrPanic(sessionSigPrk1Path)
	puk1 := publicKeyOrPanic(prk1, "sig")

	prk2 := loadKeyPEMOrPanic(sessionSigPrk2Path)
	puk2 := publicKeyOrPanic(prk2, "sig")

	jwks := jwk.NewSet()
	jwks.AddKey(puk1)
	jwks.AddKey(puk2)

	jwksJson, err := json.Marshal(jwks)
	if err != nil {
		t.Fatalf("failed to marshal jwks: %v", err)
	}
	t.Log(string(jwksJson))

}

func TestValidSign(t *testing.T) {
	key := loadKeyPEMOrPanic(sessionSigPrk1Path)
	publicKey := publicKeyOrPanic(key, "sig")
	key.Set(jwk.KeyIDKey, publicKey.KeyID())

	token, err := jwt.NewBuilder().
		Issuer("urn:me").
		Build()

	if err != nil {
		t.Fatalf("failed to build JWT: %v", err)
	}

	signed, err := jwt.Sign(token, jwt.WithKey(jwa.ES256, key))
	if err != nil {
		fmt.Printf("failed to sign token: %s\n", err)
		return
	}

	t.Log(string(signed))

	signJwks := loadJwksOrPanic(sessionJwksPath)
	_, err = jwt.Parse(signed, jwt.WithKeySet(signJwks))
	if err != nil {
		t.Fatalf("failed to verify JWT: %v", err)
	}
}

func TestInvalidSign(t *testing.T) {
	invalidKey := parseKeyPEMOrPanic([]byte(invalidKeyPem))
	invalidPublicKey := publicKeyOrPanic(invalidKey, "sig")
	invalidKey.Set(jwk.KeyIDKey, invalidPublicKey.KeyID())

	token, err := jwt.NewBuilder().
		Issuer("urn:me").
		IssuedAt(time.Now()).
		Build()

	if err != nil {
		t.Fatalf("failed to build JWT: %v", err)
	}

	signed, err := jwt.Sign(token, jwt.WithKey(jwa.ES256, invalidKey))
	if err != nil {
		fmt.Printf("failed to sign token: %s\n", err)
		return
	}

	signedString := string(signed)

	t.Log(signedString)

	signJwks := loadJwksOrPanic(sessionJwksPath)
	_, err = jwt.ParseString(signedString, jwt.WithKeySet(signJwks))
	if err == nil {
		t.Fatalf("should have failed to verify JWT with invalid key")
	} else {
		t.Logf("failed to verify JWT with invalid key: %v", err)
	}
}
