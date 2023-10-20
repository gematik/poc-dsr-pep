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
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

type SessionTokenManager struct {
	verifyJwks jwk.Set
	signKey    jwk.Key
	Issuer     string
	Audience   []string
}

func NewSessionTokenManager(
	verifyJwks jwk.Set,
	signKey jwk.Key,
	issuer string,
	audience []string,
) (*SessionTokenManager, error) {

	signPublicKey, err := signKey.PublicKey()
	if err != nil {
		return nil, fmt.Errorf("failed to get public key: %w", err)
	}

	signThumbprint, err := signPublicKey.Thumbprint(crypto.SHA256)
	if err != nil {
		return nil, fmt.Errorf("failed to get thumbprint: %w", err)
	}
	signKey.Set(jwk.KeyIDKey, base64.StdEncoding.EncodeToString(signThumbprint))

	return &SessionTokenManager{
		verifyJwks: verifyJwks,
		signKey:    signKey,
		Issuer:     issuer,
		Audience:   audience,
	}, nil
}

func (manager *SessionTokenManager) newSessionId() string {
	b := make([]byte, 32)
	_, err := rand.Read(b)
	if err != nil {
		panic(fmt.Errorf("failed to generate session id: %w", err))
	}
	return base64.URLEncoding.EncodeToString(b)
}

func (manager *SessionTokenManager) Issue(
	subject string,
	duration time.Duration,
	certThumbprint string,
) (string, string, error) {
	sessionId := manager.newSessionId()
	token := jwt.New()
	token.Set(jwt.IssuerKey, manager.Issuer)
	token.Set(jwt.SubjectKey, subject)
	token.Set(jwt.AudienceKey, manager.Audience)
	token.Set(jwt.IssuedAtKey, time.Now())
	token.Set(jwt.ExpirationKey, time.Now().Add(duration))
	token.Set(jwt.JwtIDKey, sessionId)

	if certThumbprint != "" {
		var err error
		token, err = BindTokenToCertThumbprint(token, certThumbprint)
		if err != nil {
			return "", "", fmt.Errorf("failed to bind token to cert thumbprint: %w", err)
		}
	}

	signed, err := jwt.Sign(token, jwt.WithKey(jwa.ES256, manager.signKey))
	if err != nil {
		return "", "", fmt.Errorf("failed to sign token: %w", err)
	}
	return sessionId, string(signed), nil
}

func (manager *SessionTokenManager) Verify(
	sessionToken string,
) (string, jwt.Token, error) {
	token, err := jwt.ParseString(sessionToken, jwt.WithKeySet(manager.verifyJwks))
	if err != nil {
		return "", nil, fmt.Errorf("failed to parse token: %w", err)
	}
	// verify audience
	audience, ok := token.Get(jwt.AudienceKey)
	if !ok {
		return "", nil, fmt.Errorf("audience not found")
	}

	audienceArray, ok := audience.([]string)
	if !ok {
		return "", nil, fmt.Errorf("audience is not array")
	}

	// check if audienceArray contains all elements of manager.Audience
	for _, a := range manager.Audience {
		found := false
		for _, aa := range audienceArray {
			if a == aa {
				found = true
				break
			}
		}
		if !found {
			return "", nil, fmt.Errorf("audience not found")
		}
	}

	return token.JwtID(), token, nil
}
