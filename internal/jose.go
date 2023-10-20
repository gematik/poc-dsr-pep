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
	"fmt"
	"os"

	"github.com/lestrrat-go/jwx/v2/jwk"
)

func LoadJwksFromFile(path string) (jwk.Set, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read jwks: %w", err)
	}
	jwks, err := jwk.Parse(data)
	if err != nil {
		return nil, fmt.Errorf("failed to parse jwks file %s: %w", path, err)
	}
	return jwks, nil
}

func ParseKeyFromPemBytes(pemBytes []byte) (jwk.Key, error) {
	key, err := jwk.ParseKey(pemBytes, jwk.WithPEM(true))
	if err != nil {
		return nil, fmt.Errorf("failed to parse key from PEM: %w", err)
	}
	return key, nil
}

func CreateJwks(publicOnly bool, keys ...jwk.Key) (jwk.Set, error) {
	var err error
	set := jwk.NewSet()
	for _, key := range keys {
		if key.KeyID() == "" {
			t, err := key.Thumbprint(crypto.SHA256)
			if err != nil {
				panic(err)
			}
			key.Set(jwk.KeyIDKey, base64.StdEncoding.EncodeToString(t))
		}
		if publicOnly {
			key, err = key.PublicKey()
			if err != nil {
				return nil, fmt.Errorf("failed to get public key: %w", err)
			}
		}
		if err := set.AddKey(key); err != nil {
			return nil, fmt.Errorf("failed to add key to jwks: %w", err)
		}
	}
	return set, nil
}
