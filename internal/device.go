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
	"fmt"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

type DeviceTokenVerifier struct {
	verifyJwks jwk.Set
}

func NewDeviceTokenVerifier(
	verifyJwks jwk.Set,
	bindingMethod TokenBindingMethod,
) (*DeviceTokenVerifier, error) {
	return &DeviceTokenVerifier{
		verifyJwks: verifyJwks,
	}, nil
}

func (v *DeviceTokenVerifier) Verify(tokenStr string) (jwt.Token, error) {
	var token jwt.Token
	var err error
	if v.verifyJwks.Len() == 1 {
		// TODO: temporary fallback mode use only first key from jwks
		key, ok := v.verifyJwks.Key(0)
		if !ok {
			return nil, fmt.Errorf("failed to get key")
		}
		token, err = jwt.ParseString(tokenStr, jwt.WithKey(jwa.ES256, key))
	} else {
		token, err = jwt.ParseString(tokenStr, jwt.WithKeySet(v.verifyJwks))
	}

	if err != nil {
		return nil, fmt.Errorf("failed to parse token: %w", err)
	}

	return token, nil
}
