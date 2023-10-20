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
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"net/url"

	"github.com/lestrrat-go/jwx/v2/jwt"
)

// Takes the URL-encoded PEM string and returns the parsed certificate
func ParseURLEncodedPEM(urlEncodedPEM string) (*x509.Certificate, error) {
	unescaped, err := url.QueryUnescape(urlEncodedPEM)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode([]byte(unescaped))
	if block == nil {
		return nil, fmt.Errorf("failed to decode pem")
	}

	return x509.ParseCertificate(block.Bytes)
}

func CalculateCertThumbprint(cert *x509.Certificate) string {
	// calculate hash of cert.Raw
	hashfunc := crypto.SHA256.New()
	hashfunc.Write(cert.Raw)
	hash := hashfunc.Sum(nil)

	return base64.RawURLEncoding.EncodeToString(hash)
}

func VerifyTokenBindingX5T(token jwt.Token, cert *x509.Certificate) error {
	certThumbprint := CalculateCertThumbprint(cert)
	cnf, ok := token.Get("cnf")
	if !ok {
		return fmt.Errorf("cnf claim not found")
	}

	cnfMap, ok := cnf.(map[string]interface{})
	if !ok {
		return fmt.Errorf("cnf claim has invalid syntax: %v", cnf)
	}

	if cnfMap["x5t#S256"] != certThumbprint {
		return fmt.Errorf("thumbprint mismatch")
	}

	return nil
}

func BindTokenToCertThumbprint(token jwt.Token, certThumbprint string) (jwt.Token, error) {
	token.Set("cnf", map[string]interface{}{"x5t#S256": certThumbprint})
	return token, nil
}
