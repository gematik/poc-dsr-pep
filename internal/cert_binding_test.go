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
	"crypto/x509"
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestX5TBinding(t *testing.T) {
	certB64 := "MIICGTCCAb+gAwIBAgIRAPmXmc5mtdVWo99CCgltfkAwCgYIKoZIzj0EAwIwWDELMAkGA1UEBhMCREUxDzANBgNVBAgMBkJlcmxpbjEPMA0GA1UEBwwGQmVybGluMRUwEwYDVQQKDAxnZW1hdGlrIEdtYkgxEDAOBgNVBAMMB0RTUi1HTVMwHhcNMjMwOTIxMDUzMzU2WhcNMjQwOTIwMDUzMzU2WjCBwzEcMBoGCSqGSIb3DQEJARYNbm9uZUBub25lLmNvbTESMBAGA1UECgwJV2lraXBlZGlhMQ0wCwYDVQQLDARub25lMQ0wCwYDVQQIDARub25lMQswCQYDVQQGDAJFTjENMAsGA1UEBwwEbm9uZTEYMBYGA1UEAwwPKi53aWtpcGVkaWEub3JnMTswOQYJKoZIhvcNAQkHDCxRWW9WRGprVThOOEJGNy8rWmhvc1RicmRYUlVWYk9OSjZvQ3ZiSUlGdGJnPTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABN20kWMIXynewqsuDmVEP5ThMGB/w6pQ+kDFp0ouhiIrvtqaOdgwGMkHkujctpij/FE6S0dtUkZb4NEbQidayjgwCgYIKoZIzj0EAwIDSAAwRQIhAJSKs/RClX3F5IQGpg0QnwjL2vYtWS8TTEtjTmD7/5DeAiBJimOW3BwvY69wY8/qdJKUaoGHK9S+q6FIQlZKYtqdsg=="
	expectedThumbprint := "7UDk5HhpjDg9fL-Z6bwZXCU6z45UiSBS52nUHXNiOKI"
	// decode base64 to bytes
	certBytes, err := base64.StdEncoding.DecodeString(certB64)

	if err != nil {
		t.Fatalf("failed to decode cert: %s", err)
	}

	x509Cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		t.Fatalf("failed to parse cert: %s", err)
	}

	thumbprint := CalculateCertThumbprint(x509Cert)

	assert.NotEqual(t, expectedThumbprint, thumbprint, "thumbprint should not match")

}
