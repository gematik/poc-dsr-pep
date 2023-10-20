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
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestSessionTokenManager(t *testing.T) {
	mgr, err := NewSessionTokenManager(
		loadJwksOrPanic(sessionJwksPath),
		loadKeyPEMOrPanic(sessionSigPrk1Path),
		"urn:session-manager",
		[]string{"urn:session-manager"},
	)
	if err != nil {
		t.Fatalf("failed to create session token manager: %s", err)
	}
	sessionId, sessionJWT, err := mgr.Issue(
		"test",
		time.Hour*24,
		"",
	)
	if err != nil {
		t.Fatalf("failed to issue session token: %s", err)
	}
	t.Logf("session id: %s", sessionId)
	t.Logf("session token: %s", sessionJWT)

	sessionIdFromToken, sessionToken, err := mgr.Verify(sessionJWT)
	if err != nil {
		t.Fatalf("failed to verify session token: %s", err)
	}

	t.Logf("session id from token: %s", sessionIdFromToken)
	t.Logf("session token: %v", sessionToken)

	assert.Equal(t, sessionId, sessionIdFromToken, "session id should be same")
}

func TestCertBinding(t *testing.T) {
	pem := "-----BEGIN%20CERTIFICATE-----%0AMIIBqTCCAVACFFLSWY/ujEY%2BIVPiG9TrDFVJPf%2BmMAoGCCqGSM49BAMCMFgxCzAJ%0ABgNVBAYTAkRFMQ8wDQYDVQQIDAZCZXJsaW4xDzANBgNVBAcMBkJlcmxpbjEVMBMG%0AA1UECgwMZ2VtYXRpayBHbWJIMRAwDgYDVQQDDAdEU1ItR01TMB4XDTIzMDcyMTEx%0ANTUyMloXDTI0MDcyMDExNTUyMlowVzELMAkGA1UEBhMCREUxDzANBgNVBAgMBkJl%0AcmxpbjEPMA0GA1UEBwwGQmVybGluMRUwEwYDVQQKDAxnZW1hdGlrIEdtYkgxDzAN%0ABgNVBAMMBmRldmljZTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABH3VkKZ4efbj%0AYBzqq3GBNtGv0iFKe24cBvdOEQhjgCu81ImQ5OhxwZlALbDXn7wwzxciaa/z4Jvl%0AJmKjP/58SlYwCgYIKoZIzj0EAwIDRwAwRAIgHeU0PkZywO8cISaMj/BWzDWZUtHE%0AJNNmHihFxNoAc6wCIGZIDMF1DmBQeCeQc2pWGxfZxW%2BP8bGnApUJczzGwnDE%0A-----END%20CERTIFICATE-----%0A"

	cert, err := ParseURLEncodedPEM(pem)
	if err != nil {
		t.Errorf("failed to parse PEM: %s", err)
	}

	thumbprint := CalculateCertThumbprint(cert)

	t.Logf("thumbprint: %s", thumbprint)

	assert.Equal(t, "f3It_L5xjN07cvtD7x0pa_yeIr5TRNeVz0BsbWOk5HM", thumbprint, "thumbprint mismatch")

	mgr, err := NewSessionTokenManager(
		loadJwksOrPanic(sessionJwksPath),
		loadKeyPEMOrPanic(sessionSigPrk2Path),
		"urn:session-manager",
		[]string{"urn:session-manager"},
	)
	if err != nil {
		t.Fatalf("failed to create session token manager: %s", err)
	}
	_, sessionJWT, err := mgr.Issue(
		"test",
		time.Hour*24,
		thumbprint,
	)

	_, verifiedSessionToken, err := mgr.Verify(sessionJWT)
	if err != nil {
		t.Fatalf("failed to verify session token: %s", err)
	}

	cnfClaim, ok := verifiedSessionToken.Get("cnf")
	if !ok {
		t.Fatalf("cnf claim not found")
	}
	assert.Equal(t, map[string]interface{}{"x5t#S256": thumbprint}, cnfClaim, "cnf claim mismatch")
}
