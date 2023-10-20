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
	"net/http"
	"os"
	"testing"
	"time"

	sdktest "github.com/open-policy-agent/opa/sdk/test"

	"github.com/stretchr/testify/assert"
)

func TestPEPServer(t *testing.T) {
	var err error
	// create a mock HTTP bundle server
	mockBundleServer, err := sdktest.NewServer(sdktest.MockBundle("/bundles/sample-policy-bundle.tar.gz", map[string]string{
		"example.rego": `
			package sample

			import data.sample.data
			import future.keywords.in
			
			default allow = false
			
			# match the english greeting
			messageMatch {
				"Hello World" in input.request.headers["X-Message"]
			}
			
			# Generate violation if is not "Hello World"
			violations[v] {
				not messageMatch
				v := {
					"error": "message_not_match",
					"error_description": "X-Message header does not match",
				}
			}
			
			allow {
				messageMatch
			}
			
			verdict := {
				"allow": allow,
				"violations": violations,
			}`,
	}))
	if err != nil {
		t.Error(err)
	}

	defer mockBundleServer.Stop()

	os.Setenv("MOCK_BUNDLE_SERVICE_URL", mockBundleServer.URL())

	cfg := Config{
		Address:              ":18282",
		DeviceVerifyJwksPath: "../e2e-tests/secrets/device-verify-jwks.json",
		EmbeddedOpa: &EmbeddedOpaConfig{
			ConfigPath: "./server_test_opa_config.yaml",
		},
		Profiles: []*ProfileConfig{
			{
				Name:                      "lax",
				DeviceTokenBindingMethod:  TokenBindingNONE,
				RequireDeviceToken:        false,
				SessionTokenBindingMethod: TokenBindingNONE,
			},
			{
				Name:                      "strict",
				DeviceTokenBindingMethod:  TokenBindingX5T,
				RequireDeviceToken:        true,
				SessionTokenBindingMethod: TokenBindingX5T,
			},
		},
		Session: &SessionConfig{
			SignPrivateKeyPath: "../e2e-tests/secrets/session-sign-private-key.pem",
			VerifyJwksPath:     "../e2e-tests/secrets/session-verify-jwks.json",
		},
	}

	srv, err := NewPEPServer(cfg, "")
	if err != nil {
		t.Fatalf("failed to create server: %s", err)
	}

	go srv.Start()

	client := &http.Client{}

	var req *http.Request
	var resp *http.Response

	// make http request
	req, err = http.NewRequest("GET", "http://localhost:18282/lax/auth_request/sample/verdict", nil)

	if err != nil {
		t.Fatalf("failed to create request: %s", err)
	}

	req.Header.Add("X-Message", "Hello World")

	// retry 10 times, just in case server is not ready
	for i := 0; i < 10; i++ {
		resp, err = client.Do(req)
		if err != nil {
			time.Sleep(1 * time.Second)
			continue
		} else {
			break
		}
	}

	if err != nil {
		t.Fatalf("failed to make request: %s", err)
	}

	assert.Equal(t, http.StatusOK, resp.StatusCode, "should return 200")

	req, err = http.NewRequest("GET", "http://localhost:18282/strict/auth_request/sample/verdict", nil)
	if err != nil {
		t.Fatalf("failed to create request: %s", err)
	}

	resp, err = client.Do(req)

	if err != nil {
		t.Fatalf("failed to make request: %s", err)
	}

	assert.Equal(t, http.StatusForbidden, resp.StatusCode, "should return 403")

	req, err = http.NewRequest("GET", "http://localhost:18282/health", nil)
	if err != nil {
		t.Fatalf("failed to create request: %s", err)
	}

	resp, err = client.Do(req)

	if err != nil {
		t.Fatalf("failed to make request: %s", err)
	}

	assert.Equal(t, http.StatusOK, resp.StatusCode, "should return 200")

	srv.Stop()
}
