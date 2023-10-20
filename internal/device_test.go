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

	"github.com/stretchr/testify/assert"
)

func TestDeviceTokenVerifier(t *testing.T) {
	jwks, err := LoadJwksFromFile("../e2e-tests/secrets/device-verify-jwks.json")
	assert.NoError(t, err, "should not fail to load jwks")

	verifier, err := NewDeviceTokenVerifier(jwks, TokenBindingX5T)
	assert.NoError(t, err, "should not fail to create verifier")

	tokenStr := "eyJhbGciOiJFUzI1NiIsImtpZCI6IlRwT3BQTlVUUEdUNjJNT1JsR2NzNVBQWmxUQ0s1eG5LbEd2VXV5ZHJsZTgiLCJ0eXAiOiJKV1QifQ.eyJjbmYiOnsieDV0I1MyNTYiOiJmM0l0X0w1eGpOMDdjdnREN3gwcGFfeWVJcjVUUk5lVnowQnNiV09rNUhNIn0sImRldmljZUhlYWx0aCI6eyJhc3NlcnRpb24iOnsiY291bnRlciI6MSwicmlza01ldHJpYyI6InVuYXZhaWxhYmxlIiwicnBJRCI6IjgvRlIyN3d5SUlYSVROTFNrZXBOOW5lTmNWRytnQUtWTDBrODkvRkVHbFkifSwiZGV2aWNlQXR0cmlidXRlcyI6eyJpZGVudGlmaWVyRm9yVmVuZG9yIjoiQjhDOTRCMUMtMUZDOS00QjJELUI5QkYtOUY5NEE1MzRCRkExIiwic3lzdGVtTW9kZWwiOiJpUGhvbmUgMTQiLCJzeXN0ZW1OYW1lIjoiIiwic3lzdGVtVmVyc2lvbiI6ImlPUyAxNiJ9fSwiZXhwIjoyMzIzNTE4MzAwLCJpYXQiOjE2OTI3OTgzMDAsImlzcyI6IkRTUiBHTVMgMS4wLjAiLCJqdGkiOiIyNjVjYWVlZS0zNThjLTRjOGYtOTYzYy0yYTlkYjEwMDY5ZWUiLCJzdWIiOiJhQzZLNm5raFRTVGlGZythQWRTaFJGMzRLbi84cGV2a1pEaGJ6OVBKK2RBPSIsInR5cGUiOiJJT1MiLCJ1c2VySWRlbnRpZmllciI6IlRFU1QgS1ZOUiJ9.gaND7WR9oz3MiEyAijFsuMLAhBJmeablqAIYvWLTFgO6FhTv7hMjn97ZXx4CuyG_iODCW6aJ6-ZrHJVZft1Whw"

	token, err := verifier.Verify(tokenStr)
	assert.NoError(t, err, "should not fail to verify token")

	t.Log(token)
}
