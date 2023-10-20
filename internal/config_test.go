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

func TestConfig(t *testing.T) {
	cfg, err := ReadConfig("../pep-config.yaml")
	if err != nil {
		t.Fatalf("failed to read config: %s", err)
	}

	assert.Equal(t, TokenBindingX5T, cfg.Profiles[0].DeviceTokenBindingMethod, "strict profile token binding method should be x5t")
	assert.Equal(t, TokenBindingNONE, cfg.Profiles[1].DeviceTokenBindingMethod, "lax profile token binding method should be none")
}
