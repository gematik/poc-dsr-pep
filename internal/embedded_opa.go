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
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/open-policy-agent/opa/logging"
	"github.com/open-policy-agent/opa/sdk"
)

type embeddedOPA struct {
	// context the opa instance is running in
	ctx context.Context
	// opa instance
	opa *sdk.OPA
}

func (e *embeddedOPA) Decision(request sdk.DecisionOptions) (*sdk.DecisionResult, error) {
	return e.opa.Decision(e.ctx, request)
}

func (e *embeddedOPA) Stop() {
	e.opa.Stop(e.ctx)
}

// given the path to a config file, expand the environment variables and return a reader
func expandOpaConfig(configPath string) (*strings.Reader, error) {
	cfgBytes, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read opa config file %s: %w", configPath, err)
	}
	cfgStr := string(cfgBytes)
	cfgStr = os.ExpandEnv(cfgStr)
	return strings.NewReader(cfgStr), nil
}

func NewEmbeddedOPA(id string, configPath string) (OPAInstance, error) {
	cfg, err := expandOpaConfig(configPath)
	if err != nil {
		return nil, err
	}
	ctx := context.Background()

	logger := logging.New()

	opa, err := sdk.New(ctx, sdk.Options{
		ID:            id,
		Config:        cfg,
		Logger:        logger,
		ConsoleLogger: logger,
	})

	if err != nil {
		return nil, fmt.Errorf("failed to create opa instance %s: %w", id, err)
	}

	return &embeddedOPA{
		ctx: context.Background(),
		opa: opa,
	}, nil
}
