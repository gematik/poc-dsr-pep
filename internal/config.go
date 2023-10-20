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
	log "github.com/sirupsen/logrus"

	"github.com/go-playground/validator/v10"
	"github.com/spf13/viper"
)

type Config struct {
	Address              string             `mapstructure:"address" validate:"required"`
	DeviceVerifyJwksPath string             `mapstructure:"device_verify_jwks_path" validate:"required"`
	EmbeddedOpa          *EmbeddedOpaConfig `mapstructure:"embedded_opa"`
	Session              *SessionConfig     `mapstructure:"session"`
	Profiles             []*ProfileConfig   `mapstructure:"profiles" validate:"required,dive"`
}

type EmbeddedOpaConfig struct {
	ConfigPath           string `mapstructure:"config_path" validate:"required"`
	SimulationConfigPath string `mapstructure:"simulation_config_path"`
}

type CredentialsConfig struct {
	// TODO: add credentials config
}

type RemoteOpaConfig struct {
	Url         string             `mapstructure:"url" validate:"required"`
	Credentials *CredentialsConfig `mapstructure:"credentials"`
}

type SessionConfig struct {
	SignPrivateKeyPath string `mapstructure:"sign_private_key_path" validate:"required"`
	VerifyJwksPath     string `mapstructure:"verify_jwks_path" validate:"required"`
}

type TokenBindingMethod string

const (
	//  is the x5t token binding method, RFC8705
	TokenBindingX5T TokenBindingMethod = "x5t"
	// JKT is the jkt token binding method, RFC9449
	TokenBindingJKT TokenBindingMethod = "jkt"
	// NONE is the none token binding method
	TokenBindingNONE TokenBindingMethod = "none"
)

type ProfileConfig struct {
	Name                      string             `mapstructure:"name" validate:"required"`
	DeviceTokenBindingMethod  TokenBindingMethod `mapstructure:"device_token_binding_method" validate:"required"`
	RequireDeviceToken        bool               `mapstructure:"require_device_token"`
	SessionTokenBindingMethod TokenBindingMethod `mapstructure:"session_token_binding_method" validate:"required"`
}

func ReadConfig(path string) (*Config, error) {
	vpr := viper.New()
	vpr.SetConfigFile(path)
	if err := vpr.ReadInConfig(); err != nil {
		return nil, err
	}
	var config Config
	err := vpr.Unmarshal(&config)
	if err != nil {
		return nil, err
	}

	val := validator.New(validator.WithRequiredStructEnabled())

	log.Println(config.Profiles[0])
	err = val.Struct(config)
	if err != nil {
		return nil, err
	}
	return &config, nil
}
