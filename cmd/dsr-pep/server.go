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

package main

import (
	"path/filepath"

	"github.com/gematik/poc-dsr-pep/internal"
	log "github.com/sirupsen/logrus"

	"github.com/spf13/cobra"
)

var (
	configPath string
)

var serverCmd = &cobra.Command{
	Use:   "server",
	Short: "Runs PEP server",
	Run: func(cmd *cobra.Command, args []string) {
		if configPath != "" {
			pepViper.SetConfigFile(configPath)
		}
		if err := pepViper.ReadInConfig(); err != nil {
			log.Fatal(err)
		}

		var cfg internal.Config
		if err := pepViper.Unmarshal(&cfg); err != nil {
			log.Fatal(err)
		}

		server, err := internal.NewPEPServer(
			cfg,
			filepath.Dir(pepViper.ConfigFileUsed()),
		)
		if err != nil {
			log.Fatal(err)
		}
		defer server.Stop()
		err = server.Start()
		if err != nil {
			log.Fatal(err)
		}
	},
}

func init() {
	rootCmd.AddCommand(serverCmd)
	pepViper.SetEnvPrefix("PEP")
	pepViper.AutomaticEnv()
	pepViper.SetConfigName("pep-config")
	pepViper.AddConfigPath(".")
	pepViper.AddConfigPath("/etc/pep")

	serverCmd.Flags().StringVarP(&configPath, "config", "c", pepViper.GetString("CONFIG_PATH"), "PEP config file")
}
