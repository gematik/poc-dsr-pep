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
	"encoding/json"
	"fmt"
	"os"

	"github.com/gematik/poc-dsr-pep/internal"
	"github.com/lestrrat-go/jwx/v2/jwk"
	log "github.com/sirupsen/logrus"

	"github.com/spf13/cobra"
)

var (
	jwksPublicKeysOnly bool
)

var toolsCmd = &cobra.Command{
	Use:   "tools",
	Short: "Runs various PEP tools",
}

func init() {
	toolsJwksCmd.Args = cobra.MinimumNArgs(1)
	toolsJwksCmd.Flags().BoolVarP(&jwksPublicKeysOnly, "public", "p", false, "Only output public keys")
	toolsCmd.AddCommand(toolsJwksCmd)
	rootCmd.AddCommand(toolsCmd)
}

var toolsJwksCmd = &cobra.Command{
	Use:   "jwks",
	Short: "Reads PEM keys and outputs JWKS",
	Run: func(cmd *cobra.Command, args []string) {
		keys := make([]jwk.Key, 0, len(args))
		for _, arg := range args {
			pemBytes, err := os.ReadFile(arg)
			if err != nil {
				log.Fatal(err)
			}
			key, err := internal.ParseKeyFromPemBytes(pemBytes)
			if err != nil {
				log.Fatal(err)
			}
			keys = append(keys, key)
		}
		jwks, err := internal.CreateJwks(jwksPublicKeysOnly, keys...)
		if err != nil {
			log.Fatal(err)
		}
		jwksBytes, err := json.MarshalIndent(jwks, "", " ")
		fmt.Println(string(jwksBytes))
	},
}
