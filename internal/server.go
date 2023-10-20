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
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"path/filepath"

	log "github.com/sirupsen/logrus"

	"github.com/gin-gonic/gin"
	"github.com/go-playground/validator/v10"
	"github.com/open-policy-agent/opa/sdk"
)

type OPAInstance interface {
	Decision(request sdk.DecisionOptions) (*sdk.DecisionResult, error)
	Stop()
}

type PepResultError struct {
	ErrorCode   string                 `json:"errorCode,omitempty"`
	Description string                 `json:"description,omitempty"`
	Decision    map[string]interface{} `json:"decision,omitempty"`
}

var (
	errorAccessDenied = PepResultError{
		ErrorCode:   "ACCESS_DENIED",
		Description: "Access denied",
	}
	errorInternalServerError = PepResultError{
		ErrorCode:   "INTERNAL_SERVER_ERROR",
		Description: "Internal server error",
	}
)

type PEPServer struct {
	cfg                 Config
	deviceTokenVerifier *DeviceTokenVerifier
	SessionTokenManager SessionTokenManager
	opa                 OPAInstance
	opaSim              OPAInstance
	srv                 *http.Server
}

func NewPEPServer(
	cfg Config,
	basePath string,
) (*PEPServer, error) {

	var err error
	val := validator.New(validator.WithRequiredStructEnabled())

	if err = val.Struct(cfg); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}

	var opa OPAInstance
	var opaSim OPAInstance

	if cfg.EmbeddedOpa != nil {
		opa, err = NewEmbeddedOPA("pdp", filepath.Join(basePath, cfg.EmbeddedOpa.ConfigPath))
		if err != nil {
			return nil, fmt.Errorf("unable to create OPA instance: %w", err)
		}

		if cfg.EmbeddedOpa.SimulationConfigPath != "" {
			opaSim, err = NewEmbeddedOPA("pdp-sumulation", filepath.Join(basePath, cfg.EmbeddedOpa.SimulationConfigPath))
			if err != nil {
				return nil, fmt.Errorf("unable to create OPA simulation instance: %w", err)
			}
		}
	}

	jwks, err := LoadJwksFromFile(filepath.Join(basePath, cfg.DeviceVerifyJwksPath))
	if err != nil {
		return nil, fmt.Errorf("unable to load device verify jwks: %w", err)
	}

	deviceTokenVerifier, err := NewDeviceTokenVerifier(jwks, TokenBindingX5T)

	return &PEPServer{
		cfg:                 cfg,
		opa:                 opa,
		opaSim:              opaSim,
		deviceTokenVerifier: deviceTokenVerifier,
	}, nil
}

func (s *PEPServer) Start() error {
	if s.srv != nil {
		return errors.New("server already started")
	}
	log.Printf("Starting PEP server at %s", s.cfg.Address)
	// create and start gin engine to answer http requests
	engine := gin.Default()
	// mount health check
	engine.GET("/health", s.getHealth)
	// mount auth request handler for each profile
	for _, profile := range s.cfg.Profiles {
		log.Println("Registering profile", profile.Name)
		engine.GET(fmt.Sprintf("/%s/auth_request/*policyPath", profile.Name), s.handleAuthRequest(profile))
	}
	s.srv = &http.Server{
		Addr:    s.cfg.Address,
		Handler: engine,
	}
	return s.srv.ListenAndServe()
}

func (s *PEPServer) Stop() {
	if s.srv != nil {
		s.srv.Shutdown(context.Background())
	}
	if s.opa != nil {
		s.opa.Stop()
	}
	if s.opaSim != nil {
		s.opaSim.Stop()
	}
}

func respondWithError(c *gin.Context, code int, response PepResultError) {
	log.Printf("%+v", response)
	resultJson, err := json.Marshal(response)
	if err != nil {
		log.Printf("failed to marshal result: %v", err)
		resultJson = []byte("{errorCode=\"INTERNAL_SERVER_ERROR\", errorDescription=\"Internal server error\"}")
	}

	c.Header("X-Pep-Result", string(resultJson))
	c.String(code, "")
}

func (s *PEPServer) handleAuthRequest(profile *ProfileConfig) func(c *gin.Context) {
	return func(c *gin.Context) {
		policyPath := c.Param("policyPath")
		log.Printf("Received PEP request for security profile '%s', policy path '%s'", profile.Name, policyPath)

		// create empty policy input
		input := map[string]interface{}{}

		// request input from request
		if err := s.retrieveRequest(c, input); err != nil {
			log.Printf("failed to retrieve request input: %v", err)
			respondWithError(c, 403, errorAccessDenied)
			return
		}

		// verify device token
		// if the token cannot be verified, the request is still processed
		// but the input.device will not be available
		// it is up to policy to decide whether this is an error or not
		if profile.RequireDeviceToken {
			if err := s.retrieveDeviceToken(profile, c, input); err != nil {
				log.Printf("failed to retrieve device token: %v", err)
				respondWithError(c, 403, errorAccessDenied)
				return
			}
		}

		log.Printf("OPA decision input: %+v", input)

		if s.opa == nil {
			log.Println("OPA instance is not available")
			respondWithError(c, 500, errorInternalServerError)
			return
		}

		// create OPA Query
		query := sdk.DecisionOptions{
			Path:  policyPath,
			Input: input,
		}
		decision, err := s.opa.Decision(query)
		var opaErr *sdk.Error
		if errors.As(err, &opaErr) && opaErr.Code == sdk.UndefinedErr {
			log.Printf("policy decision error for path %s: %s", policyPath, err)
			respondWithError(c, 500, errorInternalServerError)
			return
		} else if err != nil {
			log.Printf("OPA decision error: %v", err)
			respondWithError(c, 500, errorInternalServerError)
			return
		}

		// run simulation in background
		if s.opaSim != nil {
			go s.simulate(query)
		}

		code := calculateResponseCode(decision)

		log.Println("Decision result code:", code)

		pdpDecision := map[string]interface{}{
			"id":     decision.ID,
			"result": decision.Result,
		}

		if code != 200 {
			respondWithError(c, code, PepResultError{
				ErrorCode:   "POLICY_DENIED",
				Description: "Policy denied",
				Decision:    pdpDecision,
			})
		} else {
			// success
			c.String(code, "")
		}

	}
}

// retrieves the information from HTTP request and writes it to policy input to be processed by OPA
func (s *PEPServer) retrieveRequest(c *gin.Context, input map[string]interface{}) error {
	request := make(map[string]interface{})
	request["method"] = c.Request.Method
	request["headers"] = c.Request.Header

	if requestURI := c.Request.Header.Get("X-Original-URI"); requestURI != "" {
		url, err := url.Parse(requestURI)
		if err != nil {
			return fmt.Errorf("failed to parse X-Original-URI header: %w", err)
		}
		request["path"] = url.Path
		request["query"] = url.Query()
		request["url"] = requestURI
	}

	if clientIP := c.Request.Header.Get("X-Real-IP"); clientIP != "" {
		request["clientIP"] = clientIP
	} else {
		request["clientIP"] = c.ClientIP()
	}

	request["countryCode"] = c.Request.Header.Get("X-Country-Code")

	input["request"] = request
	return nil
}

// retrieves and verifies device token from the request
// when successful writes the token to policy input
func (s *PEPServer) retrieveDeviceToken(profile *ProfileConfig, c *gin.Context, input map[string]interface{}) error {

	// retrieve device token from the request
	tokenString := c.Request.Header.Get("X-Device-Token")
	if tokenString == "" {
		return fmt.Errorf("missing device token header")
	}

	// verify token signature und standard claims
	deviceToken, err := s.deviceTokenVerifier.Verify(tokenString)
	if err != nil {
		return fmt.Errorf("unable to verify device token: %w", err)
	}

	// when specified, verify token binding
	switch {
	case profile.DeviceTokenBindingMethod == TokenBindingX5T:
		certEncoded := c.Request.Header.Get("X-Client-Certificate")
		if certEncoded == "" {
			return fmt.Errorf("missing X-Client-Certificate header")
		}

		cert, err := ParseURLEncodedPEM(certEncoded)
		if err != nil {
			return fmt.Errorf("failed to parse X-Client-Certificate header: %w", err)
		}

		if err := VerifyTokenBindingX5T(deviceToken, cert); err != nil {
			return fmt.Errorf("unable to verify device token binding: %w", err)
		}
	case profile.DeviceTokenBindingMethod == TokenBindingJKT:
		return fmt.Errorf("JKT token binding is not supported")
	case profile.DeviceTokenBindingMethod == TokenBindingNONE:
		// do nothing
	}

	// write device token to policy input
	deviceClaims, err := deviceToken.AsMap(context.Background())
	if err != nil {
		return err
	} else {
		log.Println("Successfully retrieved the device token")
		input["deviceTokenValid"] = true
		input["deviceTokenPayload"] = deviceClaims
	}

	// no error, no problem
	return nil
}

// runs policy decision simulation in background
// the result is written by OPA to the decision log
func (s *PEPServer) simulate(query sdk.DecisionOptions) {
	decision, err := s.opaSim.Decision(query)
	if err != nil {
		log.Printf("Simulation error: %v", err)
	}

	code := calculateResponseCode(decision)
	log.Println("Simulated decision result code:", code)
}

// calculate HTTP Response code based on the decision result of OPA
// 200 if allow == true
// 403 otherwise
func calculateResponseCode(decision *sdk.DecisionResult) int {
	if decision.Result == nil {
		return 403
	}
	result := decision.Result.(map[string]interface{})
	if result["allow"] == true {
		return 200
	}
	return 403
}

func (s *PEPServer) getHealth(c *gin.Context) {
	if s.opa == nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "OPA instance is not available",
		})
		return
	}
	// create OPA Query
	query := sdk.DecisionOptions{
		Path: "/system/bundles",
	}
	decision, err := s.opa.Decision(query)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Cannon get OPA bundles",
		})
		return
	}

	bundlesMap := decision.Result.(map[string]interface{})

	if len(bundlesMap) == 0 {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "No bundles available",
		})
		return
	}

	c.Writer.WriteHeader(http.StatusOK)
}
