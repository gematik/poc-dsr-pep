PEP_DOCKER_IMAGE := dsr-pep
#DOCKER_OPTS := --platform linux/amd64 --rm
OPA_DOCKER_IMAGE := openpolicyagent/opa:latest

info:
	@echo "Usage:"
	@echo
	@echo "    docker-build     Builds docker image for PEP"
	@echo "    policy-dist      Builds OPA bundle of a sample policy"
	@echo "    test-secrets     Generates the test keys and certificates"

docker-build:
	docker build -t $(PEP_DOCKER_IMAGE) $(DOCKER_OPTS) .

# create a bundle of a sample policy
# OPA is running in docker container, so no local installation is required
policy-dist: 
	mkdir -p ./sample-policy/dist
	docker run \
		${DOCKER_OPTS} \
		-v ${PWD}/sample-policy/src/policy-stable:/policy \
		-v ${PWD}/sample-policy/dist:/dist \
		${OPA_DOCKER_IMAGE} \
		build -t rego -o /dist/sample-bundle-stable.tar.gz -b /policy/
	docker run \
		${DOCKER_OPTS} \
		-v ${PWD}/sample-policy/src/policy-staging:/policy \
		-v ${PWD}/sample-policy/dist:/dist \
		${OPA_DOCKER_IMAGE} \
		build -t rego -o /dist/sample-bundle-staging.tar.gz -b /policy/

# Generates the test keys and certificates
test-secrets:
	mkdir -p test
	openssl ecparam -name prime256v1 -genkey -noout \
		-out test/session_sig_prk1.pem
	openssl ecparam -name prime256v1 -genkey -noout \
		-out test/session_sig_prk2.pem
