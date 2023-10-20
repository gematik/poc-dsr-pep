FROM openpolicyagent/opa:latest-debug as BUILDER

WORKDIR /app

COPY ./src .

RUN opa build -t rego -b ./policy-stable -o sample-policy-bundle-stable.tar.gz
RUN opa build -t rego -b ./policy-staging -o sample-policy-bundle-staging.tar.gz

FROM nginx:1.25-alpine

COPY --from=BUILDER /app/*.tar.gz /usr/share/nginx/html/