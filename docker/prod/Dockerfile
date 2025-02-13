FROM golang:1.24-alpine as build-stage

RUN apk --no-cache add \
    g++ \
    git \
    make \
    curl \
    bash

ARG VERSION
ENV VERSION=${VERSION}

# Compile.
WORKDIR /src
COPY . .
RUN ./scripts/build/build.sh


FROM alpine:latest

RUN apk --no-cache add \
    ca-certificates \
    bash

COPY --from=build-stage /src/bin/agebox /usr/local/bin/agebox

ENTRYPOINT ["/usr/local/bin/agebox"]