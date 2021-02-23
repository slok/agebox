#!/usr/bin/env bash

set -o errexit
set -o nounset

src=./cmd/agebox
out=./bin/agebox

ostype=${ostype:-"native"}
binary_ext=""

if [ $ostype == 'Linux' ]; then
    echo "Building linux release..."
    export GOOS=linux
    export GOARCH=amd64
    binary_ext=-linux-amd64
elif [ $ostype == 'Darwin' ]; then
    echo "Building darwin release..."
    export GOOS=darwin
    export GOARCH=amd64
    binary_ext=-darwin-amd64
elif [ $ostype == 'Windows' ]; then
    echo "Building windows release..."
    export GOOS=windows
    export GOARCH=amd64
    binary_ext=-windows-amd64.exe
elif [ $ostype == 'ARM64' ]; then
    echo "Building ARM64 release..."
    export GOOS=linux
    export GOARCH=arm64
    binary_ext=-linux-arm64
elif [ $ostype == 'ARM' ]; then
    echo "Building ARM release..."
    export GOOS=linux
    export GOARCH=arm
    export GOARM=7
    binary_ext=-linux-arm-v7
else
    echo "Building native release..."
fi

final_out=${out}${binary_ext}
ldf_cmp="-w -extldflags '-static'"
f_ver="-X main.Version=${VERSION:-dev}"

echo "Building binary at ${final_out}"
CGO_ENABLED=0 go build -o ${final_out} --ldflags "${ldf_cmp} ${f_ver}"  ${src}