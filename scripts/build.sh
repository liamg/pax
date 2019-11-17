#!/bin/bash
BINARY=pax
TAG=${TRAVIS_TAG:-development}
GO111MODULE=on
mkdir -p bin/darwin
GOOS=darwin GOARCH=amd64 go build -o bin/darwin/${BINARY}-darwin-amd64 ./cmd/pax/
mkdir -p bin/linux
GOOS=linux GOARCH=amd64 go build -o bin/linux/${BINARY}-linux-amd64 ./cmd/pax/
mkdir -p bin/windows
GOOS=windows GOARCH=amd64 go build -o bin/windows/${BINARY}-windows-amd64.exe ./cmd/pax/
