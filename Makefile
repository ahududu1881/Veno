# Makefile — test (Veno V3.0)
.PHONY: run build clean test tidy dev

APP     := test
VERSION := 1.0.0
LDFLAG  := -ldflags "-s -w -X main.version=$(VERSION)"

run:
	@go run .

build:
	@mkdir -p bin
	@go build $(LDFLAG) -trimpath -o bin/$(APP) .
	@echo "  ✓ bin/$(APP)"

clean:
	@rm -rf bin/ logs/*.jsonl plugins/*.so plugins/target/

tidy:
	@go mod tidy

test:
	@go test ./...

dev:
	@go run .

.DEFAULT_GOAL := run
