# @clawguard/scanner — Makefile
SHELL := /bin/bash

.PHONY: install build test test-watch lint clean help

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[0;32m%-15s\033[0m %s\n", $$1, $$2}'

install: ## Install dependencies
	npm install

build: ## Build with tsup (CJS + ESM + DTS)
	npm run build

test: ## Run tests (single run)
	npm run test:run

test-watch: ## Run tests in watch mode
	npm test

lint: ## Run Biome linter
	npm run lint

clean: ## Remove dist/ and node_modules/
	rm -rf dist node_modules
