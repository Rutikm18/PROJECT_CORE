# =============================================================================
#  Makefile — mac_intel developer shortcuts
#
#  Usage:
#    make help            show this message
#    make install         install all dependencies (agent + manager + dev tools)
#    make test            run full test suite
#    make test-unit       unit tests only
#    make test-integration integration tests only
#    make test-coverage   test with HTML coverage report
#    make lint            ruff + mypy
#    make lint-fix        auto-fix ruff issues
#    make security        bandit (SAST) + pip-audit (CVE scan)
#    make keygen          generate a new 256-bit API key
#    make certs           generate self-signed TLS certs (dev only)
#    make run-manager     start manager server (export API_KEY first)
#    make run-agent       start agent (requires agent.toml)
#    make docker-up       start manager in Docker
#    make docker-down     stop Docker services
#    make clean           remove compiled files and test artifacts
# =============================================================================

.DEFAULT_GOAL := help
PYTHON        := python3
PIP           := pip3

# ── Help ──────────────────────────────────────────────────────────────────────
.PHONY: help
help:
	@echo ""
	@echo "  mac_intel — available targets"
	@echo ""
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
	  awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-22s\033[0m %s\n", $$1, $$2}'
	@echo ""

# ── Setup ─────────────────────────────────────────────────────────────────────
.PHONY: install
install: ## Install all runtime + dev dependencies
	$(PIP) install -r agent/requirements.txt
	$(PIP) install -r manager/requirements.txt
	$(PIP) install pytest pytest-asyncio httpx ruff mypy bandit pip-audit

.PHONY: install-agent
install-agent: ## Install agent dependencies only
	$(PIP) install -r agent/requirements.txt

.PHONY: install-manager
install-manager: ## Install manager dependencies only
	$(PIP) install -r manager/requirements.txt

# ── Tests ─────────────────────────────────────────────────────────────────────
.PHONY: test
test: ## Run the full test suite (agent + manager)
	PYTHONPATH=. $(PYTHON) -m pytest agent/tests/ manager/tests/ -v --tb=short

.PHONY: test-agent
test-agent: ## Run agent tests only
	PYTHONPATH=. $(PYTHON) -m pytest agent/tests/ -v --tb=short

.PHONY: test-manager
test-manager: ## Run manager tests only
	PYTHONPATH=. $(PYTHON) -m pytest manager/tests/ -v --tb=short

.PHONY: test-unit
test-unit: ## Run all unit tests (agent + manager)
	PYTHONPATH=. $(PYTHON) -m pytest agent/tests/unit/ manager/tests/unit/ -v --tb=short

.PHONY: test-integration
test-integration: ## Run integration tests only
	PYTHONPATH=. $(PYTHON) -m pytest manager/tests/integration/ -v --tb=short

.PHONY: test-coverage
test-coverage: ## Run tests with HTML + terminal coverage report
	PYTHONPATH=. $(PYTHON) -m pytest agent/tests/ manager/tests/ \
	  --cov=agent/agent --cov=manager/manager --cov=shared \
	  --cov-report=term-missing \
	  --cov-report=html:htmlcov
	@echo "\n  Coverage report: htmlcov/index.html\n"

# ── Linting ───────────────────────────────────────────────────────────────────
.PHONY: lint
lint: ## Run ruff linter + mypy type checker
	$(PYTHON) -m ruff check agent/agent/ manager/manager/ shared/ agent/tests/ manager/tests/
	$(PYTHON) -m mypy agent/agent/ manager/manager/ shared/ \
	  --ignore-missing-imports --no-error-summary

.PHONY: lint-fix
lint-fix: ## Auto-fix ruff linting issues
	$(PYTHON) -m ruff check --fix agent/agent/ manager/manager/ shared/ agent/tests/ manager/tests/

# ── Security scanning ─────────────────────────────────────────────────────────
.PHONY: security
security: ## bandit SAST scan + pip-audit CVE scan
	@echo "\n--- bandit (static analysis) ---"
	$(PYTHON) -m bandit -r agent/agent/ manager/manager/ shared/ \
	  -ll --skip B101,B603,B607
	@echo "\n--- pip-audit (dependency CVEs) ---"
	$(PYTHON) -m pip_audit --requirement agent/requirements.txt
	$(PYTHON) -m pip_audit --requirement manager/requirements.txt

# ── Key + cert generation ─────────────────────────────────────────────────────
.PHONY: keygen
keygen: ## Generate a new 256-bit API key pair
	$(PYTHON) manager/scripts/keygen.py

.PHONY: certs
certs: ## Generate self-signed TLS certificate (dev use only)
	mkdir -p certs
	openssl req -x509 -newkey rsa:4096 -sha256 -days 365 -nodes \
	  -keyout certs/server.key -out certs/server.crt \
	  -subj "/CN=mac-intel-dev" \
	  -addext "subjectAltName=IP:127.0.0.1,IP:0.0.0.0"
	@echo "\n  Certs written to: certs/server.{crt,key}"
	@echo "  Remember: set tls_verify = false in agent.toml for self-signed certs\n"

# ── Run ───────────────────────────────────────────────────────────────────────
.PHONY: run-manager
run-manager: ## Start manager server (API_KEY read from agent.toml)
	@test -f certs/server.crt || (echo ""; echo "  ERROR: certs/server.crt not found. Run: make certs"; echo ""; exit 1)
	@test -f agent.toml      || (echo ""; echo "  ERROR: agent.toml not found. Run: cp agent/config/agent.toml.example agent.toml && make keygen"; echo ""; exit 1)
	@PORT=$${BIND_PORT:-8443}; \
	 PID=$$(lsof -ti tcp:$$PORT 2>/dev/null); \
	 if [ -n "$$PID" ]; then \
	   echo "  Port $$PORT in use by PID $$PID — killing..."; \
	   kill -9 $$PID 2>/dev/null; sleep 1; \
	 fi
	./scripts/run_manager.sh

.PHONY: stop-manager
stop-manager: ## Kill any process running on port 8443
	@PORT=$${BIND_PORT:-8443}; \
	 PID=$$(lsof -ti tcp:$$PORT 2>/dev/null); \
	 if [ -n "$$PID" ]; then \
	   echo "  Stopping manager (PID $$PID) on port $$PORT..."; \
	   kill -9 $$PID; \
	   echo "  Stopped."; \
	 else \
	   echo "  No process found on port $$PORT."; \
	 fi

.PHONY: run-agent
run-agent: ## Start the agent (requires agent.toml)
	@test -f agent.toml || (echo ""; echo "  ERROR: agent.toml not found."; echo "  Run:   cp agent/config/agent.toml.example agent.toml"; echo ""; exit 1)
	@grep -q "REPLACE_ME" agent.toml 2>/dev/null && (echo ""; echo "  ERROR: agent.toml still has placeholder api_key."; echo "  Run:   make keygen  then paste the key into agent.toml"; echo ""; exit 1) || true
	PYTHONPATH=. $(PYTHON) -m agent.agent.core --config agent.toml

# ── Docker ────────────────────────────────────────────────────────────────────
.PHONY: docker-up
docker-up: ## Build and start the manager in Docker
	@test -n "$$API_KEY" || (echo "ERROR: export API_KEY=... first" && exit 1)
	docker compose up -d --build manager

.PHONY: docker-down
docker-down: ## Stop all Docker services
	docker compose down

.PHONY: docker-logs
docker-logs: ## Tail manager container logs
	docker compose logs -f manager

# ── Cleanup ───────────────────────────────────────────────────────────────────
.PHONY: clean
clean: ## Remove compiled Python files and test artifacts
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete 2>/dev/null || true
	rm -rf .pytest_cache htmlcov .coverage .mypy_cache .ruff_cache
	@echo "  Cleaned."
