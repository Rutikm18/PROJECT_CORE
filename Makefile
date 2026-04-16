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
#    make run-agent       start agent (requires agent.conf)
#    make build-binaries  build arm64 agent + watchdog binaries
#    make build-pkg       build arm64 .pkg installer
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

.PHONY: enroll-token
enroll-token: ## Generate a fresh enrollment token and write it to agent.toml
	@TOKEN=$$(python3 -c "import secrets; print('sk-enroll-' + secrets.token_hex(16))"); \
	 if [ ! -f agent.toml ]; then \
	   echo "  ERROR: agent.toml not found. Run: cp agent/config/agent.toml.example agent.toml"; exit 1; \
	 fi; \
	 python3 -c "import re,sys; token=sys.argv[1]; txt=open('agent.toml').read(); result=re.sub(r'(^\s*token\s*=\s*)\"[^\"]*\"', r'\1\"'+token+'\"', txt, flags=re.MULTILINE) if '[enrollment]' in txt else txt+'\n[enrollment]\ntoken    = \"'+token+'\"\nkeystore = \"file\"\n'; open('agent.toml','w').write(result)" "$$TOKEN"; \
	 echo ""; \
	 echo "  New enrollment token: $$TOKEN"; \
	 echo "  Written to:           agent.toml [enrollment] token"; \
	 echo ""; \
	 echo "  Start manager with:   make run-manager"; \
	 echo "  (ENROLLMENT_TOKENS is read automatically from agent.toml)"; \
	 echo ""

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

.PHONY: reset-agent-key
reset-agent-key: ## Delete locally stored agent API key (forces re-enroll or use [manager] api_key)
	@rm -vf agent/security/*.key 2>/dev/null || true
	@AGENT_ID=$$(python3 -c "import tomllib; f=open('agent.toml','rb'); print(tomllib.load(f)['agent']['id'])" 2>/dev/null || echo "agent-001"); \
	 security delete-generic-password -s com.macintel.agent -a "$$AGENT_ID" 2>/dev/null && \
	   echo "  Keychain entry removed for agent_id=$$AGENT_ID" || \
	   echo "  No Keychain entry found for agent_id=$$AGENT_ID (already clean)"
	@echo "  Stale keys removed. Next: set [manager] api_key from \`make keygen\` or run enrollment with a valid token."

.PHONY: run-agent
run-agent: ## Start the agent (requires agent.toml)
	@test -f agent.toml || (echo ""; echo "  ERROR: agent.toml not found."; echo "  Run:   cp agent/config/agent.toml.example agent.toml"; echo ""; exit 1)
	@grep -q "REPLACE_ME" agent.toml 2>/dev/null && (echo ""; echo "  ERROR: agent.toml still has placeholder api_key."; echo "  Run:   make keygen  then paste the key into agent.toml"; echo ""; exit 1) || true
	PYTHONPATH=. $(PYTHON) -m agent.agent.core --config agent.toml

.PHONY: run-agent-v2
run-agent-v2: ## Start hardened agent v2 (circuit breakers, self-test, disk spool)
	@test -f agent.toml || (echo ""; echo "  ERROR: agent.toml not found."; echo "  Run:   cp agent/config/agent.toml.example agent.toml"; echo ""; exit 1)
	PYTHONPATH=. $(PYTHON) agent_v2.py --config agent.toml

# ── Windows build ─────────────────────────────────────────────────────────────
.PHONY: install-windows
install-windows: ## Install Windows-specific agent dependencies (run on Windows)
	$(PIP) install -r agent/os/windows/requirements.txt
	python Scripts/pywin32_postinstall.py -install

.PHONY: build-windows
build-windows: ## Build Windows EXE binaries via PowerShell + PyInstaller (run on Windows)
	powershell.exe -ExecutionPolicy Bypass -File agent\os\windows\pkg\build_exe.ps1

.PHONY: install-windows-agent
install-windows-agent: ## Install Windows agent from built EXEs (run on Windows as Admin)
	@test -n "$(ENROLL_TOKEN)" || (echo "ERROR: set ENROLL_TOKEN=sk-enroll-..." && exit 1)
	@test -n "$(MANAGER_URL)"  || (echo "ERROR: set MANAGER_URL=https://..." && exit 1)
	powershell.exe -ExecutionPolicy Bypass -File agent\os\windows\installer\install.ps1 \
	  -ManagerUrl "$(MANAGER_URL)" -EnrollToken "$(ENROLL_TOKEN)"

.PHONY: uninstall-windows-agent
uninstall-windows-agent: ## Uninstall Windows agent services and files (run on Windows as Admin)
	powershell.exe -ExecutionPolicy Bypass -File agent\os\windows\installer\uninstall.ps1

.PHONY: build-msi
build-msi: ## Build Windows MSI installer (run on Windows; requires WiX Toolset or dotnet)
	powershell.exe -ExecutionPolicy Bypass -File agent\os\windows\pkg\build_msi.ps1 \
	  -Version $${VERSION:-1.0.0}

.PHONY: build-msi-signed
build-msi-signed: ## Build signed Windows MSI (requires SIGN_IDENTITY and signtool.exe)
	@test -n "$(SIGN_IDENTITY)" || (echo "ERROR: set SIGN_IDENTITY=CN=..." && exit 1)
	powershell.exe -ExecutionPolicy Bypass -File agent\os\windows\pkg\build_msi.ps1 \
	  -Version $${VERSION:-1.0.0} -SignIdentity "$(SIGN_IDENTITY)"

.PHONY: install-msi
install-msi: ## Install MSI silently (run on Windows as Admin; requires MANAGER_URL and ENROLL_TOKEN)
	@test -n "$(MANAGER_URL)"  || (echo "ERROR: set MANAGER_URL=https://..." && exit 1)
	@test -n "$(ENROLL_TOKEN)" || (echo "ERROR: set ENROLL_TOKEN=sk-enroll-..." && exit 1)
	msiexec /i agent\os\windows\pkg\dist\macintel-agent-$${VERSION:-1.0.0}.msi /qn \
	  MANAGER_URL="$(MANAGER_URL)" ENROLL_TOKEN="$(ENROLL_TOKEN)" \
	  AGENT_NAME="$${AGENT_NAME:-$(COMPUTERNAME)}" TLS_VERIFY="$${TLS_VERIFY:-true}"

.PHONY: test-windows
test-windows: ## Run Windows-specific unit tests (importable on any OS)
	PYTHONPATH=. $(PYTHON) -m pytest agent/tests/unit/test_windows_normalizer.py \
	  agent/tests/unit/test_windows_keystore.py -v --tb=short

# ── macOS ARM64 build ─────────────────────────────────────────────────────────
.PHONY: install-macos
install-macos: ## Install macOS-specific agent dependencies
	$(PIP) install -r agent/os/macos/requirements.txt

.PHONY: build-macos
build-macos: ## Build macOS ARM64 .pkg installer (run on macOS)
	VERSION=$${VERSION:-1.0.0} ARCH=$${ARCH:-arm64} bash agent/os/macos/pkg/build_pkg.sh

.PHONY: install-macos-agent
install-macos-agent: ## Install macOS agent (run on macOS as root)
	@test -n "$(MANAGER_URL)"  || (echo "ERROR: set MANAGER_URL=https://..."; exit 1)
	@test -n "$(ENROLL_TOKEN)" || (echo "ERROR: set ENROLL_TOKEN=sk-enroll-..."; exit 1)
	sudo bash agent/os/macos/installer/install.sh \
	  --manager-url "$(MANAGER_URL)" \
	  --enroll-token "$(ENROLL_TOKEN)" \
	  $${AGENT_NAME:+--agent-name "$$AGENT_NAME"}

.PHONY: uninstall-macos-agent
uninstall-macos-agent: ## Uninstall macOS agent (run on macOS as root)
	sudo bash agent/os/macos/installer/uninstall.sh

.PHONY: test-macos
test-macos: ## Run macOS ARM64-specific unit tests (importable on any OS)
	PYTHONPATH=. $(PYTHON) -m pytest agent/tests/unit/test_macos_normalizer.py \
	  agent/tests/unit/test_macos_keystore.py -v --tb=short

# ── Binary build (PyInstaller → ARM64 .pkg) ──────────────────────────────────
.PHONY: build-agent
build-agent: ## Build macintel-agent binary (arm64 macOS)
	pip install pyinstaller
	pyinstaller --onefile --clean --name macintel-agent \
	  --target-architecture arm64 \
	  --hidden-import agent.agent.collectors \
	  --hidden-import agent.agent.normalizer \
	  --hidden-import agent.agent.enrollment \
	  --hidden-import agent.agent.keystore \
	  agent/agent/core.py

.PHONY: build-watchdog
build-watchdog: ## Build macintel-watchdog binary (arm64 macOS)
	pip install pyinstaller
	pyinstaller --onefile --clean --name macintel-watchdog \
	  --target-architecture arm64 \
	  agent/agent/watchdog.py

.PHONY: build-binaries
build-binaries: build-agent build-watchdog ## Build both agent + watchdog binaries

.PHONY: build-pkg
build-pkg: build-binaries ## Build .pkg installer (arm64)
	VERSION=$${VERSION:-1.0.0} bash agent/pkg/build_pkg.sh

.PHONY: install-pkg
install-pkg: ## Install the latest .pkg (requires sudo)
	sudo installer -pkg $$(ls -t agent/pkg/build/*.pkg | head -1) -target /

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
