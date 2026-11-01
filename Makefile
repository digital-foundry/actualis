# Shortcuts for running, installing and testing actualis from a checkout.
# Nothing here is required: actualis is one file, and `python3 actualis.py`
# always works. `make` with no target lists what is here.

PYTHON ?= python3
ARGS   ?=

.DEFAULT_GOAL := help
.PHONY: help run network check install uninstall test pii pii-full security security-remote tray formula clean

help:
	@echo "make run [ARGS='--days 30']  run the report from this checkout"
	@echo "make network                 what agents downloaded (--network)"
	@echo "make check                   --self-check: what it read and whether it can be trusted"
	@echo "make install                 install the 'actualis' command from this checkout (uv, else pipx)"
	@echo "make uninstall               remove the installed command"
	@echo "make test                    run the test suite"
	@echo "make pii                     PII gate: personal data in tracked files (built-in detectors)"
	@echo "make pii-full                PII gate plus the private terms list (before a release)"
	@echo "make security [FUZZ_ITERATIONS=300]  Kali scanners + transcript fuzzer (needs Docker)"
	@echo "make security-remote [SECURITY_HOST=mac-mini]  same scan, on the build server over SSH"
	@echo "make tray                    build the tray app (needs Go)"
	@echo "make formula [VERSION=x.y.z] print the Homebrew formula for a PyPI release"
	@echo "make clean                   remove build output and caches"

run:
	$(PYTHON) actualis.py $(ARGS)

network:
	$(PYTHON) actualis.py --network $(ARGS)

check:
	$(PYTHON) actualis.py --self-check $(ARGS)

# --force because uv and pipx copy the code: without it a re-install after
# `git pull` silently keeps the old version.
install:
	@if command -v uv >/dev/null 2>&1; then \
		uv tool install --force . ; \
	elif command -v pipx >/dev/null 2>&1; then \
		pipx install --force . ; \
	else \
		echo "install uv (https://docs.astral.sh/uv/) or pipx, or run: $(PYTHON) actualis.py" >&2; exit 1; \
	fi
	@actualis --version

uninstall:
	-@command -v uv >/dev/null 2>&1 && uv tool uninstall actualis
	-@command -v pipx >/dev/null 2>&1 && pipx uninstall actualis

test:
	$(PYTHON) -m unittest discover -s tests

# The PII gate (tools/pii-gate.py, CONTRIBUTING.md). CI runs the built-in
# detectors. pii-full adds the private terms list (names, places, employers),
# which never lives in this repo: from the file named by ACTUALIS_PII_TERMS,
# else from 1Password through the Foundry Admin service account. The token is
# read from the login keychain and never printed.
pii:
	$(PYTHON) tools/pii-gate.py $(ARGS)

pii-full:
	@if [ -n "$$ACTUALIS_PII_TERMS" ]; then \
		$(PYTHON) tools/pii-gate.py --full $(ARGS); \
	else \
		OP_SERVICE_ACCOUNT_TOKEN="$$(security find-generic-password -s foundry-admin-op-sa -w)" \
			$(PYTHON) tools/pii-gate.py --full $(ARGS); \
	fi

tray:
	cd tray-go && go build -ldflags "-s -w" -o actualis-tray .

formula:
	@$(PYTHON) tools/brew-formula.py $(VERSION)

clean:
	rm -rf build dist *.egg-info __pycache__ tests/__pycache__ tools/__pycache__

# Kali-packaged scanners (bandit, trufflehog, gitleaks, zzuf) plus the
# transcript fuzzer, in a container with the checkout mounted read-only, no
# network, and a throwaway HOME: it cannot see this machine's transcripts.
# Reports land in security-out/.
FUZZ_ITERATIONS ?= 300
SECURITY_LABEL ?= local
security:
	docker build -q -t actualis-security:kali tools/security
	mkdir -p security-out
	# --user: the host uid, so the container can write security-out/ on a
	# native Linux Docker host (Docker Desktop remaps uids; Linux does not).
	docker run --rm --network none --read-only --tmpfs /tmp:exec,size=2g \
		--label actualis-security="$(SECURITY_LABEL)" \
		--user "$$(id -u):$$(id -g)" \
		-e FUZZ_ITERATIONS=$(FUZZ_ITERATIONS) \
		-v "$(CURDIR):/src:ro" -v "$(CURDIR)/security-out:/out" \
		actualis-security:kali sh /src/tools/security/run.sh

# The same scan on the build server (default mac-mini), over SSH rather than
# Actions: this repo is public and the build server's runners do not take
# public repositories. Sends committed history only; reports come back to
# security-out/.
SECURITY_HOST ?= mac-mini
security-remote:
	SECURITY_HOST=$(SECURITY_HOST) FUZZ_ITERATIONS=$(FUZZ_ITERATIONS) sh tools/security/remote.sh
