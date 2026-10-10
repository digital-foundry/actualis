# Shortcuts for running, installing and testing actualis from a checkout.
# Nothing here is required: actualis is one file, and `python3 actualis.py`
# always works. `make` with no target lists what is here.

PYTHON ?= python3
ARGS   ?=

.DEFAULT_GOAL := help
.PHONY: help run network check install uninstall test tray formula clean

help:
	@echo "make run [ARGS='--days 30']  run the report from this checkout"
	@echo "make network                 what agents downloaded (--network)"
	@echo "make check                   --self-check: what it read and whether it can be trusted"
	@echo "make install                 install the 'actualis' command from this checkout (uv, else pipx)"
	@echo "make uninstall               remove the installed command"
	@echo "make test                    run the test suite"
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

tray:
	cd tray-go && go build -ldflags "-s -w" -o actualis-tray .

formula:
	@$(PYTHON) tools/brew-formula.py $(VERSION)

clean:
	rm -rf build dist *.egg-info __pycache__ tests/__pycache__ tools/__pycache__
