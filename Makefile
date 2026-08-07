.PHONY: help test check sync-skill validate

PYTHON ?= python3

help:
	@echo "test        run the offline unit tests"
	@echo "check       everything CI runs: tests, stub wiring, skill sync"
	@echo "sync-skill  regenerate the bundled skill copy from the repository"
	@echo "validate    validate one package: make validate PKG=path/to/plugin.difypkg"

test:
	$(PYTHON) -m unittest discover -t . -s tests

# Every stub is a six-line adapter, so importing it is a real test: it proves the
# check module resolves, that run_check accepts the arguments the stub passes, and
# that no two flags collide. A broken stub is otherwise invisible until CI runs it
# against a real package. check-pkg-paths and check-prefix predate run_check
# and read PR context instead of taking --help, so they sit outside the probe.
check: test
	@for stub in validator/check-*.py; do \
		case "$$stub" in \
			validator/check-pkg-paths.py|validator/check-prefix.py) continue;; \
		esac; \
		$(PYTHON) $$stub --help > /dev/null || { echo "FAILED: $$stub"; exit 1; }; \
	done
	@echo "all check stubs load"
	$(PYTHON) tools/sync-skill.py --check

sync-skill:
	$(PYTHON) tools/sync-skill.py

validate:
	@test -n "$(PKG)" || { echo "usage: make validate PKG=path/to/plugin.difypkg"; exit 2; }
	$(PYTHON) validator/validate-difypkg.py "$(PKG)" --output-dir ./validation-report
