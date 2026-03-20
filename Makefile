.PHONY: help test lint typecheck clean audit-docker audit-direct

PYTHON ?= python3
ES_CONTAINER ?= elasticsearch

help:
	@echo "elastic-stig-audit — Makefile targets"
	@echo ""
	@echo "  make test            Run unit tests"
	@echo "  make lint            Run flake8 linter"
	@echo "  make typecheck       Run mypy type checker"
	@echo "  make clean           Remove output files and caches"
	@echo "  make audit-docker    Audit ES_CONTAINER (default: elasticsearch)"
	@echo "  make audit-direct    Audit localhost:9200 directly"
	@echo ""
	@echo "Variables:"
	@echo "  ES_CONTAINER=$(ES_CONTAINER)"

test:
	$(PYTHON) -m pytest test/ -v

lint:
	$(PYTHON) -m flake8 audit.py runner.py checks/ mappings/ output/ \
	  --max-line-length=120 \
	  --extend-ignore=E501,W503

typecheck:
	$(PYTHON) -m mypy audit.py runner.py checks/ mappings/ output/ \
	  --ignore-missing-imports

clean:
	rm -f *.sarif *.json *.csv *.zip
	rm -rf data/cve_cache.json data/kev_cache.json
	find . -name "__pycache__" -type d -exec rm -rf {} + 2>/dev/null || true
	find . -name "*.pyc" -delete

audit-docker:
	$(PYTHON) audit.py \
	  --mode docker \
	  --container $(ES_CONTAINER) \
	  --sarif output/results.sarif \
	  --json output/results.json \
	  --csv output/results.csv \
	  --bundle output/evidence.zip

audit-direct:
	$(PYTHON) audit.py \
	  --mode direct \
	  --host 127.0.0.1 \
	  --port 9200 \
	  --sarif output/results.sarif \
	  --json output/results.json \
	  --csv output/results.csv
