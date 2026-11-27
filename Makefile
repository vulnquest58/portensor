SHELL := /usr/bin/env bash
CARGO ?= cargo
ACTIONLINT ?= actionlint

VERSION     ?= 1.0.0
MUSL_TARGET := x86_64-unknown-linux-musl
PREFIX      ?= /usr/local
DESTDIR     ?=
P4_EXTERNAL_EVIDENCE ?= docs/distribution/p4-2-external-evidence.template.json

.PHONY: all build release test fmt lint audit deny fuzz sign ci workflow-lint release-check \
        p4-local-check p4-evidence-check p4-external-evidence-status p4-external-evidence-check \
        package-metadata package-check lab lab-down lab-check bench bench-test bench-validate scale-baseline distributed-lab soak localhost-gate \
        syn-gate service-gate syn-service-gate loss-gate loss-lab \
        musl install docker man sbom dist clean

all: build

build:
	$(CARGO) build

release:
	$(CARGO) build --release --locked

test:
	$(CARGO) test --all-targets --all-features

fmt:
	$(CARGO) fmt --all -- --check

lint:
	$(CARGO) clippy --all-targets --all-features -- -D warnings

audit:
	$(CARGO) audit

## License, advisory, source, and dependency-duplication policy.
## Install once: cargo install cargo-deny --locked
deny:
	$(CARGO) deny check

## Run a libFuzzer target for 60 seconds (default: service_inspect).
## Install once: cargo install cargo-fuzz --locked && rustup toolchain install nightly
FUZZ_TARGET ?= service_inspect
FUZZ_SECONDS ?= 60
fuzz:
	$(CARGO) +nightly fuzz run $(FUZZ_TARGET) -- -max_total_time=$(FUZZ_SECONDS)

## Sign dist/SHA256SUMS with GPG and/or cosign (see scripts/sign-release.sh).
sign:
	bash scripts/sign-release.sh

ci: fmt lint test bench-test release

## Validate every GitHub Actions workflow. Install actionlint first.
workflow-lint:
	$(ACTIONLINT)

## Full pre-tag gate. Run from a clean tree after the release commit exists.
## Requires actionlint, cargo-audit, cargo-deny, and Python 3.
release-check: workflow-lint
	@bash scripts/release-check.sh
	@$(MAKE) ci
	@$(MAKE) audit
	@$(MAKE) deny

## Validate local P4 signing, SBOM, and release-workflow controls.
## External key custody, registry ownership, clean-runner execution, and OT
## approval are not covered; see docs/p4-release-readiness.md.
p4-local-check:
	bash scripts/p4-local-check.sh

## Validate P4 evidence paths, checklist/JSON consistency, local artifacts, and CI controls.
p4-evidence-check:
	python3 scripts/p4_evidence_check.py

## Report the completeness of a P4-2 external evidence packet without failing on gaps.
p4-external-evidence-status:
	python3 scripts/p4_external_evidence_check.py --packet "$(P4_EXTERNAL_EVIDENCE)" --allow-incomplete

## Enforce P4-2 external evidence acceptance. Fails until every channel is accepted.
p4-external-evidence-check:
	python3 scripts/p4_external_evidence_check.py --packet "$(P4_EXTERNAL_EVIDENCE)"

## Generate local package-manager metadata from verified dist archives.
## Does not publish, authenticate, or contact registries.
package-metadata:
	python3 scripts/generate_package_metadata.py --version "$(VERSION)" --dist-dir dist --output-dir dist/packages

## Generate package metadata, run local syntax checks, and run packaging tests.
## Clean-environment installs remain external P4-2 evidence.
package-check:
	python3 scripts/generate_package_metadata.py --version "$(VERSION)" --dist-dir dist --output-dir dist/packages --syntax-check
	python3 -m unittest discover -s bench/tests -p 'test_p4_packaging.py' -v

# ── Phase 6 targets ───────────────────────────────────────────────────────────

## Build a fully-static musl binary (Linux only).
## Run once to add the target: rustup target add x86_64-unknown-linux-musl
## Requires musl-tools: sudo apt-get install -y musl-tools
musl:
	rustup target add $(MUSL_TARGET)
	$(CARGO) build --release --locked --target $(MUSL_TARGET)
	@echo ""
	@echo "Static binary: target/$(MUSL_TARGET)/release/portensor"
	@file target/$(MUSL_TARGET)/release/portensor 2>/dev/null || true

## Install portensor to $(DESTDIR)$(PREFIX)/bin and man pages to share/man/man1.
install: release
	install -Dm755 target/release/portensor \
		$(DESTDIR)$(PREFIX)/bin/portensor
	@for page in man/*.1; do \
		install -Dm644 "$$page" \
			"$(DESTDIR)$(PREFIX)/share/man/man1/$$(basename $$page)"; \
		echo "Installed man page $$page"; \
	done
	@echo "Installed portensor to $(DESTDIR)$(PREFIX)/bin/portensor"

## Generate the man page from the CLI definition via clap_mangen.
man:
	$(CARGO) run --bin gen_man
	@echo "Man page written to man/portensor.1"

## Build a Docker image (multi-stage, musl-based, scratch final layer).
docker:
	docker build -t portensor:latest .
	@echo "Built portensor:latest"

## Generate the CycloneDX SBOM used by local and release checks.
sbom:
	@mkdir -p dist
	$(CARGO) cyclonedx --format json --spec-version 1.5 --override-filename "portensor-$(VERSION).cdx"
	@mv -f "portensor-$(VERSION).cdx.json" "dist/portensor-$(VERSION).cdx.json"

## Package release archives (.tar.gz, .zip, and SHA256SUMS).
dist: man
	@mkdir -p dist
	@rm -rf /tmp/portensor-dist-linux /tmp/portensor-dist-win
	@mkdir -p /tmp/portensor-dist-linux/bin /tmp/portensor-dist-linux/share/man/man1 /tmp/portensor-dist-linux/packs
	@mkdir -p /tmp/portensor-dist-win/bin /tmp/portensor-dist-win/packs
	@cp portensor-static-musl /tmp/portensor-dist-linux/bin/portensor
	@cp portensor-linux /tmp/portensor-dist-linux/bin/portensor-linux
	@cp man/*.1 /tmp/portensor-dist-linux/share/man/man1/
	@cp README.md CHANGELOG.md LICENSE /tmp/portensor-dist-linux/
	@cp -r packs/official-baseline /tmp/portensor-dist-linux/packs/
	@tar -czf dist/portensor-$(VERSION)-linux-x86_64.tar.gz -C /tmp/portensor-dist-linux .
	@cp portensor.exe /tmp/portensor-dist-win/bin/
	@cp README.md CHANGELOG.md LICENSE /tmp/portensor-dist-win/
	@cp -r packs/official-baseline /tmp/portensor-dist-win/packs/
	@python3 -c "import os, zipfile; base = '/tmp/portensor-dist-win'; zf = zipfile.ZipFile('dist/portensor-$(VERSION)-windows-x86_64.zip', 'w', zipfile.ZIP_DEFLATED); [zf.write(os.path.join(r, f), os.path.relpath(os.path.join(r, f), base)) for r, _, fs in os.walk(base) for f in fs]; zf.close()"
	@cd dist && { sha256sum portensor-$(VERSION)-linux-x86_64.tar.gz portensor-$(VERSION)-windows-x86_64.zip; if [ -f portensor-$(VERSION).cdx.json ]; then sha256sum portensor-$(VERSION).cdx.json; fi; } > SHA256SUMS
	@echo "Release archives created in dist/:"
	@cat dist/SHA256SUMS
	@if [ -n "$${PORTENSOR_GPG_KEY:-}" ] || [ -n "$${PORTENSOR_COSIGN_KEY:-}" ]; then \
		bash scripts/sign-release.sh; \
	else \
		echo "no signing key configured; run 'make sign' with PORTENSOR_GPG_KEY or PORTENSOR_COSIGN_KEY"; \
	fi

# ── Lab / gate targets ────────────────────────────────────────────────────────

lab:
	@if [ "$$(id -u)" -eq 0 ]; then bash lab/lab.sh up; else sudo -E bash lab/lab.sh up; fi

lab-down:
	@if [ "$$(id -u)" -eq 0 ]; then bash lab/lab.sh down; else sudo -E bash lab/lab.sh down; fi

lab-check:
	@if [ "$$(id -u)" -eq 0 ]; then bash lab/lab.sh cycle; else sudo -E bash lab/lab.sh cycle; fi

bench-test:
	python3 -m unittest discover -s bench/tests -t . -v

bench:
	python3 bench/bench.py --lab

bench-validate:
	python3 bench/validate.py

## 65,535 ports x 16 hosts full-range scale baseline.
scale-baseline:
	python3 bench/scale_baseline.py --repeat 3 \
		--output bench/results/full-range-v070.json \
		--markdown bench/results/full-range-v070.md

## Fake-worker coordinator crash and uneven-load lab. Use --baseline pre-P3.
distributed-lab:
	python3 bench/distributed_lab.py --baseline \
		--output bench/results/distributed-lab-v070.json \
		--markdown bench/results/distributed-lab-v070.md

## High-concurrency loopback soak. Override SOAK_SECONDS for a longer run.
SOAK_SECONDS ?= 30
soak:
	python3 bench/soak.py --duration $(SOAK_SECONDS) --output bench/results/soak.json

localhost-gate:
	python3 bench/localhost_gate.py

syn-gate:
	python3 bench/syn_gate.py

loss-gate:
	@if [ "$$(id -u)" -eq 0 ]; then python3 bench/accuracy_suite.py; else sudo -E python3 bench/accuracy_suite.py; fi

loss-lab:
	@if [ "$$(id -u)" -eq 0 ]; then bash scripts/syn-loss-lab.sh; else sudo -E bash scripts/syn-loss-lab.sh; fi

service-gate:
	python3 bench/service_gate.py

syn-service-gate:
	@if [ "$$(id -u)" -eq 0 ]; then python3 bench/service_gate.py --syn; else sudo -E python3 bench/service_gate.py --syn; fi

clean:
	$(CARGO) clean
	rm -rf bench/results
