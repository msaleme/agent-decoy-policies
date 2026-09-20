# Copyright (c) 2026 msaleme. Licensed under the MIT License.
unexport PDK_COMPATIBILITY_VERSION
DEFINITION_NAME = decoy-coordinator-v0-1
POLICY_REF_NAME = $(DEFINITION_NAME)-impl
.PHONY: build generate show-policy-ref-name
build:
	cd .. && python3 scripts/flex_runtime_gate.py --prepare --assets-only
generate:
	cargo anypoint config-gen -p -m definition/gcl.yaml -o src/generated/config.rs
show-policy-ref-name:
	@echo $(POLICY_REF_NAME)
