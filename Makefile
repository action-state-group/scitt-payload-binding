# SPDX-License-Identifier: Apache-2.0
# Self-service pre-submission checks for registry entries. See REGISTRY.md's
# "How to Register" section for the full submission flow.

.PHONY: validate-entry

# Usage: make validate-entry DIR=path/to/your/vectors
# Runs the same mechanical checker + per-entry two-sidedness coverage report
# used to grade a registry PR, against a registrant's own candidate vector
# directory, before they open the PR. Mechanical checks only -- Gates B/C
# (consuming profile, independence) are Designated Expert judgment and are
# not checked here; check_vectors.py --candidate prints that disclaimer with
# every run.
validate-entry:
ifndef DIR
	$(error DIR is required: make validate-entry DIR=path/to/your/vectors)
endif
	python3 .github/check_vectors.py --candidate "$(DIR)"
