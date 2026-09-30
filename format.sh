#!/usr/bin/env bash
# Formats and lints the plugin with the tools and versions SkyPilot pins.
#
#   bash format.sh          format in place, then lint
#   bash format.sh --check  fail on any needed change; what CI runs
#
# Install the tools with: pip install -r requirements-dev.txt
set -euo pipefail
cd "$(dirname "$0")"

CHECK=0
if [[ "${1:-}" == "--check" ]]; then
  CHECK=1
fi

TARGETS=(skypilot_require_identity tests)

for tool in yapf isort pylint mypy; do
  command -v "${tool}" >/dev/null || {
    echo "${tool} not found; pip install -r requirements-dev.txt" >&2
    exit 1
  }
done

echo 'yapf:'
if ((CHECK)); then
  yapf --diff --recursive "${TARGETS[@]}"
else
  yapf --in-place --recursive "${TARGETS[@]}"
fi

echo 'isort:'
if ((CHECK)); then
  isort --check-only --diff "${TARGETS[@]}"
else
  isort "${TARGETS[@]}"
fi

echo 'pylint:'
pylint --rcfile=.pylintrc --load-plugins pylint_quotes "${TARGETS[@]}"

echo 'mypy:'
mypy "${TARGETS[@]}"

echo 'done'
