#!/usr/bin/env bash
set -eu
set -o pipefail


export GHIDRA_VERSION="${2}"
export GHIDRA_INSTALL_DIR="${1}/${GHIDRA_VERSION}"
export GHIDRA_EXTENSION_DIR="${HOME}/.ghidra/.${GHIDRA_VERSION}/Extensions"
export EXTENSION_NAME="ghidra-faultinjector"

./gradlew

rm -rf "${GHIDRA_EXTENSION_DIR}/${EXTENSION_NAME}"

CURRENT_DATE=$(date '+%Y%m%d')
unzip -q "dist/${GHIDRA_VERSION}_${CURRENT_DATE}_${EXTENSION_NAME}.zip" -d "${GHIDRA_EXTENSION_DIR}"

export LAUNCH_MODE=fg
${GHIDRA_INSTALL_DIR}/support/ghidraDebug
