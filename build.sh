#!/bin/bash
set -euo pipefail

docker run --rm \
  -v ./firmware:/hsm \
  -v ./global.secrets:/secrets/global.secrets:ro \
  -v ./build:/out \
  -e HSM_PIN='123abc' \
  -e PERMISSIONS='0001=R--:1111=RWC' \
  build-hsm