#!/bin/bash
cd /home/kavia/workspace/code-generation/secure-password-generator-301610-301619/password_generator_backend
source venv/bin/activate
flake8 .
LINT_EXIT_CODE=$?
if [ $LINT_EXIT_CODE -ne 0 ]; then
  exit 1
fi

