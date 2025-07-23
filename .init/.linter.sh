#!/bin/bash
cd /home/kavia/workspace/code-generation/student-attendance-management-system-27454/student_portal_backend
source venv/bin/activate
flake8 .
LINT_EXIT_CODE=$?
if [ $LINT_EXIT_CODE -ne 0 ]; then
  exit 1
fi

