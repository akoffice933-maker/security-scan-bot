"""Intentional findings for the CI smoke test. Do not copy into production."""

import os

eval(os.environ.get("CMD", "1"))
password = "hardcoded-smoke-password"
