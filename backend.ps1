@'
[build-system]
requires = ["setuptools>=68", "wheel"]
build-backend = "setuptools.build_meta"

[project]
name = "agentic-ai-iam"
version = "0.2.0"
description = "Self-hosted multi-agent IAM anomaly detection POC"
requires-python = ">=3.11"
dependencies = [
  "fastapi>=0.115.0,<1",
  "uvicorn[standard]>=0.30.0,<1",
  "pydantic>=2.8.0,<3",
  "httpx>=0.27.0,<1",
]

[project.optional-dependencies]
dev = [
  "pytest>=8.0.0,<9",
]

[tool.setuptools]
packages = ["iam"]

[tool.pytest.ini_options]
pythonpath = ["."]
'@ | Set-Content -Encoding utf8 pyproject.toml