from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]


def test_dockerfile_uses_a_non_root_minimal_runtime_contract():
    dockerfile = (PROJECT_ROOT / "Dockerfile").read_text(encoding="utf-8")

    assert "FROM python:3.12.14-alpine3.24" in dockerfile
    assert "USER app" in dockerfile
    assert "adduser -S -D -H -u 10001" in dockerfile
    assert "HEALTHCHECK" in dockerfile
    assert "COPY --chown=app:app" not in dockerfile
    assert "COPY tests" not in dockerfile
    assert "requirements-dev.txt" not in dockerfile
    assert "apk upgrade" not in dockerfile
    assert '"setuptools==83.0.0"' in dockerfile
    assert "site-packages/pip" in dockerfile
    assert "site-packages/setuptools" in dockerfile


def test_dockerignore_excludes_local_and_development_artifacts():
    dockerignore = (PROJECT_ROOT / ".dockerignore").read_text(encoding="utf-8")
    ignored_entries = set(dockerignore.splitlines())

    assert ".venv/" in ignored_entries
    assert "venv/" in ignored_entries
    assert "*.db" in ignored_entries
    assert "tests/" in ignored_entries
    assert ".git/" in ignored_entries
