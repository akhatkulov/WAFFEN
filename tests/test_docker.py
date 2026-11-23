"""Tests for Docker setup files."""
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def test_dockerfile_exists():
    assert (ROOT / "Dockerfile").is_file()


def test_dockerfile_has_entrypoint():
    text = (ROOT / "Dockerfile").read_text()
    assert "ENTRYPOINT" in text
    assert "waffen" in text


def test_dockerfile_installs_curl():
    text = (ROOT / "Dockerfile").read_text()
    assert "curl" in text


def test_dockerfile_uses_slim_base():
    text = (ROOT / "Dockerfile").read_text()
    assert "slim" in text.split("\n")[0]


def test_dockerignore_exists():
    assert (ROOT / ".dockerignore").is_file()


def test_dockerignore_excludes_venv():
    text = (ROOT / ".dockerignore").read_text()
    assert ".venv" in text


def test_docker_compose_exists():
    assert (ROOT / "docker-compose.yml").is_file()


def test_docker_compose_has_waffen_service():
    text = (ROOT / "docker-compose.yml").read_text()
    assert "waffen" in text
    assert "build" in text
