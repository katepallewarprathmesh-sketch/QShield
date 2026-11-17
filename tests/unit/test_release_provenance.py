"""Release workflow must attest the exact Python distributions before publishing."""

from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
RELEASE_WORKFLOW = ROOT / ".github" / "workflows" / "release.yaml"


def test_pypi_release_attests_built_wheel_and_sdist_before_publish() -> None:
    workflow = RELEASE_WORKFLOW.read_text(encoding="utf-8")

    pypi_job = workflow.split("\n  pypi:\n", maxsplit=1)[1].split("\n  ghcr:\n", maxsplit=1)[0]
    assert "      attestations: write" in pypi_job
    assert "      id-token: write" in pypi_job
    assert (
        "uses: actions/attest-build-provenance@"
        "c074443f1aee8d4aeeae555aebba3282517141b2"
    ) in pypi_job
    assert "subject-path: |\n            dist/*.whl\n            dist/*.tar.gz" in pypi_job
    assert pypi_job.index("python3 -m build") < pypi_job.index("Attest sdist and wheel provenance")
    assert pypi_job.index("Attest sdist and wheel provenance") < pypi_job.index(
        "Publish to PyPI (trusted publishing)"
    )
