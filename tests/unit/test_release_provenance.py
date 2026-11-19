"""Release workflow must verify and attest the exact published artifacts."""

from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
RELEASE_WORKFLOW = ROOT / ".github" / "workflows" / "release.yaml"


def _job(workflow: str, name: str, next_name: str) -> str:
    return workflow.split(f"\n  {name}:\n", maxsplit=1)[1].split(f"\n  {next_name}:\n", maxsplit=1)[0]


def test_pypi_release_attests_reproducibly_built_wheel_and_sdist() -> None:
    workflow = RELEASE_WORKFLOW.read_text(encoding="utf-8")
    pypi_job = _job(workflow, "pypi", "ghcr")
    rebuild_job = _job(workflow, "reproducible-build", "compare-reproducible-builds")
    compare_job = _job(workflow, "compare-reproducible-builds", "release")

    assert "      attestations: write" in pypi_job
    assert "      id-token: write" in pypi_job
    assert (
        "uses: actions/attest-build-provenance@"
        "c074443f1aee8d4aeeae555aebba3282517141b2"
    ) in pypi_job
    assert "subject-path: |\n            dist/*.whl\n            dist/*.tar.gz" in pypi_job
    assert "name: qshield-rebuild-a" in pypi_job
    assert "python3 -m twine check dist/*" in pypi_job
    assert pypi_job.index("actions/download-artifact@") < pypi_job.index("Attest sdist and wheel provenance")
    assert pypi_job.index("Attest sdist and wheel provenance") < pypi_job.index(
        "Publish to PyPI (trusted publishing)"
    )

    assert "replica: [a, b]" in rebuild_job
    assert "SOURCE_DATE_EPOCH" in rebuild_job
    assert "scripts/normalize_sdist.py" in rebuild_job
    assert rebuild_job.index("python -m build --outdir dist") < rebuild_job.index(
        "actions/upload-artifact@"
    )
    assert 'cmp "$a_file" "$b_file"' in compare_job
    assert "compare-reproducible-builds" in pypi_job


def test_ghcr_release_attests_the_pushed_image_digest() -> None:
    workflow = RELEASE_WORKFLOW.read_text(encoding="utf-8")
    ghcr_job = workflow.split("\n  ghcr:\n", maxsplit=1)[1]

    assert "      packages: write" in ghcr_job
    assert "      attestations: write" in ghcr_job
    assert "      id-token: write" in ghcr_job
    assert "id: push" in ghcr_job
    assert "DIGEST=" in ghcr_job and 'test -n "$DIGEST"' in ghcr_job
    assert "uses: actions/attest-build-provenance@" in ghcr_job
    assert "subject-name: ${{ steps.push.outputs.image }}" in ghcr_job
    assert "subject-digest: ${{ steps.push.outputs.digest }}" in ghcr_job
    assert "push-to-registry: true" in ghcr_job
    assert ghcr_job.index('docker push "$IMG:$TAG"') < ghcr_job.index("Attest pushed container image")
