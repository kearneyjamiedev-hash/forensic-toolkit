from pathlib import Path
from uuid import uuid4

import pytest

from forensics.acquisition import (
    acquire_logical_file,
    load_acquisition_manifest,
    verify_before_analysis,
)


pytestmark = pytest.mark.unit


def acquire_sample(tmp_path: Path, content: bytes = b"forensic evidence"):
    source = tmp_path / "source.bin"
    source.write_bytes(content)

    evidence_root = tmp_path / "evidence"
    evidence_id = str(uuid4())

    manifest = acquire_logical_file(
        source_path=source,
        evidence_root=evidence_root,
        evidence_id=evidence_id,
        max_size=1024 * 1024,
        case_reference="CASE-AUTO-001",
        evidence_description="Automated acquisition regression test",
        collector_name="Automated Test",
    )

    return source, evidence_root, evidence_id, manifest


def test_source_master_and_working_hashes_match(tmp_path):
    _, _, _, manifest = acquire_sample(tmp_path)

    integrity = manifest["integrity"]

    assert integrity["source_content_unchanged"] is True
    assert integrity["master_verified"] is True
    assert integrity["working_verified"] is True

    assert (
        integrity["source_sha256_during_copy"]
        == integrity["source_sha256_after"]
        == integrity["master_sha256"]
        == integrity["working_sha256"]
    )


def test_acquisition_manifest_is_written_and_loadable(tmp_path):
    _, evidence_root, evidence_id, manifest = acquire_sample(tmp_path)

    loaded = load_acquisition_manifest(
        evidence_root=evidence_root,
        evidence_id=evidence_id,
    )

    assert loaded["evidence_id"] == evidence_id
    assert loaded["case_reference"] == "CASE-AUTO-001"
    assert loaded["integrity"]["master_sha256"] == (
        manifest["integrity"]["master_sha256"]
    )


def test_pre_analysis_verification_detects_working_copy_tampering(tmp_path):
    _, _, _, manifest = acquire_sample(tmp_path)

    working_path = Path(
        manifest["storage"]["working_path"]
    )
    working_path.write_bytes(b"tampered working copy")

    verification = verify_before_analysis(manifest)

    assert verification["master_verified"] is True
    assert verification["working_verified"] is False


def test_oversize_source_is_rejected(tmp_path):
    source = tmp_path / "oversize.bin"
    source.write_bytes(b"A" * 100)

    with pytest.raises(
        ValueError,
        match="exceeds the maximum permitted size",
    ):
        acquire_logical_file(
            source_path=source,
            evidence_root=tmp_path / "evidence",
            evidence_id=str(uuid4()),
            max_size=10,
            case_reference="CASE-AUTO-002",
            evidence_description="Oversize source",
            collector_name="Automated Test",
        )

def test_invalid_evidence_id_cannot_escape_evidence_root(tmp_path):
    with pytest.raises(ValueError):
        load_acquisition_manifest(
            evidence_root=tmp_path / "evidence",
            evidence_id="../../outside",
        )

