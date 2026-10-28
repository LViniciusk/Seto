from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from internal_functions import (
    DiscoveredFunction,
    FunctionManifest,
    InternalFunction,
    counts_as_decompiled_code,
    internal_catalog_metrics,
    internal_function_key,
    load_internal_catalog,
    load_function_manifest,
    parse_ghidra_enumeration,
    serialize_function_manifest,
    select_internal_discoveries,
    write_function_manifest,
)


def _write_catalog(path: Path, functions: list[dict[str, object]]) -> None:
    path.write_text(
        json.dumps({"schema_version": 2, "functions": functions}), encoding="utf-8"
    )


def _entry(
    module: str, address: str, size_bytes: int, *, boundary_status: str = "EXACT"
) -> dict[str, object]:
    numeric = int(address, 0)
    if module == "EBOOT":
        section = ".text"
    elif module == "libtutoriallist.prx":
        section = ".text" if numeric < 0x25B0 else ".sceStub.text"
    elif module == "libhtml_view.prx":
        section = ".text" if numeric < 0x7F4 else ".sceStub.text"
    else:
        section = ".text"
    return {
        "module": module,
        "address": address,
        "size_bytes": size_bytes,
        "instruction_count": size_bytes // 4,
        "boundary_status": boundary_status,
        "kind": "import_stub" if section == ".sceStub.text" else "code",
        "section": section,
        "evidence_path": "docs/decomp-progress.md#internal-functions",
        "result": {"status": "UNMATCHED"},
    }


def test_internal_identity_is_module_and_address(tmp_path: Path) -> None:
    catalog = tmp_path / "internal.json"
    _write_catalog(
        catalog,
        [
            _entry("EBOOT", "0x31308", 92),
            _entry("libtutoriallist.prx", "0x200", 32),
            _entry("EBOOT", "0x3129c", 108),
        ],
    )

    functions = load_internal_catalog(catalog)

    assert functions == (
        InternalFunction("EBOOT", 0x3129C, 108, "EXACT", "docs/decomp-progress.md#internal-functions"),
        InternalFunction("EBOOT", 0x31308, 92, "EXACT", "docs/decomp-progress.md#internal-functions"),
        InternalFunction(
            "libtutoriallist.prx",
            0x200,
            32,
            "EXACT",
            "docs/decomp-progress.md#internal-functions",
            "code",
            ".text",
        ),
    )
    assert internal_function_key(functions[1]) == ("eboot", 0x31308)
    assert internal_function_key(functions[2]) == ("libtutoriallist.prx", 0x200)


def test_internal_catalog_rejects_duplicate_module_address(tmp_path: Path) -> None:
    catalog = tmp_path / "internal.json"
    _write_catalog(catalog, [_entry("EBOOT", "0x31308", 92), _entry("eboot", "0x31308", 92)])

    with pytest.raises(ValueError, match="duplicate internal function"):
        load_internal_catalog(catalog)


def test_internal_catalog_rejects_overlapping_exact_ranges(tmp_path: Path) -> None:
    catalog = tmp_path / "internal.json"
    _write_catalog(catalog, [_entry("EBOOT", "0x3129c", 108), _entry("EBOOT", "0x31300", 16)])

    with pytest.raises(ValueError, match="overlapping EXACT internal functions"):
        load_internal_catalog(catalog)


def test_internal_catalog_requires_exact_ranges_to_be_word_sized(tmp_path: Path) -> None:
    catalog = tmp_path / "internal.json"
    _write_catalog(catalog, [_entry("EBOOT", "0x31308", 91)])

    with pytest.raises(ValueError, match="positive multiple of four"):
        load_internal_catalog(catalog)


def test_internal_catalog_rejects_invented_nids(tmp_path: Path) -> None:
    catalog = tmp_path / "internal.json"
    entry = _entry("EBOOT", "0x31308", 92)
    entry["nid"] = "0x00000000"
    _write_catalog(catalog, [entry])

    with pytest.raises(ValueError, match="must not contain an NID"):
        load_internal_catalog(catalog)


def test_unverified_internal_entry_may_have_no_size(tmp_path: Path) -> None:
    catalog = tmp_path / "internal.json"
    _write_catalog(
        catalog,
        [_entry("EBOOT", "0x40000", 0, boundary_status="UNVERIFIED")],
    )

    functions = load_internal_catalog(catalog)
    assert len(functions) == 1
    assert functions[0].boundary_status == "UNVERIFIED"


def test_ghidra_enumeration_parser_requires_consistent_bounded_markers() -> None:
    rows = [
        {
            "module": "EBOOT",
            "address": "0x1000",
            "size_bytes": 16,
            "instruction_count": 4,
            "calls": ["0x1100"],
            "data_reference_count": 0,
            "boundary_hint": "CONTIGUOUS",
        },
        {
            "module": "EBOOT",
            "address": "0x1100",
            "size_bytes": 12,
            "instruction_count": 3,
            "calls": [],
            "data_reference_count": 0,
            "boundary_hint": "CONTIGUOUS",
        },
    ]
    output = "\n".join(
        [
            "INFO SetoEnumerateFunctions.java> SETO_ENUMERATION_BEGIN module=EBOOT total=5000 limit=4096 (GhidraScript)",
            *("INFO SetoEnumerateFunctions.java> SETO_FUNCTION_JSON=" + json.dumps(row) + " (GhidraScript)" for row in rows),
            "INFO SetoEnumerateFunctions.java> SETO_ENUMERATION_END module=EBOOT emitted=2 total=5000 truncated=true (GhidraScript)",
        ]
    )

    manifest = parse_ghidra_enumeration(output)

    assert manifest.module == "EBOOT"
    assert manifest.total_functions == 5000
    assert manifest.truncated is True
    assert [row.address for row in manifest.functions] == [0x1000, 0x1100]
    assert manifest.functions[0].calls == (0x1100,)


def test_ghidra_enumeration_parser_rejects_inconsistent_output() -> None:
    output = "\n".join(
        [
            "SETO_ENUMERATION_BEGIN module=EBOOT total=1 limit=8",
            "SETO_FUNCTION_JSON={broken}",
            "SETO_ENUMERATION_END module=EBOOT emitted=1 total=1 truncated=false",
        ]
    )

    with pytest.raises(ValueError, match="invalid function JSON"):
        parse_ghidra_enumeration(output)


def test_ghidra_enumeration_rejects_overlapping_contiguous_ranges() -> None:
    rows = [
        {
            "module": "EBOOT",
            "address": "0x1000",
            "size_bytes": 16,
            "instruction_count": 4,
            "calls": [],
            "data_reference_count": 0,
            "boundary_hint": "CONTIGUOUS",
        },
        {
            "module": "EBOOT",
            "address": "0x100c",
            "size_bytes": 8,
            "instruction_count": 2,
            "calls": [],
            "data_reference_count": 0,
            "boundary_hint": "CONTIGUOUS",
        },
    ]
    output = "\n".join(
        [
            "SETO_ENUMERATION_BEGIN module=EBOOT total=2 limit=8",
            *("SETO_FUNCTION_JSON=" + json.dumps(row) for row in rows),
            "SETO_ENUMERATION_END module=EBOOT emitted=2 total=2 truncated=false",
        ]
    )

    with pytest.raises(ValueError, match="overlapping contiguous function ranges"):
        parse_ghidra_enumeration(output)


def test_function_manifest_serialization_is_deterministic_and_idempotent(tmp_path: Path) -> None:
    rows = [
        {
            "module": "EBOOT",
            "address": "0x1000",
            "size_bytes": 12,
            "instruction_count": 3,
            "calls": ["0x1020"],
            "data_reference_count": 0,
            "boundary_hint": "CONTIGUOUS",
        }
    ]
    output = "\n".join(
        [
            "SETO_ENUMERATION_BEGIN module=EBOOT total=1 limit=8",
            "SETO_FUNCTION_JSON=" + json.dumps(rows[0]),
            "SETO_ENUMERATION_END module=EBOOT emitted=1 total=1 truncated=false",
        ]
    )
    manifest = parse_ghidra_enumeration(output)
    path = tmp_path / "build" / "manifest.json"

    digest = write_function_manifest(path, manifest)

    assert digest == write_function_manifest(path, manifest)
    assert path.read_text(encoding="utf-8") == serialize_function_manifest(manifest)
    assert json.loads(path.read_text(encoding="utf-8"))["functions"][0]["address"] == "0x1000"
    assert load_function_manifest(path) == manifest
    path.write_text("different\n", encoding="utf-8")
    with pytest.raises(ValueError, match="refusing to overwrite"):
        write_function_manifest(path, manifest)


def test_checked_in_internal_catalog_has_verified_31308_and_no_fake_nids() -> None:
    catalog = Path(__file__).resolve().parents[1] / "config" / "decomp_internal_inventory.json"

    functions = load_internal_catalog(catalog)

    helper = next(item for item in functions if internal_function_key(item) == ("eboot", 0x31308))
    assert helper.size_bytes == 92
    assert helper.boundary_status == "EXACT"
    assert helper.kind == "code"
    assert helper.section == ".text"


def test_import_stubs_are_technical_matches_not_decompiled_code() -> None:
    repo = Path(__file__).resolve().parents[1]
    document = json.loads(
        (repo / "config" / "decomp_internal_inventory.json").read_text(encoding="utf-8")
    )

    tutorial_stub = next(
        entry
        for entry in document["functions"]
        if entry["module"] == "libtutoriallist.prx" and entry["address"] == "0x3790"
    )
    html_stub = next(
        entry
        for entry in document["functions"]
        if entry["module"] == "libhtml_view.prx" and entry["address"] == "0x2ef4"
    )

    assert tutorial_stub["kind"] == html_stub["kind"] == "import_stub"
    assert tutorial_stub["section"] == html_stub["section"] == ".sceStub.text"
    assert not counts_as_decompiled_code(tutorial_stub)
    assert not counts_as_decompiled_code(html_stub)
    assert counts_as_decompiled_code(
        next(entry for entry in document["functions"] if entry["address"] == "0x31308")
    )

    export_metrics = {
        "eboot_matched_functions": 16,
        "eboot_matched_instructions": 368,
        "prx_matched_functions": 16,
        "prx_matched_instructions": 912,
    }
    metrics = internal_catalog_metrics(document["functions"], export_metrics)
    expected_code_instructions = sum(
        entry["instruction_count"]
        for entry in document["functions"]
        if counts_as_decompiled_code(entry)
    )
    expected_import_stub_instructions = sum(
        entry["instruction_count"]
        for entry in document["functions"]
        if entry["kind"] == "import_stub" and entry["result"]["status"] == "MATCHED"
    )
    expected_code_instructions += (
        export_metrics["eboot_matched_instructions"]
        + export_metrics["prx_matched_instructions"]
    )
    assert metrics["code_matched_instructions"] >= 3000
    assert metrics["code_matched_instructions"] == expected_code_instructions
    assert metrics["import_stub_matched_instructions"] == 184
    assert metrics["import_stub_matched_instructions"] == expected_import_stub_instructions
    assert metrics["technical_matched_instructions"] == (
        expected_code_instructions + expected_import_stub_instructions
    )


def test_import_stub_cannot_claim_code_section_or_eboot_identity(tmp_path: Path) -> None:
    catalog = tmp_path / "internal.json"
    entry = _entry("EBOOT", "0x31308", 92)
    entry.update({"section": ".sceStub.text", "kind": "code"})
    _write_catalog(catalog, [entry])

    with pytest.raises(ValueError, match="section disagrees with module address range"):
        load_internal_catalog(catalog)


def test_every_catalogued_internal_match_has_two_full_identical_build_hashes() -> None:
    repo = Path(__file__).resolve().parents[1]
    catalog_path = repo / "config" / "decomp_internal_inventory.json"
    document = json.loads(catalog_path.read_text(encoding="utf-8"))
    matched = [
        entry
        for entry in document["functions"]
        if entry.get("result", {}).get("status") == "MATCHED"
    ]

    assert matched
    for entry in matched:
        result = entry["result"]
        assert entry["boundary_status"] == "EXACT"
        assert result["matching_words"] == result["total_words"] == entry["size_bytes"] // 4
        assert len(result["object_sha256s"]) == 2
        assert result["object_sha256s"][0] == result["object_sha256s"][1]
        assert all(
            len(digest) == 64 and all(char in "0123456789abcdef" for char in digest)
            for digest in result["object_sha256s"]
        )
        assert "certificate_path" in result and "certificate_sha256" in result
        source = repo / entry["source_path"]
        assert hashlib.sha256(source.read_bytes()).hexdigest() == entry["source_sha256"]


def test_internal_discovery_ranks_matched_export_callees_without_promoting_hints() -> None:
    rows = [
        {
            "module": "EBOOT",
            "address": "0x1000",
            "size_bytes": 16,
            "instruction_count": 4,
            "calls": ["0x1100"],
            "data_reference_count": 0,
            "boundary_hint": "CONTIGUOUS",
        },
        {
            "module": "EBOOT",
            "address": "0x1100",
            "size_bytes": 16,
            "instruction_count": 4,
            "calls": [],
            "data_reference_count": 0,
            "boundary_hint": "CONTIGUOUS",
        },
        {
            "module": "EBOOT",
            "address": "0x1200",
            "size_bytes": 8,
            "instruction_count": 2,
            "calls": [],
            "data_reference_count": 0,
            "boundary_hint": "CONTIGUOUS",
        },
        {
            "module": "EBOOT",
            "address": "0x1300",
            "size_bytes": 24,
            "instruction_count": 6,
            "calls": [],
            "data_reference_count": 1,
            "boundary_hint": "CONTIGUOUS",
        },
        {
            "module": "EBOOT",
            "address": "0x1400",
            "size_bytes": 16,
            "instruction_count": 4,
            "calls": [],
            "data_reference_count": 0,
            "boundary_hint": "MULTIRANGE_OR_GAPPED",
        },
        {
            "module": "EBOOT",
            "address": "0x1500",
            "size_bytes": 8,
            "instruction_count": 2,
            "calls": [],
            "data_reference_count": 0,
            "boundary_hint": "CONTIGUOUS",
        },
    ]
    output = "\n".join(
        [
            "SETO_ENUMERATION_BEGIN module=EBOOT total=6 limit=32",
            *("SETO_FUNCTION_JSON=" + json.dumps(row) for row in rows),
            "SETO_ENUMERATION_END module=EBOOT emitted=6 total=6 truncated=false",
        ]
    )
    manifest = parse_ghidra_enumeration(output)

    candidates = select_internal_discoveries(
        manifest,
        known_exports={("EBOOT", 0x1000)},
        known_internal=(InternalFunction("EBOOT", 0x1500, 8, "EXACT", "docs/known.md"),),
        calls_from_matched_exports={("EBOOT", 0x1100)},
        evidence_path="build/seto049/function-manifests/EBOOT.json",
    )

    assert [internal_function_key(item) for item in candidates] == [
        ("eboot", 0x1100),
        ("eboot", 0x1300),
        ("eboot", 0x1200),
    ]
    assert [item.priority for item in candidates] == [3, 2, 1]
    assert all(item.boundary_status == "UNVERIFIED" for item in candidates)
    assert all(item.evidence_path.endswith("EBOOT.json") for item in candidates)


def test_internal_discovery_excludes_ranges_not_just_known_entry_addresses() -> None:
    manifest = FunctionManifest(
        "EBOOT",
        1,
        8,
        False,
        (DiscoveredFunction("EBOOT", 0x1008, 8, 2, (), 0, "CONTIGUOUS"),),
    )

    candidates = select_internal_discoveries(
        manifest,
        known_exports=set(),
        known_internal=(),
        calls_from_matched_exports=(),
        evidence_path="build/seto049/functions.json",
        known_exact_ranges={("EBOOT", 0x1000, 16)},
    )

    assert candidates == ()


def test_internal_match_requires_two_full_identical_builds() -> None:
    from decomp_campaign import is_deterministic_match

    def report(object_sha: str) -> dict[str, object]:
        return {
            "status": "MATCHED",
            "verified_decompilation": True,
            "evidence": "compiled-object",
            "address": "0x2bd58",
            "symbol": "func_0002BD58",
            "provenance": {
                "source_sha256": "a" * 64,
                "object_sha256": object_sha,
                "compiler": "/tools/mwccpsp.exe",
                "flags": ["-O4,p", "-sdatathreshold", "0"],
            },
            "match": {
                "status": "MATCHED",
                "matching_words": 7,
                "total_words": 7,
                "difference_count": 0,
                "differences": [],
                "limitations": [],
                "relocation_issues": [],
            },
        }

    digest = "b" * 64
    result = {
        "status": "MATCHED",
        "source_sha256": "a" * 64,
        "build_sha256": [digest, digest],
        "reports": [report(digest), report(digest)],
    }

    assert is_deterministic_match(result, expected_address=0x2BD58, expected_size=28)
    result["reports"] = [report(digest)]
    assert not is_deterministic_match(result, expected_address=0x2BD58, expected_size=28)


def _matcher_report(
    *, address: int, size_bytes: int, source: str, source_sha256: str, object_sha256: str
) -> dict[str, object]:
    symbol = f"func_{address:08X}"
    return {
        "address": f"0x{address:x}",
        "equivalence": "binary equality of the compared range",
        "evidence": "compiled-object",
        "exit_code": 0,
        "function": symbol,
        "provenance": {
            "compiler": "/tools/mwccpsp.exe",
            "flags": ["-O4,p", "-sdatathreshold", "0"],
            "includes": ["decomp/include"],
            "source": source,
            "source_sha256": source_sha256,
            "object": f"build/objects/{object_sha256}.o",
            "object_sha256": object_sha256,
        },
        "section": ".text",
        "status": "MATCHED",
        "symbol": symbol,
        "verified_decompilation": True,
        "match": {
            "status": "MATCHED",
            "address": address,
            "matching_words": size_bytes // 4,
            "total_words": size_bytes // 4,
            "difference_count": 0,
            "differences": [],
            "limitations": [],
            "relocation_issues": [],
            "resolved_calls": [],
            "resolved_data": [],
        },
    }


def _certificate_fixture(tmp_path: Path) -> tuple[Path, Path, Path, dict[str, object]]:
    source = tmp_path / "decomp" / "src" / "eboot" / "func_00001000.c"
    source.parent.mkdir(parents=True)
    source.write_text("int func_00001000(void) { return 0; }\n", encoding="utf-8")
    source_sha256 = hashlib.sha256(source.read_bytes()).hexdigest()
    object_sha256 = "c" * 64
    reports = []
    for index in (1, 2):
        payload = _matcher_report(
            address=0x1000,
            size_bytes=8,
            source="decomp/src/eboot/func_00001000.c",
            source_sha256=source_sha256,
            object_sha256=object_sha256,
        )
        payload["provenance"]["object"] = f"build/objects/verify-{index}.o"
        report = tmp_path / "build" / "reports" / f"verify-{index}.json"
        report.parent.mkdir(parents=True, exist_ok=True)
        report.write_text(json.dumps(payload), encoding="utf-8")
        reports.append(report)
    return source, reports[0], reports[1], {"object_sha256": object_sha256}


def test_internal_certificate_is_deterministic_across_two_identical_builds(
    tmp_path: Path,
) -> None:
    from internal_functions import build_internal_certificate, serialize_internal_certificate

    source, first, second, fixture = _certificate_fixture(tmp_path)

    document, digest = build_internal_certificate(
        module="EBOOT",
        address=0x1000,
        size_bytes=8,
        source_path=source,
        report_paths=[first, second],
        repo_root=tmp_path,
    )

    assert document["deterministic_match"] is True
    assert document["independent_builds"] == 2
    assert document["build_sha256"] == [fixture["object_sha256"]] * 2
    assert document["source_path"] == "decomp/src/eboot/func_00001000.c"
    assert digest == hashlib.sha256(
        serialize_internal_certificate(document).encode("utf-8")
    ).hexdigest()
    assert build_internal_certificate(
        module="EBOOT",
        address=0x1000,
        size_bytes=8,
        source_path=source,
        report_paths=[first, second],
        repo_root=tmp_path,
    )[1] == digest


def test_internal_certificate_rejects_divergent_or_stale_evidence(tmp_path: Path) -> None:
    from internal_functions import build_internal_certificate

    source, first, second, fixture = _certificate_fixture(tmp_path)
    source_sha256 = hashlib.sha256(source.read_bytes()).hexdigest()

    divergent = json.loads(second.read_text(encoding="utf-8"))
    divergent["provenance"]["object_sha256"] = "d" * 64
    second.write_text(json.dumps(divergent), encoding="utf-8")
    with pytest.raises(ValueError, match="different objects"):
        build_internal_certificate(
            module="EBOOT",
            address=0x1000,
            size_bytes=8,
            source_path=source,
            report_paths=[first, second],
            repo_root=tmp_path,
        )

    stale = json.loads(first.read_text(encoding="utf-8"))
    stale["provenance"]["source_sha256"] = "e" * 64
    first.write_text(json.dumps(stale), encoding="utf-8")
    with pytest.raises(ValueError, match="different source"):
        build_internal_certificate(
            module="EBOOT",
            address=0x1000,
            size_bytes=8,
            source_path=source,
            report_paths=[first, second],
            repo_root=tmp_path,
        )

    first.write_text(
        json.dumps(
            _matcher_report(
                address=0x1000,
                size_bytes=8,
                source="decomp/src/eboot/func_00001000.c",
                source_sha256=source_sha256,
                object_sha256=str(fixture["object_sha256"]),
            )
        ),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="two independent matcher reports"):
        build_internal_certificate(
            module="EBOOT",
            address=0x1000,
            size_bytes=8,
            source_path=source,
            report_paths=[first],
            repo_root=tmp_path,
        )


def test_internal_certificate_writer_refuses_conflicting_content(tmp_path: Path) -> None:
    from internal_functions import (
        build_internal_certificate,
        write_internal_certificate,
    )

    source, first, second, _ = _certificate_fixture(tmp_path)
    document, digest = build_internal_certificate(
        module="EBOOT",
        address=0x1000,
        size_bytes=8,
        source_path=source,
        report_paths=[first, second],
        repo_root=tmp_path,
    )
    path = Path("build/certificates/eboot-00001000.json")

    assert write_internal_certificate(path, document, repo_root=tmp_path) == digest
    assert write_internal_certificate(path, document, repo_root=tmp_path) == digest
    with pytest.raises(ValueError, match="repository-relative"):
        write_internal_certificate(
            tmp_path / "build" / "certificates" / "absolute.json",
            document,
            repo_root=tmp_path,
        )
    with pytest.raises(ValueError, match="non-traversing"):
        write_internal_certificate(Path("../escape.json"), document, repo_root=tmp_path)
    alias = tmp_path / "build" / "certificates" / "alias.json"
    try:
        alias.symlink_to((tmp_path / path), target_is_directory=False)
    except (OSError, NotImplementedError):
        pass
    else:
        with pytest.raises(ValueError, match="symlink"):
            write_internal_certificate(
                Path("build/certificates/alias.json"), document, repo_root=tmp_path
            )
    (tmp_path / path).write_text("different\n", encoding="utf-8")
    with pytest.raises(ValueError, match="refusing to overwrite"):
        write_internal_certificate(path, document, repo_root=tmp_path)


def test_catalog_evidence_validation_requires_certificate_coverage(tmp_path: Path) -> None:
    from internal_functions import (
        build_internal_certificate,
        serialize_internal_certificate,
        validate_internal_catalog_evidence,
        write_internal_certificate,
    )

    source, first, second, fixture = _certificate_fixture(tmp_path)
    document, digest = build_internal_certificate(
        module="EBOOT",
        address=0x1000,
        size_bytes=8,
        source_path=source,
        report_paths=[first, second],
        repo_root=tmp_path,
    )
    certificate_relative = Path("build/certificates/eboot-00001000.json")
    certificate = tmp_path / certificate_relative
    write_internal_certificate(certificate_relative, document, repo_root=tmp_path)
    entry = _entry("EBOOT", "0x1000", 8)
    entry.update(
        {
            "source_path": "decomp/src/eboot/func_00001000.c",
            "source_sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
            "result": {
                "status": "MATCHED",
                "matching_words": 2,
                "total_words": 2,
                "object_sha256s": [fixture["object_sha256"]] * 2,
                "certificate_path": "build/certificates/eboot-00001000.json",
                "certificate_sha256": digest,
            },
        }
    )
    catalog = tmp_path / "config" / "decomp_internal_inventory.json"
    catalog.parent.mkdir(parents=True)
    _write_catalog(catalog, [entry])

    assert validate_internal_catalog_evidence(
        catalog,
        repo_root=tmp_path,
        require_tracked_sources=False,
        check_export_overlaps=False,
    ) == ()

    original_certificate = certificate.read_bytes()
    tampered = json.loads(original_certificate)
    tampered["reports"][0]["match"]["limitations"] = ["comparison was incomplete"]
    tampered_bytes = serialize_internal_certificate(tampered).encode("utf-8")
    certificate.write_bytes(tampered_bytes)
    entry["result"]["certificate_sha256"] = hashlib.sha256(tampered_bytes).hexdigest()
    _write_catalog(catalog, [entry])
    problems = validate_internal_catalog_evidence(
        catalog,
        repo_root=tmp_path,
        require_tracked_sources=False,
        check_export_overlaps=False,
    )
    assert any("production strict-match gate" in problem for problem in problems)

    tampered["reports"][0]["match"]["limitations"] = []
    tampered["reports"][1]["provenance"]["object_sha256"] = "d" * 64
    tampered_bytes = serialize_internal_certificate(tampered).encode("utf-8")
    certificate.write_bytes(tampered_bytes)
    entry["result"]["certificate_sha256"] = hashlib.sha256(tampered_bytes).hexdigest()
    _write_catalog(catalog, [entry])
    problems = validate_internal_catalog_evidence(
        catalog,
        repo_root=tmp_path,
        require_tracked_sources=False,
        check_export_overlaps=False,
    )
    assert any("deterministic-match gate" in problem for problem in problems)

    certificate.write_bytes(original_certificate)
    entry["result"]["certificate_sha256"] = digest
    entry["result"]["certificate_path"] = "../escape.json"
    _write_catalog(catalog, [entry])
    problems = validate_internal_catalog_evidence(
        catalog,
        repo_root=tmp_path,
        mode="metadata-only",
        require_tracked_sources=False,
        check_export_overlaps=False,
    )
    assert any("unsafe certificate path" in problem for problem in problems)
    entry["result"]["certificate_path"] = "build/certificates/eboot-00001000.json"
    _write_catalog(catalog, [entry])

    entry["result"]["certificate_path"] = "build/certificates/missing.json"
    _write_catalog(catalog, [entry])
    problems = validate_internal_catalog_evidence(
        catalog,
        repo_root=tmp_path,
        require_tracked_sources=False,
        check_export_overlaps=False,
    )
    assert len(problems) == 1
    assert "certificate is missing" in problems[0]

    entry["result"].pop("certificate_path")
    _write_catalog(catalog, [entry])
    problems = validate_internal_catalog_evidence(
        catalog,
        repo_root=tmp_path,
        require_tracked_sources=False,
        check_export_overlaps=False,
    )
    assert len(problems) == 1
    assert "has no certificate" in problems[0]
