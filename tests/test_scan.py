from __future__ import annotations

from renovate_vuln_report import Finding, findings_from_grype_json


def test_findings_from_grype_json_maps_package_fix_epss_and_kev() -> None:
    grype_json = {
        "matches": [
            {
                "vulnerability": {
                    "id": "CVE-2024-0001",
                    "severity": "High",
                    "fix": {"versions": ["1.2.3"]},
                    "epss": [{"epss": 0.91}],
                    "knownExploited": [{"cve": "CVE-2024-0001"}],
                },
                "artifact": {"name": "openssl", "version": "1.2.0"},
            }
        ]
    }

    (finding,) = findings_from_grype_json(grype_json)

    assert finding == Finding(
        vulnerability_id="CVE-2024-0001",
        severity="High",
        package_name="openssl",
        installed_version="1.2.0",
        fixed_versions=("1.2.3",),
        epss=0.91,
        kev=True,
    )
