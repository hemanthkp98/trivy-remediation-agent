"""
Parse Trivy JSON v2 vulnerability reports.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

# Map severity labels to numeric order for filtering
SEVERITY_ORDER: dict[str, int] = {
    "CRITICAL": 4,
    "HIGH": 3,
    "MEDIUM": 2,
    "LOW": 1,
    "UNKNOWN": 0,
}


@dataclass
class Vulnerability:
    vuln_id: str
    pkg_name: str
    installed_version: str
    fixed_version: Optional[str]
    severity: str
    title: str
    description: str
    target: str
    target_class: str   # e.g. "os-pkgs", "lang-pkgs"
    target_type: str    # e.g. "debian", "pip", "npm", "gomod"
    references: list[str] = field(default_factory=list)

    @property
    def is_fixable(self) -> bool:
        return bool(self.fixed_version and self.fixed_version.strip())

    @property
    def severity_level(self) -> int:
        return SEVERITY_ORDER.get(self.severity.upper(), 0)


@dataclass
class VulnerabilityReport:
    artifact_name: str
    vulnerabilities: list[Vulnerability]

    def filter_by_severity(self, min_severity: str) -> list[Vulnerability]:
        """Return fixable vulnerabilities at or above min_severity."""
        threshold = SEVERITY_ORDER.get(min_severity.upper(), 0)
        return [
            v for v in self.vulnerabilities
            if v.severity_level >= threshold and v.is_fixable
        ]

    def group_by_target(
        self, vulns: Optional[list[Vulnerability]] = None
    ) -> dict[tuple[str, str, str], list[Vulnerability]]:
        """Group vulnerabilities by (target, class, type)."""
        source = vulns if vulns is not None else self.vulnerabilities
        groups: dict[tuple[str, str, str], list[Vulnerability]] = {}
        for v in source:
            key = (v.target, v.target_class, v.target_type)
            groups.setdefault(key, []).append(v)
        return groups

    @property
    def total_count(self) -> int:
        return len(self.vulnerabilities)

    @property
    def fixable_count(self) -> int:
        return sum(1 for v in self.vulnerabilities if v.is_fixable)


class ReportParser:
    """Parse a Trivy JSON report (schema version 2) into a VulnerabilityReport."""

    @staticmethod
    def parse(report_path: str | Path) -> VulnerabilityReport:
        path = Path(report_path)
        if not path.exists():
            raise FileNotFoundError(f"Trivy report not found: {path}")

        with path.open() as fh:
            data = json.load(fh)

        schema = data.get("SchemaVersion", 0)
        if schema not in (2, 0):  # 0 = older format that still works
            raise ValueError(f"Unsupported Trivy schema version: {schema}")

        artifact_name = data.get("ArtifactName", "unknown")
        vulnerabilities: list[Vulnerability] = []

        for result in data.get("Results") or []:
            target = result.get("Target", "")
            target_class = result.get("Class", "")
            target_type = result.get("Type", "")

            for raw in result.get("Vulnerabilities") or []:
                description = raw.get("Description", "")
                # Truncate long descriptions to keep the LLM prompt concise
                if len(description) > 600:
                    description = description[:597] + "..."

                vulnerabilities.append(
                    Vulnerability(
                        vuln_id=raw.get("VulnerabilityID", "N/A"),
                        pkg_name=raw.get("PkgName", ""),
                        installed_version=raw.get("InstalledVersion", ""),
                        fixed_version=raw.get("FixedVersion") or None,
                        severity=raw.get("Severity", "UNKNOWN"),
                        title=raw.get("Title", ""),
                        description=description,
                        target=target,
                        target_class=target_class,
                        target_type=target_type,
                        references=(raw.get("References") or [])[:3],
                    )
                )

        return VulnerabilityReport(
            artifact_name=artifact_name,
            vulnerabilities=vulnerabilities,
        )
