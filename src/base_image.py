"""
Base image parsing and root-cause upgrade-suggestion engine.

Parses Dockerfile ``FROM`` lines, correlates them with Trivy OS vulnerability
targets, and suggests safe, offline tag upgrades so that outdated OS package
CVEs can be resolved by bumping the base image tag instead of pinning
individual packages.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from packaging.version import InvalidVersion, Version

# Matches: FROM [--platform=...] <image>[:<tag>] [AS <stage>]
FROM_PATTERN = re.compile(
    r"^FROM\s+(?:--platform=\S+\s+)?([^\s:]+)(?::([^\s]+))?(?:\s+AS\s+([^\s]+))?",
    re.IGNORECASE | re.MULTILINE,
)

PLATFORM_PATTERN = re.compile(r"--platform=(\S+)", re.IGNORECASE)

# Leading numeric semantic version at the start of a tag, e.g. "3.9.12" in
# "3.9.12-slim" or "18.15.0" in "18.15.0-alpine3.17".
TAG_VERSION_PATTERN = re.compile(r"^(\d+(?:\.\d+){0,2})(.*)$")

# Offline, deterministic "patch upgrade" candidates: (image, "major.minor") ->
# latest known-good patch release within that minor family. Extend as needed;
# no live network/registry access is ever performed.
KNOWN_PATCH_CANDIDATES: dict[tuple[str, str], str] = {
    ("python", "3.8"): "3.8.20",
    ("python", "3.9"): "3.9.21",
    ("python", "3.10"): "3.10.16",
    ("python", "3.11"): "3.11.11",
    ("python", "3.12"): "3.12.8",
    ("node", "16"): "16.20.2",
    ("node", "18"): "18.20.7",
    ("node", "20"): "20.18.1",
    ("alpine", "3.16"): "3.16.9",
    ("alpine", "3.17"): "3.17.10",
    ("alpine", "3.18"): "3.18.9",
    ("alpine", "3.19"): "3.19.4",
}

# Offline "minor upgrade" candidates: (image, major) -> latest known-good
# major.minor.patch release for that major version line.
KNOWN_MINOR_CANDIDATES: dict[tuple[str, str], str] = {
    ("python", "3"): "3.12.8",
    ("node", "18"): "18.20.7",
    ("node", "20"): "20.18.1",
    ("alpine", "3"): "3.19.4",
}

# End-of-life Debian/Ubuntu codenames -> modern supported codename.
CODENAME_REFRESH: dict[str, str] = {
    "stretch": "bullseye",
    "buster": "bullseye",
    "bullseye": "bookworm",
    "xenial": "focal",
    "bionic": "focal",
    "focal": "jammy",
}


@dataclass
class BaseImageRef:
    raw_line: str
    image: str
    tag: str
    stage: str | None = None
    platform: str | None = None


@dataclass
class UpgradeCandidate:
    old_tag: str
    new_tag: str
    strategy: str  # "patch" | "codename"
    reasoning: str


class BaseImageParser:
    """Inspects Dockerfile content and extracts structured FROM references."""

    @staticmethod
    def parse(dockerfile_content: str) -> list[BaseImageRef]:
        refs: list[BaseImageRef] = []
        for line in dockerfile_content.splitlines():
            stripped = line.strip()
            match = FROM_PATTERN.match(stripped)
            if not match:
                continue
            image, tag, stage = match.groups()
            platform_match = PLATFORM_PATTERN.search(stripped)
            refs.append(
                BaseImageRef(
                    raw_line=stripped,
                    image=image,
                    tag=tag or "latest",
                    stage=stage,
                    platform=platform_match.group(1) if platform_match else None,
                )
            )
        return refs

    @staticmethod
    def find_for_target(refs: list[BaseImageRef], target: str) -> BaseImageRef | None:
        """
        Correlate a Trivy ``Target`` string (e.g. "python:3.9.12-slim (debian
        11.6)") with the matching Dockerfile FROM ref.
        """
        image_tag = target.split(" ", 1)[0].strip()
        if ":" in image_tag:
            image, tag = image_tag.split(":", 1)
        else:
            image, tag = image_tag, "latest"

        for ref in refs:
            if ref.image == image and ref.tag == tag:
                return ref
        for ref in refs:
            if ref.image == image:
                return ref
        return None


def _split_tag(tag: str) -> tuple[str | None, str]:
    """Split a tag like "3.9.12-slim" into ("3.9.12", "-slim")."""
    match = TAG_VERSION_PATTERN.match(tag)
    if not match:
        return None, ""
    return match.group(1), match.group(2)


def _minor_family(version: str) -> str | None:
    parts = version.split(".")
    if len(parts) < 2:
        return None
    return f"{parts[0]}.{parts[1]}"


def _is_newer(candidate: str, current: str) -> bool:
    try:
        return Version(candidate) > Version(current)
    except InvalidVersion:
        return False


def _normalize_image_name(image: str) -> str:
    if image.startswith("library/"):
        return image.split("/", 1)[1]
    return image


class BaseImageResolver:
    """
    Evaluates potential safe upgrade candidates for known official base
    images using a fully offline candidate table, so unit tests and
    air-gapped environments produce deterministic results.
    """

    def __init__(
        self,
        strategy: str = "patch",
        patch_candidates: dict[tuple[str, str], str] | None = None,
        minor_candidates: dict[tuple[str, str], str] | None = None,
        codename_refresh: dict[str, str] | None = None,
    ) -> None:
        self.strategy = strategy
        self.patch_candidates = (
            patch_candidates if patch_candidates is not None else KNOWN_PATCH_CANDIDATES
        )
        self.minor_candidates = (
            minor_candidates if minor_candidates is not None else KNOWN_MINOR_CANDIDATES
        )
        self.codename_refresh = (
            codename_refresh if codename_refresh is not None else CODENAME_REFRESH
        )

    def suggest(self, ref: BaseImageRef) -> UpgradeCandidate | None:
        """Suggest a safe tag upgrade for the given base image reference, if any."""
        image = _normalize_image_name(ref.image)
        version, variant = _split_tag(ref.tag)

        if version:
            family_key: tuple[str, str] | None = None
            candidate_map = self.patch_candidates
            if self.strategy == "minor":
                candidate_map = self.minor_candidates
                family_key = (image, version.split(".")[0])
            else:
                family = _minor_family(version)
                if family:
                    family_key = (image, family)

            if family_key:
                candidate_version = candidate_map.get(family_key)
                if candidate_version and _is_newer(candidate_version, version):
                    new_tag = f"{candidate_version}{variant}"
                    return UpgradeCandidate(
                        old_tag=ref.tag,
                        new_tag=new_tag,
                        strategy="patch",
                        reasoning=(
                            f"Upgrade {ref.image} base image tag from {ref.tag} to "
                            f"{new_tag} to pick up upstream OS security patches."
                        ),
                    )

        codename_match = self._match_codename(ref.tag)
        if codename_match:
            old_codename, new_codename = codename_match
            new_tag = re.sub(
                rf"(?<![a-z0-9]){re.escape(old_codename)}(?![a-z0-9])",
                new_codename,
                ref.tag,
                flags=re.IGNORECASE,
            )
            return UpgradeCandidate(
                old_tag=ref.tag,
                new_tag=new_tag,
                strategy="codename",
                reasoning=(
                    f"Refresh end-of-life distribution codename '{old_codename}' to "
                    f"'{new_codename}' in the {ref.image} base image tag."
                ),
            )

        return None

    def _match_codename(self, tag: str) -> tuple[str, str] | None:
        for old, new in self.codename_refresh.items():
            if re.search(
                rf"(?<![a-z0-9]){re.escape(old)}(?![a-z0-9])", tag, re.IGNORECASE
            ):
                return old, new
        return None
