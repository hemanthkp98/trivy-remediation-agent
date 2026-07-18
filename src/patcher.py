"""
Apply file changes produced by the LLM to the repository on disk.
"""
from __future__ import annotations

import shutil
from dataclasses import dataclass, field
from pathlib import Path

from .llm_analyzer import FileChange, RemediationPlan


@dataclass
class PatchResult:
    applied: list[str] = field(default_factory=list)     # relative paths of successfully patched files
    skipped: list[dict] = field(default_factory=list)    # changes that could not be applied
    backed_up: list[str] = field(default_factory=list)   # files that were backed up before patching

    @property
    def success(self) -> bool:
        return len(self.applied) > 0

    @property
    def cves_fixed(self) -> list[str]:
        return []  # populated by orchestrator after cross-referencing changes


class Patcher:
    """
    Applies a RemediationPlan's FileChange list to files on disk.

    Each FileChange uses a simple search-and-replace strategy:
      - `search`      : exact text currently in the file
      - `replacement` : text to replace it with

    A backup of each file is made before modification.
    """

    BACKUP_SUFFIX = ".trivy-backup"

    def __init__(self, repo_path: str | Path):
        self.repo_path = Path(repo_path).resolve()

    def apply(self, plan: RemediationPlan) -> PatchResult:
        result = PatchResult()

        for change in plan.changes:
            file_path = self.repo_path / change.file_path
            outcome = self._apply_change(file_path, change)

            if outcome is None:
                # Successful
                rel = str(Path(change.file_path))
                if rel not in result.applied:
                    result.applied.append(rel)
            else:
                result.skipped.append({
                    "file": change.file_path,
                    "cves": change.cves,
                    "reason": outcome,
                    "search_snippet": change.search[:120],
                })

        return result

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _apply_change(self, file_path: Path, change: FileChange) -> str | None:
        """
        Apply one FileChange.
        Returns None on success, or an error string on failure.
        """
        # If the file doesn't exist, create it (LLM might generate a new manifest)
        if not file_path.exists():
            if change.search.strip():
                return f"File does not exist and search text is non-empty: {file_path}"
            # Empty search + non-empty replacement → create the file
            file_path.parent.mkdir(parents=True, exist_ok=True)
            file_path.write_text(change.replacement)
            return None

        original = file_path.read_text(errors="replace")

        # Normalize the search string: the LLM sometimes escapes \n literally
        search_text = change.search.replace("\\n", "\n")
        replacement_text = change.replacement.replace("\\n", "\n")

        if search_text not in original:
            # Try a whitespace-normalised match as a fallback
            return (
                f"Search text not found in {file_path.name}. "
                f"Expected to find: {repr(search_text[:80])}"
            )

        # Backup before modifying
        backup = file_path.with_suffix(file_path.suffix + self.BACKUP_SUFFIX)
        shutil.copy2(file_path, backup)

        patched = original.replace(search_text, replacement_text, 1)
        file_path.write_text(patched)
        return None

    def restore_backups(self) -> None:
        """Restore all backup files (undo patches). Useful on failure."""
        for backup in self.repo_path.rglob(f"*{self.BACKUP_SUFFIX}"):
            original = backup.with_suffix("")  # strip .trivy-backup
            shutil.move(str(backup), str(original))

    def remove_backups(self) -> None:
        """Delete backup files after a successful patch cycle."""
        for backup in self.repo_path.rglob(f"*{self.BACKUP_SUFFIX}"):
            backup.unlink(missing_ok=True)
