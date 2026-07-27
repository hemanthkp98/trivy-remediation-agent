import unittest
import tempfile
import shutil
from pathlib import Path
from unittest.mock import MagicMock, patch
from src.orchestrator import Orchestrator
from src.llm_analyzer import RemediationPlan, FileChange


class TestVerificationLoop(unittest.TestCase):
    def setUp(self):
        self.temp_dir = Path(tempfile.mkdtemp())
        
        # Create a mock report path
        self.report_path = Path(__file__).parent / "fixtures" / "sample_trivy_report.json"
        
        # Create a dummy requirements.txt in temp_dir
        self.req_file = self.temp_dir / "requirements.txt"
        self.req_file.write_text("setuptools==65.5.0\n")

    def tearDown(self):
        shutil.rmtree(self.temp_dir)

    @patch("src.orchestrator.LLMAnalyzer")
    def test_verification_success(self, MockLLMAnalyzer):
        # Mock LLM response
        mock_analyzer = MagicMock()
        MockLLMAnalyzer.return_value = mock_analyzer

        initial_plan = RemediationPlan(
            changes=[
                FileChange(
                    file_path="requirements.txt",
                    search="setuptools==65.5.0",
                    replacement="setuptools==65.5.1",
                    cves=["CVE-2022-40897"],
                    reasoning="Upgrade"
                )
            ],
            summary="Initial plan"
        )
        mock_analyzer.analyze.return_value = initial_plan

        config = {
            "min_severity": "HIGH",
            "dry_run": True,
            "verification": {
                "command": "python3 -c 'import os, sys; sys.exit(0 if os.path.exists(\"requirements.txt\") else 1)'",
                "max_retries": 2
            }
        }

        orchestrator = Orchestrator(config, repo_path=self.temp_dir)
        result = orchestrator.run(self.report_path)

        # Verification should succeed immediately, no correction called
        self.assertTrue(result.get("dry_run"))
        self.assertFalse(result.get("verification_failed", False))
        mock_analyzer.analyze_correction.assert_not_called()

    @patch("src.orchestrator.LLMAnalyzer")
    def test_verification_self_healing_success(self, MockLLMAnalyzer):
        mock_analyzer = MagicMock()
        MockLLMAnalyzer.return_value = mock_analyzer

        # Initial plan is broken (sets setuptools to a bad format)
        broken_plan = RemediationPlan(
            changes=[
                FileChange(
                    file_path="requirements.txt",
                    search="setuptools==65.5.0",
                    replacement="setuptools broken-format",
                    cves=["CVE-2022-40897"],
                    reasoning="Broken patch"
                )
            ],
            summary="Broken initial plan"
        )
        # Corrected plan fixes it
        corrected_plan = RemediationPlan(
            changes=[
                FileChange(
                    file_path="requirements.txt",
                    search="setuptools==65.5.0",
                    replacement="setuptools==65.5.1",
                    cves=["CVE-2022-40897"],
                    reasoning="Fixed patch"
                )
            ],
            summary="Fixed plan"
        )

        mock_analyzer.analyze.return_value = broken_plan
        mock_analyzer.analyze_correction.return_value = corrected_plan

        # Verification checks if requirements.txt has valid format (no spaces around package name unless specifiers)
        # Specifically, we verify that "broken-format" is not in requirements.txt
        config = {
            "min_severity": "HIGH",
            "dry_run": True,
            "verification": {
                "command": "python3 -c 'import sys; f=open(\"requirements.txt\").read(); sys.exit(1 if \"broken-format\" in f else 0)'",
                "max_retries": 2
            }
        }

        orchestrator = Orchestrator(config, repo_path=self.temp_dir)
        result = orchestrator.run(self.report_path)

        # Verification should fail initially, self-heal, and then succeed
        self.assertTrue(result.get("dry_run"))
        self.assertFalse(result.get("verification_failed", False))
        mock_analyzer.analyze_correction.assert_called_once()
        
        # Verify that the final file content matches corrected_plan (but wait, in dry-run it restores backups at the very end)
        # Since it is dry-run, the requirements.txt was restored back to original setuptools==65.5.0
        self.assertEqual(self.req_file.read_text(), "setuptools==65.5.0\n")

    @patch("src.orchestrator.LLMAnalyzer")
    def test_verification_failure_exhausted_retries(self, MockLLMAnalyzer):
        mock_analyzer = MagicMock()
        MockLLMAnalyzer.return_value = mock_analyzer

        broken_plan = RemediationPlan(
            changes=[
                FileChange(
                    file_path="requirements.txt",
                    search="setuptools==65.5.0",
                    replacement="setuptools broken-format",
                    cves=["CVE-2022-40897"],
                    reasoning="Broken patch"
                )
            ],
            summary="Broken initial plan"
        )

        mock_analyzer.analyze.return_value = broken_plan
        mock_analyzer.analyze_correction.return_value = broken_plan  # LLM keeps failing to fix

        # Verification always fails
        config = {
            "min_severity": "HIGH",
            "dry_run": True,
            "verification": {
                "command": "python3 -c 'import sys; sys.exit(1)'",
                "max_retries": 2
            }
        }

        orchestrator = Orchestrator(config, repo_path=self.temp_dir)
        result = orchestrator.run(self.report_path)

        # Verification fails, retries are exhausted, original file restored, orchestrator aborts
        self.assertTrue(result.get("verification_failed"))
        self.assertEqual(mock_analyzer.analyze_correction.call_count, 2)
        # Original file should be restored
        self.assertEqual(self.req_file.read_text(), "setuptools==65.5.0\n")


if __name__ == "__main__":
    unittest.main()
