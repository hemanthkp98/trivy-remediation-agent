import unittest
import tempfile
import shutil
from pathlib import Path
from src.patcher import Patcher
from src.llm_analyzer import FileChange, RemediationPlan


class TestPatcherResilience(unittest.TestCase):
    def setUp(self):
        self.temp_dir = Path(tempfile.mkdtemp())
        self.patcher = Patcher(self.temp_dir)

    def tearDown(self):
        shutil.rmtree(self.temp_dir)

    def test_exact_match(self):
        file_path = self.temp_dir / "Dockerfile"
        file_content = "FROM python:3.9-slim\nRUN pip install urllib3==1.26.5\n"
        file_path.write_text(file_content)

        change = FileChange(
            file_path="Dockerfile",
            search="RUN pip install urllib3==1.26.5",
            replacement="RUN pip install urllib3==1.26.18",
            cves=["CVE-2023-37895"],
            reasoning="Upgrade to fixed version"
        )
        plan = RemediationPlan(changes=[change], summary="Test plan")

        result = self.patcher.apply(plan)
        self.assertIn("Dockerfile", result.applied)
        self.assertEqual(len(result.skipped), 0)
        self.assertEqual(
            file_path.read_text(),
            "FROM python:3.9-slim\nRUN pip install urllib3==1.26.18\n"
        )

    def test_resilient_whitespace_match(self):
        file_path = self.temp_dir / "Dockerfile"
        # File has lots of spaces and a newline in pip install command
        file_content = "FROM python:3.9-slim\nRUN    pip    install   \\\n   urllib3==1.26.5\n"
        file_path.write_text(file_content)

        # LLM output has standard formatting: "RUN pip install urllib3==1.26.5"
        change = FileChange(
            file_path="Dockerfile",
            search="RUN pip install urllib3==1.26.5",
            replacement="RUN pip install urllib3==1.26.18",
            cves=["CVE-2023-37895"],
            reasoning="Upgrade to fixed version"
        )
        plan = RemediationPlan(changes=[change], summary="Test plan")

        result = self.patcher.apply(plan)
        self.assertIn("Dockerfile", result.applied)
        self.assertEqual(len(result.skipped), 0)
        self.assertEqual(
            file_path.read_text(),
            "FROM python:3.9-slim\nRUN pip install urllib3==1.26.18\n"
        )


if __name__ == "__main__":
    unittest.main()
