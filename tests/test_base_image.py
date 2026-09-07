import shutil
import tempfile
import unittest
from pathlib import Path

from src.base_image import BaseImageParser, BaseImageRef, BaseImageResolver
from src.llm_analyzer import FileChange, LLMAnalyzer, RemediationPlan
from src.patcher import Patcher
from src.report_parser import Vulnerability, VulnerabilityReport


class TestBaseImageParser(unittest.TestCase):
    def test_parse_single_stage(self):
        content = "FROM python:3.9.12-slim\n\nWORKDIR /app\n"
        refs = BaseImageParser.parse(content)
        self.assertEqual(len(refs), 1)
        ref = refs[0]
        self.assertEqual(ref.image, "python")
        self.assertEqual(ref.tag, "3.9.12-slim")
        self.assertIsNone(ref.stage)
        self.assertIsNone(ref.platform)

    def test_parse_no_tag_defaults_to_latest(self):
        content = "FROM python\n"
        refs = BaseImageParser.parse(content)
        self.assertEqual(refs[0].tag, "latest")

    def test_parse_multi_stage(self):
        content = (
            "FROM golang:1.20 AS builder\n"
            "WORKDIR /src\n"
            "RUN go build -o app .\n"
            "\n"
            "FROM alpine:3.17 AS runner\n"
            "COPY --from=builder /src/app /app\n"
        )
        refs = BaseImageParser.parse(content)
        self.assertEqual(len(refs), 2)

        builder, runner = refs
        self.assertEqual(builder.image, "golang")
        self.assertEqual(builder.tag, "1.20")
        self.assertEqual(builder.stage, "builder")

        self.assertEqual(runner.image, "alpine")
        self.assertEqual(runner.tag, "3.17")
        self.assertEqual(runner.stage, "runner")

    def test_parse_platform_prefixed(self):
        content = "FROM --platform=linux/amd64 python:3.9-slim\n"
        refs = BaseImageParser.parse(content)
        self.assertEqual(len(refs), 1)
        ref = refs[0]
        self.assertEqual(ref.image, "python")
        self.assertEqual(ref.tag, "3.9-slim")
        self.assertEqual(ref.platform, "linux/amd64")

    def test_parse_platform_and_stage_combined(self):
        content = "FROM --platform=linux/arm64 node:18-alpine AS builder\n"
        refs = BaseImageParser.parse(content)
        ref = refs[0]
        self.assertEqual(ref.image, "node")
        self.assertEqual(ref.tag, "18-alpine")
        self.assertEqual(ref.stage, "builder")
        self.assertEqual(ref.platform, "linux/arm64")

    def test_parse_registry_prefixed_image(self):
        content = "FROM ghcr.io/org/repo:v1.2.3\n"
        refs = BaseImageParser.parse(content)
        self.assertEqual(refs[0].image, "ghcr.io/org/repo")
        self.assertEqual(refs[0].tag, "v1.2.3")

    def test_parse_ignores_non_from_lines(self):
        content = "WORKDIR /app\nRUN echo hi\n"
        refs = BaseImageParser.parse(content)
        self.assertEqual(refs, [])

    def test_find_for_target_exact_match(self):
        refs = BaseImageParser.parse("FROM python:3.9.12-slim\n")
        found = BaseImageParser.find_for_target(
            refs, "python:3.9.12-slim (debian 11.6)"
        )
        self.assertIsNotNone(found)
        self.assertEqual(found.tag, "3.9.12-slim")

    def test_find_for_target_image_only_fallback(self):
        refs = BaseImageParser.parse("FROM python:3.9.12-slim\n")
        found = BaseImageParser.find_for_target(refs, "python:3.9.9-slim (debian 11.3)")
        self.assertIsNotNone(found)
        self.assertEqual(found.image, "python")

    def test_find_for_target_no_match(self):
        refs = BaseImageParser.parse("FROM python:3.9.12-slim\n")
        found = BaseImageParser.find_for_target(refs, "alpine:3.17 (alpine 3.17)")
        self.assertIsNone(found)


class TestBaseImageResolverPatchStrategy(unittest.TestCase):
    def setUp(self):
        self.resolver = BaseImageResolver(strategy="patch")

    def test_python_patch_upgrade(self):
        ref = BaseImageRef(
            raw_line="FROM python:3.9.12-slim", image="python", tag="3.9.12-slim"
        )
        candidate = self.resolver.suggest(ref)
        self.assertIsNotNone(candidate)
        self.assertEqual(candidate.new_tag, "3.9.21-slim")
        self.assertEqual(candidate.strategy, "patch")

    def test_node_patch_upgrade(self):
        ref = BaseImageRef(
            raw_line="FROM node:18.14.0-alpine", image="node", tag="18.14.0-alpine"
        )
        candidate = self.resolver.suggest(ref)
        self.assertIsNotNone(candidate)
        self.assertEqual(candidate.new_tag, "18.20.7-alpine")

    def test_alpine_patch_upgrade(self):
        ref = BaseImageRef(raw_line="FROM alpine:3.17.0", image="alpine", tag="3.17.0")
        candidate = self.resolver.suggest(ref)
        self.assertIsNotNone(candidate)
        self.assertEqual(candidate.new_tag, "3.17.10")

    def test_already_up_to_date_returns_none(self):
        ref = BaseImageRef(
            raw_line="FROM python:3.9.21-slim", image="python", tag="3.9.21-slim"
        )
        candidate = self.resolver.suggest(ref)
        self.assertIsNone(candidate)

    def test_newer_than_known_candidate_returns_none(self):
        ref = BaseImageRef(
            raw_line="FROM python:3.9.99-slim", image="python", tag="3.9.99-slim"
        )
        candidate = self.resolver.suggest(ref)
        self.assertIsNone(candidate)

    def test_unknown_image_returns_none(self):
        ref = BaseImageRef(
            raw_line="FROM myco/custom:1.0.0", image="myco/custom", tag="1.0.0"
        )
        candidate = self.resolver.suggest(ref)
        self.assertIsNone(candidate)

    def test_library_prefixed_image_normalized(self):
        ref = BaseImageRef(
            raw_line="FROM library/python:3.9.12-slim",
            image="library/python",
            tag="3.9.12-slim",
        )
        candidate = self.resolver.suggest(ref)
        self.assertIsNotNone(candidate)
        self.assertEqual(candidate.new_tag, "3.9.21-slim")

    def test_codename_refresh(self):
        ref = BaseImageRef(
            raw_line="FROM debian:bullseye-slim", image="debian", tag="bullseye-slim"
        )
        candidate = self.resolver.suggest(ref)
        self.assertIsNotNone(candidate)
        self.assertEqual(candidate.new_tag, "bookworm-slim")
        self.assertEqual(candidate.strategy, "codename")

    def test_eol_codename_refresh(self):
        ref = BaseImageRef(raw_line="FROM ubuntu:bionic", image="ubuntu", tag="bionic")
        candidate = self.resolver.suggest(ref)
        self.assertIsNotNone(candidate)
        self.assertEqual(candidate.new_tag, "focal")

    def test_no_version_no_codename_returns_none(self):
        ref = BaseImageRef(raw_line="FROM python:latest", image="python", tag="latest")
        candidate = self.resolver.suggest(ref)
        self.assertIsNone(candidate)


class TestBaseImageResolverMinorStrategy(unittest.TestCase):
    def test_minor_strategy_upgrade(self):
        resolver = BaseImageResolver(strategy="minor")
        ref = BaseImageRef(
            raw_line="FROM python:3.9.12-slim", image="python", tag="3.9.12-slim"
        )
        candidate = resolver.suggest(ref)
        self.assertIsNotNone(candidate)
        self.assertEqual(candidate.new_tag, "3.12.8-slim")

    def test_minor_strategy_unknown_family_returns_none(self):
        resolver = BaseImageResolver(strategy="minor")
        ref = BaseImageRef(
            raw_line="FROM node:16.20.2-alpine", image="node", tag="16.20.2-alpine"
        )
        candidate = resolver.suggest(ref)
        self.assertIsNone(candidate)


class TestBaseImageResolverCustomCandidates(unittest.TestCase):
    def test_custom_candidate_tables_used_offline(self):
        resolver = BaseImageResolver(
            strategy="patch",
            patch_candidates={("myimage", "1.0"): "1.0.99"},
            minor_candidates={},
            codename_refresh={},
        )
        ref = BaseImageRef(raw_line="FROM myimage:1.0.0", image="myimage", tag="1.0.0")
        candidate = resolver.suggest(ref)
        self.assertIsNotNone(candidate)
        self.assertEqual(candidate.new_tag, "1.0.99")


class TestLLMAnalyzerBaseImageContext(unittest.TestCase):
    def setUp(self):
        self.temp_dir = Path(tempfile.mkdtemp())
        self.dockerfile = self.temp_dir / "Dockerfile"
        self.dockerfile.write_text(
            'FROM python:3.9.12-slim\n\nWORKDIR /app\nCOPY . .\nCMD ["python", "app.py"]\n'
        )

    def tearDown(self):
        shutil.rmtree(self.temp_dir)

    def _make_analyzer(self, base_image_cfg=None):
        config = {
            "llm": {"provider": "claude"},
            "base_image": base_image_cfg
            if base_image_cfg is not None
            else {"enabled": True},
        }
        analyzer = LLMAnalyzer.__new__(LLMAnalyzer)
        base_image_cfg = config.get("base_image", {})
        analyzer.base_image_enabled = bool(base_image_cfg.get("enabled", True))
        analyzer.base_image_strategy = base_image_cfg.get("strategy", "patch")
        analyzer.base_image_fallback = bool(
            base_image_cfg.get("fallback_to_package_pin", True)
        )
        return analyzer

    def _grouped_os_vulns(self):
        vuln = Vulnerability(
            vuln_id="CVE-2023-2975",
            pkg_name="libssl1.1",
            installed_version="1.1.1n-0+deb11u1",
            fixed_version="1.1.1w-0+deb11u1",
            severity="HIGH",
            title="OpenSSL vulnerability",
            description="desc",
            target="python:3.9.12-slim (debian 11.3)",
            target_class="os-pkgs",
            target_type="debian",
        )
        report = VulnerabilityReport(
            artifact_name="myapp:latest", vulnerabilities=[vuln]
        )
        return report.group_by_target([vuln])

    def test_prompt_includes_base_image_context_section(self):
        analyzer = self._make_analyzer()
        grouped = self._grouped_os_vulns()
        file_contents = {"Dockerfile": self.dockerfile.read_text()}

        prompt = analyzer._build_prompt("myapp:latest", grouped, file_contents)

        self.assertIn("Base Image Context", prompt)
        self.assertIn("FROM python:3.9.12-slim", prompt)
        self.assertIn("FROM python:3.9.21-slim", prompt)
        self.assertIn("CVE-2023-2975", prompt)

    def test_prompt_omits_base_image_context_when_disabled(self):
        analyzer = self._make_analyzer(base_image_cfg={"enabled": False})
        grouped = self._grouped_os_vulns()
        file_contents = {"Dockerfile": self.dockerfile.read_text()}

        prompt = analyzer._build_prompt("myapp:latest", grouped, file_contents)

        self.assertNotIn("Base Image Context", prompt)

    def test_prompt_omits_base_image_context_without_dockerfile(self):
        analyzer = self._make_analyzer()
        grouped = self._grouped_os_vulns()

        prompt = analyzer._build_prompt("myapp:latest", grouped, {})

        self.assertNotIn("Base Image Context", prompt)

    def test_prompt_fallback_message_when_no_candidate_and_fallback_enabled(self):
        analyzer = self._make_analyzer(
            base_image_cfg={"enabled": True, "fallback_to_package_pin": True}
        )
        # Already-latest tag: no upgrade candidate available, but has a CVE target.
        up_to_date_dockerfile = self.temp_dir / "Dockerfile2"
        up_to_date_dockerfile.write_text("FROM python:3.9.21-slim\n")

        vuln = Vulnerability(
            vuln_id="CVE-2099-0001",
            pkg_name="libssl1.1",
            installed_version="1.0",
            fixed_version="1.1",
            severity="HIGH",
            title="t",
            description="d",
            target="python:3.9.21-slim (debian 11.6)",
            target_class="os-pkgs",
            target_type="debian",
        )
        report = VulnerabilityReport(artifact_name="myapp", vulnerabilities=[vuln])
        grouped = report.group_by_target([vuln])

        prompt = analyzer._build_prompt(
            "myapp", grouped, {"Dockerfile": up_to_date_dockerfile.read_text()}
        )
        self.assertIn("targeted package", prompt)

    def test_system_prompt_prioritizes_base_image_upgrade(self):
        from src.llm_analyzer import SYSTEM_PROMPT

        self.assertIn("ROOT-CAUSE", SYSTEM_PROMPT)
        self.assertIn("FROM <image>:<new_tag>", SYSTEM_PROMPT)


class TestPatcherAppliesBaseImageUpgrade(unittest.TestCase):
    def setUp(self):
        self.temp_dir = Path(tempfile.mkdtemp())
        self.patcher = Patcher(self.temp_dir)

    def tearDown(self):
        shutil.rmtree(self.temp_dir)

    def test_search_and_replace_from_line(self):
        file_path = self.temp_dir / "Dockerfile"
        file_path.write_text("FROM python:3.9.12-slim\n\nWORKDIR /app\nCOPY . .\n")

        change = FileChange(
            file_path="Dockerfile",
            search="FROM python:3.9.12-slim",
            replacement="FROM python:3.9.21-slim",
            cves=["CVE-2023-2975", "CVE-2023-3817"],
            reasoning="Upgrade base image to resolve OS CVEs.",
        )
        plan = RemediationPlan(changes=[change], summary="Upgrade base image")

        result = self.patcher.apply(plan)

        self.assertIn("Dockerfile", result.applied)
        self.assertEqual(len(result.skipped), 0)
        self.assertEqual(
            file_path.read_text(),
            "FROM python:3.9.21-slim\n\nWORKDIR /app\nCOPY . .\n",
        )


class TestBaseImageDisabledFallback(unittest.TestCase):
    """Fallback behavior when base_image.enabled: false — no regression to
    the existing language-package remediation flow."""

    def setUp(self):
        self.temp_dir = Path(tempfile.mkdtemp())

    def tearDown(self):
        shutil.rmtree(self.temp_dir)

    def test_no_base_image_section_and_pip_flow_unaffected(self):
        config = {"llm": {"provider": "claude"}, "base_image": {"enabled": False}}
        analyzer = LLMAnalyzer.__new__(LLMAnalyzer)
        base_image_cfg = config.get("base_image", {})
        analyzer.base_image_enabled = bool(base_image_cfg.get("enabled", True))
        analyzer.base_image_strategy = base_image_cfg.get("strategy", "patch")
        analyzer.base_image_fallback = bool(
            base_image_cfg.get("fallback_to_package_pin", True)
        )

        vuln = Vulnerability(
            vuln_id="CVE-2023-0001",
            pkg_name="urllib3",
            installed_version="1.26.5",
            fixed_version="1.26.18",
            severity="HIGH",
            title="t",
            description="d",
            target="requirements.txt",
            target_class="lang-pkgs",
            target_type="pip",
        )
        report = VulnerabilityReport(artifact_name="myapp", vulnerabilities=[vuln])
        grouped = report.group_by_target([vuln])

        prompt = analyzer._build_prompt(
            "myapp", grouped, {"requirements.txt": "urllib3==1.26.5\n"}
        )

        self.assertNotIn("Base Image Context", prompt)
        self.assertIn("CVE-2023-0001", prompt)
        self.assertIn("requirements.txt", prompt)


if __name__ == "__main__":
    unittest.main()
