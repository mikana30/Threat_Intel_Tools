#!/usr/bin/env python3
"""
Change Detection Engine
-----------------------
Compares current scan results against baseline to identify changes in:
- Subdomains, IPs, DNS records
- Web hosts and technologies
- Security exposures (admin panels, git leaks, VNC, buckets)
- SSL/TLS certificates

Supports multi-client environments with independent baselines per organization.
"""

from __future__ import annotations

import argparse
import csv
import json
import logging
import re
import shutil
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

import yaml

# Setup logging
LOG_DIR = Path("logs")
LOG_DIR.mkdir(exist_ok=True)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler(LOG_DIR / "change_detector.log", mode="a"),
        logging.StreamHandler(),
    ],
)
logger = logging.getLogger("change_detector")


class ChangeDetector:
    """Main change detection engine"""

    def __init__(self, config_path: Path):
        self.config = self.load_config(config_path)
        self.changes: List[Dict[str, Any]] = []
        self.summary: Dict[str, Any] = {
            "total_changes": 0,
            "by_severity": defaultdict(int),
            "by_file": defaultdict(int),
            "priority_findings": [],
            "timestamp": datetime.now().isoformat(),
        }

    @staticmethod
    def load_config(path: Path) -> dict:
        """Load change detection configuration"""
        if not path.exists():
            logger.warning(f"Config not found at {path}, using defaults")
            return {"monitored_files": []}
        with path.open("r", encoding="utf-8") as f:
            return yaml.safe_load(f) or {}

    def compare_csv_files(
        self,
        current_file: Path,
        baseline_file: Path,
        file_config: dict,
    ) -> List[Dict[str, Any]]:
        """
        Compare two CSV files column-aware
        Returns list of changes with metadata
        """
        changes = []
        key_col = file_config.get("key_column", "domain")
        columns = file_config.get("columns", [])

        # Load current data
        current_data = self.load_csv_data(current_file, key_col)
        baseline_data = self.load_csv_data(baseline_file, key_col)

        # Find additions
        added_keys = set(current_data.keys()) - set(baseline_data.keys())
        for key in added_keys:
            change = {
                "file": file_config["file"],
                "change_type": "ADDED",
                "key": key,
                "current_value": current_data[key],
                "baseline_value": None,
                "severity": "MEDIUM",
            }
            severity = self.evaluate_priority(change, file_config)
            change["severity"] = severity
            changes.append(change)

        # Find removals
        removed_keys = set(baseline_data.keys()) - set(current_data.keys())
        for key in removed_keys:
            change = {
                "file": file_config["file"],
                "change_type": "REMOVED",
                "key": key,
                "current_value": None,
                "baseline_value": baseline_data[key],
                "severity": "LOW",
            }
            severity = self.evaluate_priority(change, file_config)
            change["severity"] = severity
            changes.append(change)

        # Find modifications
        common_keys = set(current_data.keys()) & set(baseline_data.keys())
        for key in common_keys:
            if current_data[key] != baseline_data[key]:
                change = {
                    "file": file_config["file"],
                    "change_type": "MODIFIED",
                    "key": key,
                    "current_value": current_data[key],
                    "baseline_value": baseline_data[key],
                    "modified_fields": self.get_modified_fields(
                        current_data[key], baseline_data[key]
                    ),
                    "severity": "MEDIUM",
                }
                severity = self.evaluate_priority(change, file_config)
                change["severity"] = severity
                changes.append(change)

        return changes

    @staticmethod
    def load_csv_data(file_path: Path, key_column: str) -> Dict[str, dict]:
        """Load CSV file into dictionary keyed by specified column"""
        data = {}
        if not file_path.exists():
            return data

        try:
            with file_path.open("r", encoding="utf-8") as f:
                reader = csv.DictReader(f)
                for row in reader:
                    if key_column in row:
                        key = row[key_column].strip().lower()
                        data[key] = row
        except Exception as e:
            logger.error(f"Error reading CSV {file_path}: {e}")

        return data

    @staticmethod
    def get_modified_fields(current: dict, baseline: dict) -> List[str]:
        """Identify which fields changed between two records"""
        modified = []
        all_keys = set(current.keys()) | set(baseline.keys())
        for key in all_keys:
            curr_val = current.get(key, "").strip()
            base_val = baseline.get(key, "").strip()
            if curr_val != base_val:
                modified.append(key)
        return modified

    def compare_text_files(
        self,
        current_file: Path,
        baseline_file: Path,
        file_config: dict,
    ) -> List[Dict[str, Any]]:
        """
        Compare line-based text files
        Returns list of changes
        """
        changes = []

        # Load lines
        current_lines = self.load_text_lines(current_file)
        baseline_lines = self.load_text_lines(baseline_file)

        # Find additions
        added_lines = current_lines - baseline_lines
        for line in added_lines:
            change = {
                "file": file_config["file"],
                "change_type": "ADDED",
                "key": line,
                "current_value": line,
                "baseline_value": None,
                "severity": "MEDIUM",
            }
            severity = self.evaluate_priority(change, file_config)
            change["severity"] = severity
            changes.append(change)

        # Find removals
        removed_lines = baseline_lines - current_lines
        for line in removed_lines:
            change = {
                "file": file_config["file"],
                "change_type": "REMOVED",
                "key": line,
                "current_value": None,
                "baseline_value": line,
                "severity": "LOW",
            }
            severity = self.evaluate_priority(change, file_config)
            change["severity"] = severity
            changes.append(change)

        return changes

    @staticmethod
    def load_text_lines(file_path: Path) -> Set[str]:
        """Load text file lines into set"""
        if not file_path.exists():
            return set()

        try:
            with file_path.open("r", encoding="utf-8") as f:
                return {line.strip().lower() for line in f if line.strip()}
        except Exception as e:
            logger.error(f"Error reading text file {file_path}: {e}")
            return set()

    def evaluate_priority(self, change: dict, file_config: dict) -> str:
        """
        Evaluate priority/severity based on rules in config
        Returns severity level (CRITICAL, HIGH, MEDIUM, LOW)
        """
        priority_rules = file_config.get("priority_rules", [])

        for rule in priority_rules:
            if self.rule_matches(change, rule):
                return rule.get("severity", "MEDIUM")

        # Default severity based on change type
        if change["change_type"] == "ADDED":
            return "MEDIUM"
        elif change["change_type"] == "REMOVED":
            return "LOW"
        else:
            return "MEDIUM"

    def rule_matches(self, change: dict, rule: dict) -> bool:
        """
        Check if a change matches a priority rule
        Supports simple condition evaluation
        """
        condition = rule.get("condition", "")

        # Simple condition parsing
        if "change_type ==" in condition:
            match = re.search(r"change_type == ['\"](\w+)['\"]", condition)
            if match and match.group(1) != change["change_type"]:
                return False

        if "status_code ==" in condition:
            match = re.search(r"status_code == (\d+)", condition)
            if match:
                expected = match.group(1)
                actual = change.get("current_value", {}).get("status_code", "")
                if expected != actual:
                    return False

        if "detected ==" in condition:
            match = re.search(r"detected == ['\"](\w+)['\"]", condition)
            if match:
                expected = match.group(1)
                actual = change.get("current_value", {}).get("detected", "")
                if expected.lower() != actual.lower():
                    return False

        if "status ==" in condition:
            match = re.search(r"status == ['\"](\w+)['\"]", condition)
            if match:
                expected = match.group(1)
                actual = change.get("current_value", {}).get("status", "")
                if expected.lower() != actual.lower():
                    return False

        if "accessible ==" in condition:
            match = re.search(r"accessible == ['\"](\w+)['\"]", condition)
            if match:
                expected = match.group(1)
                actual = change.get("current_value", {}).get("accessible", "")
                if expected.lower() != actual.lower():
                    return False

        # Check for field changes
        if " changed" in condition:
            field_match = re.search(r"(\w+) changed", condition)
            if field_match:
                field = field_match.group(1)
                modified_fields = change.get("modified_fields", [])
                if field not in modified_fields:
                    return False

        return True

    def compare_files(
        self,
        current_dir: Path,
        baseline_dir: Path,
    ) -> None:
        """
        Compare all monitored files between current and baseline
        """
        monitored_files = self.config.get("monitored_files", [])

        for file_config in monitored_files:
            filename = file_config["file"]
            file_type = file_config.get("type", "csv")

            current_file = current_dir / filename
            baseline_file = baseline_dir / filename

            # Handle missing files
            if not current_file.exists() and not baseline_file.exists():
                logger.info(f"Skipping {filename} (not found in current or baseline)")
                continue

            if not baseline_file.exists():
                logger.warning(
                    f"No baseline for {filename} - treating all as new additions"
                )
                # All current entries are new
                if file_type == "line_based":
                    changes = self.compare_text_files(
                        current_file, baseline_file, file_config
                    )
                else:
                    changes = self.compare_csv_files(
                        current_file, baseline_file, file_config
                    )
            else:
                # Normal comparison
                if file_type == "line_based":
                    changes = self.compare_text_files(
                        current_file, baseline_file, file_config
                    )
                else:
                    changes = self.compare_csv_files(
                        current_file, baseline_file, file_config
                    )

            # Record changes
            self.changes.extend(changes)
            self.summary["by_file"][filename] = len(changes)
            logger.info(f"Detected {len(changes)} changes in {filename}")

    def generate_summary(self) -> dict:
        """Generate summary statistics"""
        self.summary["total_changes"] = len(self.changes)

        # Count by severity
        for change in self.changes:
            severity = change.get("severity", "MEDIUM")
            self.summary["by_severity"][severity] += 1

        # Extract priority findings (HIGH and CRITICAL)
        priority_findings = [
            c for c in self.changes if c.get("severity") in ["HIGH", "CRITICAL"]
        ]
        self.summary["priority_findings"] = sorted(
            priority_findings, key=lambda x: ("CRITICAL", "HIGH").index(x["severity"])
        )

        # Convert defaultdicts to regular dicts for JSON serialization
        self.summary["by_severity"] = dict(self.summary["by_severity"])
        self.summary["by_file"] = dict(self.summary["by_file"])

        return self.summary

    def write_outputs(self, output_dir: Path, org_name: str) -> None:
        """Write all output files"""
        output_dir.mkdir(parents=True, exist_ok=True)

        # 1. Summary JSON
        summary_file = output_dir / "changes_summary.json"
        with summary_file.open("w", encoding="utf-8") as f:
            json.dump(self.summary, f, indent=2)
        logger.info(f"Summary written to {summary_file}")

        # 2. Detailed CSV
        detailed_file = output_dir / "changes_detailed.csv"
        self.write_detailed_csv(detailed_file)
        logger.info(f"Detailed changes written to {detailed_file}")

        # 3. Priority findings TXT
        priority_file = output_dir / "priority_findings.txt"
        self.write_priority_findings(priority_file)
        logger.info(f"Priority findings written to {priority_file}")

    def write_detailed_csv(self, output_file: Path) -> None:
        """Write detailed changes to CSV"""
        if not self.changes:
            output_file.write_text("No changes detected\n")
            return

        fieldnames = [
            "file",
            "change_type",
            "severity",
            "key",
            "current_value",
            "baseline_value",
            "modified_fields",
        ]

        with output_file.open("w", encoding="utf-8", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()

            for change in self.changes:
                row = {
                    "file": change.get("file", ""),
                    "change_type": change.get("change_type", ""),
                    "severity": change.get("severity", ""),
                    "key": change.get("key", ""),
                    "current_value": json.dumps(change.get("current_value")),
                    "baseline_value": json.dumps(change.get("baseline_value")),
                    "modified_fields": ",".join(change.get("modified_fields", [])),
                }
                writer.writerow(row)

    def write_priority_findings(self, output_file: Path) -> None:
        """Write high-priority findings to text file"""
        priority_findings = [
            c for c in self.changes if c.get("severity") in ["CRITICAL", "HIGH"]
        ]

        if not priority_findings:
            output_file.write_text("No high-priority findings detected.\n")
            return

        lines = [
            "=" * 80,
            "PRIORITY FINDINGS - CHANGE DETECTION REPORT",
            "=" * 80,
            f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            f"Total Priority Findings: {len(priority_findings)}",
            "",
        ]

        # Group by severity
        critical = [c for c in priority_findings if c["severity"] == "CRITICAL"]
        high = [c for c in priority_findings if c["severity"] == "HIGH"]

        if critical:
            lines.extend([
                "CRITICAL FINDINGS",
                "-" * 80,
            ])
            for i, change in enumerate(critical, 1):
                lines.extend(self.format_finding(i, change))
                lines.append("")

        if high:
            lines.extend([
                "HIGH PRIORITY FINDINGS",
                "-" * 80,
            ])
            for i, change in enumerate(high, 1):
                lines.extend(self.format_finding(i, change))
                lines.append("")

        lines.extend([
            "=" * 80,
            "END OF REPORT",
            "=" * 80,
        ])

        output_file.write_text("\n".join(lines))

    @staticmethod
    def format_finding(index: int, change: dict) -> List[str]:
        """Format a single finding for text output"""
        lines = [
            f"{index}. [{change['severity']}] {change['file']}",
            f"   Change Type: {change['change_type']}",
            f"   Key: {change['key']}",
        ]

        if change.get("modified_fields"):
            lines.append(f"   Modified Fields: {', '.join(change['modified_fields'])}")

        if change.get("current_value"):
            lines.append(f"   Current: {change['current_value']}")

        if change.get("baseline_value"):
            lines.append(f"   Previous: {change['baseline_value']}")

        return lines

    def update_baseline(
        self,
        current_dir: Path,
        baseline_dir: Path,
        org_name: str,
    ) -> None:
        """
        Update baseline with current run artifacts
        Maintains baseline history per retention policy
        """
        baseline_dir.mkdir(parents=True, exist_ok=True)

        # Archive existing baseline
        if baseline_dir.exists() and any(baseline_dir.iterdir()):
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            archive_name = f"baseline_{org_name}_{timestamp}"
            archive_dir = baseline_dir.parent / "archive" / archive_name
            archive_dir.mkdir(parents=True, exist_ok=True)

            logger.info(f"Archiving previous baseline to {archive_dir}")
            for item in baseline_dir.iterdir():
                if item.is_file():
                    shutil.copy2(item, archive_dir / item.name)

        # Copy current results to baseline
        monitored_files = self.config.get("monitored_files", [])
        for file_config in monitored_files:
            filename = file_config["file"]
            current_file = current_dir / filename

            if current_file.exists():
                dest_file = baseline_dir / filename
                shutil.copy2(current_file, dest_file)
                logger.info(f"Updated baseline: {filename}")

        # Write metadata
        metadata = {
            "org_name": org_name,
            "timestamp": datetime.now().isoformat(),
            "source_dir": str(current_dir),
            "files_updated": [
                f["file"] for f in monitored_files if (current_dir / f["file"]).exists()
            ],
        }
        metadata_file = baseline_dir / "baseline_metadata.json"
        with metadata_file.open("w", encoding="utf-8") as f:
            json.dump(metadata, f, indent=2)

        # Clean old archives per retention policy
        self.cleanup_old_baselines(baseline_dir.parent / "archive", org_name)

    def cleanup_old_baselines(self, archive_dir: Path, org_name: str) -> None:
        """Remove old baselines per retention policy"""
        if not archive_dir.exists():
            return

        retention = self.config.get("baseline_retention", {})
        max_baselines = retention.get("max_baselines", 5)

        # Find all archived baselines for this org
        org_archives = sorted(
            [d for d in archive_dir.iterdir() if d.name.startswith(f"baseline_{org_name}_")],
            key=lambda x: x.name,
            reverse=True,
        )

        # Remove excess archives
        if len(org_archives) > max_baselines:
            for old_archive in org_archives[max_baselines:]:
                logger.info(f"Removing old baseline archive: {old_archive.name}")
                shutil.rmtree(old_archive)


def main():
    parser = argparse.ArgumentParser(
        description="Change Detection Engine for Threat Intelligence"
    )
    parser.add_argument(
        "--current-dir",
        required=True,
        help="Path to current scan results (e.g., results/ORG_TIMESTAMP/raw_outputs)",
    )
    parser.add_argument(
        "--baseline-dir",
        required=True,
        help="Path to baseline directory (e.g., baselines/ORG)",
    )
    parser.add_argument(
        "--org-name",
        required=True,
        help="Organization name for baseline tracking",
    )
    parser.add_argument(
        "--output-dir",
        required=True,
        help="Directory for change detection outputs",
    )
    parser.add_argument(
        "--config",
        default="config/change_detection.yml",
        help="Change detection config file",
    )
    parser.add_argument(
        "--update-baseline",
        action="store_true",
        help="Update baseline after comparison",
    )
    parser.add_argument(
        "--skip-comparison",
        action="store_true",
        help="Skip comparison, only update baseline",
    )

    args = parser.parse_args()

    # Initialize detector
    detector = ChangeDetector(Path(args.config))

    current_dir = Path(args.current_dir)
    baseline_dir = Path(args.baseline_dir)
    output_dir = Path(args.output_dir)

    # Validate paths
    if not current_dir.exists():
        logger.error(f"Current directory does not exist: {current_dir}")
        return 1

    # Run comparison
    if not args.skip_comparison:
        if not baseline_dir.exists() or not any(baseline_dir.iterdir()):
            logger.warning(
                f"No baseline found for {args.org_name}. "
                f"This appears to be the first run - all findings will be marked as new."
            )
            baseline_dir.mkdir(parents=True, exist_ok=True)

        logger.info(f"Starting change detection for {args.org_name}")
        logger.info(f"Current: {current_dir}")
        logger.info(f"Baseline: {baseline_dir}")

        detector.compare_files(current_dir, baseline_dir)
        detector.generate_summary()

        # Write outputs
        detector.write_outputs(output_dir, args.org_name)

        # Log summary
        logger.info("=" * 60)
        logger.info(f"Total changes detected: {detector.summary['total_changes']}")
        for severity, count in detector.summary["by_severity"].items():
            logger.info(f"  {severity}: {count}")
        logger.info("=" * 60)

    # Update baseline if requested
    if args.update_baseline:
        logger.info(f"Updating baseline for {args.org_name}")
        detector.update_baseline(current_dir, baseline_dir, args.org_name)

    logger.info("Change detection complete!")
    return 0


if __name__ == "__main__":
    exit(main())
