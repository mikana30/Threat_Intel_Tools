#!/usr/bin/env python3
"""
Baseline Manager
----------------
Utility for managing threat intelligence baselines across multiple clients.
Supports listing, resetting, comparing, and exporting baseline data.
"""

from __future__ import annotations

import argparse
import json
import shutil
import sys
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

import yaml


class BaselineManager:
    """Manages baselines for multiple organizations"""

    def __init__(self, baselines_root: Path, config_path: Optional[Path] = None):
        self.baselines_root = baselines_root
        self.config = self.load_config(config_path) if config_path else {}

    @staticmethod
    def load_config(path: Path) -> dict:
        """Load configuration"""
        if not path.exists():
            return {}
        with path.open("r", encoding="utf-8") as f:
            return yaml.safe_load(f) or {}

    def list_baselines(self, verbose: bool = False) -> None:
        """List all client baselines"""
        if not self.baselines_root.exists():
            print(f"Baselines directory not found: {self.baselines_root}")
            return

        orgs = sorted([d for d in self.baselines_root.iterdir() if d.is_dir()])

        if not orgs:
            print("No baselines found.")
            return

        print("=" * 80)
        print(f"CLIENT BASELINES ({len(orgs)} organizations)")
        print("=" * 80)

        for org_dir in orgs:
            org_name = org_dir.name
            if org_name == "archive":
                continue

            metadata_file = org_dir / "baseline_metadata.json"
            metadata = {}
            if metadata_file.exists():
                try:
                    with metadata_file.open("r") as f:
                        metadata = json.load(f)
                except Exception:
                    pass

            # Count files
            baseline_files = [f for f in org_dir.iterdir() if f.is_file() and f.suffix in ['.csv', '.txt']]

            print(f"\n{org_name}")
            print(f"  Location: {org_dir}")
            print(f"  Files: {len(baseline_files)}")

            if metadata:
                print(f"  Last Updated: {metadata.get('timestamp', 'Unknown')}")
                if verbose and metadata.get('files_updated'):
                    print(f"  Tracked Files:")
                    for fname in metadata['files_updated']:
                        print(f"    - {fname}")

            # Check for archives
            archive_dir = self.baselines_root / "archive"
            if archive_dir.exists():
                org_archives = [
                    d for d in archive_dir.iterdir()
                    if d.name.startswith(f"baseline_{org_name}_")
                ]
                if org_archives:
                    print(f"  Archived Versions: {len(org_archives)}")
                    if verbose:
                        for arch in sorted(org_archives, reverse=True)[:3]:
                            print(f"    - {arch.name}")

        print("=" * 80)

    def reset_baseline(self, org_name: str, confirm: bool = False) -> bool:
        """Reset (delete) baseline for an organization"""
        org_dir = self.baselines_root / org_name

        if not org_dir.exists():
            print(f"Baseline not found for organization: {org_name}")
            return False

        if not confirm:
            print(f"WARNING: This will delete the baseline for {org_name}")
            print(f"Location: {org_dir}")
            response = input("Are you sure? (yes/no): ").strip().lower()
            if response != "yes":
                print("Reset cancelled.")
                return False

        # Archive before deletion
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        archive_dir = self.baselines_root / "archive" / f"baseline_{org_name}_{timestamp}_reset"
        archive_dir.mkdir(parents=True, exist_ok=True)

        print(f"Archiving current baseline to {archive_dir}...")
        for item in org_dir.iterdir():
            if item.is_file():
                shutil.copy2(item, archive_dir / item.name)

        # Delete baseline directory
        shutil.rmtree(org_dir)
        print(f"Baseline reset for {org_name}")
        return True

    def compare_runs(
        self,
        run1_dir: Path,
        run2_dir: Path,
        output_file: Optional[Path] = None,
    ) -> None:
        """
        Compare two specific runs without using baselines
        Useful for ad-hoc comparisons
        """
        from change_detector import ChangeDetector

        if not run1_dir.exists():
            print(f"Run 1 directory not found: {run1_dir}")
            return

        if not run2_dir.exists():
            print(f"Run 2 directory not found: {run2_dir}")
            return

        print(f"Comparing:")
        print(f"  Run 1 (baseline): {run1_dir}")
        print(f"  Run 2 (current):  {run2_dir}")
        print()

        # Use change detector
        config_path = Path("config/change_detection.yml")
        detector = ChangeDetector(config_path)

        detector.compare_files(run2_dir, run1_dir)
        detector.generate_summary()

        # Display summary
        print("=" * 80)
        print("COMPARISON SUMMARY")
        print("=" * 80)
        print(f"Total Changes: {detector.summary['total_changes']}")
        print()
        print("By Severity:")
        for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            count = detector.summary['by_severity'].get(severity, 0)
            if count > 0:
                print(f"  {severity}: {count}")
        print()
        print("By File:")
        for filename, count in detector.summary['by_file'].items():
            print(f"  {filename}: {count}")
        print("=" * 80)

        # Write output if requested
        if output_file:
            output_dir = output_file.parent
            output_dir.mkdir(parents=True, exist_ok=True)
            detector.write_outputs(output_dir, "comparison")
            print(f"\nDetailed results written to: {output_dir}")

    def export_baseline_history(self, org_name: str, output_dir: Path) -> None:
        """Export baseline history for an organization"""
        org_dir = self.baselines_root / org_name
        archive_dir = self.baselines_root / "archive"

        if not org_dir.exists():
            print(f"No baseline found for {org_name}")
            return

        output_dir.mkdir(parents=True, exist_ok=True)

        # Export current baseline
        current_export = output_dir / "current"
        current_export.mkdir(exist_ok=True)
        print(f"Exporting current baseline...")
        for item in org_dir.iterdir():
            if item.is_file():
                shutil.copy2(item, current_export / item.name)

        # Export archives
        if archive_dir.exists():
            org_archives = sorted(
                [d for d in archive_dir.iterdir() if d.name.startswith(f"baseline_{org_name}_")],
                reverse=True,
            )

            if org_archives:
                print(f"Exporting {len(org_archives)} archived versions...")
                for archive in org_archives:
                    archive_export = output_dir / archive.name
                    shutil.copytree(archive, archive_export)

        # Create index
        index = {
            "organization": org_name,
            "export_timestamp": datetime.now().isoformat(),
            "current_baseline": str(current_export),
            "archived_versions": [str(d.name) for d in org_archives],
        }

        index_file = output_dir / "export_index.json"
        with index_file.open("w") as f:
            json.dump(index, f, indent=2)

        print(f"\nExport complete: {output_dir}")
        print(f"  Current baseline: {current_export}")
        print(f"  Archived versions: {len(org_archives)}")

    def baseline_stats(self) -> Dict[str, any]:
        """Get statistics about all baselines"""
        stats = {
            "total_organizations": 0,
            "organizations": [],
            "total_archived_versions": 0,
        }

        if not self.baselines_root.exists():
            return stats

        orgs = [d for d in self.baselines_root.iterdir() if d.is_dir() and d.name != "archive"]
        stats["total_organizations"] = len(orgs)

        for org_dir in orgs:
            org_name = org_dir.name
            metadata_file = org_dir / "baseline_metadata.json"

            metadata = {}
            if metadata_file.exists():
                try:
                    with metadata_file.open("r") as f:
                        metadata = json.load(f)
                except Exception:
                    pass

            file_count = len([f for f in org_dir.iterdir() if f.is_file()])

            org_info = {
                "name": org_name,
                "files": file_count,
                "last_updated": metadata.get("timestamp", "Unknown"),
            }
            stats["organizations"].append(org_info)

        # Count archives
        archive_dir = self.baselines_root / "archive"
        if archive_dir.exists():
            stats["total_archived_versions"] = len(list(archive_dir.iterdir()))

        return stats

    def cleanup_archives(self, org_name: Optional[str] = None, keep_last: int = 5) -> None:
        """Clean up old archived baselines"""
        archive_dir = self.baselines_root / "archive"
        if not archive_dir.exists():
            print("No archives to clean up.")
            return

        if org_name:
            # Clean specific org
            org_archives = sorted(
                [d for d in archive_dir.iterdir() if d.name.startswith(f"baseline_{org_name}_")],
                reverse=True,
            )

            if len(org_archives) <= keep_last:
                print(f"No cleanup needed for {org_name} (only {len(org_archives)} archives)")
                return

            to_remove = org_archives[keep_last:]
            print(f"Removing {len(to_remove)} old archives for {org_name}:")
            for archive in to_remove:
                print(f"  - {archive.name}")
                shutil.rmtree(archive)
        else:
            # Clean all orgs
            all_orgs = set()
            for archive in archive_dir.iterdir():
                if archive.name.startswith("baseline_"):
                    parts = archive.name.split("_")
                    if len(parts) >= 2:
                        org = parts[1]
                        all_orgs.add(org)

            for org in all_orgs:
                self.cleanup_archives(org, keep_last)

        print("Cleanup complete.")


def main():
    parser = argparse.ArgumentParser(
        description="Baseline Manager for Threat Intelligence"
    )
    parser.add_argument(
        "--baselines-root",
        default="baselines",
        help="Root directory for baselines (default: baselines/)",
    )
    parser.add_argument(
        "--config",
        default="config/change_detection.yml",
        help="Change detection config file",
    )

    # Commands
    subparsers = parser.add_subparsers(dest="command", help="Command to execute")

    # List command
    list_parser = subparsers.add_parser("list", help="List all client baselines")
    list_parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")

    # Reset command
    reset_parser = subparsers.add_parser("reset", help="Reset baseline for an organization")
    reset_parser.add_argument("--org", required=True, help="Organization name")
    reset_parser.add_argument("-y", "--yes", action="store_true", help="Skip confirmation")

    # Compare command
    compare_parser = subparsers.add_parser("compare", help="Compare two specific runs")
    compare_parser.add_argument("run1", help="First run directory (baseline)")
    compare_parser.add_argument("run2", help="Second run directory (current)")
    compare_parser.add_argument(
        "--output",
        help="Output file for detailed comparison results",
    )

    # Export command
    export_parser = subparsers.add_parser("export", help="Export baseline history")
    export_parser.add_argument("--org", required=True, help="Organization name")
    export_parser.add_argument(
        "--output-dir",
        required=True,
        help="Output directory for export",
    )

    # Stats command
    subparsers.add_parser("stats", help="Show baseline statistics")

    # Cleanup command
    cleanup_parser = subparsers.add_parser("cleanup", help="Clean up old archives")
    cleanup_parser.add_argument("--org", help="Organization name (optional, all if not specified)")
    cleanup_parser.add_argument(
        "--keep-last",
        type=int,
        default=5,
        help="Number of recent archives to keep (default: 5)",
    )

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return 1

    # Initialize manager
    baselines_root = Path(args.baselines_root)
    config_path = Path(args.config) if args.config else None
    manager = BaselineManager(baselines_root, config_path)

    # Execute command
    if args.command == "list":
        manager.list_baselines(verbose=args.verbose)

    elif args.command == "reset":
        manager.reset_baseline(args.org, confirm=args.yes)

    elif args.command == "compare":
        run1 = Path(args.run1)
        run2 = Path(args.run2)
        output = Path(args.output) if args.output else None
        manager.compare_runs(run1, run2, output)

    elif args.command == "export":
        output_dir = Path(args.output_dir)
        manager.export_baseline_history(args.org, output_dir)

    elif args.command == "stats":
        stats = manager.baseline_stats()
        print("=" * 80)
        print("BASELINE STATISTICS")
        print("=" * 80)
        print(f"Total Organizations: {stats['total_organizations']}")
        print(f"Total Archived Versions: {stats['total_archived_versions']}")
        print()
        if stats['organizations']:
            print("Organizations:")
            for org in stats['organizations']:
                print(f"  - {org['name']}")
                print(f"    Files: {org['files']}")
                print(f"    Last Updated: {org['last_updated']}")
                print()
        print("=" * 80)

    elif args.command == "cleanup":
        manager.cleanup_archives(args.org, args.keep_last)

    return 0


if __name__ == "__main__":
    sys.exit(main())
