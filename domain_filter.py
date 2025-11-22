#!/usr/bin/env python3
"""
Domain Filter
-------------
Parses Phase 1 recon outputs, applies YAML-driven heuristics, and emits a
structured allow-list for downstream DNS/web stages.
"""
from __future__ import annotations

import argparse
import csv
import json
import logging
import re
from pathlib import Path
from typing import Dict, List, Set

import yaml

from dev_mode import get_target_cap, load_env_settings

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.FileHandler("logs/domain_filter.log", mode="w"), logging.StreamHandler()],
)
logger = logging.getLogger("domain_filter")


def load_config(path: Path) -> dict:
    if not path.exists():
        raise FileNotFoundError(f"Domain filter config not found: {path}")
    with path.open("r", encoding="utf-8") as fh:
        return yaml.safe_load(fh) or {}


def load_inventory(recon_dir: Path) -> Dict[str, Set[str]]:
    inventory: Dict[str, Set[str]] = {}
    for agg_path in recon_dir.glob("*/aggregated_domains.json"):
        try:
            entries = json.loads(agg_path.read_text())
        except json.JSONDecodeError as exc:
            logger.warning("Failed to parse %s: %s", agg_path, exc)
            continue
        for entry in entries or []:
            domain = (entry or {}).get("domain", "").strip().lower()
            if not domain:
                continue
            sources = entry.get("sources") or []
            current = inventory.setdefault(domain, set())
            for src in sources:
                if src:
                    current.add(src.lower())
    return inventory


def compile_filters(cfg: dict) -> dict:
    filters = cfg.get("filters", {})
    compiled = {
        "allow_suffixes": [s.lower() for s in filters.get("allow_suffixes", [])],
        "allow_keywords": [s.lower() for s in filters.get("allow_keywords", [])],
        "block_suffixes": [s.lower() for s in filters.get("block_suffixes", [])],
        "block_keywords": [s.lower() for s in filters.get("block_keywords", [])],
        "block_regex": [re.compile(expr) for expr in filters.get("block_regex", [])],
    }
    return compiled


def score_sources(sources: Set[str], cfg: dict) -> float:
    weights = cfg.get("weights", {})
    default_weight = cfg.get("defaults", {}).get("default_weight", 0.1)
    total = 0.0
    for src in sources:
        total += weights.get(src, weights.get(f"source_{src}", default_weight))
    return min(1.0, total)


def evaluate_domain(domain: str, sources: Set[str], cfg: dict, compiled_filters: dict) -> dict:
    defaults = cfg.get("defaults", {})
    max_len = defaults.get("max_domain_length", 255)
    min_sources = defaults.get("min_sources", 1)
    confidence_threshold = defaults.get("confidence_threshold", 0.2)

    decision = {
        "domain": domain,
        "kept": True,
        "reason": [],
        "score": 0.0,
        "sources": ";".join(sorted(sources)),
    }

    if len(domain) > max_len:
        decision["kept"] = False
        decision["reason"].append("too_long")

    if len(sources) < min_sources:
        decision["kept"] = False
        decision["reason"].append("insufficient_sources")

    lower_domain = domain.lower()
    allow_suffixes = compiled_filters["allow_suffixes"]
    allow_keywords = compiled_filters["allow_keywords"]

    if allow_suffixes and not any(lower_domain.endswith(sfx) for sfx in allow_suffixes):
        if allow_keywords and not any(keyword in lower_domain for keyword in allow_keywords):
            decision["kept"] = False
            decision["reason"].append("no_allow_match")

    for suffix in compiled_filters["block_suffixes"]:
        if lower_domain.endswith(suffix):
            decision["kept"] = False
            decision["reason"].append(f"blocked_suffix:{suffix}")

    for keyword in compiled_filters["block_keywords"]:
        if keyword in lower_domain:
            decision["kept"] = False
            decision["reason"].append(f"blocked_keyword:{keyword}")

    for pattern in compiled_filters["block_regex"]:
        if pattern.search(domain):
            decision["kept"] = False
            decision["reason"].append(f"blocked_regex:{pattern.pattern}")

    score = score_sources(sources, cfg)
    decision["score"] = score
    if score < confidence_threshold:
        decision["kept"] = False
        decision["reason"].append("low_confidence")

    return decision


def write_outputs(decisions: List[dict], csv_path: Path, txt_path: Path) -> None:
    csv_path.parent.mkdir(parents=True, exist_ok=True)
    with csv_path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(
            fh,
            fieldnames=["Domain", "Kept", "Score", "Sources", "Reason"],
        )
        writer.writeheader()
        for item in decisions:
            if not item["kept"]:
                continue
            writer.writerow(
                {
                    "Domain": item["domain"],
                    "Kept": item["kept"],
                    "Score": f"{item['score']:.4f}",
                    "Sources": item.get("sources", ""),
                    "Reason": ";".join(item["reason"]),
                }
            )

    kept = [item["domain"] for item in decisions if item["kept"]]
    txt_path.parent.mkdir(parents=True, exist_ok=True)
    txt_path.write_text("\n".join(sorted(kept)))


def main():
    parser = argparse.ArgumentParser(description="Domain filtering pipeline")
    parser.add_argument("--recon-dir", required=True, help="Directory containing recon_outputs")
    parser.add_argument("--config", default="config/domain_filters.yml", help="Filter config file")
    parser.add_argument("--output-csv", required=True)
    parser.add_argument("--output-txt", required=True)
    parser.add_argument(
        "--env-config",
        default="config/environment.yml",
        help="Optional environment config to honor dev caps",
    )
    args = parser.parse_args()

    cfg = load_config(Path(args.config))
    compiled_filters = compile_filters(cfg)
    inventory = load_inventory(Path(args.recon_dir))

    env_settings = load_env_settings(Path(args.env_config))
    cap = get_target_cap(env_settings)
    domains = list(inventory.items())
    if cap:
        domains = domains[:cap]
        logger.info("Dev cap active (%d) in domain_filter - limiting evaluation set.", cap)

    decisions = [
        evaluate_domain(domain, sources, cfg, compiled_filters) for domain, sources in domains
    ]
    write_outputs(decisions, Path(args.output_csv), Path(args.output_txt))
    kept_count = sum(1 for d in decisions if d["kept"])
    logger.info(
        "Domain filter kept %d of %d domains (%.1f%%).",
        kept_count,
        len(decisions),
        (kept_count / max(1, len(decisions))) * 100,
    )


if __name__ == "__main__":
    main()
