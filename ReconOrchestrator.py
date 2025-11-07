#!/usr/bin/env python3
"""
ReconOrchestrator
-----------------
Modular recon pipeline that runs enabled enumeration modules, aggregates results,
and writes structured outputs for downstream phases.
"""

from __future__ import annotations

import argparse
import json
import logging
import random
import time
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Dict, Iterable, List

import yaml

from recon.modules import MODULE_REGISTRY, ModuleConfig

# Import modules for registration side-effects
from recon.modules import amass as _amass  # noqa: F401
from recon.modules import assetfinder as _assetfinder  # noqa: F401
from recon.modules import gau as _gau  # noqa: F401
from recon.modules import subdomz as _subdomz  # noqa: F401
from recon.modules import subfinder as _subfinder  # noqa: F401

LOG_DIR = Path("logs")
LOG_DIR.mkdir(exist_ok=True)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler(LOG_DIR / "ReconOrchestrator.log", mode="w"),
        logging.StreamHandler(),
    ],
)
logger = logging.getLogger("recon.orchestrator")


def load_targets(path: Path) -> List[str]:
    if path.suffix.lower() == ".json":
        data = json.loads(path.read_text())
        if isinstance(data, list):
            return [item["domain"] if isinstance(item, dict) else item for item in data]
        raise ValueError("targets JSON must be a list")
    # Plain text fallback
    domains = []
    for line in path.read_text().splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            domains.append(line)
    return domains


def load_config(path: Path) -> dict:
    with path.open("r", encoding="utf-8") as fh:
        return yaml.safe_load(fh) or {}


def instantiate_modules(config: dict) -> List:
    modules = []
    for name, cfg in (config or {}).items():
        if not cfg.get("enabled", True):
            continue
        cls = MODULE_REGISTRY.get(name)
        if not cls:
            logger.warning("Unknown recon module '%s' in config", name)
            continue
        module_cfg = ModuleConfig(
            enabled=cfg.get("enabled", True),
            path=cfg.get("path"),
            flags=cfg.get("flags", []),
            timeout=cfg.get("timeout", 300),
            rate_limit_seconds=cfg.get("rate_limit_seconds", 0.0),
        )
        module = cls(module_cfg)
        if not module.is_available():
            logger.warning("Module %s is not available, skipping.", name)
            continue
        modules.append(module)
    return modules


def ensure_dirs(domain: str, base_output: Path) -> dict[str, Path]:
    domain_dir = base_output / "recon_outputs" / domain
    sources_dir = domain_dir / "sources"
    domain_dir.mkdir(parents=True, exist_ok=True)
    sources_dir.mkdir(exist_ok=True)
    return {"domain_dir": domain_dir, "sources_dir": sources_dir}


def write_sources(sources_dir: Path, module_name: str, domains: Iterable[str]) -> None:
    out_path = sources_dir / f"{module_name}.txt"
    out_path.write_text("\n".join(sorted(set(domains))))


def write_aggregated(domain_dir: Path, aggregated_map: Dict[str, List[str]]) -> None:
    agg_path = domain_dir / "aggregated_domains.json"
    payload = []
    for host, modules in sorted(aggregated_map.items()):
        payload.append(
            {
                "domain": host,
                "sources": sorted(modules),
            }
        )
    agg_path.write_text(json.dumps(payload, indent=2))
    (domain_dir / "all_domains.txt").write_text(
        "\n".join(host for host in sorted(aggregated_map))
    )
    csv_path = domain_dir / f"{domain_dir.name}_recon.csv"
    csv_lines = ["domain,module"]
    for host, modules in sorted(aggregated_map.items()):
        for module in sorted(modules):
            csv_lines.append(f"{host},{module}")
    csv_path.write_text("\n".join(csv_lines))


def process_domain(domain: str, modules, base_output: Path, delay_cfg: dict) -> dict:
    dirs = ensure_dirs(domain, base_output)
    aggregated = defaultdict(set)
    results_per_module = {}

    for module in modules:
        logger.info("Running %s for %s", module.name, domain)
        findings = module.run(domain) or []
        results_per_module[module.name] = findings
        if findings:
            write_sources(dirs["sources_dir"], module.name, findings)
            for host in findings:
                aggregated[host].add(module.name)
        delay = module.config.rate_limit_seconds or delay_cfg.get("base_delay", 0.0)
        jitter = delay_cfg.get("jitter", 0.0)
        if delay + jitter > 0:
            sleep_for = max(0.0, delay + random.uniform(0, jitter))
            time.sleep(sleep_for)

    write_aggregated(dirs["domain_dir"], aggregated)
    return {"domain": domain, "total": sum(len(v) for v in aggregated.values())}


def main():
    parser = argparse.ArgumentParser(description="Modular recon orchestrator")
    parser.add_argument("--targets", required=True, help="Path to targets file (txt/json)")
    parser.add_argument(
        "--output-dir",
        required=True,
        help="Base output directory (usually {output_dir}/raw_outputs)",
    )
    parser.add_argument("--config", default="config/recon.yml", help="Recon config file")
    parser.add_argument("--max-workers", type=int, default=None, help="Worker threads")
    args = parser.parse_args()

    targets_file = Path(args.targets)
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    targets = load_targets(targets_file)
    if not targets:
        logger.error("No targets found in %s", targets_file)
        return

    cfg = load_config(Path(args.config))
    module_cfg = cfg.get("modules", {})
    delay_cfg = cfg.get("general", {})
    modules = instantiate_modules(module_cfg)
    if not modules:
        logger.error("No recon modules enabled/available. Aborting.")
        return

    max_workers = args.max_workers or cfg.get("general", {}).get("max_workers", 2)
    logger.info("Processing %d targets with %d workers", len(targets), max_workers)

    summaries = []
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_map = {
            executor.submit(process_domain, domain, modules, output_dir, delay_cfg): domain
            for domain in targets
        }
        for future in as_completed(future_map):
            domain = future_map[future]
            try:
                result = future.result()
                summaries.append(result)
                logger.info(
                    "Completed %s (%d findings)",
                    domain,
                    result.get("total", 0),
                )
            except Exception as exc:
                logger.exception("Processing %s failed: %s", domain, exc)

    summary_path = output_dir / "phase1_recon_summary.json"
    summary_path.write_text(json.dumps(summaries, indent=2))
    logger.info("Recon summary written to %s", summary_path)


if __name__ == "__main__":
    main()
