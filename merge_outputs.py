#!/usr/bin/env python3
"""merge_outputs.py - deduplicate and normalize raw outputs into cleaned CSVs/JSONs"""
import argparse, os, glob, json, pandas as pd

def core_normalize_df(df):
    for c in df.columns:
        if df[c].dtype == object:
            lowc = c.lower()
            if any(k in lowc for k in ['domain','host','url','email','subdomain','name']):
                df[c] = df[c].astype(str).str.strip().str.lower()
            else:
                df[c] = df[c].astype(str).str.strip()
    return df

def process_csv(path):
    try:
        df = pd.read_csv(path, dtype=str, keep_default_na=False)
    except Exception:
        try:
            df = pd.read_csv(path, encoding='utf-8', dtype=str, keep_default_na=False)
        except Exception as e:
            print(f"Failed to read {path}: {e}")
            return None
    df = core_normalize_df(df)
    df = df.dropna(how='all')
    df = df.drop_duplicates()
    return df

def walk_and_merge(indir, outdir):
    os.makedirs(outdir, exist_ok=True)
    raw_files = glob.glob(os.path.join(indir, '*'))
    groups = {}
    for p in raw_files:
        name = os.path.basename(p)
        stem = name.replace('_raw','').replace('raw','')
        stem = os.path.splitext(stem)[0]
        groups.setdefault(stem, []).append(p)

    summary = {'merged': {}, 'generated_at': pd.Timestamp.now().isoformat()}

    for stem, paths in groups.items():
        dfs = []
        for p in paths:
            if p.lower().endswith('.csv'):
                df = process_csv(p)
                if df is not None:
                    dfs.append(df)
            elif p.lower().endswith('.json'):
                try:
                    with open(p, 'r', encoding='utf-8') as f:
                        obj = json.load(f)
                    if isinstance(obj, list):
                        df = pd.DataFrame(obj)
                        df = core_normalize_df(df)
                        dfs.append(df)
                except Exception as e:
                    print(f"Skipping json {p}: {e}")
            else:
                continue
        if not dfs:
            continue
        merged = pd.concat(dfs, ignore_index=True, sort=False)
        merged = merged.drop_duplicates()
        candidate_cols = [c for c in merged.columns if 'domain' in c.lower() or 'host' in c.lower() or 'subdomain' in c.lower()]
        if candidate_cols:
            merged = merged.sort_values(by=candidate_cols).drop_duplicates(subset=candidate_cols)
        out_csv = os.path.join(outdir, f"{stem}_clean.csv")
        try:
            merged.to_csv(out_csv, index=False)
            summary['merged'][stem] = {'rows': len(merged), 'files_merged': paths, 'out': out_csv}
            print(f"Wrote cleaned: {out_csv} ({len(merged)} rows)")
        except Exception as e:
            print(f"Failed to write {out_csv}: {e}")

    summary_path = os.path.join(outdir, 'merge_summary.json')
    with open(summary_path, 'w', encoding='utf-8') as sf:
        json.dump(summary, sf, indent=2)
    print("Merge complete. Summary:", summary_path)

def main():
    parser = argparse.ArgumentParser(description='Merge raw outputs into cleaned CSVs/JSONs')
    parser.add_argument('--indir', required=True, help='Raw outputs directory')
    parser.add_argument('--outdir', required=True, help='Clean outputs directory')
    args = parser.parse_args()
    walk_and_merge(args.indir, args.outdir)

if __name__ == '__main__':
    main()
