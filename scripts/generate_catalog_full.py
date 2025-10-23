import argparse, csv, hashlib, os
from pathlib import Path
from datetime import datetime

def sha256_of_file(path, block_size=65536):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(block_size), b""):
            h.update(chunk)
    return h.hexdigest()

def guess_label_from_path(path):
    p = Path(path)
    parts = [x.lower() for x in p.parts]
    if "malicious" in parts or "malware" in parts:
        return "malicious"
    if "benign" in parts or "system32" in parts:
        return "benign"
    if "dummy" in parts:
        return "dummy"
    return "unknown"

def get_file_date(path):
    # Use file creation time as first_seen fallback
    try:
        t = Path(path).stat().st_ctime
        return datetime.utcfromtimestamp(t).strftime("%Y-%m-%d")
    except Exception:
        return datetime.utcnow().strftime("%Y-%m-%d")

def main(samples_dir, out_csv, source_tag="local"):
    samples_dir = Path(samples_dir)
    if not samples_dir.exists():
        print(f"[!] samples folder does not exist: {samples_dir}")
        return
    rows = []
    for root, dirs, files in os.walk(samples_dir):
        for fname in files:
            path = Path(root) / fname
            try:
                h = sha256_of_file(path)
            except Exception as e:
                print(f"[!] Error hashing {path}: {e}")
                continue
            label = guess_label_from_path(path)
            first_seen = get_file_date(path)
            rows.append({
                "sha256": h,
                "label": label,
                "source": source_tag,
                "first_seen": first_seen,
                "local_path": str(path.resolve()),
                "notes": ""
            })
    os.makedirs(Path(out_csv).parent, exist_ok=True)
    with open(out_csv, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=["sha256","label","source","first_seen","local_path","notes"])
        writer.writeheader()
        for r in rows:
            writer.writerow(r)
    print(f"[+] Wrote {len(rows)} entries to {out_csv}")

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--samples", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--source", default="local")
    args = ap.parse_args()
    main(args.samples, args.out, args.source)

