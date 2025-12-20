import requests
import argparse
import os
import json
from typing import List

PAGE_SIZE = 1000  # safe, explicit

def parse_args():
    parser = argparse.ArgumentParser(
        description="Enumerate and dump readable Supabase tables using an anon JWT (read-only)."
    )
    parser.add_argument("--url", help="Supabase project URL (https://xxxx.supabase.co)")
    parser.add_argument("--apikey", help="Supabase anon API key")
    parser.add_argument("--jwt", help="JWT token (Bearer)")
    parser.add_argument("--out", default="dump", help="Output directory")
    parser.add_argument("--page-size", type=int, default=PAGE_SIZE)
    return parser.parse_args()

def get_config(args):
    url = args.url or os.getenv("SUPABASE_URL")
    apikey = args.apikey or os.getenv("SUPABASE_APIKEY")
    jwt = args.jwt or os.getenv("SUPABASE_JWT")

    if not all([url, apikey, jwt]):
        raise SystemExit(
            "Missing configuration. Provide --url, --apikey, --jwt "
            "or set SUPABASE_URL, SUPABASE_APIKEY, SUPABASE_JWT"
        )

    return url.rstrip("/"), apikey, jwt

def get_paths(base_url, headers) -> List[str]:
    r = requests.get(f"{base_url}/rest/v1/", headers=headers, timeout=10)
    r.raise_for_status()

    return [
        p.strip("/")
        for p in r.json().get("paths", {}).keys()
        if not p.startswith("/rpc") and p != "/"
    ]

def dump_table(base_url, table, headers, page_size):
    all_rows = []
    offset = 0

    while True:
        url = f"{base_url}/rest/v1/{table}?limit={page_size}&offset={offset}"
        r = requests.get(url, headers=headers, timeout=10)

        if r.status_code != 200:
            return None, r.status_code

        chunk = r.json()
        all_rows.extend(chunk)

        if len(chunk) < page_size:
            break

        offset += page_size

    return all_rows, 200

def main():
    args = parse_args()
    base_url, apikey, jwt = get_config(args)

    headers = {
        "apikey": apikey,
        "Authorization": f"Bearer {jwt}",
    }

    os.makedirs(args.out, exist_ok=True)

    print("[*] Enumerating exposed tables...")
    tables = get_paths(base_url, headers)

    print(f"[+] Found {len(tables)} tables\n")

    summary = []

    for table in tables:
        print(f"[*] Dumping table: {table}")
        rows, status = dump_table(base_url, table, headers, args.page_size)

        if status == 200 and rows is not None:
            path = os.path.join(args.out, f"{table}.json")
            with open(path, "w") as f:
                json.dump(rows, f, indent=2)

            print(f"    [+] Dumped {len(rows)} rows → {path}")
            summary.append({
                "table": table,
                "readable": True,
                "rows": len(rows),
                "file": path,
            })
        else:
            print(f"    [-] Blocked (HTTP {status})")
            summary.append({
                "table": table,
                "readable": False,
                "status_code": status,
            })

    with open(os.path.join(args.out, "_summary.json"), "w") as f:
        json.dump(summary, f, indent=2)

    print("\n[+] Done. Summary written to dump/_summary.json")

if __name__ == "__main__":
    main()
