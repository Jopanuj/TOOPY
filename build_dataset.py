#!/usr/bin/env python3
import csv
import gzip
import io
import json
import os
import re
import sqlite3
import sys
import urllib.request

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SHARDS_DIR = os.path.join(ROOT_DIR, "db", "shards")
CATALOG_DIR = os.path.join(ROOT_DIR, "catalog")
DB_PATH = os.path.join(ROOT_DIR, "db", "secdict.db")

HEADERS = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64)"}
SHARD_SIZE = 20000

CAT_MAP = {
    "blackarch-recon": "recon-osint",
    "blackarch-osint": "recon-osint",
    "blackarch-scanner": "recon-osint",
    "blackarch-webapp": "webapp",
    "blackarch-fuzzer": "webapp",
    "blackarch-networking": "network-wireless",
    "blackarch-wireless": "network-wireless",
    "blackarch-sniffer": "network-wireless",
    "blackarch-bluetooth": "network-wireless",
    "blackarch-exploitation": "exploitation",
    "blackarch-backdoor": "exploitation",
    "blackarch-automation": "exploitation",
    "blackarch-cracker": "cracking-crypto",
    "blackarch-crypto": "cracking-crypto",
    "blackarch-reversing": "reversing-forensics",
    "blackarch-decompiler": "reversing-forensics",
    "blackarch-disassembler": "reversing-forensics",
    "blackarch-forensic": "reversing-forensics",
    "blackarch-binary": "reversing-forensics",
    "blackarch-mobile": "reversing-forensics",
}


def fetch_bytes(url, timeout=45):
    req = urllib.request.Request(url, headers=HEADERS)
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read()


def pull_blackarch(entries, catalog_buckets):
    print("[1/5] Fetching BlackArch tool index...")
    try:
        html = fetch_bytes("https://blackarch.org/tools.html").decode("utf-8", errors="ignore")
        rows = re.findall(r"<tr>\s*<td.*?</tr>", html, re.DOTALL)
        count = 0
        for row in rows:
            cols = re.findall(r"<td[^>]*>(.*?)</td>", row, re.DOTALL)
            if len(cols) < 4:
                continue
            name = re.sub(r"<.*?>", "", cols[0]).strip()
            desc = re.sub(r"<.*?>", "", cols[2]).strip()
            raw_cat = re.sub(r"<.*?>", "", cols[3]).strip()
            link_m = re.search(r'href=["\'](http[^"\']+)["\']', cols[4] if len(cols) > 4 else "")
            link = link_m.group(1) if link_m else f"https://blackarch.org/tools.html#{name}"

            if not name:
                continue

            cat_key = raw_cat.split()[0] if raw_cat else ""
            mapped = CAT_MAP.get(cat_key, "exploitation")
            tag = raw_cat.replace("blackarch-", "") if raw_cat else "cli"
            cmd = f"pkg install {name} || pacman -S {name}"

            item = {
                "name": name,
                "kind": "tool",
                "category": mapped,
                "summary": desc,
                "cmd": cmd,
                "tags": f"tool,blackarch,{tag}",
                "ref": link,
            }
            entries.append(item)
            catalog_buckets.setdefault(mapped, []).append(item)
            count += 1
        print(f"      Added {count:,} BlackArch CLI tools.")
    except Exception as e:
        print(f"      Skipped BlackArch ({e})")


def pull_exploitdb(entries):
    print("[2/5] Fetching Exploit-DB exploits & shellcodes...")
    urls = [
        ("exploit", "https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv"),
        ("shellcode", "https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_shellcodes.csv"),
    ]
    for kind, url in urls:
        try:
            raw = fetch_bytes(url, timeout=60).decode("utf-8", errors="ignore")
            reader = csv.DictReader(io.StringIO(raw))
            count = 0
            for row in reader:
                edb_id = (row.get("id") or "").strip()
                desc = (row.get("description") or "").strip()
                platform = (row.get("platform") or "multi").strip()
                etype = (row.get("type") or kind).strip()
                codes = (row.get("codes") or "").strip()
                if not edb_id or not desc:
                    continue
                entries.append({
                    "name": f"EDB-{edb_id}",
                    "kind": kind,
                    "category": etype,
                    "summary": desc,
                    "cmd": f"curl -sL https://www.exploit-db.com/raw/{edb_id} -o exploit_{edb_id}.txt",
                    "tags": f"{kind},{platform},{etype},{codes}".strip(","),
                    "ref": f"https://www.exploit-db.com/exploits/{edb_id}",
                })
                count += 1
            print(f"      Added {count:,} {kind}s.")
        except Exception as e:
            print(f"      Skipped {kind}s ({e})")


def pull_metasploit(entries):
    print("[3/5] Fetching Metasploit Framework module metadata...")
    url = "https://raw.githubusercontent.com/rapid7/metasploit-framework/master/db/modules_metadata_base.json"
    try:
        raw = fetch_bytes(url, timeout=60).decode("utf-8", errors="ignore")
        data = json.loads(raw)
        count = 0
        for _, mod in data.items():
            fullname = mod.get("fullname") or mod.get("name")
            desc = " ".join((mod.get("description") or "").split())
            mtype = mod.get("mod_type") or "module"
            refs = ",".join((mod.get("references") or [])[:4])
            if not fullname:
                continue
            entries.append({
                "name": fullname,
                "kind": "msf",
                "category": mtype,
                "summary": desc[:260],
                "cmd": f"msfconsole -q -x 'use {fullname}; info'",
                "tags": f"metasploit,{mtype},{refs}".strip(","),
                "ref": "https://github.com/rapid7/metasploit-framework",
            })
            count += 1
        print(f"      Added {count:,} Metasploit modules.")
    except Exception as e:
        print(f"      Skipped Metasploit ({e})")


def pull_nuclei(entries):
    print("[4/5] Fetching ProjectDiscovery Nuclei templates index...")
    url = "https://raw.githubusercontent.com/projectdiscovery/nuclei-templates/main/cves.json"
    try:
        raw = fetch_bytes(url, timeout=60).decode("utf-8", errors="ignore")
        count = 0
        for line in raw.splitlines():
            line = line.strip()
            if not line:
                continue
            obj = json.loads(line)
            cid = obj.get("ID") or ""
            info = obj.get("Info") or {}
            name = info.get("Name") or cid
            sev = info.get("Severity") or "info"
            desc = " ".join((info.get("Description") or name).split())
            fpath = obj.get("file_path") or ""
            if not cid:
                continue
            entries.append({
                "name": f"nuclei/{cid}",
                "kind": "nuclei",
                "category": sev,
                "summary": f"[{sev.upper()}] {name} - {desc[:200]}",
                "cmd": f"nuclei -id {cid} -u https://target.tld",
                "tags": f"nuclei,cve,{sev},{cid}",
                "ref": f"https://github.com/projectdiscovery/nuclei-templates/blob/main/{fpath}",
            })
            count += 1
        print(f"      Added {count:,} Nuclei CVE templates.")
    except Exception as e:
        print(f"      Skipped Nuclei ({e})")


def pull_epss_cves(entries, target_total=115000):
    needed = max(0, target_total - len(entries))
    if needed == 0:
        return
    print(f"[5/5] Fetching FIRST EPSS vulnerability index ({needed:,} records)...")
    urls = [
        "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz",
        "https://epss.cyentia.com/epss_scores-current.csv.gz",
    ]
    raw_gz = None
    for u in urls:
        try:
            raw_gz = fetch_bytes(u, timeout=60)
            if raw_gz:
                break
        except Exception:
            continue

    if not raw_gz:
        print("      Skipped EPSS feed.")
        return

    try:
        text = gzip.decompress(raw_gz).decode("utf-8", errors="ignore")
        rows = []
        for line in text.splitlines():
            if line.startswith("#") or line.startswith("cve,"):
                continue
            parts = line.split(",")
            if len(parts) >= 3:
                rows.append((parts[0], float(parts[1]), float(parts[2])))

        rows.sort(key=lambda x: x[1], reverse=True)
        count = 0
        for cve_id, score, pct in rows[:needed]:
            pct_str = f"{pct * 100:.1f}%"
            prob_str = f"{score * 100:.2f}%"
            entries.append({
                "name": cve_id,
                "kind": "cve",
                "category": "vulnerability",
                "summary": f"Exploitation probability: {prob_str} (Percentile: {pct_str})",
                "cmd": f"secdict {cve_id} || nuclei -id {cve_id}",
                "tags": f"cve,epss,{cve_id}",
                "ref": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
            })
            count += 1
        print(f"      Added {count:,} prioritized CVE records.")
    except Exception as e:
        print(f"      Failed parsing EPSS feed ({e})")


def write_catalog_markdown(catalog_buckets, total_entries):
    os.makedirs(CATALOG_DIR, exist_ok=True)
    index_lines = [
        "# Security Tool & Exploit Catalog",
        "",
        f"Total indexed records across repository shards: **{total_entries:,}**",
        "",
        "## Browsable Tool Categories",
        "",
    ]

    for cat, items in sorted(catalog_buckets.items()):
        fname = f"{cat}.md"
        index_lines.append(f"- [{cat}]({fname}) ({len(items):,} tools)")
        md_path = os.path.join(CATALOG_DIR, fname)
        with open(md_path, "w", encoding="utf-8") as f:
            f.write(f"# Category: {cat} ({len(items):,} tools)\n\n")
            f.write("| Tool | Summary | Command | Source |\n")
            f.write("| :--- | :--- | :--- | :--- |\n")
            for it in sorted(items, key=lambda x: x["name"].lower()):
                name = it["name"].replace("|", "/")
                summ = it["summary"].replace("|", "/").replace("\n", " ")
                cmd = it["cmd"].replace("|", "\\|")
                ref = it["ref"]
                f.write(f"| **{name}** | {summ} | `{cmd}` | [link]({ref}) |\n")

    with open(os.path.join(CATALOG_DIR, "INDEX.md"), "w", encoding="utf-8") as f:
        f.write("\n".join(index_lines) + "\n")


def write_shards(entries):
    os.makedirs(SHARDS_DIR, exist_ok=True)
    for old in os.listdir(SHARDS_DIR):
        if old.endswith(".jsonl.gz"):
            os.remove(os.path.join(SHARDS_DIR, old))

    shard_idx = 1
    for i in range(0, len(entries), SHARD_SIZE):
        chunk = entries[i:i + SHARD_SIZE]
        shard_path = os.path.join(SHARDS_DIR, f"part_{shard_idx:02d}.jsonl.gz")
        with gzip.open(shard_path, "wt", encoding="utf-8") as gz:
            for item in chunk:
                gz.write(json.dumps(item, ensure_ascii=False) + "\n")
        shard_idx += 1
    print(f"[+] Wrote {shard_idx - 1} compressed data shards to db/shards/")


def build_sqlite_from_shards():
    if os.path.exists(DB_PATH):
        os.remove(DB_PATH)
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("PRAGMA synchronous = OFF;")
    cur.execute("PRAGMA journal_mode = MEMORY;")
    cur.execute(
        "CREATE VIRTUAL TABLE items USING fts5(name, kind, category, summary, cmd, tags, ref);"
    )

    shards = sorted(f for f in os.listdir(SHARDS_DIR) if f.endswith(".jsonl.gz"))
    total = 0
    batch = []
    for s in shards:
        spath = os.path.join(SHARDS_DIR, s)
        with gzip.open(spath, "rt", encoding="utf-8") as gz:
            for line in gz:
                obj = json.loads(line)
                batch.append((
                    obj["name"],
                    obj["kind"],
                    obj["category"],
                    obj["summary"],
                    obj["cmd"],
                    obj["tags"],
                    obj["ref"],
                ))
                if len(batch) >= 10000:
                    cur.executemany("INSERT INTO items VALUES (?, ?, ?, ?, ?, ?, ?);", batch)
                    total += len(batch)
                    batch.clear()
    if batch:
        cur.executemany("INSERT INTO items VALUES (?, ?, ?, ?, ?, ?, ?);", batch)
        total += len(batch)

    conn.commit()
    conn.close()
    print(f"[+] Built local SQLite FTS5 index ({total:,} entries) at db/secdict.db")


def main():
    if "--from-shards" in sys.argv:
        build_sqlite_from_shards()
        return

    entries = []
    catalog_buckets = {}
    pull_blackarch(entries, catalog_buckets)
    pull_exploitdb(entries)
    pull_metasploit(entries)
    pull_nuclei(entries)
    pull_epss_cves(entries, target_total=115000)

    print(f"[+] Total harvested entries: {len(entries):,}")
    write_catalog_markdown(catalog_buckets, len(entries))
    write_shards(entries)
    build_sqlite_from_shards()


if __name__ == "__main__":
    main()
