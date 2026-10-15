# secdict

Offline command-line index and GitHub catalog covering 110,000+ security utilities, BlackArch packages, Exploit-DB scripts, shellcodes, Metasploit modules, Nuclei templates, and high-risk CVE records.

## Features

- **110,000+ Indexed Records:** Aggregates CLI tools, exploits, shellcodes, Metasploit modules, and vulnerability templates into compressed repository shards (`db/shards/`).
- **Sub-15ms Terminal Search:** Uses Python's native SQLite FTS5 engine with zero external pip dependencies.
- **GitHub Browsable Catalog:** Browse categorized CLI tool tables directly on GitHub under `catalog/INDEX.md`.
- **Termux & Linux Native:** Installs directly into `$PREFIX/bin` on Termux or `/usr/local/bin` on standard Linux distributions.

## Installation (Termux / Linux)

```bash
cd secdict
bash install.sh
```

## CLI Usage

```bash
# Search across all 110,000+ entries
secdict nmap
secdict eternalblue
secdict wordpress sqli

# Filter by specific record type (tool, exploit, shellcode, msf, nuclei, cve)
secdict smb --type tool
secdict apache --type exploit -n 50
secdict ssh --type msf

# Launch interactive search shell
secdict -i

# View database record counts
secdict --stats

# Refresh all feeds from upstream sources
secdict --sync
```

## Repository Structure

```
.
├── bin/
│   └── secdict
├── catalog/
├── db/
│   └── shards/
├── scripts/
│   └── build_dataset.py
├── install.sh
├── LICENSE
└── README.md
```

## License

MIT License. Copyright (c) 2026 TL Coding.
