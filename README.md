# 🦉 Strix — static malware triage & analysis framework

Strix safely dissects a suspicious file and tells you **what it is, what it can
do, and how worried you should be** — *without ever running it*. Everything it
does is read-only static analysis: parsing headers, hashing, measuring entropy,
extracting strings and IOCs, mapping imported APIs to MITRE ATT&CK, and matching
heuristic signatures.

> **Defensive by construction.** Strix never executes, unpacks-and-runs, or
> otherwise detonates a sample. It is a triage tool for SOC analysts, incident
> responders, and malware researchers. It ships with *inert* synthetic test
> specimens (valid headers + suspicious static features, zero executable logic)
> so you can see detection work without touching real malware.

```
╔══════════════════════════════════════════════════════════════╗
║  STRIX — static malware triage report                        ║
╚══════════════════════════════════════════════════════════════╝

  File      : specimen_suspicious.exe.bin
  Type      : PE / MZ executable  (pe, x86-64)
  Size      : 6,144 bytes    entropy 6.860/8.0
  SHA256    : 4950d185174185ab5b6caff04dd9639d...
  imphash   : 29b54bbefe3cfd009c4d9742cdd0a19f

  VERDICT   :  MALICIOUS
  THREAT    : ██████████████████████████████ 100/100
```

## Why Strix

- **Zero required dependencies.** PE, ELF, and Mach-O are parsed in *pure
  Python*. Drop it on an air-gapped triage box and it just runs (Python 3.9+).
- **Explainable scoring.** Every point of the 0–100 threat score traces back to
  a concrete finding with evidence — no black box.
- **ATT&CK-native.** Findings carry MITRE technique IDs, so you can pivot a
  report by adversary behavior.
- **Bring-your-own signatures.** A built-in YARA-flavored rule engine (no native
  library needed) ships with curated rules and takes your own.
- **Three output formats.** Colorized console, machine-readable JSON (for
  SIEM/pipelines), and a self-contained HTML report.

## Install

```bash
# from the project root
pip install -e .
# optional accelerators (Strix works fine without them):
pip install -e ".[yara,fuzzy,dev]"
```

Or run straight from the source tree with no install:

```bash
python -m strix scan <file>
```

## Usage

```bash
# triage a single file (colorized console report)
strix scan suspicious.bin

# machine-readable JSON for a pipeline / SIEM
strix scan suspicious.bin -f json -o report.json

# a shareable, self-contained HTML report
strix scan suspicious.bin -f html -o report.html --strings

# sweep a directory, show only files scoring >= 25, one line each
strix scan ./incoming/ --recursive --min-score 25 --quiet

# load your own signature rules alongside the bundled set
strix scan sample.bin --rules ./my_rules/ --rules extra.strx

# list the loaded detection rules
strix rules -v

# cluster files by fuzzy-hash similarity
strix compare a.bin b.bin c.bin
```

**Exit codes:** `0` clean (below `--min-score`), `1` something detected at/above
the threshold, `2` error — convenient for CI gates and scripted pipelines.

## What it analyzes

| Stage | Output |
|-------|--------|
| **File typing** | magic-byte identification (PE/ELF/Mach-O/archive/document/script) |
| **Hashing** | MD5 / SHA-1 / SHA-256, PE `imphash`, and a self-contained fuzzy hash for clustering |
| **Entropy** | whole-file and per-section Shannon entropy → packing/encryption detection |
| **Header parsing** | sections/segments, imports, exports, data directories, TLS callbacks, signing, timestamps, overlay |
| **Structural heuristics** | RWX / W^X sections, entry point outside code, missing ASLR/DEP, sparse-imports-plus-packing, timestomp/forged timestamps |
| **Capability mapping** | imported APIs → behaviors (injection, persistence, keylogging, C2, ransomware, discovery…) → ATT&CK |
| **Strings & IOCs** | ASCII + UTF-16LE strings; URLs, IPs, domains, emails, registry keys, paths, crypto-wallet addresses, LOLBins, PowerShell cradles, sandbox/VM awareness |
| **Signatures** | YARA-flavored rule engine with bundled ransomware / injection / C2 / stealer / packer rules |
| **Scoring** | saturating 0–100 threat score + verdict (clean → malicious) |

## Signature rule language

Strix rules live in `*.strx` files and read like a practical subset of YARA:

```
rule Ransom_ShadowCopy_Destruction {
    meta:
        severity    = critical
        category    = ransomware
        attack      = T1490, T1486
        description = "Destroys recovery options — hallmark ransomware precursor"
    strings:
        $vss  = "vssadmin delete shadows" nocase
        $wmic = "wmic shadowcopy delete" nocase
        $hex  = { 6A 40 68 00 30 00 00 }
        $re   = /\.(locky|wncry|crypt)/ nocase
    condition:
        any of them
}
```

Supported:

- **String modifiers:** `nocase`, `wide`, `ascii`, `fullword`, `xor`
- **Hex patterns** with `??` / nibble wildcards (`5?`, `?F`) and jumps (`[4-6]`)
- **Regex patterns** `/.../` with `nocase`
- **Conditions:** `$id`, `#id > N` (counts), `N of them`, `all of them`,
  `any of them`, `N of ($a,$b,$pre*)`, boolean `and`/`or`/`not` with parentheses,
  and the special terms `filesize` and `entropy` with numeric comparisons
  (`KB`/`MB`/`GB` suffixes).

If the real `yara-python` is installed, you can keep using it too — the engines
are complementary.

## Architecture

```
strix/
  core/        model · filetype · hashing · entropy · analyzer (orchestrator)
  parsers/     pure-python pe · elf · macho  →  format-neutral ParsedBinary
  extractors/  strings · iocs
  detect/      capabilities (API→ATT&CK) · heuristics · engine (signatures)
               rules/*.strx  (bundled detection signatures)
  report/      console · jsonout · html
  cli.py       scan / rules / compare
tests/         pytest suite + inert synthetic fixtures
```

The whole pipeline writes into one `AnalysisReport`; renderers only read from
it, so adding an output format never touches analysis logic.

## Testing

```bash
pytest -q                      # 17 tests, pure-python, no sample malware needed
python tests/fixtures.py samples   # (re)generate the inert test specimens
```

The fixtures are built by `tests/fixtures.py`: they emit files with a valid PE
header, an import table naming injection/download APIs, a high-entropy section,
and ransom-note / C2 strings — but the code section is filler bytes. **Nothing in
them can execute.** They exist purely to exercise the analyzer deterministically.

## Scope & honesty

Strix does *static* triage. It will not:

- unpack, emulate, or run anything;
- replace a full disassembler, a sandbox, or a seasoned reverse engineer;
- give a guaranteed malicious/benign label — the score is a prioritization aid.

Use it to triage fast, cluster, and decide what deserves deeper analysis.

## License

MIT.
