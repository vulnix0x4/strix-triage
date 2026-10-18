"""Indicator-of-compromise extraction from recovered strings.

Pulls network, host, and crypto indicators plus a curated set of
"suspicious-string" hints (LOLBins, PowerShell switches, AV/sandbox product
names). Private/benign noise (localhost, RFC1918, common Microsoft domains) is
filtered so the report highlights what matters.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Iterable

# --- patterns --------------------------------------------------------------
RE = {
    "url": re.compile(r"\b(?:https?|ftp|ftps)://[^\s\"'<>\\)]{4,2048}", re.I),
    "ipv4": re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b"),
    "ipv6": re.compile(r"\b(?:[A-F0-9]{1,4}:){2,7}[A-F0-9]{1,4}\b", re.I),
    "email": re.compile(r"\b[A-Z0-9._%+\-]{1,64}@[A-Z0-9.\-]{1,255}\.[A-Z]{2,24}\b", re.I),
    "domain": re.compile(r"\b(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}\b", re.I),
    "win_path": re.compile(r"\b[A-Za-z]:\\(?:[^\\/:*?\"<>|\r\n]+\\){0,12}[^\\/:*?\"<>|\r\n]*"),
    "unc_path": re.compile(r"\\\\[A-Za-z0-9._\-]+\\[^\\/:*?\"<>|\r\n]+"),
    "registry": re.compile(r"\b(?:HKLM|HKCU|HKCR|HKU|HKEY_[A-Z_]+)\\[^\r\n\"]{2,256}", re.I),
    "guid": re.compile(r"\{?[0-9A-F]{8}-(?:[0-9A-F]{4}-){3}[0-9A-F]{12}\}?", re.I),
    "btc": re.compile(r"\b(?:bc1[ac-hj-np-z02-9]{11,71}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b"),
    "eth": re.compile(r"\b0x[a-fA-F0-9]{40}\b"),
    "xmr": re.compile(r"\b4[0-9AB][0-9a-zA-Z]{93}\b"),
    "pdb": re.compile(r"[A-Za-z]:\\[^\r\n]{1,200}\.pdb", re.I),
    "user_agent": re.compile(r"(?:Mozilla|curl|Wget|python-requests|Go-http-client)/[0-9][^\r\n\"']{0,120}", re.I),
    "base64_blob": re.compile(r"\b[A-Za-z0-9+/]{120,}={0,2}\b"),
}

# Noise we never want to treat as an exfil/C2 indicator.
_BENIGN_DOMAINS = {
    "microsoft.com", "windows.com", "windowsupdate.com", "msftncsi.com",
    "schemas.microsoft.com", "w3.org", "verisign.com", "digicert.com",
    "example.com", "example.org", "localhost", "google.com", "gstatic.com",
    "comodoca.com", "sectigo.com", "entrust.net", "symcb.com", "symcd.com",
    "apple.com", "icloud.com", "gnu.org", "python.org",
}
_TLD_HINT = re.compile(r"\.(?:com|net|org|io|ru|cn|top|xyz|info|biz|su|tk|onion|cc|me|pw|gg|app|dev|co|us|uk|de)$", re.I)

# High-signal "suspicious string" hints → (label, note)
SUSPICIOUS_STRINGS = {
    "powershell": "PowerShell invocation",
    "-enc ": "PowerShell encoded command",
    "-encodedcommand": "PowerShell encoded command",
    "-nop ": "PowerShell -NoProfile",
    "-w hidden": "hidden window",
    "-windowstyle hidden": "hidden window",
    "iex(": "PowerShell Invoke-Expression",
    "invoke-expression": "PowerShell Invoke-Expression",
    "downloadstring": "remote download (Net.WebClient)",
    "downloadfile": "remote file download",
    "frombase64string": "base64 decode at runtime",
    "cmd.exe /c": "command shell exec",
    "rundll32": "LOLBin rundll32",
    "regsvr32": "LOLBin regsvr32 (squiblydoo)",
    "mshta": "LOLBin mshta",
    "certutil": "LOLBin certutil (download/decode)",
    "bitsadmin": "LOLBin bitsadmin transfer",
    "wscript.shell": "WScript.Shell automation",
    "schtasks": "scheduled task persistence",
    "vssadmin delete": "shadow-copy deletion (ransomware)",
    "wbadmin delete": "backup deletion (ransomware)",
    "bcdedit": "boot config tamper (ransomware)",
    "net user": "account enumeration/creation",
    "net localgroup administrators": "privilege enumeration",
    "reg add": "registry persistence",
    "currentversion\\run": "Run-key persistence",
    "/etc/crontab": "cron persistence (linux)",
    "ld_preload": "LD_PRELOAD hijack (linux)",
    ".onion": "Tor hidden service",
    "wannacry": "known ransomware family string",
    "your files have been encrypted": "ransom note text",
    "bitcoin": "ransom/payment reference",
}

# AV / sandbox / VM product names → sandbox-evasion signal
EVASION_STRINGS = [
    "vmware", "virtualbox", "vboxservice", "qemu", "xen", "sandboxie",
    "wine", "cuckoo", "joeboxserver", "vmtoolsd", "vboxtray",
    "sbiedll.dll", "dbghelp.dll", "procmon", "wireshark", "ollydbg",
    "x64dbg", "ida ", "immunity", "windbg",
]


@dataclass
class IOCSet:
    urls: list[str] = field(default_factory=list)
    ipv4: list[str] = field(default_factory=list)
    ipv6: list[str] = field(default_factory=list)
    emails: list[str] = field(default_factory=list)
    domains: list[str] = field(default_factory=list)
    win_paths: list[str] = field(default_factory=list)
    unc_paths: list[str] = field(default_factory=list)
    registry: list[str] = field(default_factory=list)
    guids: list[str] = field(default_factory=list)
    crypto: list[str] = field(default_factory=list)
    pdb: list[str] = field(default_factory=list)
    user_agents: list[str] = field(default_factory=list)
    suspicious: list[str] = field(default_factory=list)  # "label: evidence"
    evasion: list[str] = field(default_factory=list)

    def total(self) -> int:
        return sum(len(v) for v in vars(self).values() if isinstance(v, list))

    def to_dict(self):
        return {k: v for k, v in vars(self).items() if v}


def _is_private_ip(ip: str) -> bool:
    try:
        a, b, *_ = (int(x) for x in ip.split("."))
    except ValueError:
        return True
    if a in (10, 127, 0) or (a == 192 and b == 168) or (a == 172 and 16 <= b <= 31):
        return True
    if a == 169 and b == 254:
        return True
    if a >= 224:  # multicast/reserved
        return True
    return False


def _reg_domain(host: str) -> str:
    parts = host.lower().strip(".").split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else host.lower()


def _dedup(seq: Iterable[str], cap: int = 500) -> list[str]:
    seen, out = set(), []
    for x in seq:
        if x not in seen:
            seen.add(x)
            out.append(x)
            if len(out) >= cap:
                break
    return out


def extract(strings: Iterable[str]) -> IOCSet:
    s = IOCSet()
    url_hosts = set()
    for text in strings:
        low = text.lower()

        for u in RE["url"].findall(text):
            s.urls.append(u)
            m = re.search(r"://([^/:\s]+)", u)
            if m:
                url_hosts.add(m.group(1).lower())
        for ip in RE["ipv4"].findall(text):
            if not _is_private_ip(ip):
                s.ipv4.append(ip)
        for ip in RE["ipv6"].findall(text):
            if ip.count(":") >= 3 and ip.lower() not in ("::", "::1"):
                s.ipv6.append(ip)
        s.emails.extend(RE["email"].findall(text))
        s.win_paths.extend(RE["win_path"].findall(text))
        s.unc_paths.extend(RE["unc_path"].findall(text))
        s.registry.extend(RE["registry"].findall(text))
        s.pdb.extend(RE["pdb"].findall(text))
        s.user_agents.extend(RE["user_agent"].findall(text))
        s.guids.extend(RE["guid"].findall(text))
        for pat in ("btc", "eth", "xmr"):
            for v in RE[pat].findall(text):
                s.crypto.append(f"{pat}:{v}")

        # domains: keep only those that look like real hostnames and aren't benign
        for d in RE["domain"].findall(text):
            dl = d.lower().rstrip(".")
            if not _TLD_HINT.search(dl):
                continue
            if _reg_domain(dl) in _BENIGN_DOMAINS or dl in _BENIGN_DOMAINS:
                continue
            if dl.endswith((".dll", ".exe", ".sys", ".tmp", ".dat", ".bin", ".node")):
                continue
            s.domains.append(dl)

        for needle, label in SUSPICIOUS_STRINGS.items():
            if needle in low:
                snippet = text.strip()
                if len(snippet) > 120:
                    snippet = snippet[:117] + "..."
                s.suspicious.append(f"{label}: {snippet}")
        for needle in EVASION_STRINGS:
            if needle in low:
                s.evasion.append(f"{needle} ({text.strip()[:80]})")

    # domains that merely echo a URL host are redundant
    s.domains = [d for d in s.domains if d not in url_hosts]

    for attr in vars(s):
        val = getattr(s, attr)
        if isinstance(val, list):
            setattr(s, attr, _dedup(val))
    return s
