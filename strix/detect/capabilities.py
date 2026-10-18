"""Map imported API symbols to behavioral capabilities and MITRE ATT&CK.

Each rule matches an imported function name (case-insensitive substring) and
describes a *capability* — something the binary is able to do. On its own a
capability is rarely conclusive (lots of benign software calls ``CreateFileW``),
so weights are conservative; the scoring model and the signature engine do the
heavier lifting by combining capabilities that co-occur in malware.
"""

from __future__ import annotations

from dataclasses import dataclass

from ..core.model import Severity


@dataclass(frozen=True)
class CapRule:
    needle: str            # lowercase substring matched against the symbol name
    capability: str
    severity: Severity
    attack: tuple[str, ...]
    note: str = ""


# fmt: off
CAP_RULES: list[CapRule] = [
    # --- process injection / manipulation -------------------------------
    CapRule("virtualallocex", "remote memory allocation", Severity.HIGH, ("T1055",), "allocate memory in another process"),
    CapRule("writeprocessmemory", "write to remote process", Severity.HIGH, ("T1055",), "classic injection primitive"),
    CapRule("createremotethread", "remote thread creation", Severity.HIGH, ("T1055.002",), "execute code in another process"),
    CapRule("ntmapviewofsection", "section mapping injection", Severity.HIGH, ("T1055.012",), "map section into remote process"),
    CapRule("ntunmapviewofsection", "process hollowing primitive", Severity.HIGH, ("T1055.012",), "hollowing / RunPE"),
    CapRule("setthreadcontext", "thread context hijack", Severity.HIGH, ("T1055.003",), "hijack execution via context"),
    CapRule("queueuserapc", "APC injection", Severity.HIGH, ("T1055.004",), "async procedure call injection"),
    CapRule("rtlcreateuserthread", "remote thread (native)", Severity.HIGH, ("T1055",)),
    CapRule(" zwwritevirtualmemory", "write remote memory (native)", Severity.HIGH, ("T1055",)),
    CapRule("setwindowshookex", "global hook / keylogging", Severity.HIGH, ("T1056.001", "T1055"), "keyboard/mouse hook"),
    CapRule("openprocess", "open another process", Severity.LOW, ("T1055",)),

    # --- dynamic code / anti-analysis -----------------------------------
    CapRule("loadlibrary", "dynamic library load", Severity.LOW, ("T1129",)),
    CapRule("getprocaddress", "dynamic API resolution", Severity.MEDIUM, ("T1027", "T1106"), "resolve APIs at runtime (obfuscation)"),
    CapRule("ldrloaddll", "native library load", Severity.MEDIUM, ("T1129",)),
    CapRule("ldrgetprocedureaddress", "native API resolution", Severity.MEDIUM, ("T1106",)),
    CapRule("isdebuggerpresent", "debugger check", Severity.MEDIUM, ("T1622",), "anti-debug"),
    CapRule("checkremotedebuggerpresent", "remote debugger check", Severity.MEDIUM, ("T1622",)),
    CapRule("ntqueryinformationprocess", "process info query (anti-debug)", Severity.MEDIUM, ("T1622",)),
    CapRule("outputdebugstring", "debugger-trap", Severity.LOW, ("T1622",)),
    CapRule("getticktick", "timing check", Severity.LOW, ("T1497.003",)),
    CapRule("queryperformancecounter", "timing-based evasion", Severity.LOW, ("T1497.003",)),
    CapRule("gettickcount", "timing check (sleep/stall)", Severity.LOW, ("T1497.003",)),
    CapRule("ntdelayexecution", "execution stall (sandbox stall)", Severity.LOW, ("T1497.003",)),
    CapRule("findwindow", "analysis-tool window check", Severity.MEDIUM, ("T1497.001",), "look for debugger/AV windows"),
    CapRule("blockinput", "block user input", Severity.MEDIUM, ("T1056",)),

    # --- persistence -----------------------------------------------------
    CapRule("regsetvalue", "registry write (persistence)", Severity.MEDIUM, ("T1547.001", "T1112")),
    CapRule("regcreatekey", "registry key creation", Severity.LOW, ("T1112",)),
    CapRule("createservice", "service creation (persistence)", Severity.HIGH, ("T1543.003",)),
    CapRule("openscmanager", "service control access", Severity.MEDIUM, ("T1543.003",)),
    CapRule("startservice", "service start", Severity.LOW, ("T1543.003",)),
    CapRule("schtask", "scheduled task (persistence)", Severity.MEDIUM, ("T1053.005",)),
    CapRule("createprocess", "child process launch", Severity.LOW, ("T1106",)),
    CapRule("shellexecute", "shell execution", Severity.MEDIUM, ("T1059",)),
    CapRule("winexec", "command execution", Severity.MEDIUM, ("T1059",)),

    # --- credential / data theft ----------------------------------------
    CapRule("cryptunprotectdata", "DPAPI decrypt (credential theft)", Severity.HIGH, ("T1555.004",), "decrypt browser/Windows secrets"),
    CapRule("getkeystate", "keystroke capture", Severity.HIGH, ("T1056.001",)),
    CapRule("getasynckeystate", "keylogging", Severity.HIGH, ("T1056.001",)),
    CapRule("getforegroundwindow", "active-window tracking (keylogger)", Severity.MEDIUM, ("T1056.001",)),
    CapRule("bitblt", "screen capture", Severity.MEDIUM, ("T1113",)),
    CapRule("getclipboarddata", "clipboard theft", Severity.MEDIUM, ("T1115",)),
    CapRule("enumprocesses", "process enumeration", Severity.LOW, ("T1057",)),
    CapRule("createtoolhelp32snapshot", "process/module enumeration", Severity.LOW, ("T1057", "T1518.001")),
    CapRule("samqueryinformation", "SAM access", Severity.HIGH, ("T1003.002",)),
    CapRule("lsaretrieveprivatedata", "LSA secret access", Severity.HIGH, ("T1003.004",)),

    # --- networking / C2 -------------------------------------------------
    CapRule("internetopen", "WinINet HTTP", Severity.LOW, ("T1071.001",)),
    CapRule("internetconnect", "HTTP connect", Severity.LOW, ("T1071.001",)),
    CapRule("httpopenrequest", "HTTP request", Severity.LOW, ("T1071.001",)),
    CapRule("httpsendrequest", "HTTP send (C2/exfil)", Severity.MEDIUM, ("T1071.001", "T1041")),
    CapRule("internetreadfile", "HTTP download", Severity.MEDIUM, ("T1105",)),
    CapRule("urldownloadtofile", "URL download-to-disk", Severity.HIGH, ("T1105",), "download & stage payload"),
    CapRule("winhttpsendrequest", "WinHTTP C2", Severity.MEDIUM, ("T1071.001",)),
    CapRule("wsastartup", "raw sockets init", Severity.LOW, ("T1095",)),
    CapRule("connect", "socket connect", Severity.LOW, ("T1095",)),
    CapRule("send", "socket send", Severity.LOW, ("T1095",)),
    CapRule("recv", "socket recv", Severity.LOW, ("T1095",)),
    CapRule("gethostbyname", "DNS resolution", Severity.LOW, ("T1071.004",)),
    CapRule("dnsquery", "DNS query (possible DGA/tunnel)", Severity.LOW, ("T1071.004",)),

    # --- crypto / ransomware --------------------------------------------
    CapRule("cryptencrypt", "data encryption", Severity.MEDIUM, ("T1486",), "possible ransomware"),
    CapRule("cryptgenkey", "crypto key generation", Severity.LOW, ("T1486",)),
    CapRule("cryptacquirecontext", "crypto provider access", Severity.LOW, ("T1486",)),
    CapRule("bcryptencrypt", "CNG encryption", Severity.MEDIUM, ("T1486",)),
    CapRule("cryptdecrypt", "data decryption", Severity.LOW, ("T1140",)),

    # --- discovery -------------------------------------------------------
    CapRule("getadaptersinfo", "network config discovery", Severity.LOW, ("T1016",)),
    CapRule("getcomputername", "host discovery", Severity.LOW, ("T1082",)),
    CapRule("getusername", "user discovery", Severity.LOW, ("T1033",)),
    CapRule("getsysteminfo", "system info discovery", Severity.LOW, ("T1082",)),
    CapRule("getvolumeinformation", "volume/serial discovery (fingerprint)", Severity.LOW, ("T1082",)),
    CapRule("netuseradd", "account creation", Severity.MEDIUM, ("T1136.001",)),

    # --- defense evasion -------------------------------------------------
    CapRule("adjusttokenprivileges", "privilege adjustment", Severity.MEDIUM, ("T1134.001",)),
    CapRule("setfiletime", "timestomping", Severity.MEDIUM, ("T1070.006",), "anti-forensic timestamp edit"),
    CapRule("deletefile", "file deletion", Severity.LOW, ("T1070.004",)),
    CapRule("ntsetinformationthread", "hide thread from debugger", Severity.MEDIUM, ("T1562",)),
    CapRule("virtualprotect", "memory protection change (RWX)", Severity.MEDIUM, ("T1055",), "make memory executable"),

    # --- linux / unix capabilities --------------------------------------
    CapRule("ptrace", "anti-debug / process trace (unix)", Severity.MEDIUM, ("T1622",)),
    CapRule("dlopen", "dynamic library load (unix)", Severity.LOW, ("T1129",)),
    CapRule("dlsym", "dynamic symbol resolution (unix)", Severity.MEDIUM, ("T1106",)),
    CapRule("fork", "process fork (unix)", Severity.INFO, ()),
    CapRule("execve", "process exec (unix)", Severity.LOW, ("T1059.004",)),
    CapRule("setuid", "privilege change (unix)", Severity.MEDIUM, ("T1548",)),
    CapRule("chmod", "file mode change (unix)", Severity.LOW, ("T1222.002",)),
    CapRule("mprotect", "memory protection change (unix)", Severity.MEDIUM, ("T1055",)),
    CapRule("inotify", "filesystem monitoring (unix)", Severity.LOW, ()),
    CapRule("task_for_pid", "process access (macOS injection)", Severity.HIGH, ("T1055",)),
    CapRule("mach_vm_write", "remote memory write (macOS)", Severity.HIGH, ("T1055",)),
]
# fmt: on


def analyze(imports: list[str]):
    """Return ``(capabilities, grouped)`` where ``capabilities`` is a list of
    ``(CapRule, symbol)`` hits and ``grouped`` maps capability→evidence list."""

    hits: list[tuple[CapRule, str]] = []
    grouped: dict[str, dict] = {}
    # symbol names only (strip the "lib." prefix for matching)
    for full in imports:
        sym = full.split(".", 1)[-1].lower()
        for rule in CAP_RULES:
            if rule.needle in sym:
                hits.append((rule, full))
                g = grouped.setdefault(rule.capability, {
                    "severity": rule.severity.label,
                    "attack": list(rule.attack),
                    "note": rule.note,
                    "symbols": [],
                })
                if full not in g["symbols"]:
                    g["symbols"].append(full)
    return hits, grouped
