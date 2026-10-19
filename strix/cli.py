"""Command-line interface for Strix.

Examples
--------
    strix scan suspicious.exe
    strix scan sample.bin --format json -o report.json
    strix scan sample.bin --format html -o report.html --strings
    strix scan ./incoming/ --recursive --min-score 25 --quiet
    strix rules --list
    strix compare a.bin b.bin        # fuzzy-hash similarity
"""

from __future__ import annotations

import argparse
import os
import sys

from . import __version__
from .core.analyzer import Analyzer
from .core.hashing import fuzzy_compare, fuzzy_hash
from .report import console, html, jsonout, navigator

_EXIT_CLEAN = 0
_EXIT_DETECTED = 1
_EXIT_ERROR = 2


def _iter_targets(path: str, recursive: bool):
    if os.path.isfile(path):
        yield path
    elif os.path.isdir(path):
        if recursive:
            for root, _dirs, files in os.walk(path):
                for fn in sorted(files):
                    yield os.path.join(root, fn)
        else:
            for fn in sorted(os.listdir(path)):
                full = os.path.join(path, fn)
                if os.path.isfile(full):
                    yield full


def _cmd_scan(args) -> int:
    analyzer = Analyzer(
        extra_rule_paths=args.rules or None,
        use_bundled_rules=not args.no_bundled_rules,
        min_string_len=args.min_string_len,
        deep_code=not args.no_deep_code,
    )
    corpus = None
    if args.save or args.corpus:
        from .corpus import Corpus
        corpus = Corpus(args.corpus) if args.corpus else Corpus()
    targets = []
    for t in args.targets:
        targets.extend(_iter_targets(t, args.recursive))
    if not targets:
        print("strix: no input files", file=sys.stderr)
        return _EXIT_ERROR

    worst_exit = _EXIT_CLEAN
    reports = []
    for path in targets:
        try:
            report = analyzer.analyze_file(path)
        except Exception as exc:  # pragma: no cover - defensive
            print(f"strix: failed to analyze {path}: {exc!r}", file=sys.stderr)
            worst_exit = max(worst_exit, _EXIT_ERROR)
            continue
        reports.append(report)
        if corpus is not None:
            try:
                corpus.add(report)
            except Exception as exc:
                print(f"strix: corpus save failed: {exc!r}", file=sys.stderr)
        if report.score >= args.min_score:
            worst_exit = max(worst_exit, _EXIT_DETECTED)
    if corpus is not None:
        corpus.close()

    # output
    multi = len(reports) > 1
    if args.format == "json":
        if multi:
            import json
            payload = json.dumps([r.to_dict() for r in reports], indent=2, default=str)
        else:
            payload = jsonout.render(reports[0]) if reports else "[]"
        _emit(payload, args.output)
    elif args.format == "navigator":
        import json as _json
        if multi:
            payload = _json.dumps([navigator.build_layer(r) for r in reports], indent=2)
        else:
            payload = navigator.render(reports[0]) if reports else "{}"
        _emit(payload, args.output)
    elif args.format == "html":
        if multi and not args.output:
            print("strix: --output is required for HTML with multiple files", file=sys.stderr)
            return _EXIT_ERROR
        if multi:
            base, ext = os.path.splitext(args.output)
            for i, r in enumerate(reports):
                _emit(html.render(r), f"{base}.{i}{ext or '.html'}")
        else:
            _emit(html.render(reports[0]) if reports else "", args.output)
    else:  # text
        if args.quiet:
            for r in reports:
                if r.score >= args.min_score:
                    print(f"{r.verdict.value:>16}  {r.score:3d}  {r.file.hashes.get('sha256','')[:16]}  {r.file.path}")
        else:
            out = ("\n\n".join(console.render(r, show_strings=args.strings) for r in reports))
            _emit(out, args.output)

    return worst_exit


def _cmd_rules(args) -> int:
    from .detect import engine
    rules = engine.load_bundled()
    if args.rules:
        rules += engine.load_paths(args.rules)
    print(f"Loaded {len(rules)} rule(s):\n")
    for r in rules:
        sev = r.meta.get("severity", "?")
        cat = r.meta.get("category", "?")
        print(f"  [{sev:^8}] {r.name}  ({cat})")
        if args.verbose:
            print(f"             {r.meta.get('description','')}")
            print(f"             patterns: {', '.join(r.pattern_names())}")
            print(f"             condition: {r.condition}")
    return _EXIT_CLEAN


def _cmd_compare(args) -> int:
    hashes = []
    for p in args.files:
        with open(p, "rb") as fh:
            hashes.append((p, fuzzy_hash(fh.read())))
    for p, h in hashes:
        print(f"{h}  {p}")
    print()
    for i in range(len(hashes)):
        for j in range(i + 1, len(hashes)):
            sim = fuzzy_compare(hashes[i][1], hashes[j][1])
            print(f"  {sim:3d}%  {os.path.basename(hashes[i][0])} ~ {os.path.basename(hashes[j][0])}")
    return _EXIT_CLEAN


def _cmd_corpus(args) -> int:
    from .corpus import Corpus
    with Corpus(args.db) if args.db else Corpus() as c:
        if args.cluster:
            clusters = c.cluster(threshold=args.threshold)
            if not clusters:
                print("no multi-member clusters yet.")
                return _EXIT_CLEAN
            for i, g in enumerate(clusters, 1):
                print(f"\ncluster {i}  ({len(g)} samples):")
                for row in g:
                    print(f"  [{row['verdict']:>16}] {row['score']:3d}  {row['sha256'][:16]}  {row['path']}")
            return _EXIT_CLEAN
        stats = c.stats()
        print(f"corpus: {args.db or '~/.strix/corpus.db'}  —  {stats['total']} samples")
        for v, n in stats["by_verdict"].items():
            print(f"  {v:>16}: {n}")
        print()
        for row in c.all(args.limit):
            print(f"  [{row['verdict']:>16}] {row['score']:3d}  {row['sha256'][:16]}  "
                  f"{row['format']:<6}  {row['path']}")
    return _EXIT_CLEAN


def _cmd_genrule(args) -> int:
    from .detect.genrule import generate
    analyzer = Analyzer(deep_code=not args.no_deep_code)
    report = analyzer.analyze_file(args.file)
    rule = generate(report, max_strings=args.max_strings, rule_name=args.name)
    _emit(rule, args.output)
    return _EXIT_CLEAN


def _cmd_serve(args) -> int:
    from .web import serve
    serve(host=args.host, port=args.port, db_path=args.db,
          rule_paths=args.rules or None, deep_code=not args.no_deep_code)
    return _EXIT_CLEAN


def _emit(text: str, output):
    if output:
        with open(output, "w", encoding="utf-8") as fh:
            fh.write(text)
        print(f"strix: wrote {output}", file=sys.stderr)
    else:
        print(text)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="strix",
        description="Strix — static malware triage & analysis (the sample is never executed).",
    )
    p.add_argument("--version", action="version", version=f"strix {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="analyze a file or directory")
    scan.add_argument("targets", nargs="+", help="file(s) or directory to analyze")
    scan.add_argument("-f", "--format", choices=["text", "json", "html", "navigator"], default="text",
                      help="navigator = MITRE ATT&CK Navigator layer JSON")
    scan.add_argument("-o", "--output", help="write report to a file instead of stdout")
    scan.add_argument("-r", "--recursive", action="store_true", help="recurse into directories")
    scan.add_argument("--strings", action="store_true", help="include extracted strings (text/html)")
    scan.add_argument("--rules", action="append", default=[], metavar="PATH",
                      help="extra .strx rule file or directory (repeatable)")
    scan.add_argument("--no-bundled-rules", action="store_true", help="skip Strix's built-in rules")
    scan.add_argument("--no-deep-code", action="store_true",
                      help="skip disassembly + sandboxed emulation stages")
    scan.add_argument("--save", action="store_true", help="save result(s) to the default corpus")
    scan.add_argument("--corpus", metavar="DB", help="save result(s) to this corpus database")
    scan.add_argument("--min-string-len", type=int, default=5)
    scan.add_argument("--min-score", type=int, default=1,
                      help="score at/above which a file is 'detected' (affects exit code & --quiet)")
    scan.add_argument("-q", "--quiet", action="store_true", help="one summary line per detected file")
    scan.set_defaults(func=_cmd_scan)

    rules = sub.add_parser("rules", help="list detection rules")
    rules.add_argument("--rules", action="append", default=[], metavar="PATH")
    rules.add_argument("--list", action="store_true", help="(default) list rules")
    rules.add_argument("-v", "--verbose", action="store_true")
    rules.set_defaults(func=_cmd_rules)

    comp = sub.add_parser("compare", help="fuzzy-hash similarity between files")
    comp.add_argument("files", nargs="+")
    comp.set_defaults(func=_cmd_compare)

    corp = sub.add_parser("corpus", help="browse the sample corpus")
    corp.add_argument("--db", metavar="PATH", help="corpus database (default ~/.strix/corpus.db)")
    corp.add_argument("--cluster", action="store_true", help="show similarity clusters")
    corp.add_argument("--threshold", type=int, default=55, help="cluster similarity threshold (0-100)")
    corp.add_argument("--limit", type=int, default=100)
    corp.set_defaults(func=_cmd_corpus)

    gr = sub.add_parser("gen-rule", help="auto-generate a detection rule from a sample")
    gr.add_argument("file")
    gr.add_argument("-o", "--output", help="write the rule to a file")
    gr.add_argument("--name", help="rule name")
    gr.add_argument("--max-strings", type=int, default=8)
    gr.add_argument("--no-deep-code", action="store_true")
    gr.set_defaults(func=_cmd_genrule)

    sv = sub.add_parser("serve", help="launch the local web triage dashboard")
    sv.add_argument("--host", default="127.0.0.1")
    sv.add_argument("--port", type=int, default=8710)
    sv.add_argument("--db", metavar="PATH", help="corpus database to use")
    sv.add_argument("--rules", action="append", default=[], metavar="PATH")
    sv.add_argument("--no-deep-code", action="store_true")
    sv.set_defaults(func=_cmd_serve)
    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except KeyboardInterrupt:
        return _EXIT_ERROR
    except BrokenPipeError:
        return _EXIT_CLEAN


if __name__ == "__main__":
    sys.exit(main())
