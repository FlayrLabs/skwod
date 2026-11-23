#!/usr/bin/env python3
"""Enforce the expiry dates on deny.toml's advisory ignores.

    tools/release/deny-expiry.py deny.toml [--today YYYY-MM-DD] [--warn-days N]

cargo-deny has no notion of an ignore that runs out, so an `ignore` entry would otherwise live
for ever. Every entry in `[advisories] ignore` must be preceded by a comment block containing
`Expires YYYY-MM-DD`; on or after that date the entry fails this check (exit 1), as does an
entry with no date or no reason. Entries within --warn-days (default 30) of expiry are listed
as warnings. Stdlib only; reads the file as text so the comments are visible.
"""
import datetime
import re
import sys

ENTRY = re.compile(r'^\s*\{\s*id\s*=\s*"([^"]+)"(.*)\}\s*,?\s*$')
EXPIRES = re.compile(r"\bExpires\s+(\d{4}-\d{2}-\d{2})\b")
BARE_ID = re.compile(r'^\s*"(RUSTSEC-[^"]+)"\s*,?\s*$')


def check(text, today, warn_days=30):
    """Return (errors, warnings, entries) for the ignore list in `text`."""
    errors, warnings, entries = [], [], []
    in_ignore, comments = False, []
    for line in text.splitlines():
        stripped = line.strip()
        if not in_ignore:
            if re.match(r"^ignore\s*=\s*\[", stripped):
                in_ignore, comments = True, []
                if stripped.endswith("]") and stripped != "ignore = [":
                    inner = stripped[stripped.index("[") + 1:-1].strip()
                    if inner:
                        errors.append("ignore list is written on one line: put each entry on its own line under a dated comment")
                    in_ignore = False
            continue
        if stripped.startswith("]"):
            break
        if stripped.startswith("#"):
            comments.append(stripped)
            continue
        if not stripped:
            comments = []
            continue
        bare = BARE_ID.match(line)
        m = ENTRY.match(line)
        if bare:
            errors.append(f"{bare.group(1)}: a bare id has no reason; write {{ id = \"…\", reason = \"…\" }} under a dated comment")
            comments = []
            continue
        if not m:
            errors.append(f"unrecognised line in the ignore list: {stripped[:80]}")
            comments = []
            continue
        ident, rest = m.group(1), m.group(2)
        if not re.search(r'reason\s*=\s*"[^"]{10,}"', rest):
            errors.append(f"{ident}: no reason given")
        dates = EXPIRES.findall("\n".join(comments))
        comments = []
        if not dates:
            errors.append(f"{ident}: no 'Expires YYYY-MM-DD' in the comment above it")
            continue
        try:
            expiry = min(datetime.date.fromisoformat(d) for d in dates)
        except ValueError:
            errors.append(f"{ident}: unreadable expiry date {dates}")
            continue
        entries.append((ident, expiry))
        if today >= expiry:
            errors.append(f"{ident}: ignore expired on {expiry} — remove it, run check-deps.sh, fix or re-justify what comes back")
        elif (expiry - today).days <= warn_days:
            warnings.append(f"{ident}: ignore expires on {expiry} ({(expiry - today).days} days)")
    return errors, warnings, entries


def main(argv):
    args = argv[1:]
    today, warn_days, path = datetime.date.today(), 30, None
    while args:
        a = args.pop(0)
        if a == "--today":
            today = datetime.date.fromisoformat(args.pop(0))
        elif a == "--warn-days":
            warn_days = int(args.pop(0))
        else:
            path = a
    if not path:
        print(__doc__, file=sys.stderr)
        return 2
    errors, warnings, entries = check(open(path, encoding="utf-8").read(), today, warn_days)
    for w in warnings:
        print(f"⚠ {w}")
    for e in errors:
        print(f"✗ {e}")
    if errors:
        return 1
    soonest = min((e for _, e in entries), default=None)
    print(f"✓ {len(entries)} advisory ignore(s), all dated and in force" + (f" (first expiry {soonest})" if soonest else ""))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
