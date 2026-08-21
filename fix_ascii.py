"""One-shot script: replace all non-ASCII characters in runner.py and run_experiment.py
with clean ASCII equivalents so they work on Windows cp1252 terminals."""

replacements = [
    ("\u2014", "--"),    # em dash  —
    ("\u2013", "-"),     # en dash  –
    ("\u2019", "'"),     # right single quote  '
    ("\u2018", "'"),     # left single quote  '
    ("\u2022", "*"),     # bullet  •
    ("\u2026", "..."),   # ellipsis  …
    ("\u00d7", "x"),     # multiplication sign  ×
    ("\u2265", ">="),    # >=
    ("\u2264", "<="),    # <=
    ("\u2500", "-"),     # box drawing light horizontal  ─
    ("\u2502", "|"),     # box drawing light vertical  │
    ("\u2550", "="),     # box drawing double horizontal  ═
    ("\u2551", "|"),     # box drawing double vertical  ║
    ("\u2713", "[+]"),   # checkmark  ✓
    ("\u2717", "[x]"),   # cross  ✗
    ("\u25b3", "/\\"),   # triangle  △
    ("\u2212", "-"),     # minus sign  −
    ("\u26a0", "[!]"),   # warning sign  ⚠
    ("\u2192", "->"),    # right arrow  →
    ("\u00a7", "S"),     # section sign  §
    ("\u2248", "~="),    # approx equal  ≈
    ("\u2260", "!="),    # not equal  ≠
    ("\u00b7", "."),     # middle dot  ·
    ("\u2265", ">="),    # greater-than-or-equal  ≥
    ("\u2039", "<"),     # single left angle quote  ‹
    ("\u203a", ">"),     # single right angle quote  ›
    ("\u00ab", "<<"),    # double left angle quote  «
    ("\u00bb", ">>"),    # double right angle quote  »
    ("\u2014", "--"),    # em dash again (covers any missed)
]

files = ["pipeline/runner.py", "experiments/run_experiment.py"]
for fpath in files:
    with open(fpath, encoding="utf-8") as f:
        content = f.read()
    total_changes = 0
    for old, new in replacements:
        count = content.count(old)
        if count:
            content = content.replace(old, new)
            total_changes += count
            print(f"  {fpath}: replaced {count}x U+{ord(old):04X} -> {new!r}")
    # Verify no non-ASCII remains (except in string literals we can't control)
    with open(fpath, "w", encoding="utf-8") as f:
        f.write(content)
    print(f"[OK] {fpath}: {total_changes} replacements made")
    # Check what's left
    remaining = [(i+1, line) for i, line in enumerate(content.splitlines())
                 if any(ord(c) > 127 for c in line)]
    if remaining:
        print(f"  [!] {len(remaining)} lines still have non-ASCII:")
        for lineno, line in remaining[:10]:
            chars = [c for c in line if ord(c) > 127]
            print(f"      line {lineno}: {chars}")
    else:
        print(f"  All ASCII clean.")
    print()
