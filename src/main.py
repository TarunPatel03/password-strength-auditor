import argparse
from typing import List
from rich.table import Table
from rich import print

from .hash_utils import argon2_hash
from .report import render_pdf
from .auditor import AuditResult, score_password
from .hibp import hibp_breach_count


def audit_many(passwords: List[str], use_hibp: bool) -> List[AuditResult]:
    results = []
    for pw in passwords:
        pw = pw.rstrip("\n\r")
        hibp_hits = hibp_breach_count(pw) if use_hibp else None
        results.append(score_password(pw, hibp_hits))
    return results


def print_table(results: List[AuditResult]):
    t = Table(title="Password Audit Results")
    t.add_column("Password", justify="left")
    t.add_column("Len")
    t.add_column("Entropy")
    t.add_column("Score")
    t.add_column("Verdict")
    t.add_column("HIBP")

    for r in results:
        masked = r.password if len(r.password) <= 4 else (r.password[:2] + "•••" + r.password[-2:])
        hibp = "skip" if r.hibp_breaches is None else (str(r.hibp_breaches) if r.hibp_breaches > 0 else "0")
        t.add_row(masked, str(r.length), f"{r.entropy:.1f}", str(r.score), r.verdict, hibp)

    print(t)


def main():
    p = argparse.ArgumentParser(description="Password Strength Auditor")
    g = p.add_mutually_exclusive_group(required=True)
    g.add_argument("--password", help="single password literal")
    g.add_argument("--file", help="path to file with one password per line")
    p.add_argument("--no-hibp", action="store_true", help="skip HIBP check (offline)")
    p.add_argument("--no-hash", action="store_true", help="skip Argon2 hash demo")
    p.add_argument("--pdf", help="optional PDF output path")

    args = p.parse_args()

    if args.file:
        with open(args.file, "r", encoding="utf-8") as f:
            passwords = [line.strip() for line in f if line.strip()]
    else:
        passwords = [args.password]

    results = audit_many(passwords, use_hibp=not args.no_hibp)

    print_table(results)

    if not args.no_hash:
        strong = [r for r in results if r.verdict == "Strong" and (r.hibp_breaches in (None, 0))]
        if strong:
            demo = strong[0]
            h = argon2_hash(demo.password)
            print("\n[bold]Argon2id hash demo (first strong candidate):[/bold]")
            print(h)

    if args.pdf:
        render_pdf(results, args.pdf)
        print(f"\n[green]PDF report saved to[/green] {args.pdf}")


if __name__ == "__main__":
    main()
