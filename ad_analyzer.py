#!/usr/bin/env python3
"""
ADScan v2.0 — Active Directory Security Analyzer
Kali Linux | 50-point security assessment
"""
import argparse, os, sys, time
from datetime import datetime

R='\033[91m';G='\033[92m';Y='\033[93m';B='\033[94m'
C='\033[96m';W='\033[97m';DIM='\033[2m';BOLD='\033[1m';E='\033[0m'

BANNER = f"""{R}{BOLD}
 █████╗ ██████╗ ███████╗ ██████╗ █████╗ ███╗   ██╗
██╔══██╗██╔══██╗██╔════╝██╔════╝██╔══██╗████╗  ██║
███████║██║  ██║███████╗██║     ███████║██╔██╗ ██║
██╔══██║██║  ██║╚════██║██║     ██╔══██║██║╚██╗██║
██║  ██║██████╔╝███████║╚██████╗██║  ██║██║ ╚████║
╚═╝  ╚═╝╚═════╝ ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝{E}
{C}  ADScan v2.0 — Active Directory Security Analyzer  |  Kali Linux{E}
{Y}  ⚠  Use only on authorized systems  ⚠{E}
"""

CHECK_GROUPS_HELP = """
Check Groups (-cg):
  kerberos       → Checks 1-5   (AS-REP, Kerberoasting, Delegation, krbtgt)
  password       → Checks 6-13  (Password policy, lockout, spray risk)
  accounts       → Checks 14-20 (Privileged accounts, DA, guest)
  user           → Checks 25-31 (User hygiene, stale, pwd never expires)
  serviceaccount → Checks 21-24 (Service account risks)
  hygiene        → Checks 25-32 (All account hygiene)
  systems        → Checks 33-37 (EOL OS, WinRM, SMB)
  domain         → Checks 38-45 (GPO, trusts, domain config)
  all            → All 50 checks (default)
"""

def _scope_label(c_arg, cg_arg, check_ids):
    if check_ids is None:
        return "Full scan — all 50 controls executed"
    if cg_arg:
        ids = sorted(check_ids)
        return f"Group scan — \"{cg_arg}\" (Controls: {', '.join(str(i) for i in ids)})"
    if c_arg:
        ids = sorted(check_ids)
        return f"Custom scan — Controls: {', '.join(str(i) for i in ids)}"
    return "Full scan — all 50 controls executed"

def sec(t):
    bar="═"*58
    print(f"\n{C}{BOLD}╔{bar}╗\n║  {t:<56}║\n╚{bar}╝{E}")

def info(m):  print(f"  {B}[*]{E} {m}")
def ok(m):    print(f"  {G}[+]{E} {m}")
def warn(m):  print(f"  {Y}[!]{E} {m}")

def progress(lbl, n=18, d=0.04):
    sys.stdout.write(f"  {B}[*]{E} {lbl}: [")
    for _ in range(n):
        time.sleep(d)
        sys.stdout.write(f"{G}█{E}")
        sys.stdout.flush()
    print(f"] {G}OK{E}")

def main():
    print(BANNER)
    p = argparse.ArgumentParser(
        description="ADScan v2.0 — Active Directory Security Analyzer",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=CHECK_GROUPS_HELP
    )
    p.add_argument("--dc",            required=True,  help="Domain Controller IP")
    p.add_argument("--domain",        required=True,  help="Domain name (e.g. lab.local)")
    p.add_argument("-u","--username", required=True,  help="AD username")
    p.add_argument("-p","--password", required=True,  help="Password")
    p.add_argument("--out",           default="./report", help="Report output directory")
    p.add_argument("--no-nmap",       action="store_true", help="Skip nmap port scan")

    chk = p.add_mutually_exclusive_group()
    chk.add_argument("-c",  metavar="CHECKS",
        help="Check IDs: -c 27  or  -c 1-5  or  -c 1,3,5")
    chk.add_argument("-cg", metavar="GROUP",
        help="Check group: kerberos|password|accounts|user|serviceaccount|hygiene|systems|domain|all")

    a = p.parse_args()

    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from modules.scanner   import port_scan
    from modules.collector import ADCollector
    from modules.analyzer  import analyze, parse_check_filter
    from modules.reporter  import build_report

    check_ids = parse_check_filter(c_arg=a.c, cg_arg=a.cg)
    scope     = _scope_label(a.c, a.cg, check_ids)

    if check_ids is not None:
        info(f"Scope: {scope}")
    else:
        info("Running all 50 checks")

    start = datetime.now()

    # Phase 1
    sec("PHASE 1 — Network & Port Scan")
    net = {"dc_ip": a.dc, "ports": [], "services": {}}
    if not a.no_nmap:
        progress("Scanning DC ports (nmap)", 15, 0.06)
        net = port_scan(a.dc)
        if net["ports"]:
            ok(f"Open ports: {', '.join(str(x) for x in net['ports'])}")
        else:
            warn("Port scan returned no results")
    else:
        info("nmap skipped (--no-nmap)")

    # Phase 2
    sec("PHASE 2 — LDAP Data Collection")
    info(f"DC: {Y}{a.dc}{E}  Domain: {Y}{a.domain}{E}  User: {Y}{a.username}{E}")
    col = ADCollector(a.dc, a.domain, a.username, a.password)
    ad  = col.run()
    ad["open_ports"] = net.get("ports", [])

    ok(f"Users: {W}{len(ad['users'])}{E}  "
       f"Groups: {W}{len(ad['groups'])}{E}  "
       f"Computers: {W}{len(ad['computers'])}{E}  "
       f"GPOs: {W}{len(ad.get('gpos',[]))}{E}")
    ok(f"SPNs: {W}{len(ad['spns'])}{E}  "
       f"AS-REP: {W}{len(ad['asrep_users'])}{E}  "
       f"Trusts: {W}{len(ad.get('trusts',[]))}{E}")

    # Phase 3
    checks_label = f"50 Checks" if check_ids is None else f"{len(check_ids)} Selected Check(s)"
    sec(f"PHASE 3 — Security Analysis ({checks_label})")
    progress("Running security checks", 25, 0.04)
    findings, summary = analyze(ad, check_ids=check_ids)

    print()
    for key, col, label in [("CRITICAL",R,"CRITICAL"),("HIGH",Y,"HIGH    "),
                              ("MEDIUM",B,"MEDIUM  "),("LOW",G,"LOW     ")]:
        cnt = summary.get(key, 0)
        if not cnt: continue
        print(f"  {col}{BOLD}[{label}]{E}  {cnt} finding(s)")
        for f in [x for x in findings if x["severity"] == key]:
            aff = f"({len(f['affected'])} affected)" if f.get("affected") else ""
            print(f"    {col}•{E} {f['title']} {DIM}{aff}{E}")
    print()

    sc    = summary.get("SCORE", 0)
    grade = summary.get("GRADE","F")
    sc_c  = G if sc >= 70 else Y if sc >= 40 else R
    info(f"Checks run    : {W}{summary.get('CHECKS',0)}{E} / 50")
    info(f"Total findings: {W}{summary.get('TOTAL',0)}{E}")
    info(f"Security score: {sc_c}{BOLD}{sc}/100  Grade: {grade}{E}")

    # Phase 4
    sec("PHASE 4 — HTML Report Generation")
    os.makedirs(a.out, exist_ok=True)
    sure = str(datetime.now() - start).split(".")[0]
    meta = {
        "dc":     a.dc,
        "domain": a.domain,
        "user":   a.username,
        "sure":   sure,
        "tarih":  datetime.now().strftime("%d.%m.%Y %H:%M"),
        "scope":  scope,
    }
    progress("Generating HTML report", 18, 0.04)
    html_path = build_report(meta, net, ad, findings, summary, a.out)
    ok(f"Report ready: {G}{html_path}{E}")
    print(f"\n  {C}Open:{E}  {W}firefox {html_path} &{E}")
    print(f"\n  {G}{BOLD}[✔] Scan complete! ({sure}){E}\n")


if __name__ == "__main__":
    main()
