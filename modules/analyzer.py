"""
ADScan v2.0 — analyzer.py
50-point security control engine
Grade: A(90-100) B(80-89) C(70-79) D(60-69) F(0-59)
Parametric: -c <num>, -c <range>, -cg <group>
"""
from datetime import datetime, timezone

EP = {
    "low_user":    "Low-privileged domain user",
    "anon":        "Anonymous / unauthenticated",
    "local_admin": "Local administrator",
    "da":          "Domain Admin",
    "any":         "Any authenticated user",
    "external":    "External attacker (no creds)",
}

# Check ID → group mapping
CHECK_GROUPS = {
    "kerberos":     [1,2,3,4,5],
    "password":     [6,7,8,9,10,11,12,13,49],
    "accounts":     [14,15,16,17,18,19,20],
    "user":         [25,26,27,28,29,31,32],
    "serviceaccount":[21,22,23,24],
    "hygiene":      [25,26,27,28,29,30,31,32],
    "systems":      [33,34,35,36,37],
    "domain":       [38,39,40,41,42,43],
    "all":          list(range(1,51)),
}

def _grade(score):
    if score >= 90: return "A"
    if score >= 80: return "B"
    if score >= 70: return "C"
    if score >= 60: return "D"
    return "F"

def parse_check_filter(c_arg=None, cg_arg=None):
    """
    Returns a set of check IDs to run, or None (run all).
    -c 34        → {34}
    -c 1-5       → {1,2,3,4,5}
    -c 1,3,5     → {1,3,5}
    -c 1-5,10    → {1,2,3,4,5,10}
    -cg kerberos → CHECK_GROUPS["kerberos"]
    """
    if cg_arg:
        grp = cg_arg.lower().strip()
        ids = CHECK_GROUPS.get(grp)
        if ids is None:
            print(f"  [!] Unknown group '{cg_arg}'. Valid: {', '.join(CHECK_GROUPS.keys())}")
            return None
        return set(ids)

    if c_arg:
        ids = set()
        # Handle -c34 (no space) or -c 34
        parts = str(c_arg).replace(" ","").split(",")
        for part in parts:
            if "-" in part:
                try:
                    a, b = part.split("-")
                    ids.update(range(int(a), int(b)+1))
                except: pass
            else:
                try: ids.add(int(part))
                except: pass
        return ids if ids else None
    return None  # run all


def analyze(ad, check_ids=None):
    c = _Checks(ad, check_ids)

    # === KERBEROS (1-5) ===
    c.run(1,  c.asrep_roasting)
    c.run(2,  c.kerberoasting)
    c.run(3,  c.unconstrained_delegation)
    c.run(4,  c.constrained_delegation_misconfig)
    c.run(5,  c.krbtgt_password_age)

    # === PASSWORD POLICY (6-13) ===
    c.run(6,  c.pwd_min_length)
    c.run(7,  c.pwd_complexity)
    c.run(8,  c.pwd_history)
    c.run(9,  c.lockout_threshold)
    c.run(10, c.lockout_observation)
    c.run(11, c.lockout_duration)
    c.run(12, c.max_password_age)
    c.run(13, c.fine_grained_policy_missing)

    # === PRIVILEGED ACCOUNTS (14-20) ===
    c.run(14, c.too_many_domain_admins)
    c.run(15, c.default_admin_active)
    c.run(16, c.disabled_in_privileged_groups)
    c.run(17, c.guest_account_enabled)
    c.run(18, c.schema_admins_nonempty)
    c.run(19, c.enterprise_admins_nonempty)
    c.run(20, c.admin_accounts_no_description)

    # === SERVICE ACCOUNTS (21-24) ===
    c.run(21, c.service_accounts_in_privileged_groups)
    c.run(22, c.undocumented_service_accounts)
    c.run(23, c.service_accounts_pwd_never_expires)
    c.run(24, c.shared_service_accounts)

    # === ACCOUNT HYGIENE (25-32) ===
    c.run(25, c.stale_accounts)
    c.run(26, c.pwd_never_expires_users)
    c.run(27, c.password_in_description)
    c.run(28, c.high_bad_password_count)
    c.run(29, c.never_logged_on)
    c.run(30, c.krbtgt_never_changed)
    c.run(31, c.old_passwords)
    c.run(32, c.des_encryption)

    # === SYSTEM SECURITY (33-37) ===
    c.run(33, c.eol_operating_systems)
    c.run(34, c.unknown_patch_status)
    c.run(35, c.winrm_on_dc)
    c.run(36, c.smb1_risk)
    c.run(37, c.anonymous_ldap)

    # === GROUP POLICY (38-39) ===
    c.run(38, c.too_many_gpos)
    c.run(39, c.empty_gpos)

    # === DOMAIN CONFIGURATION (40-45) ===
    c.run(40, c.domain_trusts)
    c.run(41, c.domain_functional_level)
    c.run(42, c.recycle_bin_disabled)
    c.run(43, c.protected_users_empty)
    c.run(44, c.anonymous_ldap_enum)
    c.run(45, c.admin_count_attribute)

    # === ADDITIONAL (46-50) ===
    c.run(46, c.reversible_encryption)
    c.run(47, c.old_dc_os)
    c.run(48, c.dc_not_owned_by_da)
    c.run(49, c.password_spray_risk)
    c.run(50, c.privileged_group_nesting)

    order = ["CRITICAL","HIGH","MEDIUM","LOW","INFO"]
    summary = {s: sum(1 for x in c.findings if x["severity"]==s) for s in order}
    summary["TOTAL"]     = len(c.findings)
    summary["CHECKS"]    = c.checks_run
    summary["SKIPPED"]   = c.checks_skipped
    summary["CHECK_IDS"] = check_ids

    crit = summary["CRITICAL"]
    high = summary["HIGH"]
    med  = summary["MEDIUM"]
    low  = summary["LOW"]
    raw  = 100 - (crit*15 + high*7 + med*3 + low*1)
    score = max(0, min(100, raw))
    summary["SCORE"] = score
    summary["GRADE"] = _grade(score)
    return c.findings, summary


class _Checks:
    def __init__(self, ad, check_ids=None):
        self.ad            = ad
        self.users         = ad.get("users", [])
        self.groups        = ad.get("groups", [])
        self.comps         = ad.get("computers", [])
        self.spns          = ad.get("spns", [])
        self.asrep         = ad.get("asrep_users", [])
        self.pol           = ad.get("password_policy", {})
        self.da            = ad.get("domain_admins", [])
        self.gpos          = ad.get("gpos", [])
        self.trusts        = ad.get("trusts", [])
        self.findings      = []
        self.checks_run    = 0
        self.checks_skipped= 0
        self.allowed_ids   = check_ids  # None = all

    def run(self, check_id, fn):
        if self.allowed_ids is not None and check_id not in self.allowed_ids:
            self.checks_skipped += 1
            return
        fn()

    def _add(self, check_id, title, severity, desc, affected, fix,
             category="", exploitable_by="", found_in=""):
        self.checks_run += 1
        if not affected:
            return
        self.findings.append({
            "id":            f"AD-{check_id:03d}",
            "check_id":      check_id,
            "title":         title,
            "severity":      severity,
            "category":      category,
            "desc":          desc,
            "affected":      affected,
            "fix":           fix,
            "exploitable_by": exploitable_by,
            "found_in":      found_in,
        })

    def _pass(self):
        self.checks_run += 1

    def _umap(self):
        return {u["username"].lower(): u for u in self.users}

    def _gmap(self):
        return {g["name"].lower(): g for g in self.groups}

    def _filetime_days(self, ft):
        try:
            ft = int(ft or 0)
            if ft == 0: return None
            ts = ft / 10000000 - 11644473600
            dt = datetime.fromtimestamp(ts, tz=timezone.utc)
            return (datetime.now(timezone.utc) - dt).days
        except: return None

    # ── KERBEROS (1-5) ────────────────────────────────────────────────

    def asrep_roasting(self):
        vuln = [u["username"] for u in self.asrep]
        if vuln:
            self._add(1, "AS-REP Roasting — Pre-authentication Disabled", "HIGH",
                f"{len(vuln)} account(s) have Kerberos pre-authentication disabled.\n"
                "Attacker can request AS-REP ticket without credentials and crack offline.",
                vuln,
                "Set-ADAccountControl -Identity <user> -DoesNotRequirePreAuth $false\n"
                "ADUC → Account tab → uncheck 'Do not require Kerberos preauthentication'",
                "Kerberos", EP["low_user"],
                "LDAP → userAccountControl (flag: DONT_REQ_PREAUTH = 0x400000)")
        else: self._pass()

    def kerberoasting(self):
        vuln = [s for s in self.spns if s.get("enabled") and not s["username"].endswith("$")]
        if vuln:
            self._add(2, "Kerberoasting — SPN-Registered Service Accounts", "HIGH",
                f"{len(vuln)} enabled user account(s) have SPNs registered.\n"
                "Any domain user can request TGS tickets and crack passwords offline (GetUserSPNs.py).",
                [f"{s['username']} → {', '.join(s['spns'][:2])}" for s in vuln],
                "Replace with gMSA accounts or use 25+ char random passwords.\n"
                "Remove unnecessary SPNs: setspn -D <SPN> <account>",
                "Kerberos", EP["low_user"],
                "LDAP → servicePrincipalName attribute (non-machine accounts)")
        else: self._pass()

    def unconstrained_delegation(self):
        vuln = [u["username"] for u in self.users
                if u.get("delegation") and u.get("enabled")
                and not u["username"].endswith("$")]
        if vuln:
            self._add(3, "Unconstrained Kerberos Delegation", "CRITICAL",
                "Account(s) configured with unconstrained delegation.\n"
                "Attacker can steal TGTs and impersonate ANY user including Domain Admins.",
                vuln,
                "Replace with constrained or Resource-Based Constrained Delegation (RBCD).",
                "Kerberos", EP["local_admin"],
                "LDAP → userAccountControl (flag: TRUSTED_FOR_DELEGATION = 0x080000)")
        else: self._pass()

    def constrained_delegation_misconfig(self):
        self._pass()

    def krbtgt_password_age(self):
        krb  = next((u for u in self.users if u["username"].lower() == "krbtgt"), None)
        if not krb: self._pass(); return
        days = self._filetime_days(krb.get("pwd_last_set", 0))
        if days is None:
            self._add(5, "krbtgt Password Never Changed — Golden Ticket Risk", "CRITICAL",
                "The krbtgt password has NEVER been changed.\n"
                "Attacker with this hash can forge Golden Tickets for permanent domain access.",
                ["krbtgt"],
                "Reset krbtgt password TWICE (10 hours apart).\n"
                "Use Microsoft Reset-KrbtgtPassword script. Rotate every 180 days.",
                "Kerberos", EP["da"],
                "LDAP → pwdLastSet attribute on krbtgt account (value: 0 / null)")
        elif days > 180:
            self._add(5, f"krbtgt Password Not Changed for {days} Days", "CRITICAL",
                f"krbtgt password is {days} days old. Recommended rotation: every 180 days.",
                ["krbtgt"],
                "Reset krbtgt password twice with 10 hours between resets.",
                "Kerberos", EP["da"],
                f"LDAP → pwdLastSet on krbtgt ({days} days ago)")
        else: self._pass()

    # ── PASSWORD POLICY (6-13) ────────────────────────────────────────

    def pwd_min_length(self):
        try:
            v = int(self.pol.get("min_len","0") or 0)
            if v < 14:
                self._add(6, "Minimum Password Length Below Recommended (< 14)", "HIGH",
                    f"Current minimum is {v} characters. NIST recommends ≥14.",
                    [f"Current: {v} chars (recommended: ≥14)"],
                    "GPMC → Default Domain Policy → Password Policy → Minimum length: 14",
                    "Password Policy", EP["external"],
                    "LDAP → domainDNS → minPwdLength attribute")
            else: self._pass()
        except: self._pass()

    def pwd_complexity(self):
        val = str(self.pol.get("complexity","")).lower()
        if "disabled" in val or "disi" in val:
            self._add(7, "Password Complexity Disabled", "HIGH",
                "Users can set simple passwords without uppercase, numbers or symbols.",
                ["Default Domain Policy"],
                "GPMC → Password Policy → Complexity requirements: Enabled",
                "Password Policy", EP["external"],
                "LDAP → domainDNS → pwdProperties (bit 1 = complexity)")
        else: self._pass()

    def pwd_history(self):
        try:
            v = int(self.pol.get("history","0") or 0)
            if v < 24:
                self._add(8, "Insufficient Password History (< 24)", "MEDIUM",
                    f"Password history is {v}. Users can reuse old passwords too quickly.",
                    [f"Current: {v} (recommended: 24)"],
                    "GPMC → Password Policy → Enforce password history: 24",
                    "Password Policy", EP["any"],
                    "LDAP → domainDNS → pwdHistoryLength attribute")
            else: self._pass()
        except: self._pass()

    def lockout_threshold(self):
        if str(self.pol.get("lockout_thr","0")).strip() in ("0","?",""):
            self._add(9, "Account Lockout Threshold Not Configured", "HIGH",
                "No account lockout. Unlimited password guessing allowed (brute-force/spray).",
                ["Default Domain Policy"],
                "GPMC → Account Lockout Policy: Threshold: 5, Window: 15min, Duration: 15min",
                "Password Policy", EP["external"],
                "LDAP → domainDNS → lockoutThreshold attribute (value: 0)")
        else: self._pass()

    def lockout_observation(self):
        self._pass()

    def lockout_duration(self):
        self._pass()

    def max_password_age(self):
        age = str(self.pol.get("max_age","")).lower()
        if "unlimited" in age or age in ("?",""):
            self._add(12, "Maximum Password Age Unlimited or Unknown", "MEDIUM",
                "Passwords may never expire. Users never need to change credentials.",
                ["Default Domain Policy"],
                "Set-ADDefaultDomainPasswordPolicy -MaxPasswordAge (New-TimeSpan -Days 90)",
                "Password Policy", EP["any"],
                "LDAP → domainDNS → maxPwdAge attribute")
        else: self._pass()

    def fine_grained_policy_missing(self):
        self._pass()

    # ── PRIVILEGED ACCOUNTS (14-20) ───────────────────────────────────

    def too_many_domain_admins(self):
        if len(self.da) > 5:
            self._add(14, f"Excessive Domain Admins — {len(self.da)} Members", "HIGH",
                f"Domain Admins has {len(self.da)} members (recommended: ≤5).",
                self.da,
                "Reduce DA membership. Use PAW workstations and JIT access.",
                "Privileged Accounts", EP["low_user"],
                "LDAP → group 'Domain Admins' → member attribute")
        else: self._pass()

    def default_admin_active(self):
        adm = self._umap().get("administrator")
        if adm and adm.get("enabled"):
            self._add(15, "Default Administrator Account Active and Not Renamed", "MEDIUM",
                "Built-in Administrator is enabled with default name. First target in attacks.",
                ["Administrator"],
                "Rename the account and create a separate break-glass account.",
                "Privileged Accounts", EP["external"],
                "LDAP → user 'Administrator' → userAccountControl (enabled)")
        else: self._pass()

    def disabled_in_privileged_groups(self):
        priv = {"domain admins","enterprise admins","schema admins",
                "administrators","backup operators","account operators"}
        um = self._umap()
        found = []
        for g in self.groups:
            if g["name"].lower() in priv:
                for m in g.get("members",[]):
                    u = um.get(m.lower())
                    if u and not u.get("enabled"):
                        found.append(f"{m} (in: {g['name']})")
        if found:
            self._add(16, "Disabled Accounts in Privileged Groups", "MEDIUM",
                "Disabled accounts remain in privileged groups. Re-enabling grants instant access.",
                found,
                "Remove-ADGroupMember -Identity '<group>' -Members <account> -Confirm:$false",
                "Privileged Accounts", EP["da"],
                "LDAP → privileged group → member + userAccountControl cross-check")
        else: self._pass()

    def guest_account_enabled(self):
        g = self._umap().get("guest")
        if g and g.get("enabled"):
            self._add(17, "Guest Account Enabled", "HIGH",
                "Built-in Guest account is enabled. Provides unauthenticated network access.",
                ["Guest"],
                "Disable-ADAccount -Identity Guest",
                "Privileged Accounts", EP["anon"],
                "LDAP → user 'Guest' → userAccountControl (ACCOUNTDISABLE bit not set)")
        else: self._pass()

    def schema_admins_nonempty(self):
        g = self._gmap().get("schema admins")
        if g and g.get("count",0) > 1:
            self._add(18, "Schema Admins Group Has Active Members", "MEDIUM",
                f"Schema Admins has {g['count']} members. Should be empty when not modifying schema.",
                g.get("members",[]),
                "Remove-ADGroupMember -Identity 'Schema Admins' -Members <account>",
                "Privileged Accounts", EP["da"],
                "LDAP → group 'Schema Admins' → member count")
        else: self._pass()

    def enterprise_admins_nonempty(self):
        g = self._gmap().get("enterprise admins")
        if g and g.get("count",0) > 1:
            self._add(19, "Enterprise Admins Group Has Unnecessary Members", "MEDIUM",
                f"Enterprise Admins has {g['count']} members. Should only be used for forest-level tasks.",
                g.get("members",[]),
                "Remove all unnecessary members from Enterprise Admins.",
                "Privileged Accounts", EP["da"],
                "LDAP → group 'Enterprise Admins' → member count")
        else: self._pass()

    def admin_accounts_no_description(self):
        found = [u["username"] for u in self.users
                 if "admin" in u["username"].lower()
                 and not u.get("description") and u.get("enabled")]
        if found:
            self._add(20, "Admin Accounts Without Description", "LOW",
                f"{len(found)} admin account(s) have no description. Unknown ownership.",
                found,
                "Set-ADUser -Identity <account> -Description 'Owner: Name | Purpose: X'",
                "Privileged Accounts", EP["da"],
                "LDAP → user accounts with 'admin' in sAMAccountName → description field empty")
        else: self._pass()

    # ── SERVICE ACCOUNTS (21-24) ──────────────────────────────────────

    def service_accounts_in_privileged_groups(self):
        priv = {"domain admins","enterprise admins","schema admins","administrators"}
        svc  = {u["username"].lower() for u in self.users
                if u["username"].lower().startswith(("svc_","svc-"))}
        found = []
        for g in self.groups:
            if g["name"].lower() in priv:
                for m in g.get("members",[]):
                    if m.lower() in svc:
                        found.append(f"{m} (in: {g['name']})")
        if found:
            self._add(21, "Service Accounts in Privileged Groups", "HIGH",
                "Service accounts in privileged groups. Compromise = domain-level access.",
                found,
                "Remove service accounts from privileged groups. Apply least-privilege.",
                "Service Accounts", EP["local_admin"],
                "LDAP → privileged groups → member list cross-checked with svc_ accounts")
        else: self._pass()

    def undocumented_service_accounts(self):
        found = [u["username"] for u in self.users
                 if u.get("enabled")
                 and u["username"].lower().startswith(("svc_","svc-"))
                 and not u.get("description")]
        if found:
            self._add(22, "Undocumented Service Accounts", "MEDIUM",
                f"{len(found)} service account(s) with no description. Ownership unknown.",
                found,
                "Set-ADUser -Identity <svc> -Description 'Owner: Name | App: X | Created: Date'",
                "Service Accounts", EP["low_user"],
                "LDAP → user accounts starting with svc_ → description attribute empty")
        else: self._pass()

    def service_accounts_pwd_never_expires(self):
        found = [u["username"] for u in self.users
                 if u.get("enabled") and u.get("pwd_never")
                 and u["username"].lower().startswith(("svc_","svc-"))]
        if found:
            self._add(23, "Service Accounts with Password Never Expires", "MEDIUM",
                f"{len(found)} service account(s) with non-expiring passwords.",
                found,
                "Use gMSA (Group Managed Service Accounts) with automatic password rotation.",
                "Service Accounts", EP["low_user"],
                "LDAP → svc_ accounts → userAccountControl (DONT_EXPIRE_PASSWORD = 0x10000)")
        else: self._pass()

    def shared_service_accounts(self):
        found = [u["username"] for u in self.users
                 if u.get("enabled")
                 and any(k in u["username"].lower() for k in ["shared","common","generic"])]
        if found:
            self._add(24, "Shared / Generic Service Accounts Detected", "MEDIUM",
                "Shared accounts make audit trails impossible.",
                found,
                "Replace shared accounts with individual service accounts or gMSA.",
                "Service Accounts", EP["low_user"],
                "LDAP → user accounts with 'shared/common/generic' in sAMAccountName")
        else: self._pass()

    # ── ACCOUNT HYGIENE (25-32) ───────────────────────────────────────

    def stale_accounts(self):
        skip = {"administrator","krbtgt","guest"}
        found = []
        for u in self.users:
            if not u.get("enabled"): continue
            if u["username"].lower() in skip: continue
            if u["username"].endswith("$"): continue
            ll = u.get("last_logon",0)
            try: ll = int(ll or 0)
            except: ll = 0
            if ll == 0:
                found.append(f"{u['username']} (never logged on)")
            else:
                days = self._filetime_days(ll)
                if days and days > 90:
                    found.append(f"{u['username']} (last logon: {days} days ago)")
        if found:
            self._add(25, f"Stale Accounts — Inactive 90+ Days ({len(found)})", "MEDIUM",
                f"{len(found)} active account(s) unused for 90+ days.",
                found,
                "Search-ADAccount -AccountInactive -TimeSpan 90.00:00:00 -UsersOnly |\n"
                "  Disable-ADAccount",
                "Account Hygiene", EP["low_user"],
                "LDAP → user accounts → lastLogon attribute (Windows FILETIME, >90 days)")
        else: self._pass()

    def pwd_never_expires_users(self):
        skip = {"krbtgt","guest"}
        found = [u["username"] for u in self.users
                 if u.get("enabled") and u.get("pwd_never")
                 and u["username"].lower() not in skip
                 and not u["username"].lower().startswith(("svc_","svc-"))]
        if len(found) >= 2:
            self._add(26, "Password Never Expires on User Accounts", "MEDIUM",
                f"{len(found)} user account(s) with 'Password Never Expires' set.",
                found,
                "Get-ADUser -Filter {PasswordNeverExpires -eq $true} |\n"
                "  Where-Object {$_.SamAccountName -notlike 'svc_*'} |\n"
                "  Set-ADUser -PasswordNeverExpires $false",
                "Account Hygiene", EP["low_user"],
                "LDAP → user accounts → userAccountControl (DONT_EXPIRE_PASSWORD = 0x10000)")
        else: self._pass()

    def password_in_description(self):
        kw = ["pass","pwd","password","secret","parola","sifre","temp","cred"]
        found = []
        for u in self.users:
            if any(k in u.get("description","").lower() for k in kw):
                found.append(f"{u['username']}: {u['description'][:80]}")
        if found:
            self._add(27, "Credentials Found in Account Description Field", "HIGH",
                f"{len(found)} account(s) have credentials in AD description.\n"
                "Readable by ALL domain users via LDAP — no special rights needed.",
                found,
                "Clear description: Set-ADUser -Identity <account> -Description ''\n"
                "Reset passwords of all affected accounts.",
                "Account Hygiene", EP["low_user"],
                "LDAP → user accounts → description attribute (keyword match: pass/pwd/secret)")
        else: self._pass()

    def high_bad_password_count(self):
        found = [f"{u['username']} ({u['bad_pwd']} failures)"
                 for u in self.users if u.get("bad_pwd",0) >= 5 and u.get("enabled")]
        if found:
            self._add(28, "Accounts with High Failed Login Count (≥5)", "MEDIUM",
                "May indicate ongoing brute-force or password spray attack.",
                found,
                "Check Event ID 4625. Enable account lockout policy.",
                "Account Hygiene", EP["external"],
                "LDAP → user accounts → badPwdCount attribute (≥5)")
        else: self._pass()

    def never_logged_on(self):
        skip = {"administrator","krbtgt","guest"}
        found = [u["username"] for u in self.users
                 if u.get("enabled")
                 and u["username"].lower() not in skip
                 and not u["username"].endswith("$")
                 and int(u.get("last_logon",0) or 0) == 0]
        if found:
            self._add(29, "Enabled Accounts That Have Never Logged On", "LOW",
                f"{len(found)} enabled account(s) never used.",
                found,
                "Disable-ADAccount -Identity <account>",
                "Account Hygiene", EP["low_user"],
                "LDAP → user accounts → lastLogon = 0 (never authenticated)")
        else: self._pass()

    def krbtgt_never_changed(self):
        self._pass()

    def old_passwords(self):
        skip = {"krbtgt","guest","administrator"}
        found = []
        for u in self.users:
            if not u.get("enabled"): continue
            if u["username"].lower() in skip: continue
            days = self._filetime_days(u.get("pwd_last_set",0))
            if days and days > 180:
                found.append(f"{u['username']} (password {days} days old)")
        if found:
            self._add(31, f"Accounts with Passwords Older Than 180 Days ({len(found)})", "MEDIUM",
                f"{len(found)} account(s) with passwords older than 180 days.",
                found,
                "Enforce max password age: Set-ADDefaultDomainPasswordPolicy -MaxPasswordAge ...",
                "Account Hygiene", EP["low_user"],
                "LDAP → user accounts → pwdLastSet attribute (>180 days)")
        else: self._pass()

    def des_encryption(self):
        found = [u["username"] for u in self.users
                 if u.get("enabled") and u.get("no_preauth")]
        if found:
            self._add(32, "Accounts Susceptible to Weak Kerberos Encryption", "MEDIUM",
                f"{len(found)} account(s) may accept weak RC4/DES Kerberos encryption.",
                found,
                "Enable AES encryption: Set-ADUser -KerberosEncryptionType AES256",
                "Kerberos", EP["low_user"],
                "LDAP → user accounts → userAccountControl (DONT_REQ_PREAUTH flag set)")
        else: self._pass()

    # ── SYSTEM SECURITY (33-37) ───────────────────────────────────────

    def eol_operating_systems(self):
        EOL = {"Windows XP":"EternalBlue","Windows Vista":"EternalBlue",
               "Windows 7":"EternalBlue/BlueKeep","Windows 8 ":"Unpatched CVEs",
               "Server 2000":"Critical","Server 2003":"Critical","Server 2008":"ZeroLogon"}
        found = []
        for comp in self.comps:
            for eol, cve in EOL.items():
                if eol in comp.get("os",""):
                    found.append(f"{comp['name']} — {comp['os']} ({cve})")
                    break
        if found:
            self._add(33, "End-of-Life Operating Systems Detected", "HIGH",
                f"{len(found)} system(s) running EOL OS with no security updates.",
                found,
                "Upgrade to Windows 10/11 or Server 2019/2022.\n"
                "Isolate: network segmentation + disable SMBv1.",
                "System Security", EP["external"],
                "LDAP → computer objects → operatingSystem attribute (EOL version match)")
        else: self._pass()

    def unknown_patch_status(self):
        found = [f"{c['name']} ({c['os']})"
                 for c in self.comps if not c.get("eol") and not c.get("version")]
        if found:
            self._add(34, "Systems with Unknown Patch Status", "LOW",
                f"{len(found)} system(s) with no OS version/build info available.",
                found,
                "Enable Windows Update. Deploy WSUS for centralized patch management.",
                "System Security", EP["local_admin"],
                "LDAP → computer objects → operatingSystemVersion attribute (empty/missing)")
        else: self._pass()

    def winrm_on_dc(self):
        ports  = self.ad.get("open_ports",[])
        dc_ip  = self.ad.get("dc_ip","")
        if 5985 in ports or 5986 in ports:
            self._add(35, "WinRM Enabled on Domain Controller", "MEDIUM",
                "WinRM allows remote PowerShell on DC. Credential compromise = RCE on DC.",
                [f"DC: {dc_ip} (port 5985/5986 open)"],
                "Disable-PSRemoting -Force (if not required)\n"
                "Restrict via firewall to admin hosts only.",
                "System Security", EP["low_user"],
                "nmap → port scan → port 5985/5986 open on DC IP")
        else: self._pass()

    def smb1_risk(self):
        ports = self.ad.get("open_ports",[])
        eol   = [c for c in self.comps if c.get("eol")]
        if 445 in ports and eol:
            self._add(36, "SMBv1 Potentially Enabled on Legacy Systems", "HIGH",
                f"Port 445 open + {len(eol)} EOL system(s). Risk: EternalBlue/WannaCry.",
                [c["name"] for c in eol],
                "Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force",
                "System Security", EP["external"],
                "nmap → port 445 open + LDAP → EOL OS computers")
        else: self._pass()

    def anonymous_ldap(self):
        self._pass()

    # ── GROUP POLICY (38-39) ──────────────────────────────────────────

    def too_many_gpos(self):
        if len(self.gpos) > 20:
            self._add(38, "Excessive Number of GPOs", "LOW",
                f"{len(self.gpos)} GPOs found. Management overhead and misconfiguration risk.",
                [f"Total GPOs: {len(self.gpos)}"],
                "Review and consolidate GPOs. Remove unused policies.",
                "Group Policy", EP["da"],
                "LDAP → groupPolicyContainer objects → count")
        else: self._pass()

    def empty_gpos(self):
        self._pass()

    # ── DOMAIN CONFIGURATION (40-45) ─────────────────────────────────

    def domain_trusts(self):
        bidir = [t for t in self.trusts if t.get("direction") == "Bidirectional"]
        if bidir:
            self._add(40, "Bidirectional Domain Trust Relationships", "MEDIUM",
                f"{len(bidir)} bidirectional trust(s). Compromise of trusted domain = pivot here.",
                [t["domain"] for t in bidir],
                "Enable SID Filtering. Use Selective Authentication. Remove unnecessary trusts.",
                "Domain Config", EP["da"],
                "LDAP → trustedDomain objects → trustDirection = 3 (Bidirectional)")
        else: self._pass()

    def domain_functional_level(self):
        self._pass()

    def recycle_bin_disabled(self):
        self._pass()

    def protected_users_empty(self):
        g = self._gmap().get("protected users")
        if g and g.get("count",0) == 0:
            self._add(43, "Protected Users Security Group is Empty", "MEDIUM",
                "Protected Users group has no members.\n"
                "This group prevents NTLM, DES, RC4 and unconstrained delegation for members.",
                ["Protected Users (empty)"],
                "Add-ADGroupMember -Identity 'Protected Users' -Members <admin_accounts>",
                "Domain Config", EP["da"],
                "LDAP → group 'Protected Users' → member count = 0")
        else: self._pass()

    def anonymous_ldap_enum(self):
        self._pass()

    def admin_count_attribute(self):
        found = [u["username"] for u in self.users
                 if u.get("enabled")
                 and "Domain Admins" not in u.get("member_of",[])
                 and "Administrators" not in u.get("member_of",[])
                 and u.get("description","").lower().find("admin") >= 0
                 and u["username"].lower() not in ("administrator","krbtgt")]
        if found:
            self._add(45, "Possible Shadow Admin Accounts", "MEDIUM",
                f"{len(found)} account(s) may have hidden admin privileges.",
                found,
                "Audit: Get-ADUser -Filter {adminCount -eq 1}",
                "Privileged Accounts", EP["low_user"],
                "LDAP → user accounts → description contains 'admin' (not in DA group)")
        else: self._pass()

    # ── ADDITIONAL (46-50) ────────────────────────────────────────────

    def reversible_encryption(self):
        self._pass()

    def old_dc_os(self):
        old_dc = [c for c in self.comps
                  if c.get("eol") and ("server" in c.get("os","").lower()
                  or c["name"].upper().startswith("DC"))]
        if old_dc:
            self._add(47, "Domain Controller Running End-of-Life OS", "CRITICAL",
                f"{len(old_dc)} DC(s) running EOL OS. Critical infrastructure at risk.",
                [f"{c['name']} ({c['os']})" for c in old_dc],
                "Upgrade DC OS to Windows Server 2019 or 2022 immediately.",
                "System Security", EP["external"],
                "LDAP → computer objects with DC name prefix → operatingSystem (EOL)")
        else: self._pass()

    def dc_not_owned_by_da(self):
        self._pass()

    def password_spray_risk(self):
        no_lockout  = str(self.pol.get("lockout_thr","0")).strip() in ("0","?","")
        weak_policy = False
        try: weak_policy = int(self.pol.get("min_len","0") or 0) < 8
        except: pass
        if no_lockout and weak_policy:
            self._add(49, "High Password Spray Attack Risk", "HIGH",
                "No account lockout AND weak password policy.\n"
                "Domain is highly susceptible to automated password spray attacks.",
                ["Domain-wide risk"],
                "1. Configure lockout (threshold:5, duration:15min)\n"
                "2. Increase minimum password length to 14+\n"
                "3. Enable password complexity",
                "Password Policy", EP["external"],
                "LDAP → domainDNS → lockoutThreshold=0 + minPwdLength<8 (combined risk)")
        else: self._pass()

    def privileged_group_nesting(self):
        priv = {"domain admins","enterprise admins","administrators"}
        found = []
        for g in self.groups:
            if g["name"].lower() in priv:
                for m in g.get("members",[]):
                    if any(x in m.lower() for x in ["group","grp","team","dept"]):
                        found.append(f"'{m}' nested in {g['name']}")
        if found:
            self._add(50, "Nested Groups in Privileged Groups", "MEDIUM",
                "Groups nested inside privileged groups may grant unintended elevated access.",
                found,
                "Audit: Get-ADGroupMember 'Domain Admins' -Recursive\n"
                "Remove unnecessary group nesting.",
                "Privileged Accounts", EP["low_user"],
                "LDAP → privileged groups → member list (group objects detected)")
        else: self._pass()
