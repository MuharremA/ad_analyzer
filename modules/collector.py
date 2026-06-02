"""
ADScan — Active Directory Security Analyzer
collector.py — LDAP data collection module
"""
from ldap3 import Server, Connection, ALL, SUBTREE, SIMPLE
import re


def _dn(domain):
    return ",".join(f"DC={p}" for p in domain.split("."))


def _uac(val):
    v = int(val or 0)
    return {
        "enabled":    not bool(v & 0x0002),
        "pwd_never":  bool(v & 0x10000),
        "no_preauth": bool(v & 0x400000),
        "delegation": bool(v & 0x080000),
    }


class ADCollector:
    def __init__(self, dc_ip, domain, username, password):
        self.dc_ip    = dc_ip
        self.domain   = domain
        self.username = username
        self.password = password
        self.base     = _dn(domain)
        self.conn     = None

    def _connect(self):
        srv = Server(self.dc_ip, get_info=ALL, connect_timeout=10)
        upn = self.username if "@" in self.username else f"{self.username}@{self.domain}"
        self.conn = Connection(srv, user=upn, password=self.password,
                               authentication=SIMPLE, auto_bind=True,
                               receive_timeout=30)
        return self.conn.bound

    def _search(self, filt, attrs):
        self.conn.search(self.base, filt, SUBTREE, attributes=attrs)
        return self.conn.entries

    def run(self):
        data = {
            "users": [], "groups": [], "computers": [],
            "spns": [], "asrep_users": [], "domain_admins": [],
            "password_policy": {}, "gpos": [], "trusts": [],
            "dc_ip": self.dc_ip, "open_ports": []
        }
        print(f"  [*] Connecting to LDAP → {self.dc_ip}")
        try:
            self._connect()
        except Exception as e:
            print(f"  [-] Connection failed: {e}")
            return data
        print(f"  [+] LDAP connection successful")

        data["users"]           = self._get_users()
        data["groups"]          = self._get_groups()
        data["computers"]       = self._get_computers()
        data["spns"]            = self._get_spns()
        data["asrep_users"]     = self._get_asrep()
        data["password_policy"] = self._get_policy()
        data["domain_admins"]   = self._get_da_members()
        data["gpos"]            = self._get_gpos()
        data["trusts"]          = self._get_trusts()

        try: self.conn.unbind()
        except: pass
        return data

    def _get_users(self):
        print("  [*] Querying users...")
        try:
            entries = self._search(
                "(&(objectClass=user)(objectCategory=person))",
                ["sAMAccountName", "userAccountControl", "description",
                 "mail", "department", "title", "memberOf",
                 "badPwdCount", "lastLogon", "pwdLastSet"])
        except Exception as e:
            print(f"  [!] Error: {e}"); return []

        users = []
        for e in entries:
            sam = str(e.sAMAccountName)
            if not sam or sam.startswith("["): continue
            fl  = _uac(e.userAccountControl.value if e.userAccountControl else 0)
            mo  = [re.search(r"CN=([^,]+)", str(m)).group(1)
                   for m in (e.memberOf.values if e.memberOf else [])
                   if re.search(r"CN=([^,]+)", str(m))]
            try: ll = int(str(e.lastLogon)) if e.lastLogon else 0
            except: ll = 0
            try: pls = int(str(e.pwdLastSet)) if e.pwdLastSet else 0
            except: pls = 0

            users.append({
                "username":     sam,
                "enabled":      fl["enabled"],
                "pwd_never":    fl["pwd_never"],
                "no_preauth":   fl["no_preauth"],
                "delegation":   fl["delegation"],
                "description":  str(e.description) if e.description else "",
                "email":        str(e.mail)         if e.mail         else "",
                "department":   str(e.department)   if e.department   else "",
                "title":        str(e.title)         if e.title        else "",
                "bad_pwd":      int(e.badPwdCount.value) if e.badPwdCount else 0,
                "member_of":    mo,
                "last_logon":   ll,
                "pwd_last_set": pls,
            })
        return users

    def _get_groups(self):
        print("  [*] Querying groups...")
        try:
            entries = self._search("(objectClass=group)",
                                   ["sAMAccountName", "member", "description"])
        except Exception as e:
            print(f"  [!] Error: {e}"); return []
        groups = []
        for e in entries:
            sam = str(e.sAMAccountName)
            if not sam or sam.startswith("["): continue
            members = [re.search(r"CN=([^,]+)", str(m)).group(1)
                       for m in (e.member.values if e.member else [])
                       if re.search(r"CN=([^,]+)", str(m))]
            groups.append({
                "name":        sam,
                "description": str(e.description) if e.description else "",
                "members":     members,
                "count":       len(members),
            })
        return groups

    def _get_computers(self):
        print("  [*] Querying computers...")
        try:
            entries = self._search(
                "(objectClass=computer)",
                ["sAMAccountName", "operatingSystem",
                 "operatingSystemVersion", "dNSHostName"])
        except Exception as e:
            print(f"  [!] Error: {e}"); return []
        EOL = ["Windows XP", "Windows Vista", "Windows 7", "Windows 8 ",
               "Server 2000", "Server 2003", "Server 2008"]
        computers = []
        for e in entries:
            sam = str(e.sAMAccountName).rstrip("$")
            if not sam or sam.startswith("["): continue
            os_str = str(e.operatingSystem) if e.operatingSystem else "Unknown"
            computers.append({
                "name":    sam,
                "os":      os_str,
                "version": str(e.operatingSystemVersion) if e.operatingSystemVersion else "",
                "dns":     str(e.dNSHostName) if e.dNSHostName else "",
                "eol":     any(x in os_str for x in EOL),
            })
        return computers

    def _get_spns(self):
        print("  [*] Querying SPNs (Kerberoasting)...")
        try:
            entries = self._search(
                "(&(objectClass=user)(servicePrincipalName=*)"
                "(!(objectClass=computer))(!(sAMAccountName=*$)))",
                ["sAMAccountName", "servicePrincipalName", "userAccountControl"])
        except Exception as e:
            print(f"  [!] Error: {e}"); return []
        spns = []
        for e in entries:
            sam = str(e.sAMAccountName)
            if not sam or sam.startswith("["): continue
            fl  = _uac(e.userAccountControl.value if e.userAccountControl else 0)
            spn = [str(s) for s in
                   (e.servicePrincipalName.values if e.servicePrincipalName else [])]
            spns.append({"username": sam, "enabled": fl["enabled"], "spns": spn})
        return spns

    def _get_asrep(self):
        print("  [*] Scanning AS-REP Roasting vulnerabilities...")
        try:
            entries = self._search(
                "(&(objectClass=user)(objectCategory=person)"
                "(userAccountControl:1.2.840.113556.1.4.803:=4194304)"
                "(!(userAccountControl:1.2.840.113556.1.4.803:=2)))",
                ["sAMAccountName", "department", "memberOf"])
        except Exception as e:
            print(f"  [!] Error: {e}"); return []
        users = []
        for e in entries:
            sam = str(e.sAMAccountName)
            if not sam or sam.startswith("["): continue
            mo = [re.search(r"CN=([^,]+)", str(m)).group(1)
                  for m in (e.memberOf.values if e.memberOf else [])
                  if re.search(r"CN=([^,]+)", str(m))]
            users.append({
                "username":  sam,
                "dept":      str(e.department) if e.department else "",
                "member_of": mo,
            })
        return users

    def _get_policy(self):
        print("  [*] Querying password policy...")
        try:
            entries = self._search(
                "(objectClass=domainDNS)",
                ["minPwdLength", "pwdHistoryLength", "maxPwdAge",
                 "lockoutThreshold", "pwdProperties"])
        except: return {}
        if not entries: return {}
        e   = entries[0]
        pol = {}
        pol["min_len"]     = str(e.minPwdLength)     if e.minPwdLength     else "?"
        pol["history"]     = str(e.pwdHistoryLength) if e.pwdHistoryLength else "?"
        pol["lockout_thr"] = str(e.lockoutThreshold) if e.lockoutThreshold else "?"
        try:
            ns = abs(int(str(e.maxPwdAge))) if e.maxPwdAge else 0
            pol["max_age"] = f"{ns // 864000000000} days" if ns else "Unlimited"
        except: pol["max_age"] = "?"
        try:
            props = int(str(e.pwdProperties)) if e.pwdProperties else 0
            pol["complexity"] = "Enabled" if props & 1 else "Disabled"
        except: pol["complexity"] = "?"
        return pol

    def _get_da_members(self):
        try:
            for g in self._search(
                "(&(objectClass=group)(sAMAccountName=Domain Admins))",
                ["member"]):
                if g.member:
                    return [re.search(r"CN=([^,]+)", str(m)).group(1)
                            for m in g.member.values
                            if re.search(r"CN=([^,]+)", str(m))]
        except: pass
        return []

    def _get_gpos(self):
        print("  [*] Querying GPOs...")
        try:
            entries = self._search(
                "(objectClass=groupPolicyContainer)",
                ["displayName", "gPCFileSysPath", "whenCreated"])
        except: return []
        gpos = []
        for e in entries:
            name = str(e.displayName) if e.displayName else ""
            if name:
                gpos.append({
                    "name": name,
                    "path": str(e.gPCFileSysPath) if e.gPCFileSysPath else "",
                })
        return gpos

    def _get_trusts(self):
        print("  [*] Querying domain trusts...")
        try:
            entries = self._search(
                "(objectClass=trustedDomain)",
                ["flatName", "trustDirection", "trustType"])
        except: return []
        trusts = []
        dir_map = {"1": "Inbound", "2": "Outbound", "3": "Bidirectional"}
        for e in entries:
            flat = str(e.flatName) if e.flatName else ""
            direction = str(e.trustDirection) if e.trustDirection else "0"
            if flat:
                trusts.append({
                    "domain":    flat,
                    "direction": dir_map.get(direction, "Unknown"),
                })
        return trusts
