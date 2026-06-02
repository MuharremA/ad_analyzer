"""
ADScan v2.0 — reporter.py
"""
import os, math
from datetime import datetime
from collections import Counter

_SEV = {
    "CRITICAL": ("critical","#da3633","🔴"),
    "HIGH":     ("high",    "#f0883e","🟠"),
    "MEDIUM":   ("medium",  "#e3b341","🟡"),
    "LOW":      ("low",     "#3fb950","🟢"),
    "INFO":     ("info",    "#58a6ff","🔵"),
}
_EP_COLOR = {
    "Any authenticated user":        "#f0883e",
    "Low-privileged domain user":    "#e3b341",
    "Local administrator":           "#f0883e",
    "Domain Admin":                  "#da3633",
    "Anonymous / unauthenticated":   "#da3633",
    "External attacker (no creds)":  "#da3633",
}
_GRADE = {
    "A": ("#3fb950","Excellent"),
    "B": ("#58a6ff","Good"),
    "C": ("#e3b341","Fair"),
    "D": ("#f0883e","Poor"),
    "F": ("#da3633","Critical Risk"),
}

CHECKS_TABLE = [
    (1,"AS-REP Roasting","Kerberos","LDAP → userAccountControl (0x400000)","Low-privileged domain user","HIGH"),
    (2,"Kerberoasting — SPN Accounts","Kerberos","LDAP → servicePrincipalName","Low-privileged domain user","HIGH"),
    (3,"Unconstrained Kerberos Delegation","Kerberos","LDAP → userAccountControl (0x080000)","Local administrator","CRITICAL"),
    (4,"Constrained Delegation Misconfiguration","Kerberos","LDAP → msDS-AllowedToDelegateTo","Local administrator","HIGH"),
    (5,"krbtgt Password Age — Golden Ticket Risk","Kerberos","LDAP → krbtgt → pwdLastSet","Domain Admin","CRITICAL"),
    (6,"Minimum Password Length < 14","Password Policy","LDAP → domainDNS → minPwdLength","External attacker (no creds)","HIGH"),
    (7,"Password Complexity Disabled","Password Policy","LDAP → domainDNS → pwdProperties (bit 1)","External attacker (no creds)","HIGH"),
    (8,"Insufficient Password History","Password Policy","LDAP → domainDNS → pwdHistoryLength","Any authenticated user","MEDIUM"),
    (9,"Account Lockout Not Configured","Password Policy","LDAP → domainDNS → lockoutThreshold = 0","External attacker (no creds)","HIGH"),
    (10,"Lockout Observation Window Too Short","Password Policy","LDAP → domainDNS → lockoutObservationWindow","External attacker (no creds)","MEDIUM"),
    (11,"Lockout Duration Too Short","Password Policy","LDAP → domainDNS → lockoutDuration","External attacker (no creds)","MEDIUM"),
    (12,"Maximum Password Age Unlimited","Password Policy","LDAP → domainDNS → maxPwdAge","Any authenticated user","MEDIUM"),
    (13,"Fine-Grained Password Policy Missing","Password Policy","LDAP → msDS-PasswordSettingsContainer","Domain Admin","LOW"),
    (14,"Excessive Domain Admins (>5)","Privileged Accounts","LDAP → Domain Admins → member count","Low-privileged domain user","HIGH"),
    (15,"Default Administrator Active & Not Renamed","Privileged Accounts","LDAP → user Administrator → enabled","External attacker (no creds)","MEDIUM"),
    (16,"Disabled Accounts in Privileged Groups","Privileged Accounts","LDAP → privileged groups + UAC cross-check","Domain Admin","MEDIUM"),
    (17,"Guest Account Enabled","Privileged Accounts","LDAP → user Guest → userAccountControl","Anonymous / unauthenticated","HIGH"),
    (18,"Schema Admins Group Non-Empty","Privileged Accounts","LDAP → Schema Admins → member count","Domain Admin","MEDIUM"),
    (19,"Enterprise Admins Group Non-Empty","Privileged Accounts","LDAP → Enterprise Admins → member count","Domain Admin","MEDIUM"),
    (20,"Admin Accounts Without Description","Privileged Accounts","LDAP → users with admin in name → description","Domain Admin","LOW"),
    (21,"Service Accounts in Privileged Groups","Service Accounts","LDAP → privileged groups + svc_ cross-check","Local administrator","HIGH"),
    (22,"Undocumented Service Accounts","Service Accounts","LDAP → svc_ accounts → description = empty","Low-privileged domain user","MEDIUM"),
    (23,"Service Accounts — Password Never Expires","Service Accounts","LDAP → svc_ accounts → UAC (0x10000)","Low-privileged domain user","MEDIUM"),
    (24,"Shared / Generic Service Accounts","Service Accounts","LDAP → accounts with shared/common/generic","Low-privileged domain user","MEDIUM"),
    (25,"Stale Accounts — Inactive 90+ Days","Account Hygiene","LDAP → user accounts → lastLogon (>90 days)","Low-privileged domain user","MEDIUM"),
    (26,"Password Never Expires — User Accounts","Account Hygiene","LDAP → user accounts → UAC (DONT_EXPIRE_PASSWORD)","Low-privileged domain user","MEDIUM"),
    (27,"Credentials in Account Description Field","Account Hygiene","LDAP → description (keyword: pass/pwd/secret)","Low-privileged domain user","HIGH"),
    (28,"High Failed Login Count (>=5)","Account Hygiene","LDAP → user accounts → badPwdCount >= 5","External attacker (no creds)","MEDIUM"),
    (29,"Accounts That Have Never Logged On","Account Hygiene","LDAP → user accounts → lastLogon = 0","Low-privileged domain user","LOW"),
    (30,"krbtgt Password Never Changed","Account Hygiene","LDAP → krbtgt → pwdLastSet = 0","Domain Admin","CRITICAL"),
    (31,"Passwords Older Than 180 Days","Account Hygiene","LDAP → user accounts → pwdLastSet (>180 days)","Low-privileged domain user","MEDIUM"),
    (32,"Weak Kerberos Encryption (RC4/DES)","Account Hygiene","LDAP → UAC (DONT_REQ_PREAUTH flag)","Low-privileged domain user","MEDIUM"),
    (33,"End-of-Life Operating Systems","System Security","LDAP → computer → operatingSystem (EOL match)","External attacker (no creds)","HIGH"),
    (34,"Unknown Patch Status","System Security","LDAP → computer → operatingSystemVersion (empty)","Local administrator","LOW"),
    (35,"WinRM Enabled on Domain Controller","System Security","nmap → port 5985/5986 on DC IP","Low-privileged domain user","MEDIUM"),
    (36,"SMBv1 Risk on Legacy Systems","System Security","nmap → port 445 + LDAP → EOL computers","External attacker (no creds)","HIGH"),
    (37,"Anonymous LDAP Bind Possible","System Security","LDAP → anonymous bind attempt","Anonymous / unauthenticated","HIGH"),
    (38,"Excessive Number of GPOs (>20)","Group Policy","LDAP → groupPolicyContainer count","Domain Admin","LOW"),
    (39,"Empty / Unused GPOs","Group Policy","LDAP → groupPolicyContainer → no linked OUs","Domain Admin","LOW"),
    (40,"Bidirectional Domain Trusts","Domain Config","LDAP → trustedDomain → trustDirection = 3","Domain Admin","MEDIUM"),
    (41,"Domain Functional Level Below 2016","Domain Config","LDAP → domainDNS → msDS-Behavior-Version","Domain Admin","MEDIUM"),
    (42,"AD Recycle Bin Not Enabled","Domain Config","LDAP → Optional Features → Recycle Bin","Domain Admin","LOW"),
    (43,"Protected Users Group Empty","Domain Config","LDAP → Protected Users group → member count = 0","Domain Admin","MEDIUM"),
    (44,"Anonymous LDAP Enumeration Possible","Domain Config","LDAP → anonymous query on base DN","Anonymous / unauthenticated","HIGH"),
    (45,"Shadow Admin Accounts Detected","Privileged Accounts","LDAP → adminCount=1 attribute cross-check","Low-privileged domain user","MEDIUM"),
    (46,"Reversible Encryption Enabled","Account Hygiene","LDAP → UAC (ADS_UF_ENCRYPTED_TEXT_PASSWORD)","Low-privileged domain user","HIGH"),
    (47,"DC Running End-of-Life OS","System Security","LDAP → DC computer objects → operatingSystem","External attacker (no creds)","CRITICAL"),
    (48,"DC Not Owned by Domain Admins","Domain Config","LDAP → DC objects → nTSecurityDescriptor","Domain Admin","HIGH"),
    (49,"High Password Spray Attack Risk","Password Policy","LDAP → lockoutThreshold=0 + minPwdLength<8","External attacker (no creds)","HIGH"),
    (50,"Nested Groups in Privileged Groups","Privileged Accounts","LDAP → privileged groups → group objects nested","Low-privileged domain user","MEDIUM"),
]

# ── Knowledge Base: açıklama + çözüm + MITRE ATT&CK ──────────────────────────
KNOWLEDGE_BASE = {
    1: {
        "mitre": "T1558.004",
        "mitre_url": "https://attack.mitre.org/techniques/T1558/004/",
        "desc": "When a user account has Kerberos pre-authentication disabled (UAC flag 0x400000), any attacker on the network can request an AS-REP response from the Domain Controller for that account without providing any credentials. The response contains a portion encrypted with the user's password hash, which can then be cracked offline using tools like Hashcat or John the Ripper — no foothold required.",
        "fix": "1. Enable Kerberos pre-authentication for all user accounts: <code>Set-ADUser -Identity &lt;user&gt; -KerberosEncryptionType AES256</code><br>2. Run the following to find all vulnerable accounts: <code>Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true}</code><br>3. Only disable pre-auth if absolutely required by a legacy application — document the exception.<br>4. Enable auditing on AS-REP requests (Event ID 4768).",
    },
    2: {
        "mitre": "T1558.003",
        "mitre_url": "https://attack.mitre.org/techniques/T1558/003/",
        "desc": "Any domain user can request a Kerberos service ticket (TGS) for any account with a registered Service Principal Name (SPN). The ticket is encrypted with the account's NTLM password hash. An attacker can capture this ticket and crack it offline — especially dangerous when service accounts use RC4 encryption instead of AES256, as RC4 hashes crack significantly faster.",
        "fix": "1. Audit SPNs: <code>Get-ADUser -Filter {ServicePrincipalName -ne '$null'} -Properties ServicePrincipalName</code><br>2. Migrate service accounts to Group Managed Service Accounts (gMSA) — their passwords rotate automatically and are 120 characters long.<br>3. Enforce AES256 encryption: <code>Set-ADUser -Identity &lt;svc&gt; -KerberosEncryptionType AES256</code><br>4. Ensure service account passwords are at least 25 characters and rotated regularly.",
    },
    3: {
        "mitre": "T1134.001",
        "mitre_url": "https://attack.mitre.org/techniques/T1134/001/",
        "desc": "When a computer or user account has Unconstrained Delegation enabled, any user who authenticates to a service on that machine will have their TGT (Ticket Granting Ticket) forwarded to and cached on that machine. An attacker who compromises the machine can harvest these cached TGTs and impersonate any user — including Domain Admins — who has recently authenticated.",
        "fix": "1. Find all accounts with unconstrained delegation: <code>Get-ADComputer -Filter {TrustedForDelegation -eq $true}</code><br>2. Remove the flag unless strictly required: <code>Set-ADComputer -Identity &lt;PC&gt; -TrustedForDelegation $false</code><br>3. Add sensitive accounts (Domain Admins, service accounts) to the <strong>Protected Users</strong> security group — this group prevents credential caching.<br>4. If delegation is needed, use Constrained Delegation (msDS-AllowedToDelegateTo) instead.",
    },
    4: {
        "mitre": "T1134.001",
        "mitre_url": "https://attack.mitre.org/techniques/T1134/001/",
        "desc": "Constrained Delegation limits which services an account can delegate to. However, if misconfigured — for example, if any service is allowed, or if Protocol Transition (S4U2Self) is enabled — an attacker who compromises the delegating account can impersonate any domain user to the target service, potentially leading to privilege escalation.",
        "fix": "1. Audit constrained delegation settings: <code>Get-ADObject -Filter {msDS-AllowedToDelegateTo -like '*'} -Properties msDS-AllowedToDelegateTo</code><br>2. Prefer Resource-Based Constrained Delegation (RBCD) which gives the target resource control.<br>3. Remove Protocol Transition (TrustedToAuthForDelegation) unless absolutely required.<br>4. Scope delegation to only the specific SPNs that are actually needed.",
    },
    5: {
        "mitre": "T1558.001",
        "mitre_url": "https://attack.mitre.org/techniques/T1558/001/",
        "desc": "The krbtgt account is used to sign all Kerberos tickets in the domain. If an attacker obtains the krbtgt NTLM hash (e.g., via DCSync or domain compromise), they can forge valid Ticket Granting Tickets (TGTs) for any account, including non-existent ones, with any group memberships and any validity period — known as a Golden Ticket. If the krbtgt password has never been changed, stolen hashes from old breaches remain valid.",
        "fix": "1. Reset the krbtgt password twice (required to invalidate all existing tickets): use Microsoft's <code>Reset-KrbtgtKeyInteractive.ps1</code> script.<br>2. Schedule a krbtgt password reset every 6 months at minimum.<br>3. Monitor for Event ID 4769 with unusual ticket lifetimes.<br>4. Implement Microsoft Defender for Identity to detect Golden Ticket attacks in real time.",
    },
    6: {
        "mitre": "T1110.001",
        "mitre_url": "https://attack.mitre.org/techniques/T1110/001/",
        "desc": "Short passwords are highly vulnerable to brute-force and dictionary attacks. A minimum length below 14 characters allows common passwords like 'Password1!' to be valid. NIST SP 800-63B and CIS Benchmarks both recommend at least 14 characters for privileged accounts.",
        "fix": "1. Set minimum password length to 14+ characters via Group Policy: <em>Computer Configuration → Windows Settings → Security Settings → Account Policies → Password Policy → Minimum password length</em>.<br>2. Consider using passphrases (e.g., 'RedHorse!Lamp22') instead of complex short passwords.<br>3. Apply a stricter Fine-Grained Password Policy (FGPP) for admin accounts requiring 20+ characters.",
    },
    7: {
        "mitre": "T1110.001",
        "mitre_url": "https://attack.mitre.org/techniques/T1110/001/",
        "desc": "Without complexity requirements, users can set trivially guessable passwords such as their username, company name, or sequential numbers. This dramatically increases the success rate of dictionary and spray attacks.",
        "fix": "1. Enable complexity in Group Policy: <em>Password must meet complexity requirements → Enabled</em>.<br>2. Complexity requires: uppercase, lowercase, digit, and special character.<br>3. Consider deploying a custom password filter (e.g., PassFilt.dll) that blocks known breached passwords using a blocklist like HIBP (Have I Been Pwned).",
    },
    8: {
        "mitre": "T1078",
        "mitre_url": "https://attack.mitre.org/techniques/T1078/",
        "desc": "If password history is too short (e.g., only remembering 3 previous passwords), users can cycle through a small set of passwords and reuse old compromised ones. A history of less than 24 passwords allows rapid reuse.",
        "fix": "1. Set password history to 24 in Group Policy: <em>Enforce password history → 24 passwords remembered</em>.<br>2. Also set Minimum password age to 1 day to prevent immediate cycling.<br>3. Combine with a password blocklist to prevent re-use of known-compromised passwords.",
    },
    9: {
        "mitre": "T1110.003",
        "mitre_url": "https://attack.mitre.org/techniques/T1110/003/",
        "desc": "Without an account lockout policy, attackers can attempt unlimited password guesses against any account — enabling brute-force and password spray attacks without any risk of detection or lockout. This is especially dangerous for internet-exposed services like VPN or OWA.",
        "fix": "1. Set Account Lockout Threshold to 5 invalid attempts in Group Policy.<br>2. Set Lockout Duration to 15 minutes minimum.<br>3. Set Reset Lockout Counter After to 15 minutes.<br>4. For admin accounts, apply a stricter FGPP with threshold of 3 attempts.<br>5. Monitor Event ID 4740 (account locked out) and 4625 (failed logon) for spray detection.",
    },
    10: {
        "mitre": "T1110.003",
        "mitre_url": "https://attack.mitre.org/techniques/T1110/003/",
        "desc": "A short observation window (the time after which failed attempt counters reset) allows attackers to make several password guesses, wait for the counter to reset, then try more — effectively bypassing the lockout threshold through slow, distributed spraying.",
        "fix": "1. Set Lockout Observation Window to at least 15 minutes.<br>2. This should match or exceed the lockout duration.<br>3. For high-security environments, consider 30–60 minutes.<br>4. Configure via Group Policy: <em>Reset account lockout counter after → 15 minutes</em>.",
    },
    11: {
        "mitre": "T1110.003",
        "mitre_url": "https://attack.mitre.org/techniques/T1110/003/",
        "desc": "A very short lockout duration (e.g., 1 minute) means accounts unlock almost immediately after being locked. This lets attackers automate repeated spray attempts with minimal delay, effectively defeating the purpose of account lockout.",
        "fix": "1. Set Account Lockout Duration to at least 15 minutes (0 = admin must unlock manually — most secure).<br>2. Consider setting to 0 for privileged accounts so an admin must manually unlock.<br>3. Configure via Group Policy: <em>Account lockout duration → 15 minutes</em>.",
    },
    12: {
        "mitre": "T1078",
        "mitre_url": "https://attack.mitre.org/techniques/T1078/",
        "desc": "When passwords never expire, compromised credentials remain valid indefinitely. If a user's password was obtained through phishing, credential stuffing, or a past breach, the attacker retains persistent access with no forced rotation.",
        "fix": "1. Set Maximum Password Age to 90 days in Group Policy.<br>2. For service accounts, use Group Managed Service Accounts (gMSA) — passwords rotate automatically every 30 days.<br>3. Use Microsoft Entra ID Password Protection to block weak/expired password reuse.",
    },
    13: {
        "mitre": "T1078.002",
        "mitre_url": "https://attack.mitre.org/techniques/T1078/002/",
        "desc": "The default domain password policy applies uniformly to all users. Without Fine-Grained Password Policies (FGPPs), high-privilege accounts like Domain Admins are subject to the same weak policy as regular users. FGPPs allow stricter rules for sensitive accounts.",
        "fix": "1. Create PSOs (Password Settings Objects) via Active Directory Administrative Center or PowerShell: <code>New-ADFineGrainedPasswordPolicy</code>.<br>2. Apply stricter policy to Domain Admins: min length 20+, complexity required, max age 60 days, lockout threshold 3.<br>3. Apply to service accounts: long passwords, no expiry only if gMSA is not possible.",
    },
    14: {
        "mitre": "T1078.002",
        "mitre_url": "https://attack.mitre.org/techniques/T1078/002/",
        "desc": "The Domain Admins group grants full control over the entire Active Directory domain. Having more than 5 members significantly increases the attack surface — each extra admin account is a potential entry point for domain compromise. Most organizations need only 2–3 Domain Admins.",
        "fix": "1. Audit Domain Admins: <code>Get-ADGroupMember 'Domain Admins'</code>.<br>2. Remove any accounts that do not require full domain admin rights — use delegated OU permissions instead.<br>3. Ensure DA accounts are dedicated admin accounts (not used for daily work or email).<br>4. Enable MFA for all Domain Admin accounts.<br>5. Monitor Event ID 4728/4732 (group member added).",
    },
    15: {
        "mitre": "T1078.002",
        "mitre_url": "https://attack.mitre.org/techniques/T1078/002/",
        "desc": "The built-in Administrator account (SID ending in -500) cannot be permanently locked out, making it a persistent brute-force target. Leaving it enabled with the default name 'Administrator' is a common attack target in credential stuffing, RDP attacks, and lateral movement.",
        "fix": "1. Rename the Administrator account: <code>Rename-LocalUser -Name Administrator -NewName 'Corp-Admin-01'</code>.<br>2. Create a decoy account named 'Administrator' with no privileges and alert on any logon to it.<br>3. Disable the built-in Administrator account where possible and use named admin accounts instead.<br>4. Enable audit on the renamed account (Event ID 4624).",
    },
    16: {
        "mitre": "T1078.002",
        "mitre_url": "https://attack.mitre.org/techniques/T1078/002/",
        "desc": "Disabled accounts that remain in privileged groups (Domain Admins, Enterprise Admins, etc.) pose a risk if they are re-enabled — intentionally or accidentally. They also indicate poor access management hygiene and may reflect accounts of former employees with lingering permissions.",
        "fix": "1. Run quarterly access reviews of all privileged group memberships.<br>2. Remove disabled accounts from all privileged groups immediately upon disabling.<br>3. Automate with a script: <code>Get-ADGroupMember 'Domain Admins' | Where {(Get-ADUser $_).Enabled -eq $false}</code>.<br>4. Consider using an Identity Governance solution for automated deprovisioning.",
    },
    17: {
        "mitre": "T1078.001",
        "mitre_url": "https://attack.mitre.org/techniques/T1078/001/",
        "desc": "The built-in Guest account allows unauthenticated or anonymous access to domain resources. Even if no password is required, an enabled Guest account can be used for initial reconnaissance, anonymous LDAP queries, or lateral movement without any credentials.",
        "fix": "1. Disable the Guest account via Group Policy: <em>Computer Configuration → Windows Settings → Security Settings → Local Policies → Security Options → Accounts: Guest account status → Disabled</em>.<br>2. Verify: <code>Get-ADUser Guest | Select Enabled</code>.<br>3. Ensure the Guest account is not a member of any groups beyond the default.",
    },
    18: {
        "mitre": "T1078.002",
        "mitre_url": "https://attack.mitre.org/techniques/T1078/002/",
        "desc": "The Schema Admins group has the ability to modify the Active Directory schema — the fundamental structure of all AD objects. This is one of the most powerful privileges in the forest. Any member of this group can make irreversible changes to the AD schema affecting all domains in the forest.",
        "fix": "1. Schema Admins should be empty by default — members are only added temporarily when schema changes are needed (e.g., Exchange upgrades).<br>2. Remove all permanent members: <code>Get-ADGroupMember 'Schema Admins'</code>.<br>3. Add members only for the duration of planned schema changes, then remove immediately.<br>4. Alert on any membership change (Event ID 4728).",
    },
    19: {
        "mitre": "T1078.002",
        "mitre_url": "https://attack.mitre.org/techniques/T1078/002/",
        "desc": "Enterprise Admins have full control over all domains in the entire Active Directory forest — more powerful than Domain Admins. This group should be empty except during forest-wide operations like adding a new domain. Permanent membership greatly increases the blast radius of any account compromise.",
        "fix": "1. Enterprise Admins should be empty by default — only populated temporarily for forest-level operations.<br>2. Remove all permanent members: <code>Get-ADGroupMember 'Enterprise Admins'</code>.<br>3. Add members only for the duration of forest-level tasks, then remove immediately.<br>4. Implement a PAM (Privileged Access Management) workflow for temporary elevation.",
    },
    20: {
        "mitre": "T1087.002",
        "mitre_url": "https://attack.mitre.org/techniques/T1087/002/",
        "desc": "Admin accounts without descriptions make it impossible to determine the purpose, owner, or last review date of the account. During an incident, undocumented admin accounts create confusion and delay response. They may also indicate unauthorized accounts created by an attacker.",
        "fix": "1. Mandate descriptions for all privileged accounts: owner name, purpose, creation date, last review date.<br>2. Use a standardized format: <em>'Owner: John Smith | Purpose: SQL maintenance | Created: 2024-01 | Reviewed: 2024-06'</em>.<br>3. Include description in quarterly access reviews.<br>4. Use AD attributes: <code>Set-ADUser -Identity &lt;user&gt; -Description 'Owner: ...'</code>.",
    },
    21: {
        "mitre": "T1078.002",
        "mitre_url": "https://attack.mitre.org/techniques/T1078/002/",
        "desc": "Service accounts that are members of Domain Admins or other privileged groups are a critical risk. Service accounts are frequently the target of Kerberoasting or pass-the-hash attacks. If compromised, a service account with DA membership grants full domain control to the attacker.",
        "fix": "1. Audit: <code>Get-ADGroupMember 'Domain Admins' | Where {$_.SamAccountName -like 'svc_*'}</code>.<br>2. Remove service accounts from all privileged groups immediately.<br>3. Use the principle of least privilege — grant only the specific permissions the service needs.<br>4. Migrate to Group Managed Service Accounts (gMSA) which use auto-rotating 120-character passwords.",
    },
    22: {
        "mitre": "T1087.002",
        "mitre_url": "https://attack.mitre.org/techniques/T1087/002/",
        "desc": "Service accounts without descriptions are unmanageable. In incident response or during an audit, there is no way to determine what application uses the account, who owns it, or whether it is still needed. Orphaned undocumented service accounts are a common persistence mechanism for attackers.",
        "fix": "1. Require all service accounts to have a description: application name, server/service it runs on, owner, and last review date.<br>2. Disable service accounts that cannot be attributed to a specific service after investigation.<br>3. Use: <code>Get-ADUser -Filter {Description -eq $null -and SamAccountName -like 'svc_*'}</code> to find undocumented accounts.",
    },
    23: {
        "mitre": "T1078",
        "mitre_url": "https://attack.mitre.org/techniques/T1078/",
        "desc": "Service accounts with non-expiring passwords represent a permanent credential that never forces rotation. If the password is compromised — through Kerberoasting, phishing, or memory dumping — the attacker retains access indefinitely. This is especially dangerous for accounts with broad permissions.",
        "fix": "1. Migrate to Group Managed Service Accounts (gMSA) — passwords rotate automatically every 30 days, 120 characters long, no human knowledge needed.<br>2. If gMSA is not possible, implement manual password rotation every 90 days with a privileged access management (PAM) vault like CyberArk or HashiCorp Vault.<br>3. Remove the 'Password Never Expires' flag: <code>Set-ADUser -Identity &lt;svc&gt; -PasswordNeverExpires $false</code>.",
    },
    24: {
        "mitre": "T1078",
        "mitre_url": "https://attack.mitre.org/techniques/T1078/",
        "desc": "Shared or generic service accounts (e.g., 'svc_shared', 'common_svc', 'generic_admin') are used by multiple services or teams, making it impossible to attribute actions to a specific service. There is no accountability, and password changes affect multiple services simultaneously — leading to either infrequent rotation or outages.",
        "fix": "1. Create dedicated service accounts for each individual service or application.<br>2. Name accounts descriptively: <em>svc_sqlprod01, svc_backupexec</em>.<br>3. Never share credentials between multiple services or teams.<br>4. Use gMSA for automated, non-shared credential management.",
    },
    25: {
        "mitre": "T1078",
        "mitre_url": "https://attack.mitre.org/techniques/T1078/",
        "desc": "Accounts that have not been used for 90 or more days likely belong to former employees, contractors, or decommissioned systems. These accounts represent valid credentials that can be used for unauthorized access without triggering behavioral alerts based on usage patterns. They are a common target in insider threats and external attacks.",
        "fix": "1. Disable accounts inactive for 90+ days: <code>Search-ADAccount -AccountInactive -TimeSpan 90 | Disable-ADAccount</code>.<br>2. After 30 more days, move to a 'Disabled Users' OU and remove from all groups.<br>3. After 6 months, delete the account.<br>4. Implement an automated offboarding workflow triggered by HR system.<br>5. Review exceptions for service accounts that are expected to be inactive.",
    },
    26: {
        "mitre": "T1078",
        "mitre_url": "https://attack.mitre.org/techniques/T1078/",
        "desc": "User accounts with the 'Password Never Expires' flag set are exempt from the domain's maximum password age policy. If these accounts' passwords are compromised — through phishing, credential stuffing, or dark web leaks — the attacker retains permanent access with no forced rotation.",
        "fix": "1. Audit: <code>Get-ADUser -Filter {PasswordNeverExpires -eq $true} -Properties PasswordNeverExpires</code>.<br>2. Remove the flag for all regular user accounts: <code>Set-ADUser -Identity &lt;user&gt; -PasswordNeverExpires $false</code>.<br>3. Only allow non-expiring passwords for gMSA accounts (managed automatically) and specific break-glass accounts stored in a vault.",
    },
    27: {
        "mitre": "T1552.001",
        "mitre_url": "https://attack.mitre.org/techniques/T1552/001/",
        "desc": "Storing passwords, passphrases, or credentials in the AD Description field is a critical mistake. This field is readable by all authenticated domain users by default. An attacker with any domain account can query all descriptions and instantly harvest plaintext credentials for other accounts — often service accounts or admin accounts.",
        "fix": "1. Immediately clear description fields containing credentials: <code>Set-ADUser -Identity &lt;user&gt; -Description ''</code>.<br>2. Change the passwords of all affected accounts immediately.<br>3. Use a dedicated password manager or PAM vault for credential storage.<br>4. Regularly scan: <code>Get-ADUser -Filter * -Properties Description | Where {$_.Description -match 'pass|pwd|secret|cred'}</code>.",
    },
    28: {
        "mitre": "T1110",
        "mitre_url": "https://attack.mitre.org/techniques/T1110/",
        "desc": "Accounts with high failed login counts (badPwdCount >= 5) indicate active brute-force or password spray attacks in progress. This may represent an attacker systematically trying common passwords against these accounts, or it could indicate a misconfigured service causing repeated authentication failures.",
        "fix": "1. Immediately investigate the source of failed logins (Event ID 4625 in Security log).<br>2. Determine if this is an attack or a misconfigured application.<br>3. If under attack, block the source IP at the firewall.<br>4. Reset the badPwdCount: <code>Set-ADUser -Identity &lt;user&gt; -Replace @{badPwdCount=0}</code>.<br>5. Enable Microsoft Defender for Identity for automated spray detection.",
    },
    29: {
        "mitre": "T1078",
        "mitre_url": "https://attack.mitre.org/techniques/T1078/",
        "desc": "Accounts that have never been used since creation (lastLogon = 0 or never set) may indicate test accounts, orphaned provisioning artifacts, or accounts created by an attacker for future use. They represent credentials that could be activated at any time.",
        "fix": "1. Identify: <code>Get-ADUser -Filter {LastLogonDate -notlike '*'} -Properties LastLogonDate</code>.<br>2. Verify with the account owner whether the account is still needed.<br>3. Disable accounts that have never logged in and have existed for more than 30 days.<br>4. Review the account creation logs to identify who created them and why.",
    },
    30: {
        "mitre": "T1558.001",
        "mitre_url": "https://attack.mitre.org/techniques/T1558/001/",
        "desc": "The krbtgt account password has never been changed since the domain was created (pwdLastSet = 0 or epoch). This is a critical indicator that the domain has never been fully re-secured after initial setup or any past compromise. A stolen krbtgt hash that is years old can still be used to forge Golden Tickets.",
        "fix": "1. This requires immediate remediation — run the Microsoft Reset-KrbtgtKeyInteractive.ps1 script.<br>2. The password must be reset TWICE (24 hours apart) to fully invalidate all existing tickets across all DCs.<br>3. Coordinate with the business to schedule a maintenance window as all Kerberos tickets will be invalidated.<br>4. Schedule recurring resets every 6 months.",
    },
    31: {
        "mitre": "T1078",
        "mitre_url": "https://attack.mitre.org/techniques/T1078/",
        "desc": "Passwords that have not been changed in over 180 days significantly increase the likelihood that compromised credentials are still in use. Leaked credentials from data breaches, phishing campaigns, or malware infections that occurred within this window remain fully valid.",
        "fix": "1. Force password reset for accounts with passwords older than 180 days.<br>2. Set Maximum Password Age to 90 days in Group Policy.<br>3. Enable SSPR (Self-Service Password Reset) in Microsoft Entra ID to make user-driven resets easy.<br>4. Deploy Microsoft Entra ID Password Protection to block reuse of breached passwords.",
    },
    32: {
        "mitre": "T1558.003",
        "mitre_url": "https://attack.mitre.org/techniques/T1558/003/",
        "desc": "RC4 and DES Kerberos encryption types are considered weak by modern standards. RC4-HMAC tickets, commonly used in Kerberoasting attacks, can be cracked significantly faster than AES256 tickets using GPU-accelerated tools like Hashcat. DES is completely broken and should never be in use.",
        "fix": "1. Disable RC4 and DES on all domain controllers and clients via Group Policy: <em>Network Security: Configure encryption types allowed for Kerberos → AES128, AES256 only</em>.<br>2. Update all service account SPNs to use AES256: <code>Set-ADUser -Identity &lt;svc&gt; -KerberosEncryptionType AES256</code>.<br>3. Note: Disabling RC4 may break older applications — test in staging first.",
    },
    33: {
        "mitre": "T1190",
        "mitre_url": "https://attack.mitre.org/techniques/T1190/",
        "desc": "End-of-Life operating systems (Windows XP, Vista, 7, Server 2003/2008/2008 R2) no longer receive security patches from Microsoft. These systems contain known, publicly documented vulnerabilities — such as EternalBlue (MS17-010) which was exploited by WannaCry and NotPetya ransomware — that will never be fixed. Any EOL system on the network is a high-confidence attack vector.",
        "fix": "1. Immediately isolate EOL systems in a dedicated network segment with strict firewall rules.<br>2. Plan and execute migration to a supported OS as a priority.<br>3. If migration is impossible, apply compensating controls: host-based firewall (block all inbound), disable SMBv1, disable RDP, enable Enhanced Security Mode.<br>4. Apply Microsoft's Custom Support Agreement (CSA) for critical EOL systems during migration.",
    },
    34: {
        "mitre": "T1082",
        "mitre_url": "https://attack.mitre.org/techniques/T1082/",
        "desc": "Computer objects with no OS version information in Active Directory indicate systems that have not properly registered their details, are offline for extended periods, or are unmanaged/rogue machines. These systems cannot be assessed for patch status, creating a blind spot in security monitoring.",
        "fix": "1. Identify unresponsive systems: <code>Get-ADComputer -Filter {OperatingSystemVersion -notlike '*'}</code>.<br>2. Verify whether these are still active systems using network scanning.<br>3. Disable AD objects for systems that are confirmed decommissioned.<br>4. Ensure WSUS or SCCM/Intune is deployed to all systems for centralized patch visibility.",
    },
    35: {
        "mitre": "T1021.006",
        "mitre_url": "https://attack.mitre.org/techniques/T1021/006/",
        "desc": "WinRM (Windows Remote Management) on ports 5985/5986 enables remote PowerShell execution. If WinRM is enabled on a Domain Controller, any account with sufficient permissions can execute commands remotely on the most sensitive server in the domain. WinRM is also used by tools like Empire and CrackMapExec for lateral movement.",
        "fix": "1. Disable WinRM on Domain Controllers unless actively required for management: <code>Disable-PSRemoting -Force</code>.<br>2. If WinRM is needed, restrict to management IP addresses via Windows Firewall: <code>New-NetFirewallRule -Name 'WinRM-Admin' -LocalPort 5985 -RemoteAddress 10.0.0.0/24</code>.<br>3. Use Jump Servers / PAWs (Privileged Access Workstations) for all DC management.",
    },
    36: {
        "mitre": "T1210",
        "mitre_url": "https://attack.mitre.org/techniques/T1210/",
        "desc": "SMBv1 is a 30-year-old protocol with critical, unpatched vulnerabilities including EternalBlue (CVE-2017-0144). EternalBlue was used in the WannaCry and NotPetya ransomware attacks that caused billions of dollars in damages. Any system running SMBv1 is potentially vulnerable to remote code execution with no authentication required.",
        "fix": "1. Disable SMBv1 on all Windows systems via PowerShell: <code>Set-SmbServerConfiguration -EnableSMB1Protocol $false</code>.<br>2. Use Group Policy to prevent re-enabling: <em>Computer Configuration → Administrative Templates → Network → Lanman Server → Enable insecure guest logons</em>.<br>3. Block TCP port 445 inbound from the internet at your perimeter firewall.<br>4. Monitor for SMBv1 connections using Event ID 3000 in the SMB Client Operational log.",
    },
    37: {
        "mitre": "T1087.002",
        "mitre_url": "https://attack.mitre.org/techniques/T1087/002/",
        "desc": "Anonymous LDAP bind allows an unauthenticated attacker (or someone with no domain account) to connect to the LDAP service on the DC and potentially query directory information. Even if queries return limited data, the ability to bind anonymously is a prerequisite for further unauthenticated enumeration.",
        "fix": "1. Disable anonymous LDAP bind via Group Policy: <em>Computer Configuration → Windows Settings → Security Settings → Local Policies → Security Options → Network access: Allow anonymous SID/Name translation → Disabled</em>.<br>2. Set 'dsHeuristics' to disable anonymous access: modify attribute on the CN=Directory Service,CN=Windows NT,CN=Services,CN=Configuration object.<br>3. Verify with: <code>ldapsearch -H ldap://DC_IP -x -b '' -s base '(objectClass=*)' 2>&1</code>.",
    },
    38: {
        "mitre": "T1484.001",
        "mitre_url": "https://attack.mitre.org/techniques/T1484/001/",
        "desc": "Having more than 20 Group Policy Objects indicates GPO sprawl — accumulated configurations from years of changes, often without cleanup. Excessive GPOs make it difficult to audit security settings, increase processing time at login, and can contain conflicting or outdated security configurations that create gaps.",
        "fix": "1. Audit all GPOs: <code>Get-GPO -All | Select DisplayName, GpoStatus, CreationTime</code>.<br>2. Identify and delete empty, disabled, or unlinked GPOs.<br>3. Consolidate overlapping GPOs where possible.<br>4. Document the purpose of every GPO in its description field.<br>5. Use GPO modeling (GPMC) to verify effective settings after consolidation.",
    },
    39: {
        "mitre": "T1484.001",
        "mitre_url": "https://attack.mitre.org/techniques/T1484/001/",
        "desc": "GPOs that are not linked to any Organizational Unit, site, or domain are unused and waste processing time. More critically, empty GPOs (with no settings configured) may indicate a failed GPO deletion attempt, leaving orphaned objects that clutter AD and confuse administrators.",
        "fix": "1. Find unlinked GPOs: <code>Get-GPO -All | Where {$_ | Get-GPOReport -ReportType XML | Select-String -NotMatch 'LinksTo'}</code>.<br>2. Review each unlinked GPO — verify it is genuinely unused.<br>3. Delete confirmed unused GPOs after a 30-day review period.<br>4. Implement a GPO naming convention (e.g., CORP-SEC-PasswordPolicy-v1) for better management.",
    },
    40: {
        "mitre": "T1482",
        "mitre_url": "https://attack.mitre.org/techniques/T1482/",
        "desc": "A bidirectional (two-way) domain trust means that users in both domains can authenticate to resources in either domain. If one domain is compromised, the attacker can potentially pivot into the trusted domain. Bidirectional trusts are particularly dangerous when one of the domains has weaker security posture.",
        "fix": "1. Audit trusts: <code>Get-ADTrust -Filter *</code>.<br>2. Convert bidirectional trusts to one-way (selective trust) where possible.<br>3. Enable SID Filtering on all external trusts to prevent privilege escalation across trust boundaries: <code>netdom trust TrustingDomain /domain:TrustedDomain /enablesidhistory:no</code>.<br>4. Enable Selective Authentication to limit which resources trusted users can access.",
    },
    41: {
        "mitre": "T1562",
        "mitre_url": "https://attack.mitre.org/techniques/T1562/",
        "desc": "A domain functional level below Windows Server 2016 means the domain cannot take advantage of modern security features including Protected Users enhancements, compound authentication, Kerberos FAST (armoring), and privileged access management features. Lower functional levels also support legacy authentication protocols with known weaknesses.",
        "fix": "1. Check current level: <code>Get-ADDomain | Select DomainMode</code>.<br>2. Upgrade to Windows Server 2016 or 2019 functional level after ensuring all DCs are running at least Windows Server 2016.<br>3. Test impact on any legacy applications that rely on older protocols.<br>4. Raising the functional level enables security improvements like Kerberos armoring (FAST) and reduced-privilege tickets.",
    },
    42: {
        "mitre": "T1485",
        "mitre_url": "https://attack.mitre.org/techniques/T1485/",
        "desc": "Without the AD Recycle Bin, deleted Active Directory objects (users, computers, groups) are permanently destroyed after a short tombstone period. This makes recovery from accidental deletions, ransomware attacks, or malicious deletions significantly more complex and potentially impossible — requiring a full domain restore from backup.",
        "fix": "1. Enable the AD Recycle Bin via Active Directory Administrative Center: <em>Enable Recycle Bin</em>.<br>2. Or via PowerShell: <code>Enable-ADOptionalFeature 'Recycle Bin Feature' -Scope ForestOrConfigurationSet -Target (Get-ADForest).RootDomain</code>.<br>3. Note: This is a one-way operation and requires Forest functional level 2008 R2 or higher.<br>4. Set the deleted object lifetime to at least 180 days.",
    },
    43: {
        "mitre": "T1558",
        "mitre_url": "https://attack.mitre.org/techniques/T1558/",
        "desc": "The Protected Users security group provides additional credential protection for privileged accounts — preventing credential caching, prohibiting NTLM authentication, preventing DES/RC4 Kerberos, and requiring AES Kerberos. An empty Protected Users group means no accounts benefit from these enhanced protections, leaving all users vulnerable to credential theft attacks like Pass-the-Hash and Pass-the-Ticket.",
        "fix": "1. Add all Domain Admins, Enterprise Admins, and Schema Admins to Protected Users.<br>2. Test impact first — Protected Users breaks NTLM authentication, which may affect some legacy applications.<br>3. Add: <code>Add-ADGroupMember 'Protected Users' -Members (Get-ADGroupMember 'Domain Admins')</code>.<br>4. Document any accounts that cannot be added due to NTLM dependencies.",
    },
    44: {
        "mitre": "T1087.002",
        "mitre_url": "https://attack.mitre.org/techniques/T1087/002/",
        "desc": "Anonymous LDAP enumeration allows any unauthenticated user on the network to query the Active Directory base DN and retrieve information about users, groups, computers, and domain structure. This provides attackers with a detailed map of the environment for targeting — without needing any credentials.",
        "fix": "1. Restrict anonymous LDAP queries by setting <code>dsHeuristics</code> 7th character to '2'.<br>2. Apply GPO: <em>Network access: Do not allow anonymous enumeration of SAM accounts and shares</em>.<br>3. Block LDAP port 389 from untrusted network segments at the firewall level.<br>4. Monitor for unusual LDAP queries using Windows Security Event ID 1644.",
    },
    45: {
        "mitre": "T1078.002",
        "mitre_url": "https://attack.mitre.org/techniques/T1078/002/",
        "desc": "The adminCount=1 attribute is set automatically on accounts that are or were members of privileged groups, removing them from inheritance of permissions from parent OUs. 'Shadow admin' accounts are those with adminCount=1 that are no longer in any privileged group — suggesting they were historically privileged and may still have residual permissions that were never cleaned up.",
        "fix": "1. Find shadow admins: <code>Get-ADUser -Filter {AdminCount -eq 1} -Properties AdminCount,MemberOf | Where {$_.MemberOf -notmatch 'Admin'}</code>.<br>2. Review each account — if not intentionally privileged, reset AdminCount: <code>Set-ADUser -Identity &lt;user&gt; -Replace @{adminCount=0}</code>.<br>3. Re-enable inheritance of permissions on the account's ACL.<br>4. Investigate how the account acquired adminCount=1.",
    },
    46: {
        "mitre": "T1003",
        "mitre_url": "https://attack.mitre.org/techniques/T1003/",
        "desc": "The 'Store password using reversible encryption' setting causes Active Directory to store passwords in a form that can be decrypted back to plaintext — essentially equivalent to storing passwords in clear text. Any administrator with access to the AD database (NTDS.dit) or a DCSync capability can recover the plaintext passwords of all affected accounts.",
        "fix": "1. Disable reversible encryption in Group Policy: <em>Computer Configuration → Windows Settings → Security Settings → Account Policies → Password Policy → Store passwords using reversible encryption → Disabled</em>.<br>2. Find affected accounts: <code>Get-ADUser -Filter {AllowReversiblePasswordEncryption -eq $true}</code>.<br>3. Force password reset for all affected users — the old reversible hash remains until the password changes.",
    },
    47: {
        "mitre": "T1190",
        "mitre_url": "https://attack.mitre.org/techniques/T1190/",
        "desc": "A Domain Controller running an end-of-life operating system is the most critical finding possible. DCs are the most sensitive servers in the domain — they hold all credentials, policies, and trust relationships. An EOL DC has unpatched, publicly documented vulnerabilities that can lead to complete domain compromise with no authentication required in some cases (e.g., ZeroLogon, PrintNightmare).",
        "fix": "1. This is an emergency — treat as a critical incident.<br>2. Immediately isolate the EOL DC from untrusted network segments.<br>3. Deploy a new DC running Windows Server 2022 and transfer all FSMO roles to it.<br>4. Demote and decommission the EOL DC as a top priority.<br>5. Apply compensating controls immediately: host firewall, disable unnecessary services, monitor 24/7.",
    },
    48: {
        "mitre": "T1222",
        "mitre_url": "https://attack.mitre.org/techniques/T1222/",
        "desc": "Domain Controller computer objects should be owned by the Domain Admins group. If the owner is a regular user account or a service account, that account may have the ability to modify the DC object's security descriptor — potentially granting itself or others elevated permissions on the most sensitive servers in the domain.",
        "fix": "1. Check DC object ownership: <code>Get-ADComputer &lt;DC_Name&gt; -Properties nTSecurityDescriptor | Select -ExpandProperty nTSecurityDescriptor | Select Owner</code>.<br>2. Reset ownership to Domain Admins using ADSI Edit or: <code>$acl = Get-Acl 'AD:&lt;DC_DN&gt;'; $acl.SetOwner([System.Security.Principal.NTAccount]'DOMAIN\\Domain Admins'); Set-Acl -Path 'AD:&lt;DC_DN&gt;' -AclObject $acl</code>.<br>3. Regularly audit DC object ACLs.",
    },
    49: {
        "mitre": "T1110.003",
        "mitre_url": "https://attack.mitre.org/techniques/T1110/003/",
        "desc": "Password spray is an attack where a single common password (e.g., 'Summer2024!') is tried against every account in the domain. When the lockout threshold is 0 (no lockout) AND minimum password length is less than 8, the domain is highly vulnerable — an attacker can spray hundreds of accounts with common passwords indefinitely without any lockout, and short passwords are more likely to match common patterns.",
        "fix": "1. Immediately set account lockout threshold to 5 in Group Policy.<br>2. Set minimum password length to at least 12 characters.<br>3. Deploy Microsoft Entra ID Password Protection to block common passwords and domain-specific terms.<br>4. Enable Microsoft Defender for Identity or a SIEM rule to detect spray patterns (many failed logins from one source to many accounts within a short time window).",
    },
    50: {
        "mitre": "T1078.002",
        "mitre_url": "https://attack.mitre.org/techniques/T1078/002/",
        "desc": "When group objects (rather than user objects) are nested inside privileged groups like Domain Admins, it becomes very difficult to enumerate who actually has domain admin privileges. An attacker who compromises any account in a deeply nested group chain may unexpectedly have Domain Admin rights. This is a common misconfiguration that enables privilege escalation and makes access reviews nearly impossible.",
        "fix": "1. Audit nesting: <code>Get-ADGroupMember 'Domain Admins' -Recursive | Where {$_.objectClass -eq 'group'}</code>.<br>2. Remove group objects from Domain Admins — only individual user accounts should be direct members.<br>3. Document and flatten all nested privileged group structures.<br>4. Use BloodHound to visualize all effective membership chains and identify unexpected privilege paths.",
    },
}


def build_report(meta, net, ad, findings, summary, out_dir):
    ts   = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = os.path.join(out_dir, f"adscan_report_{ts}.html")
    with open(path,"w",encoding="utf-8") as f:
        f.write(_render(meta,net,ad,findings,summary))
    return path

def _badge(sev):
    cls,_,icon = _SEV.get(sev,("low","#3fb950","🟢"))
    return f'<span class="badge {cls}">{icon} {sev}</span>'

def _ep_badge(ep):
    if not ep: return ""
    color = _EP_COLOR.get(ep,"#8b949e")
    return f'<span class="ep-badge" style="border-color:{color};color:{color}">⚡ {ep}</span>'

def _stat(label,val,color="var(--accent)"):
    return (f'<div class="scard"><div class="snum" style="color:{color}">{val}</div>'
            f'<div class="slbl">{label}</div></div>')


def _charts(findings):
    if not findings:
        return '<p style="color:var(--t2)">No findings to chart.</p>'
    cats   = Counter(f.get("category","Other") for f in findings)
    total  = sum(cats.values())
    items  = sorted(cats.items(), key=lambda x: -x[1])
    colors = ["#da3633","#f0883e","#e3b341","#3fb950","#58a6ff","#8957e5","#db6d28","#1f6feb"]
    cx, cy, r_outer, r_inner = 130, 130, 110, 55
    angle   = -90.0
    slices  = ""
    legend  = ""
    for i,(cat,cnt) in enumerate(items):
        color  = colors[i % len(colors)]
        pct    = cnt / total
        pct_lbl= f"{pct*100:.0f}%"
        sweep  = pct * 360
        if sweep >= 359.9:
            sweep = 359.9
        x1 = cx + r_outer * math.cos(math.radians(angle))
        y1 = cy + r_outer * math.sin(math.radians(angle))
        mid_angle = angle + sweep/2
        angle += sweep
        x2 = cx + r_outer * math.cos(math.radians(angle))
        y2 = cy + r_outer * math.sin(math.radians(angle))
        large = 1 if sweep > 180 else 0
        slices += f"""
<path class="pie-slice" d="M{cx},{cy} L{x1:.2f},{y1:.2f} A{r_outer},{r_outer} 0 {large},1 {x2:.2f},{y2:.2f} Z"
  fill="{color}" stroke="#0d1117" stroke-width="2"
  data-cat="{cat}" data-cnt="{cnt}" data-pct="{pct_lbl}"
  onmouseenter="pieHover(this,true,event)" onmouseleave="pieHover(this,false,event)">
</path>"""
        legend += f"""<div class="pie-leg">
  <span class="pie-dot" style="background:{color}"></span>
  <span class="pie-name">{cat}</span>
  <span class="pie-num">{cnt}</span>
  <span class="pie-pct" style="color:{color}">{pct_lbl}</span>
</div>"""
    sev_data = [
        ("CRITICAL", summary_sev("CRITICAL", findings), "#da3633"),
        ("HIGH",     summary_sev("HIGH",     findings), "#f0883e"),
        ("MEDIUM",   summary_sev("MEDIUM",   findings), "#e3b341"),
        ("LOW",      summary_sev("LOW",      findings), "#3fb950"),
    ]
    max_val = max((v for _,v,_ in sev_data), default=1) or 1
    bars    = ""
    for sev, val, color in sev_data:
        pct = (val / max_val) * 100 if val else 0
        bars += f"""
<div class="bar-row">
  <div class="bar-label">{sev}</div>
  <div class="bar-track">
    <div class="bar-fill" style="width:{pct}%;background:{color}">
      <span class="bar-val">{val}</span>
    </div>
  </div>
</div>"""
    return f"""
<div class="charts-wrap">
  <div class="chart-box">
    <div class="chart-title">Findings by Category</div>
    <div class="pie-container">
      <svg id="pie-svg" viewBox="0 0 260 260" width="240" height="240" style="overflow:visible">
        {slices}
        <circle cx="{cx}" cy="{cy}" r="{r_inner}" fill="var(--bg2)" pointer-events="none"/>
        <text id="pie-center-num" x="{cx}" y="{cy-8}" text-anchor="middle"
              fill="var(--t)" font-size="22" font-weight="800">{total}</text>
        <text id="pie-center-lbl" x="{cx}" y="{cy+12}" text-anchor="middle"
              fill="var(--t2)" font-size="11">findings</text>
      </svg>
      <div class="pie-legend">{legend}</div>
    </div>
  </div>
  <div class="chart-box">
    <div class="chart-title">Findings by Severity</div>
    <div class="bar-chart">{bars}</div>
  </div>
</div>
<script>
function pieHover(el, enter, evt) {{
  const tt   = document.getElementById('pie-tt');
  const cNum = document.getElementById('pie-center-num');
  const cLbl = document.getElementById('pie-center-lbl');
  if (enter) {{
    const cat  = el.getAttribute('data-cat');
    const cnt  = el.getAttribute('data-cnt');
    const pct  = el.getAttribute('data-pct');
    const fill = el.getAttribute('fill');
    el.style.transform = 'scale(1.07)';
    el.style.transformOrigin = '130px 130px';
    el.style.filter = 'drop-shadow(0 0 10px ' + fill + 'aa)';
    cNum.textContent = pct;
    cNum.setAttribute('fill', fill);
    cLbl.textContent = cat;
    document.getElementById('pie-tt-cat').textContent = cat;
    document.getElementById('pie-tt-cat').style.color = fill;
    document.getElementById('pie-tt-cnt').textContent = 'Findings: ' + cnt;
    document.getElementById('pie-tt-pct').textContent = 'Share: ' + pct;
    tt.style.display = 'block';
  }} else {{
    el.style.transform = '';
    el.style.filter    = '';
    tt.style.display   = 'none';
    cNum.textContent   = '{total}';
    cNum.setAttribute('fill','var(--t)');
    cLbl.textContent   = 'findings';
  }}
}}
document.addEventListener('mousemove', function(e) {{
  const tt = document.getElementById('pie-tt');
  if (tt.style.display === 'block') {{
    tt.style.left = (e.clientX + 16) + 'px';
    tt.style.top  = (e.clientY - 10) + 'px';
  }}
}});
</script>"""


def summary_sev(sev, findings):
    return sum(1 for f in findings if f.get("severity") == sev)


def _executive_summary(meta, findings, summary):
    sc    = summary.get("SCORE",0)
    grade = summary.get("GRADE","F")
    gc,gl = _GRADE.get(grade,("#da3633","Critical Risk"))
    pct   = sc
    fill  = "#da3633" if sc<40 else "#e3b341" if sc<70 else "#3fb950"
    crit  = summary.get("CRITICAL",0)
    high  = summary.get("HIGH",0)
    med   = summary.get("MEDIUM",0)
    low   = summary.get("LOW",0)
    total = summary.get("TOTAL",0)
    chk   = summary.get("CHECKS",0)
    scope = meta.get("scope","Full scan — all 50 controls executed")
    chk_count = summary.get("CHECKS",0)
    if "Full scan" in scope:
        scope_short = f"Full Scan — {chk_count}/50 Controls"
    elif "Group scan" in scope:
        grp = scope.split(chr(34))[1] if chr(34) in scope else "group"
        scope_short = f"Group Scan: {grp} — {chk_count} Controls"
    else:
        scope_short = f"Custom Scan — {chk_count} Controls"
    order = ["CRITICAL","HIGH","MEDIUM","LOW"]
    srt   = sorted(findings, key=lambda x: order.index(x["severity"]) if x["severity"] in order else 9)
    top3  = ""
    for f in srt[:3]:
        cls,_,icon = _SEV.get(f["severity"],("low","#3fb950","🟢"))
        top3 += f"""<div class="es-finding">
          <span class="badge {cls}" style="flex-shrink:0">{icon} {f['severity']}</span>
          <div>
            <div style="font-weight:600;font-size:.9rem">{f['title']}</div>
            <div style="color:var(--t2);font-size:.82rem;margin-top:.1rem">{f['desc'].split(chr(10))[0]}</div>
          </div></div>"""
    if crit>0:
        eval_txt=(f"Assessment of <strong style='color:#58a6ff'>{meta.get('domain','')}</strong> "
                  f"identified <strong style='color:#da3633'>{crit} critical</strong> and "
                  f"<strong style='color:#f0883e'>{high} high</strong> severity findings. "
                  f"Immediate remediation is strongly recommended.")
    elif high>0:
        eval_txt=(f"Assessment of <strong style='color:#58a6ff'>{meta.get('domain','')}</strong> "
                  f"identified <strong style='color:#f0883e'>{high} high</strong> severity findings.")
    else:
        eval_txt=(f"Assessment completed with {total} findings across {chk} checks.")
    return f"""
<section id="executive-summary">
  <h2>📋 Executive Summary</h2>
  <div class="es-box">
    <div class="es-score-col">
      <div class="scope-badge">🔍 {scope_short}</div>
      <div class="es-circle" style="border-color:{gc}">
        <div class="es-num" style="color:{gc}">{sc}</div>
        <div class="es-den">/100</div>
      </div>
      <div class="es-grade" style="color:{gc}">Grade: {grade}</div>
      <div class="es-glbl" style="color:{gc}">{gl}</div>
      <div class="es-slider">
        <div class="es-sl-labels">
          <span style="color:#da3633">F</span><span style="color:#f0883e">D</span>
          <span style="color:#e3b341">C</span><span style="color:#58a6ff">B</span>
          <span style="color:#3fb950">A</span>
        </div>
        <div class="es-sl-track">
          <div class="es-sl-fill" style="width:{pct}%"></div>
          <div class="es-sl-thumb" style="left:calc({pct}% - 10px);background:{fill}"></div>
        </div>
        <div class="es-sl-mm"><span>0</span><span style="color:{gc};font-weight:700">{sc}</span><span>100</span></div>
      </div>
      <div class="es-counts">
        <div class="es-cnt" style="border-color:#da3633"><span style="color:#da3633;font-size:1.4rem;font-weight:800">{crit}</span><span>Critical</span></div>
        <div class="es-cnt" style="border-color:#f0883e"><span style="color:#f0883e;font-size:1.4rem;font-weight:800">{high}</span><span>High</span></div>
        <div class="es-cnt" style="border-color:#e3b341"><span style="color:#e3b341;font-size:1.4rem;font-weight:800">{med}</span><span>Medium</span></div>
        <div class="es-cnt" style="border-color:#3fb950"><span style="color:#3fb950;font-size:1.4rem;font-weight:800">{low}</span><span>Low</span></div>
      </div>
    </div>
    <div class="es-info-col">
      <div class="es-meta-grid">
        <div><div class="es-lbl">Target Domain</div><div class="es-val">{meta.get('domain','')}</div></div>
        <div><div class="es-lbl">Domain Controller</div><div class="es-val">{meta.get('dc','')}</div></div>
        <div><div class="es-lbl">Scan Date</div><div class="es-val">{meta.get('tarih','')}</div></div>
        <div><div class="es-lbl">Scan Duration</div><div class="es-val">{meta.get('sure','')}</div></div>
        <div><div class="es-lbl">Total Findings</div><div class="es-val">{total}</div></div>
        <div><div class="es-lbl">Checks Run</div><div class="es-val">{chk} / 50</div></div>
        <div><div class="es-lbl">Analyst</div><div class="es-val">{meta.get('user','')}</div></div>
        <div><div class="es-lbl">Tool</div><div class="es-val">ADScan v2.0</div></div>
        <div style="grid-column:1/-1">
          <div class="es-lbl">Scan Scope</div>
          <div class="es-val" style="color:#58a6ff;font-weight:600">{scope}</div>
        </div>
      </div>
      <div style="margin-top:1rem">
        <div class="es-lbl">OVERALL ASSESSMENT</div>
        <p style="color:var(--t2);font-size:.88rem;line-height:1.6;margin-top:.35rem">{eval_txt}</p>
      </div>
      <div style="margin-top:1rem">
        <div class="es-lbl" style="margin-bottom:.5rem">TOP PRIORITY FINDINGS</div>
        {top3 or '<p style="color:var(--t2);font-size:.85rem">No critical findings.</p>'}
      </div>
    </div>
  </div>
</section>"""


def _findings_html(findings):
    order = ["CRITICAL","HIGH","MEDIUM","LOW","INFO"]
    srt   = sorted(findings, key=lambda x: order.index(x["severity"]) if x["severity"] in order else 9)
    out   = ""
    for f in srt:
        cls,color,icon = _SEV.get(f["severity"],("low","#3fb950","🟢"))
        aff  = "".join(f"<li>{a}</li>" for a in f["affected"][:25])
        if len(f["affected"])>25: aff+=f"<li><em>...and {len(f['affected'])-25} more</em></li>"
        ep   = _ep_badge(f.get("exploitable_by",""))
        fi   = f.get("found_in","")
        out += f"""
<div class="finding {cls}" id="{f['id']}">
  <div class="fh" onclick="tog(this)">
    <div class="fhl"><code class="fid">{f['id']}</code><span class="ftitle">{f['title']}</span></div>
    <div class="fhr">{_badge(f['severity'])}<span class="fcat">{f.get('category','')}</span><span class="chev">▼</span></div>
  </div>
  <div class="fb">
    <div class="fsec"><div class="flab">📋 Description</div><p>{f['desc'].replace(chr(10),'<br>')}</p></div>
    <div class="fsec"><div class="flab">⚡ Exploitable By</div><div style="margin-top:.35rem">{ep or '<span style="color:var(--t2)">N/A</span>'}</div></div>
    <div class="fsec"><div class="flab">📍 Found In</div><p style="font-family:monospace;font-size:.85rem;color:#79c0ff">{fi or '—'}</p></div>
    <div class="fsec"><div class="flab">🎯 Affected ({len(f['affected'])})</div><ul class="aff">{aff}</ul></div>
    <div class="fsec fix"><div class="flab">🛠 Remediation</div><p>{f['fix'].replace(chr(10),'<br>')}</p></div>
  </div>
</div>"""
    return out or '<p class="empty">No findings detected.</p>'


def _remediation_summary(findings):
    order = ["CRITICAL","HIGH","MEDIUM","LOW"]
    srt   = sorted(findings, key=lambda x: order.index(x["severity"]) if x["severity"] in order else 9)
    rows  = ""
    for i,f in enumerate(srt,1):
        cls,_,icon = _SEV.get(f["severity"],("low","#3fb950","🟢"))
        rows += f"""<div class="rem-item">
  <div class="rem-header">
    <span class="rem-num">#{i}</span>
    <span class="rem-title">{f['title']}</span>
    <span class="badge {cls}" style="flex-shrink:0">{icon} {f['severity']}</span>
  </div>
  <div class="rem-fix">{f['fix'].replace(chr(10),'<br>')}</div>
</div>"""
    return rows or '<p class="empty">No remediation items.</p>'


def _findings_overview(findings):
    order = ["CRITICAL","HIGH","MEDIUM","LOW","INFO"]
    srt   = sorted(findings, key=lambda x: order.index(x["severity"]) if x["severity"] in order else 9)
    rows  = ""
    for f in srt:
        cls,_,icon = _SEV.get(f["severity"],("low","#3fb950","🟢"))
        rows += f"""<tr>
  <td><code>{f['id']}</code></td>
  <td>{f['title']}</td>
  <td><span class="badge {cls}">{icon} {f['severity']}</span></td>
  <td><span class="fcat">{f.get('category','')}</span></td>
  <td style="text-align:center">{len(f.get('affected',[]))}</td>
  <td><a href="#{f['id']}" onclick="scrollToFinding('{f['id']}')" style="color:var(--accent);font-size:.82rem">View →</a></td>
</tr>"""
    return rows or "<tr><td colspan=6 style='color:var(--t2)'>No findings.</td></tr>"


def _checks_table_html(findings):
    found_ids = {f.get("check_id") for f in findings}
    rows = ""
    for cid,title,cat,found_in,ep,sev in CHECKS_TABLE:
        cls,_,icon = _SEV.get(sev,("low","#3fb950","🟢"))
        ep_color   = _EP_COLOR.get(ep,"#8b949e")
        if cid in found_ids:
            status  = '<span class="tag crit">⚠ FOUND</span>'
            row_cls = ' class="check-found"'
        else:
            status  = '<span class="tag ok">✓ PASS</span>'
            row_cls = ""
        rows += f"""<tr{row_cls}>
  <td><code>AD-{cid:03d}</code></td><td>{title}</td>
  <td><span class="fcat">{cat}</span></td>
  <td><span class="badge {cls}">{icon} {sev}</span></td>
  <td style="font-size:.78rem;color:{ep_color}">⚡ {ep}</td>
  <td style="font-family:monospace;font-size:.75rem;color:var(--t2)">{found_in}</td>
  <td>{status}</td>
</tr>"""
    return rows


def _knowledge_base_html():
    """50 zafiyetin tamamı için açıklama + çözüm + MITRE ATT&CK kartları"""
    cat_colors = {
        "Kerberos":          "#8957e5",
        "Password Policy":   "#58a6ff",
        "Privileged Accounts":"#da3633",
        "Service Accounts":  "#f0883e",
        "Account Hygiene":   "#e3b341",
        "System Security":   "#db6d28",
        "Group Policy":      "#3fb950",
        "Domain Config":     "#1f6feb",
    }
    cards = ""
    for cid, title, cat, found_in, ep, sev in CHECKS_TABLE:
        kb    = KNOWLEDGE_BASE.get(cid, {})
        mitre = kb.get("mitre","—")
        murl  = kb.get("mitre_url","#")
        desc  = kb.get("desc","No description available.")
        fix   = kb.get("fix","No remediation available.")
        cls,_,icon = _SEV.get(sev,("low","#3fb950","🟢"))
        ep_color   = _EP_COLOR.get(ep,"#8b949e")
        cat_color  = cat_colors.get(cat,"#8b949e")
        cards += f"""
<div class="kb-card" id="kb-{cid}" data-cat="{cat.lower().replace(' ','-')}">
  <div class="kb-header">
    <div class="kb-left">
      <code class="kb-id">AD-{cid:03d}</code>
      <span class="kb-title">{title}</span>
    </div>
    <div class="kb-right">
      <span class="badge {cls}">{icon} {sev}</span>
      <span class="kb-cat" style="background:{cat_color}22;color:{cat_color};border:1px solid {cat_color}44">{cat}</span>
      <a class="kb-mitre" href="{murl}" target="_blank" rel="noopener"
         title="View on MITRE ATT&CK">{mitre} ↗</a>
    </div>
  </div>
  <div class="kb-body">
    <div class="kb-section">
      <div class="kb-label">⚡ Exploitable By</div>
      <span class="ep-badge" style="border-color:{ep_color};color:{ep_color};font-size:.78rem">⚡ {ep}</span>
    </div>
    <div class="kb-section">
      <div class="kb-label">📋 What is this vulnerability?</div>
      <p class="kb-text">{desc}</p>
    </div>
    <div class="kb-section kb-fix-section">
      <div class="kb-label">🛠 How to fix it</div>
      <p class="kb-text kb-fix-text">{fix}</p>
    </div>
    <div class="kb-section">
      <div class="kb-label">🔍 Detection Source</div>
      <p style="font-family:monospace;font-size:.8rem;color:#79c0ff;margin-top:.3rem">{found_in}</p>
    </div>
  </div>
</div>"""
    return cards


def _tbl_users(users):
    rows=""
    for u in users[:60]:
        tg=""
        if u.get("pwd_never"):  tg+='<span class="tag warn">Pwd∞</span>'
        if u.get("no_preauth"): tg+='<span class="tag crit">AS-REP</span>'
        if u.get("delegation"): tg+='<span class="tag crit">Delegation</span>'
        st='<span class="tag ok">Active</span>' if u.get("enabled") else '<span class="tag off">Disabled</span>'
        rows+=(f"<tr><td><code>{u['username']}</code></td><td>{st}</td>"
               f"<td>{u.get('department','')}</td><td>{u.get('title','')}</td><td>{tg}</td></tr>")
    return rows or "<tr><td colspan=5>—</td></tr>"

def _tbl_comp(comps):
    rows=""
    for c in comps:
        eol='<span class="tag crit">EOL</span>' if c.get("eol") else ""
        rows+=(f"<tr><td><code>{c['name']}</code></td><td>{c['os']} {eol}</td><td>{c.get('dns','')}</td></tr>")
    return rows or "<tr><td colspan=3>—</td></tr>"

def _tbl_spn(spns):
    rows=""
    for s in spns:
        st='<span class="tag ok">Active</span>' if s.get("enabled") else '<span class="tag off">Disabled</span>'
        lst="<br>".join(f"<code>{x}</code>" for x in s.get("spns",[]))
        rows+=(f"<tr><td><code>{s['username']}</code></td><td>{st}</td><td>{lst}</td></tr>")
    return rows or "<tr><td colspan=3>—</td></tr>"

def _tbl_asrep(users):
    rows=""
    for u in users:
        rows+=(f"<tr><td><code>{u['username']}</code></td>"
               f"<td>{u.get('dept','')}</td>"
               f"<td>{', '.join(u.get('member_of',[])[:3])}</td></tr>")
    return rows or "<tr><td colspan=3>Not detected</td></tr>"

def _tbl_group(groups):
    priv={"Domain Admins","Enterprise Admins","Schema Admins","Administrators",
          "Backup Operators","Account Operators","Protected Users","Group Policy Creator Owners"}
    rows=""
    for g in groups:
        hl=' class="priv"' if g["name"] in priv else ""
        rows+=(f"<tr{hl}><td><code>{g['name']}</code></td>"
               f"<td>{g['count']}</td><td>{g.get('description','')[:80]}</td></tr>")
    return rows or "<tr><td colspan=3>—</td></tr>"

def _pol_rows(pol):
    checks=[
        ("min_len",    "Min. Password Length", lambda v: int(v or 0)<14),
        ("history",    "Password History",      lambda v: int(v or 0)<24),
        ("complexity", "Complexity",            lambda v: "disabled" in str(v).lower() or "disi" in str(v).lower()),
        ("lockout_thr","Lockout Threshold",     lambda v: str(v).strip() in("0","?","")),
        ("max_age",    "Max. Password Age",     lambda v: "unlimited" in str(v).lower()),
    ]
    rows=""
    for key,label,is_bad in checks:
        val=pol.get(key,"?")
        try:    bad=is_bad(val)
        except: bad=False
        cls=' class="bad"' if bad else ""
        rows+=f"<tr><td><b>{label}</b></td><td{cls}>{val}{' ⚠' if bad else ''}</td></tr>"
    return rows


def _render(meta,net,ad,findings,summary):
    sc      = summary.get("SCORE",0)
    grade   = summary.get("GRADE","F")
    gc,gl   = _GRADE.get(grade,("#da3633","Critical Risk"))
    u_cnt   = len(ad.get("users",[]))
    g_cnt   = len(ad.get("groups",[]))
    c_cnt   = len(ad.get("computers",[]))
    spn_cnt = len(ad.get("spns",[]))
    ar_cnt  = len(ad.get("asrep_users",[]))
    gpo_cnt = len(ad.get("gpos",[]))
    ports   = net.get("ports",[])
    svc     = net.get("services",{})
    ph      = "".join(f'<span class="pt">{p} <small>{svc.get(p,"")}</small></span>' for p in sorted(ports)) or "—"

    return f"""<!DOCTYPE html>
<html lang="en"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>ADScan Report — {meta.get('domain','')}</title>
<style>
:root{{--bg:#0d1117;--bg2:#161b22;--bg3:#21262d;--bg4:#30363d;--t:#e6edf3;--t2:#8b949e;--brd:#30363d;--accent:#58a6ff}}
*{{box-sizing:border-box;margin:0;padding:0}}
body{{font-family:'Segoe UI',system-ui,sans-serif;background:var(--bg);color:var(--t);line-height:1.6;font-size:15px}}
code{{font-family:monospace;font-size:.85em;color:#79c0ff}}
h2{{font-size:1.05rem;font-weight:600;border-left:3px solid var(--accent);padding-left:.7rem;margin-bottom:1rem}}
section{{margin-bottom:2.5rem}}
header{{background:#161b22;border-bottom:2px solid #da3633;padding:1.5rem 2.5rem;display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:1rem}}
.hl h1{{font-size:1.6rem;color:#f85149;font-weight:800}}
.hl h1 span{{color:var(--t2);font-size:1rem;font-weight:400;margin-left:.5rem}}
.hl p{{color:var(--t2);font-size:.82rem;margin-top:.2rem}}
.hr .domain{{font-size:1rem;font-weight:600;color:var(--accent)}}
.hr .dt{{font-size:.8rem;color:var(--t2);margin-top:.2rem}}
.wrap{{max-width:1400px;margin:0 auto;padding:2rem 2.5rem}}

/* PAGE NAV */
.page-nav{{display:flex;background:var(--bg2);border-bottom:2px solid var(--brd);padding:0 2.5rem;gap:0;position:sticky;top:0;z-index:100}}
.pnav-btn{{padding:.75rem 1.4rem;cursor:pointer;font-size:.9rem;font-weight:600;color:var(--t2);border-bottom:3px solid transparent;margin-bottom:-2px;white-space:nowrap;background:none;border-top:none;border-left:none;border-right:none;transition:color .15s}}
.pnav-btn:hover{{color:var(--t)}}
.pnav-btn.on{{color:var(--accent);border-bottom-color:var(--accent)}}
.page{{display:none}}
.page.on{{display:block}}

/* ES */
.es-box{{background:var(--bg2);border:1px solid var(--brd);border-radius:12px;padding:1.5rem;display:flex;gap:2rem;flex-wrap:wrap}}
.es-score-col{{display:flex;flex-direction:column;align-items:center;gap:.9rem;min-width:200px}}
.es-circle{{width:100px;height:100px;border-radius:50%;border:4px solid;display:flex;flex-direction:column;align-items:center;justify-content:center;margin:0 auto}}
.es-num{{font-size:1.8rem;font-weight:800;line-height:1}}
.es-den{{font-size:.8rem;color:var(--t2)}}
.es-grade{{font-size:1.5rem;font-weight:800}}
.es-glbl{{font-size:.8rem;font-weight:600}}
.scope-badge{{background:rgba(88,166,255,.12);border:1px solid #58a6ff;color:#58a6ff;border-radius:6px;padding:.3rem .7rem;font-size:.78rem;font-weight:700;text-align:center;white-space:nowrap}}
.es-slider{{width:190px}}
.es-sl-labels{{display:flex;justify-content:space-between;font-size:.75rem;font-weight:700;margin-bottom:.3rem}}
.es-sl-track{{position:relative;height:8px;background:var(--bg4);border-radius:4px}}
.es-sl-fill{{height:100%;border-radius:4px;background:linear-gradient(90deg,#da3633 0%,#e3b341 50%,#3fb950 100%)}}
.es-sl-thumb{{position:absolute;top:-6px;width:20px;height:20px;border-radius:50%;box-shadow:0 0 6px rgba(0,0,0,.6)}}
.es-sl-mm{{display:flex;justify-content:space-between;font-size:.72rem;color:var(--t2);margin-top:.35rem}}
.es-counts{{display:grid;grid-template-columns:1fr 1fr;gap:.45rem;width:100%}}
.es-cnt{{background:var(--bg3);border:1px solid;border-radius:8px;padding:.45rem;text-align:center;display:flex;flex-direction:column;align-items:center;gap:.1rem}}
.es-cnt span:last-child{{font-size:.72rem;color:var(--t2)}}
.es-info-col{{flex:1;min-width:280px}}
.es-meta-grid{{display:grid;grid-template-columns:1fr 1fr;gap:.35rem .75rem}}
.es-lbl{{font-size:.72rem;color:var(--t2);text-transform:uppercase;letter-spacing:.06em;font-weight:600}}
.es-val{{font-size:.88rem;color:var(--t);font-weight:500;margin-top:.1rem}}
.es-finding{{display:flex;align-items:flex-start;gap:.75rem;padding:.55rem 0;border-bottom:1px solid var(--brd)}}
.es-finding:last-child{{border-bottom:none}}

/* Charts */
.charts-wrap{{display:flex;gap:1.5rem;flex-wrap:wrap}}
.chart-box{{background:var(--bg2);border:1px solid var(--brd);border-radius:12px;padding:1.5rem;flex:1;min-width:280px}}
.chart-title{{font-size:.9rem;font-weight:600;color:var(--t2);text-transform:uppercase;letter-spacing:.06em;margin-bottom:1rem}}
.pie-container{{display:flex;align-items:center;gap:1.5rem;flex-wrap:wrap}}
.pie-slice{{cursor:pointer;transition:transform .15s,filter .15s}}
.pie-legend{{display:flex;flex-direction:column;gap:.5rem}}
.pie-leg{{display:flex;align-items:center;gap:.6rem;font-size:.88rem}}
.pie-dot{{width:11px;height:11px;border-radius:50%;flex-shrink:0}}
.pie-name{{flex:1;color:var(--t)}}
.pie-num{{font-weight:700;color:var(--t);min-width:20px;text-align:right}}
.pie-pct{{font-size:.78rem;min-width:36px;text-align:right}}
.bar-chart{{display:flex;flex-direction:column;gap:.85rem;padding-top:.25rem}}
.bar-row{{display:flex;align-items:center;gap:.75rem}}
.bar-label{{font-size:.78rem;font-weight:700;width:70px;text-align:right;color:var(--t2)}}
.bar-track{{flex:1;background:var(--bg4);border-radius:4px;height:28px;overflow:hidden}}
.bar-fill{{height:100%;border-radius:4px;display:flex;align-items:center;justify-content:flex-end;padding-right:.5rem;transition:width .6s ease;min-width:28px}}
.bar-val{{font-size:.82rem;font-weight:700;color:#fff}}

/* Stats */
.scards{{display:grid;grid-template-columns:repeat(auto-fill,minmax(110px,1fr));gap:.7rem}}
.scard{{background:var(--bg2);border:1px solid var(--brd);border-radius:10px;padding:.9rem;text-align:center}}
.snum{{font-size:2rem;font-weight:800;line-height:1}}
.slbl{{color:var(--t2);font-size:.73rem;margin-top:.3rem}}
.dcbox{{background:var(--bg2);border:1px solid var(--brd);border-radius:10px;padding:1.25rem;display:flex;flex-wrap:wrap;gap:1.5rem}}
.dcip{{font-size:1.2rem;font-weight:700;color:var(--accent)}}
.dclbl{{color:var(--t2);font-size:.8rem;margin-bottom:.3rem}}
.pt{{display:inline-block;background:var(--bg3);border:1px solid var(--brd);border-radius:5px;padding:.15rem .5rem;margin:.2rem;font-size:.78rem}}
.polcard{{background:var(--bg2);border:1px solid var(--brd);border-radius:10px;overflow:hidden}}
.polcard table{{width:100%}}
.polcard td{{padding:.55rem 1rem;border-top:1px solid var(--brd);font-size:.9rem}}
.polcard tr:first-child td{{border-top:none}}
.bad{{color:#f85149;font-weight:600}}

/* Findings */
.finding{{border-radius:10px;margin-bottom:.65rem;border:1px solid var(--brd);overflow:hidden}}
.finding.critical{{border-left:4px solid #da3633}}
.finding.high{{border-left:4px solid #f0883e}}
.finding.medium{{border-left:4px solid #e3b341}}
.finding.low{{border-left:4px solid #3fb950}}
.fh{{display:flex;justify-content:space-between;align-items:center;padding:.8rem 1.2rem;cursor:pointer;background:var(--bg2)}}
.fh:hover{{background:var(--bg3)}}
.fhl{{display:flex;align-items:center;gap:.6rem;flex:1;min-width:0}}
.fhr{{display:flex;align-items:center;gap:.5rem;flex-shrink:0}}
.fid{{color:var(--t2);font-size:.78rem;flex-shrink:0}}
.ftitle{{font-weight:600;font-size:.95rem}}
.fcat{{font-size:.72rem;color:var(--t2);background:var(--bg4);padding:.1rem .4rem;border-radius:4px;white-space:nowrap}}
.chev{{color:var(--t2);transition:transform .2s}}
.finding.open .chev{{transform:rotate(180deg)}}
.fb{{display:none;padding:1rem 1.2rem 1.2rem;background:var(--bg2);border-top:1px solid var(--brd)}}
.finding.open .fb{{display:block}}
.fsec{{margin-top:.9rem}}
.flab{{font-size:.8rem;color:var(--t2);font-weight:600;text-transform:uppercase;letter-spacing:.05em;margin-bottom:.35rem}}
.fsec p{{color:var(--t2);font-size:.9rem}}
.aff{{margin:.35rem 0 0 1.2rem;color:var(--t2);font-size:.85rem;font-family:monospace}}
.fix{{background:rgba(63,185,80,.07);border:1px solid rgba(63,185,80,.2);border-radius:6px;padding:.85rem}}
.fix p{{color:#7ee787!important}}
.ep-badge{{display:inline-flex;align-items:center;gap:.25rem;padding:.2rem .7rem;border-radius:5px;border:1px solid;font-size:.78rem;font-weight:600;vertical-align:middle;line-height:1.4}}
.badge{{display:inline-flex;align-items:center;gap:.2rem;padding:.15rem .5rem;border-radius:4px;font-size:.72rem;font-weight:700;vertical-align:middle;white-space:nowrap}}
.badge.critical{{background:#3d1212;color:#ff7b72;font-size:.75rem}}
.badge.high{{background:#3d2200;color:#ffa657;border-left:3px solid #f0883e}}
.badge.medium{{background:#3d3000;color:#e3b341}}
.badge.low{{background:#0d4429;color:#7ee787;border-left:3px solid #3fb950}}
.badge.info{{background:#1e3a5f;color:#93c5fd}}
.tag{{display:inline-flex;align-items:center;gap:.2rem;padding:.12rem .5rem;border-radius:4px;font-size:.74rem;font-weight:600;margin:.1rem;vertical-align:middle;line-height:1.4}}
.tag.ok{{background:#0d4429;color:#3fb950}}
.tag.off{{background:#1c2128;color:#6e7681}}
.tag.warn{{background:#3d2b00;color:#e3b341}}
.tag.crit{{background:#3d1212;color:#f85149}}

/* Remediation */
.rem-item{{background:var(--bg2);border:1px solid var(--brd);border-radius:10px;margin-bottom:.75rem;overflow:hidden}}
.rem-header{{display:flex;align-items:center;gap:.75rem;padding:.85rem 1.2rem;background:var(--bg3)}}
.rem-num{{color:var(--t2);font-size:.82rem;font-weight:700;flex-shrink:0}}
.rem-title{{flex:1;font-weight:600;font-size:.95rem}}
.rem-fix{{padding:.85rem 1.2rem;color:#7ee787;font-size:.88rem;background:rgba(63,185,80,.06);border-top:1px solid var(--brd)}}

/* Tabs */
.tabs{{display:flex;border-bottom:1px solid var(--brd);margin-bottom:1rem;overflow-x:auto}}
.tab{{padding:.5rem 1rem;cursor:pointer;font-size:.88rem;color:var(--t2);border-bottom:2px solid transparent;margin-bottom:-1px;white-space:nowrap}}
.tab.on{{color:var(--accent);border-bottom-color:var(--accent)}}
.tab-p{{display:none}}
.tab-p.on{{display:block}}
.tw{{overflow-x:auto}}
table{{width:100%;border-collapse:collapse;font-size:.88rem}}
th{{background:var(--bg3);padding:.6rem .75rem;text-align:left;font-size:.76rem;color:var(--t2);text-transform:uppercase;letter-spacing:.06em;white-space:nowrap;vertical-align:middle}}
td{{padding:.5rem .75rem;border-top:1px solid var(--brd);vertical-align:middle}}
tr:hover td{{background:rgba(255,255,255,.015)}}
tr.priv td{{background:rgba(218,54,51,.06)}}
tr.check-found td{{background:rgba(218,54,51,.04)}}
.empty{{color:var(--t2);font-style:italic;padding:.5rem}}
.checks-filter{{display:flex;gap:.5rem;flex-wrap:wrap;margin-bottom:1rem}}
.cf-btn{{background:var(--bg3);border:1px solid var(--brd);color:var(--t2);padding:.3rem .75rem;border-radius:5px;cursor:pointer;font-size:.8rem}}
.cf-btn.on{{background:var(--accent);color:#000;border-color:var(--accent)}}
.pdf-btn{{text-align:center;margin:1.5rem 0}}
.pdf-btn button{{background:#1f6feb;color:#fff;border:none;padding:.7rem 2rem;border-radius:8px;font-size:.95rem;cursor:pointer;font-family:inherit}}
footer{{text-align:center;padding:1.5rem;color:var(--t2);font-size:.8rem;border-top:1px solid var(--brd)}}

/* ── KNOWLEDGE BASE ─────────────────────────────────────────────────── */
.kb-search-bar{{display:flex;gap:.75rem;margin-bottom:1.25rem;flex-wrap:wrap;align-items:center}}
.kb-search{{flex:1;min-width:200px;background:var(--bg2);border:1px solid var(--brd);color:var(--t);padding:.5rem .9rem;border-radius:8px;font-size:.9rem;font-family:inherit}}
.kb-search:focus{{outline:none;border-color:var(--accent)}}
.kb-filter-btns{{display:flex;gap:.4rem;flex-wrap:wrap}}
.kb-filter-btn{{background:var(--bg3);border:1px solid var(--brd);color:var(--t2);padding:.3rem .7rem;border-radius:5px;cursor:pointer;font-size:.78rem;transition:all .15s}}
.kb-filter-btn:hover{{color:var(--t)}}
.kb-filter-btn.on{{background:var(--accent);color:#000;border-color:var(--accent);font-weight:700}}
.kb-count{{color:var(--t2);font-size:.82rem;white-space:nowrap}}
.kb-grid{{display:flex;flex-direction:column;gap:.75rem}}
.kb-card{{background:var(--bg2);border:1px solid var(--brd);border-radius:12px;overflow:hidden;transition:border-color .15s}}
.kb-card:hover{{border-color:var(--accent)}}
.kb-header{{display:flex;justify-content:space-between;align-items:center;padding:.85rem 1.2rem;background:var(--bg3);gap:.75rem;flex-wrap:wrap}}
.kb-left{{display:flex;align-items:center;gap:.65rem;flex:1;min-width:0}}
.kb-right{{display:flex;align-items:center;gap:.5rem;flex-shrink:0;flex-wrap:wrap}}
.kb-id{{color:var(--t2);font-size:.8rem;flex-shrink:0}}
.kb-title{{font-weight:700;font-size:.95rem}}
.kb-cat{{padding:.15rem .55rem;border-radius:5px;font-size:.72rem;font-weight:700;white-space:nowrap}}
.kb-mitre{{background:rgba(88,166,255,.12);border:1px solid rgba(88,166,255,.4);color:#58a6ff;padding:.15rem .55rem;border-radius:5px;font-size:.75rem;font-weight:700;text-decoration:none;white-space:nowrap;transition:background .15s}}
.kb-mitre:hover{{background:rgba(88,166,255,.25)}}
.kb-body{{padding:1rem 1.2rem;display:grid;grid-template-columns:1fr 1fr;gap:.9rem}}
.kb-section{{}}
.kb-section:nth-child(3){{grid-column:1/-1}}
.kb-section:nth-child(4){{grid-column:1/-1}}
.kb-section:nth-child(5){{grid-column:1/-1}}
.kb-label{{font-size:.75rem;color:var(--t2);font-weight:700;text-transform:uppercase;letter-spacing:.05em;margin-bottom:.4rem}}
.kb-text{{color:var(--t2);font-size:.88rem;line-height:1.65}}
.kb-fix-section{{background:rgba(63,185,80,.06);border:1px solid rgba(63,185,80,.2);border-radius:8px;padding:.85rem}}
.kb-fix-text{{color:#7ee787!important}}
.kb-hidden{{display:none}}

/* PRINT WHITE THEME */
@media print{{
  :root{{--bg:#fff;--bg2:#f8f9fa;--bg3:#e9ecef;--bg4:#dee2e6;--t:#212529;--t2:#6c757d;--brd:#dee2e6;--accent:#0d6efd}}
  body{{background:#fff;color:#212529;font-size:13px}}
  header{{background:#fff;border-bottom:2px solid #dc3545}}
  .hl h1{{color:#dc3545}}
  .pdf-btn,.tabs,.checks-filter,.page-nav,.kb-search-bar{{display:none!important}}
  .fb,.tab-p,.page{{display:block!important}}
  .finding{{break-inside:avoid}}
  .fh{{background:#f8f9fa}}
  .badge.critical{{background:#f8d7da;color:#842029}}
  .badge.high{{background:#fff3cd;color:#664d03}}
  .badge.medium{{background:#fff3cd;color:#664d03}}
  .badge.low{{background:#d1e7dd;color:#0a3622}}
  .tag.ok{{background:#d1e7dd;color:#0a3622}}
  .tag.crit{{background:#f8d7da;color:#842029}}
  .tag.warn{{background:#fff3cd;color:#664d03}}
  .fix{{background:#d1e7dd;border-color:#a3cfbb}}
  .fix p{{color:#0a3622!important}}
  .rem-fix{{color:#0a3622;background:#d1e7dd}}
  .bar-val{{color:#212529}}
  code{{color:#0d6efd}}
  tr.check-found td{{background:#f8d7da}}
  tr.priv td{{background:#f8d7da}}
  .bad{{color:#dc3545}}
  h2{{color:#212529;border-left-color:#0d6efd}}
  section{{page-break-inside:avoid}}
  .kb-card{{break-inside:avoid;border:1px solid #dee2e6}}
  .kb-fix-section{{background:#d1e7dd;border-color:#a3cfbb}}
  .kb-fix-text{{color:#0a3622!important}}
  .kb-mitre{{background:#e9ecef;color:#0d6efd}}
}}
</style></head><body>

<header>
  <div class="hl">
    <h1>ADScan <span>Active Directory Security Analyzer</span></h1>
    <p>Active Directory Security Assessment Report</p>
  </div>
  <div class="hr">
    <div class="domain">{meta.get('domain','')}</div>
    <div class="dt">{meta.get('tarih','')}</div>
  </div>
</header>

<!-- PAGE NAVIGATION -->
<nav class="page-nav">
  <button class="pnav-btn on" onclick="showPage(this,'page-report')">📊 Scan Report</button>
  <button class="pnav-btn"    onclick="showPage(this,'page-kb')">📚 Security Knowledge Base</button>
</nav>

<!-- ══════════════════════════════════════════════════════════════
     PAGE 1 — SCAN REPORT
═══════════════════════════════════════════════════════════════ -->
<div id="page-report" class="page on">
<div class="wrap">

{_executive_summary(meta, findings, summary)}

<section>
  <h2>📊 Inventory Overview</h2>
  <div class="scards">
    <div class="scard"><div class="snum" style="color:{gc}">{sc}<span style="font-size:.9rem">/100</span></div><div class="slbl">Score · <strong style="color:{gc}">{grade}</strong></div></div>
    {_stat("Critical",    summary.get("CRITICAL",0),"#da3633")}
    {_stat("High",        summary.get("HIGH",0),    "#f0883e")}
    {_stat("Medium",      summary.get("MEDIUM",0),  "#e3b341")}
    {_stat("Low",         summary.get("LOW",0),     "#3fb950")}
    {_stat("Users",       u_cnt)}
    {_stat("Groups",      g_cnt)}
    {_stat("Computers",   c_cnt)}
    {_stat("GPOs",        gpo_cnt)}
    {_stat("SPN Accounts",spn_cnt,"#f0883e" if spn_cnt else "var(--accent)")}
    {_stat("AS-REP Vuln", ar_cnt, "#da3633" if ar_cnt  else "var(--accent)")}
  </div>
</section>

<section>
  <h2>📊 Risk Distribution</h2>
  {_charts(findings)}
</section>

<section>
  <h2>🖥 Domain Controller</h2>
  <div class="dcbox">
    <div><div class="dclbl">IP Address</div><div class="dcip">{meta.get('dc','')}</div></div>
    <div><div class="dclbl">Domain</div><div style="font-weight:600">{meta.get('domain','')}</div></div>
    <div><div class="dclbl">Open Ports</div><div>{ph}</div></div>
  </div>
</section>

<section>
  <h2>🔐 Password Policy</h2>
  <div class="polcard"><table><tbody>{_pol_rows(ad.get('password_policy',{}))}</tbody></table></div>
</section>

<section>
  <h2>⚠ Security Findings ({summary.get('TOTAL',0)})</h2>
  {_findings_html(findings)}
</section>

<section>
  <h2>📋 Findings Overview</h2>
  <div class="tw" style="background:var(--bg2);border:1px solid var(--brd);border-radius:10px;overflow:hidden">
    <table>
      <thead><tr><th>ID</th><th>Finding</th><th>Severity</th><th>Category</th><th>Affected</th><th>Detail</th></tr></thead>
      <tbody>{_findings_overview(findings)}</tbody>
    </table>
  </div>
</section>

<section>
  <h2>🛠 Remediation Summary</h2>
  <p style="color:var(--t2);font-size:.85rem;margin-bottom:1rem">All remediation steps in priority order. Address Critical and High findings first.</p>
  {_remediation_summary(findings)}
</section>

<section>
  <h2>📁 Inventory</h2>
  <div style="background:var(--bg2);border:1px solid var(--brd);border-radius:10px;padding:1.25rem">
    <div class="tabs">
      <div class="tab on" onclick="tab(this,'tu')">Users ({u_cnt})</div>
      <div class="tab"    onclick="tab(this,'tc')">Computers ({c_cnt})</div>
      <div class="tab"    onclick="tab(this,'ts')">SPN / Kerberoasting ({spn_cnt})</div>
      <div class="tab"    onclick="tab(this,'ta')">AS-REP Vulnerable ({ar_cnt})</div>
      <div class="tab"    onclick="tab(this,'tg')">Groups ({g_cnt})</div>
    </div>
    <div id="tu" class="tab-p on"><div class="tw"><table>
      <thead><tr><th>Username</th><th>Status</th><th>Department</th><th>Title</th><th>Risk Flags</th></tr></thead>
      <tbody>{_tbl_users(ad.get('users',[]))}</tbody></table></div></div>
    <div id="tc" class="tab-p"><div class="tw"><table>
      <thead><tr><th>Computer</th><th>Operating System</th><th>DNS</th></tr></thead>
      <tbody>{_tbl_comp(ad.get('computers',[]))}</tbody></table></div></div>
    <div id="ts" class="tab-p"><div class="tw">
      <p style="color:var(--t2);font-size:.85rem;margin-bottom:.75rem">TGS tickets can be requested and cracked offline.</p>
      <table><thead><tr><th>Account</th><th>Status</th><th>SPN Records</th></tr></thead>
      <tbody>{_tbl_spn(ad.get('spns',[]))}</tbody></table></div></div>
    <div id="ta" class="tab-p"><div class="tw">
      <p style="color:var(--t2);font-size:.85rem;margin-bottom:.75rem">AS-REP hash can be captured and cracked offline without credentials.</p>
      <table><thead><tr><th>Account</th><th>Department</th><th>Group Memberships</th></tr></thead>
      <tbody>{_tbl_asrep(ad.get('asrep_users',[]))}</tbody></table></div></div>
    <div id="tg" class="tab-p"><div class="tw">
      <p style="color:var(--t2);font-size:.85rem;margin-bottom:.75rem">Red rows: privileged groups.</p>
      <table><thead><tr><th>Group</th><th>Members</th><th>Description</th></tr></thead>
      <tbody>{_tbl_group(ad.get('groups',[]))}</tbody></table></div></div>
  </div>
</section>

<section>
  <h2>🔍 Security Checks Reference — All 50 Controls</h2>
  <p style="color:var(--t2);font-size:.85rem;margin-bottom:1rem">
    <span style="color:#da3633;font-weight:600">Red rows</span> = findings detected in this scan.
  </p>
  <div class="checks-filter">
    <button class="cf-btn on" onclick="filterChecks(this,'all')">All (50)</button>
    <button class="cf-btn" onclick="filterChecks(this,'kerberos')">Kerberos</button>
    <button class="cf-btn" onclick="filterChecks(this,'password')">Password Policy</button>
    <button class="cf-btn" onclick="filterChecks(this,'privileged')">Privileged Accounts</button>
    <button class="cf-btn" onclick="filterChecks(this,'service')">Service Accounts</button>
    <button class="cf-btn" onclick="filterChecks(this,'hygiene')">Account Hygiene</button>
    <button class="cf-btn" onclick="filterChecks(this,'system')">System Security</button>
    <button class="cf-btn" onclick="filterChecks(this,'domain')">Domain Config</button>
  </div>
  <div class="tw" style="background:var(--bg2);border:1px solid var(--brd);border-radius:10px;overflow:hidden">
    <table id="checks-tbl">
      <thead><tr><th>ID</th><th>Control</th><th>Category</th><th>Severity</th><th>Exploitable By</th><th>Detection Source</th><th>Status</th></tr></thead>
      <tbody>{_checks_table_html(findings)}</tbody>
    </table>
  </div>
</section>

</div><!-- /wrap -->
</div><!-- /page-report -->

<!-- ══════════════════════════════════════════════════════════════
     PAGE 2 — SECURITY KNOWLEDGE BASE
═══════════════════════════════════════════════════════════════ -->
<div id="page-kb" class="page">
<div class="wrap">

<section>
  <h2>📚 Security Knowledge Base — All 50 Controls</h2>
  <p style="color:var(--t2);font-size:.88rem;margin-bottom:1.25rem;line-height:1.6">
    Detailed explanation, attack scenario, and remediation steps for every control checked by ADScan.
    Click any MITRE ATT&amp;CK code to open the official technique page.
  </p>

  <div class="kb-search-bar">
    <input class="kb-search" type="text" id="kb-search-input"
           placeholder="🔍  Search controls, descriptions, fixes..." oninput="kbSearch()">
    <div class="kb-filter-btns">
      <button class="kb-filter-btn on"  onclick="kbFilter(this,'all')">All</button>
      <button class="kb-filter-btn" onclick="kbFilter(this,'kerberos')">Kerberos</button>
      <button class="kb-filter-btn" onclick="kbFilter(this,'password-policy')">Password</button>
      <button class="kb-filter-btn" onclick="kbFilter(this,'privileged-accounts')">Privileged</button>
      <button class="kb-filter-btn" onclick="kbFilter(this,'service-accounts')">Service Accts</button>
      <button class="kb-filter-btn" onclick="kbFilter(this,'account-hygiene')">Hygiene</button>
      <button class="kb-filter-btn" onclick="kbFilter(this,'system-security')">System</button>
      <button class="kb-filter-btn" onclick="kbFilter(this,'group-policy')">GPO</button>
      <button class="kb-filter-btn" onclick="kbFilter(this,'domain-config')">Domain</button>
    </div>
    <span class="kb-count" id="kb-count">50 controls</span>
  </div>

  <div class="kb-grid" id="kb-grid">
    {_knowledge_base_html()}
  </div>
</section>

</div><!-- /wrap -->
</div><!-- /page-kb -->

<div class="pdf-btn">
  <button onclick="window.print()">🖨 Save as PDF / Print</button>
</div>

<!-- Pie Tooltip -->
<div id="pie-tt" style="
  position:fixed;display:none;z-index:9999;
  background:#21262d;border:1px solid #58a6ff;border-radius:8px;
  padding:.6rem .9rem;pointer-events:none;
  box-shadow:0 4px 20px rgba(0,0,0,.6);min-width:140px">
  <div id="pie-tt-cat" style="font-weight:700;font-size:.9rem;margin-bottom:.25rem"></div>
  <div id="pie-tt-cnt" style="color:#8b949e;font-size:.82rem"></div>
  <div id="pie-tt-pct" style="color:#8b949e;font-size:.82rem"></div>
</div>

<footer>ADScan v2.0 — Active Directory Security Analyzer &nbsp;|&nbsp; Kali Linux &nbsp;|&nbsp; {meta.get('tarih','')}</footer>

<script>
/* ── PAGE SWITCHER ────────────────────────────────────────────── */
function showPage(btn, pageId) {{
  document.querySelectorAll('.pnav-btn').forEach(b => b.classList.remove('on'));
  document.querySelectorAll('.page').forEach(p => p.classList.remove('on'));
  btn.classList.add('on');
  document.getElementById(pageId).classList.add('on');
  window.scrollTo(0,0);
}}

/* ── FINDINGS ─────────────────────────────────────────────────── */
function tog(h){{h.closest('.finding').classList.toggle('open')}}
function tab(el,id){{
  document.querySelectorAll('.tab').forEach(t=>t.classList.remove('on'));
  document.querySelectorAll('.tab-p').forEach(p=>p.classList.remove('on'));
  el.classList.add('on');document.getElementById(id).classList.add('on');
}}
function filterChecks(btn,cat){{
  document.querySelectorAll('.cf-btn').forEach(b=>b.classList.remove('on'));
  btn.classList.add('on');
  document.querySelectorAll('#checks-tbl tbody tr').forEach(r=>{{
    if(cat==='all'){{r.style.display='';return;}}
    const c=r.cells[2]?.textContent?.toLowerCase()||'';
    r.style.display=c.includes(cat)?'':'none';
  }});
}}
function scrollToFinding(id){{
  const el=document.getElementById(id);
  if(el){{el.classList.add('open');el.scrollIntoView({{behavior:'smooth',block:'start'}});}}
}}
document.querySelectorAll('.finding').forEach((f,i)=>{{if(i<2)f.classList.add('open')}});

/* ── KNOWLEDGE BASE ───────────────────────────────────────────── */
let kbActiveFilter = 'all';

function kbFilter(btn, cat) {{
  document.querySelectorAll('.kb-filter-btn').forEach(b => b.classList.remove('on'));
  btn.classList.add('on');
  kbActiveFilter = cat;
  kbApply();
}}

function kbSearch() {{ kbApply(); }}

function kbApply() {{
  const q     = document.getElementById('kb-search-input').value.toLowerCase();
  const cards = document.querySelectorAll('.kb-card');
  let   shown = 0;
  cards.forEach(card => {{
    const catMatch = kbActiveFilter === 'all' || card.dataset.cat === kbActiveFilter;
    const text     = card.textContent.toLowerCase();
    const qMatch   = !q || text.includes(q);
    const visible  = catMatch && qMatch;
    card.classList.toggle('kb-hidden', !visible);
    if (visible) shown++;
  }});
  document.getElementById('kb-count').textContent = shown + ' control' + (shown !== 1 ? 's' : '');
}}
</script>
</body></html>"""
