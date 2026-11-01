import os
import yaml

RULES = [
    # Core 7 Rules
    {
        "id": "R-01",
        "name": "Exploit Public-Facing Application (Log4j / vCenter)",
        "mitre_id": "T1190",
        "technique": "Exploit Public-Facing Application",
        "stage": "Initial Access",
        "severity": "CRITICAL",
        "pattern": "Log4j|vCenter|Citrix|WebLogic|Buffer.Overflow|OGNL",
        "description": "Detects remote code execution exploits targeting internet-facing enterprise infrastructure."
    },
    {
        "id": "R-02",
        "name": "Authentication Burst & Credential Brute Force",
        "mitre_id": "T1110",
        "technique": "Brute Force",
        "stage": "Credential Access",
        "severity": "HIGH",
        "pattern": "failed_login|4625|brute|Password.Spray|Bad.Password",
        "description": "Detects high-frequency authentication failures indicative of dictionary attacks or password spraying."
    },
    {
        "id": "R-03",
        "name": "Suspicious Privileged Account Creation",
        "mitre_id": "T1136.001",
        "technique": "Create Account: Local/Domain Account",
        "stage": "Persistence",
        "severity": "HIGH",
        "pattern": "new_admin|4720|useradd|net user.*/add|dsadd user",
        "description": "Identifies unauthorized creation of local administrator or domain admin accounts."
    },
    {
        "id": "R-04",
        "name": "SMB / Windows Admin Share Lateral Pivot",
        "mitre_id": "T1021.002",
        "technique": "Remote Services: SMB/Windows Admin Shares",
        "stage": "Lateral Movement",
        "severity": "HIGH",
        "pattern": "smb_lateral|admin\\$|c\\$|ipc\\$|psexec|5140|5145",
        "description": "Detects lateral movement across internal subnets utilizing hidden administrative shares."
    },
    {
        "id": "R-05",
        "name": "C2 Beaconing & Web Protocol Tunnels",
        "mitre_id": "T1071.001",
        "technique": "Web Protocols: Cobalt Strike / C2 Beaconing",
        "stage": "Command and Control",
        "severity": "CRITICAL",
        "pattern": "Cobalt.Strike|beacon|Mirai|catdesc=\"Botnet\"|Sliver|Metasploit",
        "description": "Detects persistent Command-and-Control telemetry beaconing over HTTP/HTTPS/DNS."
    },
    {
        "id": "R-06",
        "name": "Outbound Exfiltration Over Alternative Protocol",
        "mitre_id": "T1048",
        "technique": "Exfiltration Over Alternative Protocol",
        "stage": "Exfiltration",
        "severity": "CRITICAL",
        "pattern": "outbound_upload|exfil|bytes_out=[5-9][0-9]{7}|sentbyte=[5-9][0-9]{7}",
        "description": "Flags massive outbound data transfers (>50MB) directed to unauthorized external IP addresses."
    },
    {
        "id": "R-07",
        "name": "Ransomware Encryption & Data Destruction",
        "mitre_id": "T1486",
        "technique": "Data Encrypted for Impact",
        "stage": "Impact",
        "severity": "CRITICAL",
        "pattern": "Ransomware|encrypt|vssadmin delete shadows|wbadmin delete catalog|virus=",
        "description": "Detects active ransomware encryption activity, shadow copy deletion, or backup catalog purging."
    },
    # 8 High-Value Enterprise Rules
    {
        "id": "R-08",
        "name": "Kerberoasting Service Ticket Extraction",
        "mitre_id": "T1558.003",
        "technique": "Steal or Forge Kerberos Tickets: Kerberoasting",
        "stage": "Credential Access",
        "severity": "HIGH",
        "pattern": "EventID=4769|Ticket_Options=0x40810000|Ticket_Encryption_Type=0x17|kerberoast",
        "description": "Identifies Active Directory Kerberos TGS requests for service accounts utilizing weak RC4 encryption."
    },
    {
        "id": "R-09",
        "name": "LSASS Memory Credential Dumping (Mimikatz)",
        "mitre_id": "T1003.001",
        "technique": "OS Credential Dumping: LSASS Memory",
        "stage": "Credential Access",
        "severity": "CRITICAL",
        "pattern": "mimikatz|sekurlsa|lsass.exe.*dump|procdump.*lsass|MiniDumpWriteDump",
        "description": "Detects unauthorized access or process memory dumping of the Local Security Authority Subsystem Service."
    },
    {
        "id": "R-10",
        "name": "Spearphishing Attachment Execution",
        "mitre_id": "T1566.001",
        "technique": "Phishing: Spearphishing Attachment",
        "stage": "Initial Access",
        "severity": "HIGH",
        "pattern": "WINWORD.EXE.*powershell|EXCEL.EXE.*cmd|invoice\\.vbs|macro_exec|outlook.*attachment",
        "description": "Detects weaponized Microsoft Office macros or child processes executing scripting interpreters."
    },
    {
        "id": "R-11",
        "name": "Obfuscated / Encoded PowerShell Execution",
        "mitre_id": "T1059.001",
        "technique": "Command and Scripting Interpreter: PowerShell",
        "stage": "Execution",
        "severity": "HIGH",
        "pattern": "powershell.*-e(nc)?\\s+[A-Za-z0-9+/=]{20,}|powershell.*-nop.*-w hidden|downloadstring|iex\\s*\\(",
        "description": "Detects Base64-encoded or obfuscated PowerShell commands executing hidden in-memory payloads."
    },
    {
        "id": "R-12",
        "name": "Pass-the-Hash / NTLM Relay Lateral Movement",
        "mitre_id": "T1550.002",
        "technique": "Use Alternate Authentication Material: Pass the Hash",
        "stage": "Lateral Movement",
        "severity": "HIGH",
        "pattern": "EventID=4624.*LogonType=3.*AuthenticationPackageName=NTLM.*KeyLength=0|mimikatz.*pth",
        "description": "Detects network logons authenticating via stolen NTLM hashes without plaintext password verification."
    },
    {
        "id": "R-13",
        "name": "Account Manipulation & SSH Authorized Keys Backdoor",
        "mitre_id": "T1098",
        "technique": "Account Manipulation: SSH Authorized Keys",
        "stage": "Persistence",
        "severity": "HIGH",
        "pattern": "authorized_keys.*echo|EventID=4738|adminCount=1.*modified|shadow_credentials",
        "description": "Detects persistence achieved by injecting SSH public keys into user profiles or modifying AD AdminSDHolder."
    },
    {
        "id": "R-14",
        "name": "Security Audit Log Tampering (EventID 1102 / Log Cleared)",
        "mitre_id": "T1070.001",
        "technique": "Indicator Removal: Clear Windows Event Logs",
        "stage": "Defense Evasion",
        "severity": "HIGH",
        "pattern": "EventID=1102|EventID=104|wevtutil.*cl.*Security|rm -rf /var/log",
        "description": "Flags attempts by adversaries to clear the Windows Security log or delete Linux audit logs."
    },
    {
        "id": "R-15",
        "name": "Cloud Storage Exfiltration via Rclone / Mega / AWS S3",
        "mitre_id": "T1567.002",
        "technique": "Exfiltration Over Web Service: Exfiltration to Cloud Storage",
        "stage": "Exfiltration",
        "severity": "CRITICAL",
        "pattern": "rclone.*copy|mega-cmd|aws s3 sync|curl -F.*file=@.*transfer.sh|dropbox_upload",
        "description": "Detects command-line synchronization tools staging and exfiltrating corporate data to personal cloud storage."
    }
]

def generate():
    rules_dir = r"C:\Users\Srishtee\Downloads\CyberForge\config\rules"
    os.makedirs(rules_dir, exist_ok=True)
    
    for r in RULES:
        clean_name = r['technique'].lower().replace(' ', '_').replace(':', '').replace('/', '_')[:30]
        fname = f"{r['mitre_id'].replace('.', '_')}_{clean_name}.yaml"
        fpath = os.path.join(rules_dir, fname)
        with open(fpath, "w", encoding="utf-8") as f:
            yaml.dump(r, f, default_flow_style=False)
        print(f"Generated {fpath}")

    # Also update master config/rules.yaml
    master_yaml = r"C:\Users\Srishtee\Downloads\CyberForge\config\rules.yaml"
    with open(master_yaml, "w", encoding="utf-8") as f:
        yaml.dump({"detection_rules": RULES, "total_rules": len(RULES)}, f, default_flow_style=False)
    print(f"Saved {master_yaml} with {len(RULES)} rules")

if __name__ == '__main__':
    generate()
