"""
MITRE ATT&CK lookup tool — local, free, no API needed.

Uses a lightweight embedded mapping of tactic/technique IDs to descriptions.
For production, replace with the full STIX bundle from attack.mitre.org.
"""
from __future__ import annotations

# Compact subset — expand with full ATT&CK STIX bundle for production
_TACTICS: dict[str, str] = {
    "TA0001": "Initial Access — gaining a foothold in the network",
    "TA0002": "Execution — running adversary-controlled code",
    "TA0003": "Persistence — maintaining presence across restarts",
    "TA0004": "Privilege Escalation — gaining higher permissions",
    "TA0005": "Defense Evasion — avoiding detection",
    "TA0006": "Credential Access — stealing credentials",
    "TA0007": "Discovery — learning about the environment",
    "TA0008": "Lateral Movement — moving through the network",
    "TA0009": "Collection — gathering data of interest",
    "TA0010": "Exfiltration — stealing data",
    "TA0011": "Command and Control — communicating with compromised systems",
    "TA0040": "Impact — disrupting availability or integrity",
    "TA0042": "Resource Development — building attack resources",
    "TA0043": "Reconnaissance — gathering target information",
}

_TECHNIQUES: dict[str, str] = {
    "T1078": "Valid Accounts — use of legitimate credentials",
    "T1110": "Brute Force — password guessing attacks",
    "T1110.001": "Brute Force: Password Guessing",
    "T1110.003": "Brute Force: Password Spraying",
    "T1021": "Remote Services — lateral movement via RDP/SSH/SMB",
    "T1021.001": "Remote Services: Remote Desktop Protocol",
    "T1059": "Command and Scripting Interpreter",
    "T1059.001": "Command and Scripting: PowerShell",
    "T1059.003": "Command and Scripting: Windows Command Shell",
    "T1055": "Process Injection",
    "T1053": "Scheduled Task/Job",
    "T1082": "System Information Discovery",
    "T1083": "File and Directory Discovery",
    "T1057": "Process Discovery",
    "T1018": "Remote System Discovery",
    "T1040": "Network Sniffing",
    "T1041": "Exfiltration Over C2 Channel",
    "T1048": "Exfiltration Over Alternative Protocol",
    "T1071": "Application Layer Protocol",
    "T1071.001": "Application Layer Protocol: Web Protocols",
    "T1566": "Phishing",
    "T1566.001": "Phishing: Spearphishing Attachment",
    "T1190": "Exploit Public-Facing Application",
    "T1133": "External Remote Services",
    "T1486": "Data Encrypted for Impact (Ransomware)",
    "T1490": "Inhibit System Recovery",
}


