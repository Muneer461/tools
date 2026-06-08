"""The curated ZorkSec tool catalog.

Each :class:`ToolDef` is a static, declarative description of a security tool.
The :class:`~zorksec.services.registry_service.RegistryService` seeds these
into the database (``tool_registry`` / ``tool_status`` / ``mitre_mappings``).

Fields
------
slug            stable unique id (lowercase, hyphenated)
name            human-friendly display name
description     one-line summary
category        UI category (e.g. "Forensics / DFIR")
team            "blue", "red", or "both"
beginner_note   plain-English "why it matters" for newcomers
install_method  apt | pip | go | snap | github | docker | builtin
install_target  package name / module / "owner/repo" / image
run_command     default command to launch (for the Run button)
docs_url        documentation link
license         SPDX-ish license label
check_binary    executable name used for installed-state detection (via PATH)
github          "owner/repo" used by the repository-health engine (optional)
requires_isolation  True for malware/RE tools that must run sandboxed
attack          list of (technique_id, technique_name, tactic) ATT&CK mappings
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class ToolDef:
    slug: str
    name: str
    description: str
    category: str
    team: str = "both"
    beginner_note: str = ""
    install_method: str = "apt"
    install_target: str = ""
    run_command: str = ""
    docs_url: str = ""
    license: str = "Unknown"
    check_binary: str = ""
    github: str = ""
    requires_isolation: bool = False
    attack: list[tuple[str, str, str]] = field(default_factory=list)


def _t(*args, **kwargs) -> ToolDef:  # small helper for compact definitions
    return ToolDef(*args, **kwargs)


# ---------------------------------------------------------------------------
# BLUE TEAM (Defensive)
# ---------------------------------------------------------------------------
_BLUE: list[ToolDef] = [
    # Log Analysis
    _t("loki", "Loki (YARA scanner)", "Simple IOC and YARA-based scanner for compromise assessment.",
       "Log Analysis", "blue", "Scans a system for known-bad indicators - a good first triage tool.",
       "github", "Neo23x0/Loki", "python3 loki.py -p .", "https://github.com/Neo23x0/Loki",
       "GPL-3.0", "", "Neo23x0/Loki"),
    _t("sigma", "Sigma", "Generic signature format for SIEM detection rules.",
       "Log Analysis", "blue", "The 'write once, run on any SIEM' format for detection rules.",
       "pip", "sigma-cli", "sigma list", "https://github.com/SigmaHQ/sigma", "DRL-1.1",
       "sigma", "SigmaHQ/sigma"),
    _t("logwatch", "Logwatch", "Summarises system logs into readable reports.",
       "Log Analysis", "blue", "Turns noisy log files into a daily human-readable summary.",
       "apt", "logwatch", "logwatch --detail high", "https://sourceforge.net/projects/logwatch/",
       "MIT", "logwatch"),
    _t("vector", "Vector", "High-performance log and metrics pipeline.",
       "Log Analysis", "blue", "Collects, transforms, and ships logs to your SIEM.",
       "github", "vectordotdev/vector", "vector --version", "https://vector.dev",
       "MPL-2.0", "vector", "vectordotdev/vector"),

    # SIEM / Logging
    _t("wazuh", "Wazuh Agent", "Open-source XDR/SIEM endpoint security agent.",
       "SIEM / Logging", "blue", "The most popular free SIEM - collects and analyses host security events.",
       "github", "wazuh/wazuh", "wazuh-control status", "https://wazuh.com",
       "GPL-2.0", "wazuh-control", "wazuh/wazuh"),
    _t("filebeat", "Filebeat", "Lightweight log shipper for the Elastic stack.",
       "SIEM / Logging", "blue", "Ships log files into Elasticsearch/OpenSearch for searching.",
       "apt", "filebeat", "filebeat version", "https://www.elastic.co/beats/filebeat",
       "Elastic-2.0", "filebeat"),

    # Threat Hunting
    _t("velociraptor", "Velociraptor", "Endpoint visibility and digital forensics at scale.",
       "Threat Hunting", "blue", "Lets you hunt across many endpoints at once using VQL queries.",
       "github", "Velocidex/velociraptor", "velociraptor version",
       "https://docs.velociraptor.app", "AGPL-3.0", "velociraptor", "Velocidex/velociraptor"),
    _t("osquery", "Osquery", "Query your operating system like a SQL database.",
       "Threat Hunting", "blue", "Ask questions about a system using SQL (e.g. 'list running processes').",
       "apt", "osquery", "osqueryi --version", "https://osquery.io", "Apache-2.0/GPL-2.0", "osqueryi"),
    _t("yara", "YARA", "Pattern-matching engine to identify and classify malware.",
       "Threat Hunting", "both", "Write rules to spot malware families by their byte/string patterns.",
       "apt", "yara", "yara --version", "https://virustotal.github.io/yara/", "BSD-3-Clause",
       "yara", "VirusTotal/yara", False,
       [("T1059", "Command and Scripting Interpreter", "Execution")]),
    _t("hayabusa", "Hayabusa", "Fast Windows event log forensics and threat hunting.",
       "Threat Hunting", "blue", "Turns Windows event logs into a timeline of Sigma-based detections.",
       "github", "Yamato-Security/hayabusa", "hayabusa --help",
       "https://github.com/Yamato-Security/hayabusa", "AGPL-3.0", "hayabusa",
       "Yamato-Security/hayabusa"),
    _t("chainsaw", "Chainsaw", "Rapidly search and hunt through Windows event logs.",
       "Threat Hunting", "blue", "Hunts through event logs with Sigma rules and prints clean results.",
       "github", "WithSecureLabs/chainsaw", "chainsaw --help",
       "https://github.com/WithSecureLabs/chainsaw", "GPL-3.0", "chainsaw",
       "WithSecureLabs/chainsaw"),
    _t("zircolite", "Zircolite", "Sigma-based detection on EVTX/JSON logs using SQLite.",
       "Threat Hunting", "blue", "Runs Sigma rules against logs without a full SIEM.",
       "github", "wagga40/Zircolite", "python3 zircolite.py --help",
       "https://github.com/wagga40/Zircolite", "LGPL-3.0", "", "wagga40/Zircolite"),

    # Incident Response
    _t("thehive", "TheHive", "Scalable security incident response platform.",
       "Incident Response", "blue", "A case-management tool where SOC teams track incidents.",
       "github", "TheHive-Project/TheHive", "", "https://thehive-project.org",
       "AGPL-3.0", "", "TheHive-Project/TheHive"),
    _t("cortex", "Cortex", "Observable analysis and active response engine.",
       "Incident Response", "blue", "Runs analyzers (e.g. VirusTotal) on IOCs from TheHive.",
       "github", "TheHive-Project/Cortex", "", "https://github.com/TheHive-Project/Cortex",
       "AGPL-3.0", "", "TheHive-Project/Cortex"),
    _t("grr", "GRR Rapid Response", "Remote live forensics for incident response.",
       "Incident Response", "blue", "Investigate and collect data from remote machines during an incident.",
       "github", "google/grr", "", "https://github.com/google/grr", "Apache-2.0", "", "google/grr"),

    # Phishing Analysis
    _t("gophish", "Gophish", "Open-source phishing simulation framework.",
       "Phishing Analysis", "blue", "Run safe phishing simulations to train users (with permission).",
       "github", "gophish/gophish", "gophish", "https://getgophish.com", "MIT",
       "gophish", "gophish/gophish"),
    _t("dnstwist", "dnstwist", "Detect typosquatting and phishing domains.",
       "Phishing Analysis", "blue", "Finds look-alike domains attackers might use to impersonate you.",
       "apt", "dnstwist", "dnstwist --help", "https://github.com/elceef/dnstwist",
       "Apache-2.0", "dnstwist", "elceef/dnstwist"),

    # Network Monitoring
    _t("zeek", "Zeek", "Powerful network analysis and security monitoring.",
       "Network Monitoring", "blue", "Turns raw network traffic into rich, searchable logs.",
       "apt", "zeek", "zeek --version", "https://zeek.org", "BSD-3-Clause", "zeek", "zeek/zeek"),
    _t("snort", "Snort", "Network intrusion detection and prevention system.",
       "Network Monitoring", "blue", "Classic IDS that alerts on malicious traffic using rules.",
       "apt", "snort", "snort -V", "https://snort.org", "GPL-2.0", "snort"),
    _t("suricata", "Suricata", "High-performance IDS/IPS and network security monitoring.",
       "Network Monitoring", "blue", "A modern, multi-threaded IDS/IPS engine.",
       "apt", "suricata", "suricata --build-info", "https://suricata.io", "GPL-2.0",
       "suricata", "OISF/suricata"),

    # Forensics / DFIR
    _t("autopsy", "Autopsy", "Graphical digital forensics platform.",
       "Forensics / DFIR", "blue", "A point-and-click tool for analysing disk images.",
       "apt", "autopsy", "autopsy", "https://www.autopsy.com", "Apache-2.0", "autopsy"),
    _t("volatility3", "Volatility 3", "Advanced memory forensics framework.",
       "Forensics / DFIR", "blue", "Extracts evidence (processes, network, malware) from RAM dumps.",
       "pip", "volatility3", "vol --help", "https://github.com/volatilityfoundation/volatility3",
       "VSL", "vol", "volatilityfoundation/volatility3"),
    _t("plaso", "Plaso (log2timeline)", "Automatic timeline generation from forensic artifacts.",
       "Forensics / DFIR", "blue", "Builds a 'super timeline' of everything that happened on a system.",
       "apt", "plaso-tools", "log2timeline.py --version",
       "https://github.com/log2timeline/plaso", "Apache-2.0", "log2timeline.py",
       "log2timeline/plaso"),
    _t("binwalk", "Binwalk", "Firmware analysis and extraction tool.",
       "Forensics / DFIR", "both", "Pulls files and code out of firmware and binary blobs.",
       "apt", "binwalk", "binwalk --help", "https://github.com/ReFirmLabs/binwalk",
       "MIT", "binwalk", "ReFirmLabs/binwalk"),
    _t("dissect", "Dissect", "Fast, modular incident-response toolkit by Fox-IT.",
       "Forensics / DFIR", "blue", "Analyse disk images and forensic artifacts quickly at scale.",
       "pip", "dissect", "target-query --help", "https://github.com/fox-it/dissect",
       "AGPL-3.0", "target-query", "fox-it/dissect"),
    _t("regripper", "RegRipper", "Windows registry data extraction tool.",
       "Forensics / DFIR", "blue", "Pulls useful evidence out of Windows registry hives.",
       "github", "keydet89/RegRipper3.0", "rip.pl", "https://github.com/keydet89/RegRipper3.0",
       "MIT", "", "keydet89/RegRipper3.0"),
    _t("cyberchef", "CyberChef", "The 'Cyber Swiss Army Knife' for data transformations.",
       "Forensics / DFIR", "both", "Decode, decrypt, and transform data in your browser.",
       "github", "gchq/CyberChef", "", "https://gchq.github.io/CyberChef/", "Apache-2.0",
       "", "gchq/CyberChef"),

    # OSINT for SOC
    _t("theharvester", "theHarvester", "Gather emails, subdomains, and hosts from public sources.",
       "OSINT for SOC", "both", "Collects an organisation's public footprint (emails, subdomains).",
       "apt", "theharvester", "theHarvester -h", "https://github.com/laramies/theHarvester",
       "GPL-2.0", "theHarvester", "laramies/theHarvester"),
    _t("spiderfoot", "SpiderFoot", "Automated OSINT collection and attack-surface mapping.",
       "OSINT for SOC", "both", "Automates open-source intelligence gathering about a target.",
       "github", "smicallef/spiderfoot", "python3 sf.py -h",
       "https://github.com/smicallef/spiderfoot", "MIT", "", "smicallef/spiderfoot"),
    _t("shodan", "Shodan CLI", "Search engine for Internet-connected devices.",
       "OSINT for SOC", "both", "Find exposed devices/services on the Internet (needs API key).",
       "pip", "shodan", "shodan version", "https://cli.shodan.io", "Proprietary-API", "shodan"),

    # Malware Analysis (isolation required)
    _t("radare2", "Radare2", "Reverse-engineering and binary analysis framework.",
       "Malware Analysis", "both", "Open a binary and explore its code - run only in isolation.",
       "apt", "radare2", "r2 -v", "https://rada.re", "LGPL-3.0", "r2",
       "radareorg/radare2", True),
    _t("capa", "CAPA", "Identify capabilities in executable files.",
       "Malware Analysis", "blue", "Tells you what a suspicious file *can do* (e.g. 'reads registry').",
       "pip", "flare-capa", "capa --help", "https://github.com/mandiant/capa",
       "Apache-2.0", "capa", "mandiant/capa", True),

    # Threat Intelligence
    _t("misp", "MISP", "Open-source threat intelligence sharing platform.",
       "Threat Intelligence", "blue", "Store, share, and correlate threat indicators (IOCs).",
       "github", "MISP/MISP", "", "https://www.misp-project.org", "AGPL-3.0", "", "MISP/MISP"),
    _t("opencti", "OpenCTI", "Open cyber threat intelligence platform.",
       "Threat Intelligence", "blue", "Organise threat knowledge using the STIX2 model.",
       "github", "OpenCTI-Platform/opencti", "", "https://www.opencti.io", "Apache-2.0",
       "", "OpenCTI-Platform/opencti"),
    _t("yeti", "Yeti", "Your everyday threat intelligence repository.",
       "Threat Intelligence", "blue", "A lightweight place to collect and pivot on IOCs.",
       "github", "yeti-platform/yeti", "", "https://yeti-platform.io", "Apache-2.0",
       "", "yeti-platform/yeti"),
    _t("intelowl", "IntelOwl", "Threat intelligence data enrichment at scale.",
       "Threat Intelligence", "blue", "Run many analyzers on an IOC from one place.",
       "github", "intelowlproject/IntelOwl", "", "https://intelowlproject.github.io",
       "AGPL-3.0", "", "intelowlproject/IntelOwl"),
]


# ---------------------------------------------------------------------------
# RED TEAM (Offensive)
# ---------------------------------------------------------------------------
_RED: list[ToolDef] = [
    # Information Gathering
    _t("nmap", "Nmap", "The classic network scanner and host discovery tool.",
       "Information Gathering", "both", "Find live hosts, open ports, and services on a network.",
       "apt", "nmap", "nmap --version", "https://nmap.org", "NPSL", "nmap", "nmap/nmap", False,
       [("T1046", "Network Service Discovery", "Discovery")]),
    _t("masscan", "Masscan", "Internet-scale TCP port scanner.",
       "Information Gathering", "red", "Scans huge IP ranges very fast.",
       "apt", "masscan", "masscan --version", "https://github.com/robertdavidgraham/masscan",
       "AGPL-3.0", "masscan", "robertdavidgraham/masscan"),
    _t("rustscan", "RustScan", "Ultra-fast port scanner that feeds into Nmap.",
       "Information Gathering", "red", "Finds open ports in seconds, then hands off to Nmap.",
       "github", "RustScan/RustScan", "rustscan --version",
       "https://github.com/RustScan/RustScan", "GPL-3.0", "rustscan", "RustScan/RustScan"),
    _t("naabu", "Naabu", "Fast port scanner written in Go.",
       "Information Gathering", "red", "A reliable, scriptable port scanner from ProjectDiscovery.",
       "go", "github.com/projectdiscovery/naabu/v2/cmd/naabu@latest", "naabu -version",
       "https://github.com/projectdiscovery/naabu", "MIT", "naabu", "projectdiscovery/naabu"),
    _t("subfinder", "Subfinder", "Passive subdomain discovery tool.",
       "Information Gathering", "red", "Finds an organisation's subdomains from public sources.",
       "go", "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
       "subfinder -version", "https://github.com/projectdiscovery/subfinder", "MIT",
       "subfinder", "projectdiscovery/subfinder"),
    _t("httpx", "httpx", "Fast and multi-purpose HTTP toolkit.",
       "Information Gathering", "red", "Probes a list of hosts to see which run web servers.",
       "go", "github.com/projectdiscovery/httpx/cmd/httpx@latest", "httpx -version",
       "https://github.com/projectdiscovery/httpx", "MIT", "httpx", "projectdiscovery/httpx"),
    _t("amass", "OWASP Amass", "In-depth attack-surface mapping and asset discovery.",
       "Information Gathering", "red", "Maps an organisation's external attack surface in depth.",
       "github", "owasp-amass/amass", "amass -version", "https://github.com/owasp-amass/amass",
       "Apache-2.0", "amass", "owasp-amass/amass"),

    # Web Application
    _t("nikto", "Nikto", "Web server scanner for known vulnerabilities.",
       "Web Application", "red", "Quickly checks a web server for thousands of known issues.",
       "apt", "nikto", "nikto -Version", "https://github.com/sullo/nikto", "GPL-2.0",
       "nikto", "sullo/nikto"),
    _t("gobuster", "Gobuster", "Directory, DNS, and vhost brute-forcing tool.",
       "Web Application", "red", "Discovers hidden directories and files on a web server.",
       "apt", "gobuster", "gobuster version", "https://github.com/OJ/gobuster", "Apache-2.0/MIT",
       "gobuster", "OJ/gobuster"),
    _t("ffuf", "ffuf", "Fast web fuzzer written in Go.",
       "Web Application", "red", "Fuzzes web apps to find hidden endpoints and parameters.",
       "go", "github.com/ffuf/ffuf/v2@latest", "ffuf -V", "https://github.com/ffuf/ffuf",
       "MIT", "ffuf", "ffuf/ffuf"),
    _t("sqlmap", "sqlmap", "Automatic SQL injection and database takeover tool.",
       "Web Application", "red", "Detects and exploits SQL injection flaws automatically.",
       "apt", "sqlmap", "sqlmap --version", "https://sqlmap.org", "GPL-2.0", "sqlmap",
       "sqlmapproject/sqlmap", False, [("T1190", "Exploit Public-Facing Application", "Initial Access")]),
    _t("xsstrike", "XSStrike", "Advanced XSS detection and exploitation suite.",
       "Web Application", "red", "Finds cross-site scripting (XSS) flaws in web apps.",
       "github", "s0md3v/XSStrike", "python3 xsstrike.py", "https://github.com/s0md3v/XSStrike",
       "GPL-3.0", "", "s0md3v/XSStrike"),
    _t("katana", "Katana", "Next-generation crawling and spidering framework.",
       "Web Application", "red", "Crawls a website to map all its links and endpoints.",
       "go", "github.com/projectdiscovery/katana/cmd/katana@latest", "katana -version",
       "https://github.com/projectdiscovery/katana", "MIT", "katana", "projectdiscovery/katana"),

    # Vulnerability Scanning
    _t("nuclei", "Nuclei", "Template-based vulnerability scanner.",
       "Vulnerability Scanning", "red", "Scans for vulnerabilities using a huge community template set.",
       "go", "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest", "nuclei -version",
       "https://github.com/projectdiscovery/nuclei", "MIT", "nuclei", "projectdiscovery/nuclei"),
    _t("lynis", "Lynis", "Security auditing and hardening tool for Linux/Unix.",
       "Vulnerability Scanning", "both", "Audits a Linux system and suggests hardening steps.",
       "apt", "lynis", "lynis show version", "https://cisofy.com/lynis/", "GPL-3.0",
       "lynis", "CISOfy/lynis"),

    # Password Auditing
    _t("john", "John the Ripper", "Fast, feature-rich password cracker.",
       "Password Auditing", "red", "Tests password strength by trying to crack hashes (lab only).",
       "apt", "john", "john --version", "https://www.openwall.com/john/", "GPL-2.0",
       "john", "openwall/john"),
    _t("hashcat", "Hashcat", "World's fastest GPU-based password recovery tool.",
       "Password Auditing", "red", "Cracks password hashes using your GPU (lab only).",
       "apt", "hashcat", "hashcat --version", "https://hashcat.net/hashcat/", "MIT",
       "hashcat", "hashcat/hashcat"),
    _t("hydra", "Hydra", "Parallelised network login brute-forcer.",
       "Password Auditing", "red", "Tests login services for weak credentials (authorised use only).",
       "apt", "hydra", "hydra -h", "https://github.com/vanhauser-thc/thc-hydra", "AGPL-3.0",
       "hydra", "vanhauser-thc/thc-hydra"),
    _t("medusa", "Medusa", "Speedy, parallel, modular login brute-forcer.",
       "Password Auditing", "red", "Another fast credential-testing tool for many protocols.",
       "apt", "medusa", "medusa -V", "https://github.com/jmk-foofus/medusa", "GPL-2.0", "medusa"),

    # Wireless Security
    _t("aircrack-ng", "Aircrack-ng", "Complete suite for Wi-Fi network security assessment.",
       "Wireless Security", "red", "The standard toolkit for testing Wi-Fi security (your own networks).",
       "apt", "aircrack-ng", "aircrack-ng --help", "https://www.aircrack-ng.org", "GPL-2.0",
       "aircrack-ng", "aircrack-ng/aircrack-ng"),
    _t("reaver", "Reaver", "Brute-force attack against Wi-Fi Protected Setup (WPS).",
       "Wireless Security", "red", "Tests routers for the WPS weakness (your own equipment only).",
       "apt", "reaver", "reaver -h", "https://github.com/t6x/reaver-wps-fork-t6x", "GPL-2.0", "reaver"),
    _t("kismet", "Kismet", "Wireless network detector, sniffer, and IDS.",
       "Wireless Security", "both", "Discovers and monitors nearby wireless networks.",
       "apt", "kismet", "kismet --version", "https://www.kismetwireless.net", "GPL-2.0",
       "kismet", "kismetwireless/kismet"),

    # Exploitation
    _t("metasploit", "Metasploit Framework", "The world's most used penetration-testing framework.",
       "Exploitation", "red", "A huge framework of exploits and payloads (lab use only).",
       "apt", "metasploit-framework", "msfconsole --version", "https://www.metasploit.com",
       "BSD-3-Clause", "msfconsole", "rapid7/metasploit-framework"),
    _t("searchsploit", "SearchSploit (Exploit-DB)", "Command-line search for the Exploit Database.",
       "Exploitation", "red", "Search offline for public exploits matching a service/version.",
       "apt", "exploitdb", "searchsploit -h", "https://www.exploit-db.com/searchsploit",
       "GPL-2.0", "searchsploit", "offensive-security/exploitdb"),
    _t("beef", "BeEF", "The Browser Exploitation Framework.",
       "Exploitation", "red", "Demonstrates browser-based attacks (lab use only).",
       "github", "beefproject/beef", "", "https://beefproject.com", "BSD-3-Clause",
       "", "beefproject/beef"),

    # Post Exploitation
    _t("linpeas", "LinPEAS", "Linux privilege-escalation enumeration script.",
       "Post Exploitation", "red", "Lists ways an attacker could escalate privileges on Linux.",
       "github", "carlospolop/PEASS-ng", "linpeas.sh", "https://github.com/carlospolop/PEASS-ng",
       "MIT", "", "carlospolop/PEASS-ng"),
    _t("empire", "Empire", "Post-exploitation and adversary-emulation framework.",
       "Post Exploitation", "red", "Emulates post-compromise attacker behaviour (lab only).",
       "github", "BC-SECURITY/Empire", "", "https://github.com/BC-SECURITY/Empire",
       "BSD-3-Clause", "", "BC-SECURITY/Empire"),

    # Active Directory
    _t("bloodhound", "BloodHound", "Reveal hidden relationships and attack paths in Active Directory.",
       "Active Directory", "red", "Maps AD to find paths an attacker could take to Domain Admin.",
       "github", "BloodHoundAD/BloodHound", "", "https://bloodhound.readthedocs.io",
       "GPL-3.0", "", "BloodHoundAD/BloodHound"),
    _t("impacket", "Impacket", "Python classes for working with network protocols.",
       "Active Directory", "red", "A toolkit of scripts for interacting with Windows/AD protocols.",
       "pip", "impacket", "", "https://github.com/fortra/impacket", "Apache-1.1", "", "fortra/impacket"),
    _t("netexec", "NetExec (CME)", "Network service exploitation and AD swiss-army knife.",
       "Active Directory", "red", "Automates assessing many hosts/services across a network (lab only).",
       "pip", "netexec", "netexec --version", "https://github.com/Pennyw0rth/NetExec",
       "BSD-2-Clause", "netexec", "Pennyw0rth/NetExec"),
    _t("responder", "Responder", "LLMNR/NBT-NS/MDNS poisoner and credential capture tool.",
       "Active Directory", "red", "Captures credentials on a local network (authorised labs only).",
       "apt", "responder", "responder -h", "https://github.com/lgandx/Responder", "GPL-3.0",
       "responder", "lgandx/Responder"),
    _t("kerbrute", "Kerbrute", "Brute-force and enumerate Active Directory accounts via Kerberos.",
       "Active Directory", "red", "Enumerates valid AD usernames quickly (authorised use only).",
       "github", "ropnop/kerbrute", "kerbrute", "https://github.com/ropnop/kerbrute",
       "MIT", "kerbrute", "ropnop/kerbrute"),

    # Reverse Engineering (isolation recommended)
    _t("ghidra", "Ghidra", "NSA's open-source software reverse-engineering suite.",
       "Reverse Engineering", "both", "Decompile and analyse binaries - run in isolation.",
       "apt", "ghidra", "ghidra", "https://ghidra-sre.org", "Apache-2.0", "ghidra",
       "NationalSecurityAgency/ghidra", True),

    # Other
    _t("cewl", "CeWL", "Custom wordlist generator that spiders a target site.",
       "Other", "red", "Builds a password wordlist from words found on a website.",
       "apt", "cewl", "cewl --help", "https://github.com/digininja/CeWL", "GPL-3.0",
       "cewl", "digininja/CeWL"),
]


CATALOG: list[ToolDef] = _BLUE + _RED


def catalog_by_team(team: str) -> list[ToolDef]:
    """Return tools for a team profile ('blue', 'red', or 'both' for all)."""
    if team == "both":
        return list(CATALOG)
    return [t for t in CATALOG if t.team in (team, "both")]


def categories(team: str | None = None) -> list[str]:
    """Return the ordered, de-duplicated list of categories (optionally filtered)."""
    tools = CATALOG if team in (None, "both") else catalog_by_team(team)
    seen: list[str] = []
    for tool in tools:
        if tool.category not in seen:
            seen.append(tool.category)
    return seen
