# ACLGuard: Identifying Privilege Escalation Paths in Active Directory

## Why I Built This & Security Relevance
I built ACLGuard to develop a deeper, practical understanding of how Active Directory Access Control Lists (ACLs) are abused in real-world enterprise environments. Misconfigurations such as GenericAll, WriteDACL, and WriteOwner permissions frequently enable stealthy privilege escalation paths that are overlooked during routine assessments.

This project focuses on identifying those misconfigurations programmatically, reinforcing how seemingly minor permission issues can lead to full domain compromise. ACLGuard is designed as a lightweight, scriptable tool suitable for offensive assessments, validation, and security research.

## Features
- Enumerates Active Directory objects and associated ACLs
- Identifies high-risk permission relationships
- Outputs structured CSV and JSON data for analysis and reporting

## Technical Implementation
- Written in C for performance and low-level interaction
- Uses optimized LDAP queries for efficient enumeration
- Inspired by BloodHound-style attack path analysis

## Build & Usage
```bash
make
./aclguard --domain example.local
---

## 🚀 Current Version: v1.0

ACLGuard v1.0 is now complete with full permission analysis and risk assessment capabilities!

### Key Features:
- **LDAP/AD Connection**: Connects to Active Directory servers
- **Permission Analysis**: Analyzes 7 types of high-risk permissions
- **Risk Scoring**: Calculates risk scores (0-100) with color-coded levels
- **Export Capabilities**: Exports results to CSV and JSON formats
- **Professional Output**: Clean, informative display with security summary

### Quick Start:

# Build
make clean && make

# Configure (create config_ad.env)
export ACLGUARD_LDAP_URI="ldap://your-ad-server:389"
export ACLGUARD_BIND_DN="Administrator@domain.local"
export ACLGUARD_BIND_PW="password"
export ACLGUARD_BASE_DN="dc=domain,dc=local"

# Run
source config_ad.env && ./aclguard

# Export results
./aclguard --export-csv --export-json
```

---

## 📚 Documentation

- **[Complete Documentation](README_v1.0.md)** - Full v1.0 documentation
- **[Wiki](wiki/)** - Detailed guides and architecture documentation

---

## 🔒 Security Note

This tool is for educational purposes only. It uses unencrypted LDAP connections and is not production-ready.

---

**ACLGuard v1.0** - A cybersecurity learning project by ForeverLX
