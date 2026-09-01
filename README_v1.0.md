# ACLGuard v1.0

> **ARCHIVED — historical snapshot of the v1.0 release.** The project is now **Lantern** (codename), currently at C v2.0.0 "Purple" with a Go rewrite in progress. See the [current README](README.md), [CHANGELOG.md](CHANGELOG.md), and [ARCHITECTURE.md](ARCHITECTURE.md). This file is preserved for reference only — commands and structure shown here are out of date.

**ACLGuard** is a C-based cybersecurity tool that connects to Active Directory, analyzes user permissions, and provides risk assessment based on group memberships and privileges.

⚠️ This is a learning/demo project — not production-ready.

---

## 🚀 Features

### Core Functionality
- **LDAP/AD Connection**: Connects to Active Directory servers
- **User Enumeration**: Fetches user attributes (CN, sAMAccountName, Email, Groups)
- **Permission Analysis**: Analyzes user permissions based on group memberships
- **Risk Scoring**: Calculates risk scores (0-100) based on privilege levels
- **Export Capabilities**: Exports results to CSV and JSON formats

### Permission Analysis
ACLGuard analyzes the following high-risk permissions:
- **Admin Privileges**: Domain Admins, Enterprise Admins, Schema Admins, etc.
- **Password Reset**: Account Operators, Help Desk groups
- **ACL Modification**: Backup Operators, Server Operators, Print Operators
- **Authentication Delegation**: Delegation and Trust groups
- **Service Accounts**: SQL, IIS, Exchange service accounts
- **Secret Access**: Read/Write access to sensitive attributes

### Risk Scoring
- **🔴 CRITICAL (80-100)**: Multiple high-risk permissions
- **🟠 HIGH (60-79)**: Significant administrative privileges
- **🟡 MEDIUM (40-59)**: Moderate risk permissions
- **🔵 LOW (20-39)**: Limited privileged access
- **🟢 MINIMAL (0-19)**: Standard user permissions

---

## 🛠️ Build & Run

### Prerequisites
```bash
# Arch Linux
sudo pacman -S base-devel openldap openldap-devel gcc make json-c

# Ubuntu/Debian
sudo apt install build-essential libldap2-dev libldap-2.4-2 liblber-dev libjson-c-dev
```

### Build
```bash
make clean && make
```

### Configuration
Create a configuration file (e.g., `config_ad.env`) using placeholder values or copy from `.env.example`:
```bash
export ACLGUARD_LDAP_URI="ldap://your-ad-host:389"
export ACLGUARD_BIND_DN="Administrator@domain.local"
export ACLGUARD_BIND_PW="your_password_here"
export ACLGUARD_BASE_DN="dc=domain,dc=local"
```

### Usage
```bash
# Basic scan
source config_ad.env && ./aclguard

# New LDAP subcommands (v2 CLI)
./aclguard status
./aclguard alerts --recent
./aclguard correlate --attack kerberoasting
./aclguard analyze --incident latest
./aclguard metrics --throughput

# Export to CSV
./aclguard --export-csv results.csv

# Export to JSON
./aclguard --export-json results.json

# Export both formats
./aclguard --export-csv --export-json

# Show help
./aclguard --help
```

---

## 📊 Output Example

```
✅ Successfully connected to LDAP server: ldap://your-ad-host:389
📊 Users retrieved: 4

═══════════════════════════════════════════════════════════════════════════════════
👤 User: Administrator (Administrator)
👥 Groups: CN=Group Policy Creator Owners,CN=Users,DC=example,DC=local
    Permissions: Admin 
⚠️  Risk Score: 40/100 🟡 MEDIUM

═══════════════════════════════════════════════════════════════════════════════════
📊 SECURITY SUMMARY
═══════════════════════════════════════════════════════════════════════════════════
Total Users: 4
High Risk Users (≥60): 0
Admin Users: 1
Privileged Users: 1
═══════════════════════════════════════════════════════════════════════════════════
```

---

## 📁 Project Structure

```
ACLGuard/
├── src/                    # Source code
│   ├── main.c             # Main program
│   ├── ldap.c             # LDAP connection & user fetching
│   ├── config.c           # Configuration management
│   ├── export.c           # CSV/JSON export functionality
│   ├── error_handler.c    # Error handling
│   └── risk_engine.c      # Risk assessment (placeholder)
├── include/               # Header files
│   ├── types.h            # Data structures
│   ├── config.h           # Configuration definitions
│   ├── aclguard_ldap.h    # LDAP function declarations
│   ├── export.h           # Export function declarations
│   └── error_handler.h    # Error handling declarations
├── config_ad.env          # AD server configuration
├── Makefile               # Build configuration
└── README_v1.0.md         # This file
```

---

## 🔒 Security Notes

- **Demo Only**: This tool is for educational purposes
- **No LDAPS**: Uses unencrypted LDAP connections
- **No Vaulting**: Credentials stored in plain text
- **Not Production Ready**: Missing security hardening

---

## 🎯 Use Cases

### Cybersecurity Learning
- Understanding AD permission structures
- Learning about privilege escalation vectors
- Practicing LDAP enumeration techniques

### Security Assessment
- Identifying overprivileged accounts
- Mapping group memberships
- Risk assessment of user accounts

### Portfolio Project
- Demonstrates C programming skills
- Shows understanding of LDAP/AD
- Cybersecurity tool development experience

---

## 🚧 Future Enhancements (v1.1)

- Ubuntu LDAP server support
- Enhanced permission analysis
- More granular risk scoring
- LDAPS support
- Configuration file support
- Advanced filtering options

---

## 📝 License

MIT License - See MIT_LICENSE file for details.

---

**ACLGuard v1.0** - A cybersecurity learning project by CR1MS0N-Operator
