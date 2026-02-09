# Getting Started with ACLGuard

This guide will help you get ACLGuard up and running quickly on your system.

## 📋 Prerequisites

### System Requirements
- **Operating System**: Linux (Arch, Ubuntu, Debian) or Windows with WSL
- **Compiler**: GCC with C99 support
- **Libraries**: OpenLDAP development libraries, JSON-C library

### Required Packages

#### Arch Linux
```bash
sudo pacman -S base-devel openldap openldap-devel gcc make json-c
```

#### Ubuntu/Debian
```bash
sudo apt update
sudo apt install build-essential libldap2-dev libldap-2.4-2 liblber-dev libjson-c-dev
```

#### CentOS/RHEL
```bash
sudo yum groupinstall "Development Tools"
sudo yum install openldap-devel json-c-devel
```

## 🔨 Building ACLGuard

1. **Clone the repository**:
   ```bash
   git clone https://github.com/yourusername/ACLGuard.git
   cd ACLGuard
   ```

2. **Build the project**:
   ```bash
   make clean && make
   ```

3. **Verify the build**:
   ```bash
   ./aclguard --help
   ```

## ⚙️ Configuration

### Step 1: Create Configuration File

Create a configuration file (e.g., `config_ad.env`):

```bash
# ACLGuard AD Server Configuration
export ACLGUARD_LDAP_URI="ldap://192.168.1.100:389"
export ACLGUARD_BIND_DN="Administrator@yourdomain.local"
export ACLGUARD_BIND_PW="Youryour_password_here"
export ACLGUARD_BASE_DN="dc=yourdomain,dc=local"
```

### Step 2: Test Connection

```bash
# Load configuration and test
source config_ad.env
./aclguard
```

## 🚀 First Run

### Basic Usage
```bash
# Simple scan
source config_ad.env && ./aclguard
```

### Export Results
```bash
# Export to CSV
./aclguard --export-csv results.csv

# Export to JSON
./aclguard --export-json results.json

# Export both formats
./aclguard --export-csv --export-json
```

## 📊 Understanding the Output

### User Information
- **Username**: sAMAccountName from AD
- **Common Name**: Display name
- **Email**: Email address (if available)
- **Groups**: Group memberships

### Permission Analysis
- **Admin**: Domain/Enterprise admin privileges
- **ResetPass**: Password reset capabilities
- **ModifyACL**: ACL modification rights
- **Delegate**: Authentication delegation
- **ServiceAcct**: Service account privileges
- **ReadSecrets**: Read sensitive attributes
- **WriteSecrets**: Write sensitive attributes

### Risk Scoring
- **🔴 CRITICAL (80-100)**: Multiple high-risk permissions
- **🟠 HIGH (60-79)**: Significant administrative privileges
- **🟡 MEDIUM (40-59)**: Moderate risk permissions
- **🔵 LOW (20-39)**: Limited privileged access
- **🟢 MINIMAL (0-19)**: Standard user permissions

## 🔧 Troubleshooting

### Common Issues

#### Build Errors
```bash
# Missing libraries
sudo apt install libldap2-dev libjson-c-dev

# Permission issues
chmod +x aclguard
```

#### Connection Errors
```bash
# Test network connectivity
ping your-ad-server

# Test LDAP port
telnet your-ad-server 389

# Verify credentials
ldapsearch -x -H ldap://your-ad-server:389 -D "Administrator@domain.local" -w "password" -b "dc=domain,dc=local" -s base "(objectClass=*)" dn
```

#### Permission Errors
- Ensure the bind user has read access to the directory
- Check that the base DN is correct
- Verify group memberships are accessible

## 📚 Next Steps

1. **Read the Architecture Guide**: Understand how ACLGuard works
2. **Explore ACL Concepts**: Learn about Active Directory permissions
3. **Set up Test Environment**: Create a lab for safe testing
4. **Customize Analysis**: Modify permission detection rules

## 🆘 Getting Help

- **Documentation**: Check other wiki pages
- **GitHub Issues**: Report bugs or ask questions
- **Community**: Join cybersecurity forums for discussions

---

**Ready to dive deeper?** Check out the [Architecture Overview]( ARCHITECTURE.md) to understand how ACLGuard works under the hood!
