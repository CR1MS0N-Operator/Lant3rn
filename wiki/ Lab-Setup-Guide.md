# Lab Setup Guide

This guide will help you set up a safe testing environment for ACLGuard, including Active Directory and OpenLDAP servers for learning and development.

## 🎯 Lab Objectives

- **Safe Testing**: Test ACLGuard without affecting production systems
- **Learning Environment**: Understand AD permissions and security concepts
- **Development**: Test new features and modifications
- **Demonstration**: Show ACLGuard capabilities to others

## 🏗️ Lab Architecture Options

### Option 1: Virtual Machines (Recommended)
```
┌─────────────────────────────────────────────────────────────┐
│                    Host Machine                            │
├─────────────────────────────────────────────────────────────┤
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────┐ │
│  │   Arch Linux    │  │  Windows AD     │  │  Ubuntu     │ │
│  │   (ACLGuard)    │  │  (192.168.56.10)│  │  OpenLDAP   │ │
│  │                 │  │                 │  │(192.168.56.20)│ │
│  └─────────────────┘  └─────────────────┘  └─────────────┘ │
└─────────────────────────────────────────────────────────────┘
```

### Option 2: Cloud Environment
- **AWS**: EC2 instances with VPC networking
- **Azure**: Virtual machines with virtual networks
- **Google Cloud**: Compute Engine with VPC

### Option 3: Containerized Environment
- **Docker**: Containerized LDAP servers
- **Kubernetes**: Orchestrated lab environment

## 🖥️ Virtual Machine Setup

### Prerequisites
- **Virtualization Software**: VirtualBox, VMware, or Hyper-V
- **RAM**: Minimum 8GB (16GB recommended)
- **Storage**: 100GB free space
- **Network**: Host-only or NAT networking

### Step 1: Windows Active Directory Server

#### System Requirements
- **OS**: Windows Server 2019/2022 or Windows 10/11 Pro
- **RAM**: 4GB minimum
- **Storage**: 50GB
- **Network**: Static IP (e.g., 192.168.56.10)

#### Installation Steps
1. **Install Windows Server**
   ```powershell
   # Set static IP
   New-NetIPAddress -IPAddress 192.168.56.10 -PrefixLength 24 -InterfaceAlias "Ethernet"
   Set-DnsClientServerAddress -InterfaceAlias "Ethernet" -ServerAddresses 192.168.56.10
   ```

2. **Promote to Domain Controller**
   ```powershell
   # Install AD DS role
   Install-WindowsFeature -Name AD-Domain-Services -IncludeManagementTools
   
   # Create new forest
   Install-ADDSForest -DomainName "example.local" -SafeModeAdministratorPassword (ConvertTo-SecureString "your_password_here" -AsPlainText -Force)
   ```

3. **Create Test Users**
   ```powershell
   # Create organizational units
   New-ADOrganizationalUnit -Name "TestUsers" -Path "DC=example,DC=local"
   New-ADOrganizationalUnit -Name "ServiceAccounts" -Path "DC=example,DC=local"
   
   # Create test users
   New-ADUser -Name "John Doe" -SamAccountName "john.doe" -UserPrincipalName "john.doe@example.local" -Path "OU=TestUsers,DC=example,DC=local" -AccountPassword (ConvertTo-SecureString "your_password_here" -AsPlainText -Force) -Enabled $true
   New-ADUser -Name "Jane Smith" -SamAccountName "jane.smith" -UserPrincipalName "jane.smith@example.local" -Path "OU=TestUsers,DC=example,DC=local" -AccountPassword (ConvertTo-SecureString "your_password_here" -AsPlainText -Force) -Enabled $true
   
   # Create service account
   New-ADUser -Name "SQL Service" -SamAccountName "sqlservice" -UserPrincipalName "sqlservice@example.local" -Path "OU=ServiceAccounts,DC=example,DC=local" -AccountPassword (ConvertTo-SecureString "your_password_here" -AsPlainText -Force) -Enabled $true -PasswordNeverExpires $true
   ```

4. **Create Test Groups**
   ```powershell
   # Create high-risk groups
   New-ADGroup -Name "Help Desk" -GroupScope Global -Path "OU=TestUsers,DC=example,DC=local"
   New-ADGroup -Name "Backup Operators" -GroupScope Global -Path "OU=TestUsers,DC=example,DC=local"
   New-ADGroup -Name "Service Admins" -GroupScope Global -Path "OU=ServiceAccounts,DC=example,DC=local"
   
   # Add users to groups
   Add-ADGroupMember -Identity "Help Desk" -Members "john.doe"
   Add-ADGroupMember -Identity "Backup Operators" -Members "jane.smith"
   Add-ADGroupMember -Identity "Service Admins" -Members "sqlservice"
   ```

### Step 2: Ubuntu OpenLDAP Server

#### System Requirements
- **OS**: Ubuntu Server 20.04/22.04
- **RAM**: 2GB minimum
- **Storage**: 20GB
- **Network**: Static IP (e.g., 192.168.56.20)

#### Installation Steps
1. **Install Ubuntu Server**
   ```bash
   # Set static IP
   sudo nano /etc/netplan/01-netcfg.yaml
   # Add:
   # network:
   #   version: 2
   #   ethernets:
   #     eth0:
   #       addresses: [192.168.56.20/24]
   #       gateway4: 192.168.56.1
   #       nameservers:
   #         addresses: [192.168.56.10, 8.8.8.8]
   
   sudo netplan apply
   ```

2. **Install OpenLDAP**
   ```bash
   sudo apt update
   sudo apt install slapd ldap-utils
   ```

3. **Configure OpenLDAP**
   ```bash
   # Reconfigure slapd
   sudo dpkg-reconfigure slapd
   
   # Use these settings:
   # Omit OpenLDAP server configuration: No
   # DNS domain name: example.com
   # Organization name: Example Organization
   # Admin password: your_password_here
   # Database backend: MDB
   # Remove database when slapd is purged: No
   # Move old database: Yes
   ```

4. **Create Test Data**
   ```bash
   # Create base.ldif
   cat > base.ldif << EOF
   dn: dc=example,dc=com
   objectClass: top
   objectClass: dcObject
   objectClass: organization
   o: Example Organization
   dc: example
   
   dn: cn=admin,dc=example,dc=com
   objectClass: simpleSecurityObject
   objectClass: organizationalRole
   cn: admin
   description: LDAP administrator
   userPassword: your_password_here
   
   dn: ou=users,dc=example,dc=com
   objectClass: organizationalUnit
   ou: users
   EOF
   
   # Add base structure
   ldapadd -x -D "cn=admin,dc=example,dc=com" -w "your_password_here" -f base.ldif
   
   # Create users.ldif
   cat > users.ldif << EOF
   dn: uid=john.doe,ou=users,dc=example,dc=com
   objectClass: inetOrgPerson
   objectClass: posixAccount
   objectClass: shadowAccount
   cn: John Doe
   sn: Doe
   uid: john.doe
   uidNumber: 1000
   gidNumber: 1000
   homeDirectory: /home/john.doe
   mail: john.doe@example.com
   userPassword: password123
   
   dn: uid=jane.smith,ou=users,dc=example,dc=com
   objectClass: inetOrgPerson
   objectClass: posixAccount
   objectClass: shadowAccount
   cn: Jane Smith
   sn: Smith
   uid: jane.smith
   uidNumber: 1001
   gidNumber: 1001
   homeDirectory: /home/jane.smith
   mail: jane.smith@example.com
   userPassword: password456
   EOF
   
   # Add users
   ldapadd -x -D "cn=admin,dc=example,dc=com" -w "your_password_here" -f users.ldif
   ```

### Step 3: ACLGuard Development Machine

#### System Requirements
- **OS**: Arch Linux (or your preferred Linux distribution)
- **RAM**: 2GB minimum
- **Storage**: 20GB
- **Network**: Same subnet as lab servers

#### Installation Steps
1. **Install Development Tools**
   ```bash
   # Arch Linux
   sudo pacman -S base-devel openldap openldap-devel gcc make json-c git
   
   # Ubuntu/Debian
   sudo apt install build-essential libldap2-dev libldap-2.4-2 liblber-dev libjson-c-dev git
   ```

2. **Clone ACLGuard**
   ```bash
   git clone https://github.com/yourusername/ACLGuard.git
   cd ACLGuard
   ```

3. **Build ACLGuard**
   ```bash
   make clean && make
   ```

## 🔧 Configuration Files

### AD Server Configuration
Create `config_ad.env`:
```bash
export ACLGUARD_LDAP_URI="ldap://192.168.56.10:389"
export ACLGUARD_BIND_DN="Administrator@example.local"
export ACLGUARD_BIND_PW="your_password_here"
export ACLGUARD_BASE_DN="dc=example,dc=local"
```

### OpenLDAP Configuration
Create `config_ldap.env`:
```bash
export ACLGUARD_LDAP_URI="ldap://192.168.56.20:389"
export ACLGUARD_BIND_DN="cn=admin,dc=example,dc=com"
export ACLGUARD_BIND_PW="your_password_here"
export ACLGUARD_BASE_DN="dc=example,dc=com"
```

## 🧪 Testing Your Lab

### Test AD Connection
```bash
# Test network connectivity
ping 192.168.56.10

# Test LDAP connection
ldapsearch -x -H ldap://192.168.56.10:389 -D "Administrator@example.local" -w "your_password_here" -b "dc=example,dc=local" -s base "(objectClass=*)" dn

# Test ACLGuard
source config_ad.env && ./aclguard
```

### Test OpenLDAP Connection
```bash
# Test network connectivity
ping 192.168.56.20

# Test LDAP connection
ldapsearch -x -H ldap://192.168.56.20:389 -D "cn=admin,dc=example,dc=com" -w "your_password_here" -b "dc=example,dc=com" -s base "(objectClass=*)" dn

# Test ACLGuard
source config_ldap.env && ./aclguard
```

## 🔒 Security Considerations

### Lab Isolation
- **Host-only Network**: Isolate lab from production networks
- **Firewall Rules**: Block unnecessary ports
- **VPN Access**: Secure remote access if needed
- **Regular Snapshots**: Backup lab state before testing

### Credential Management
- **Weak Passwords**: Use simple passwords for lab (not production)
- **Documentation**: Keep track of all credentials
- **Rotation**: Change passwords periodically
- **Access Control**: Limit who can access lab systems

### Data Protection
- **No Production Data**: Never use real production data
- **Synthetic Data**: Use generated test data only
- **Cleanup**: Regularly clean up test data
- **Monitoring**: Monitor lab for unexpected activity

## 🚀 Advanced Lab Scenarios

### Multi-Domain Environment
- **Parent-Child Domains**: Test cross-domain permissions
- **Forest Trusts**: Test trust relationship security
- **External Trusts**: Test external domain access

### Complex Permission Scenarios
- **Delegation**: Test permission delegation
- **Inheritance**: Test permission inheritance
- **Special Permissions**: Test granular permissions
- **Service Accounts**: Test service account security

### Attack Simulation
- **Privilege Escalation**: Test escalation paths
- **Lateral Movement**: Test movement between systems
- **Persistence**: Test backdoor creation
- **Data Exfiltration**: Test data access scenarios

## 📊 Lab Monitoring

### Logging
- **AD Event Logs**: Monitor domain controller logs
- **LDAP Logs**: Monitor OpenLDAP access logs
- **ACLGuard Logs**: Monitor tool execution logs
- **Network Logs**: Monitor network traffic

### Alerting
- **Permission Changes**: Alert on unexpected changes
- **Failed Logins**: Monitor authentication failures
- **High-Risk Activity**: Alert on suspicious behavior
- **System Health**: Monitor system performance

## 🧹 Lab Maintenance

### Regular Tasks
- **Weekly**: Update system patches
- **Monthly**: Review and clean test data
- **Quarterly**: Refresh lab environment
- **Annually**: Review lab architecture

### Backup Strategy
- **VM Snapshots**: Regular VM snapshots
- **Configuration Backup**: Backup configuration files
- **Data Export**: Export test data for reuse
- **Documentation**: Keep lab documentation updated

---

This lab setup provides a safe, controlled environment for learning, testing, and developing with ACLGuard. Remember to always follow security best practices and never use production data in your lab environment.
