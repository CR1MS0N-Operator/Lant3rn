# ACL Concepts Explained

This guide explains the Active Directory Access Control List (ACL) concepts that ACLGuard analyzes, helping you understand the security implications of different permissions.

## 🔐 What are ACLs?

Access Control Lists (ACLs) in Active Directory define who can access what resources and what actions they can perform. Think of them as security rules that control:

- **Who** can access a resource (users, groups, computers)
- **What** they can do with it (read, write, delete, etc.)
- **Where** these permissions apply (specific objects, containers, or the entire domain)

## 🏗️ AD Permission Structure

### Security Principals
- **Users**: Individual accounts (e.g., john.doe)
- **Groups**: Collections of users (e.g., Domain Admins)
- **Computers**: Machine accounts (e.g., SERVER01$)
- **Service Accounts**: Accounts used by applications

### Permission Types
- **Standard Permissions**: Basic operations (read, write, delete)
- **Extended Permissions**: Advanced operations (reset password, modify ACLs)
- **Special Permissions**: Granular control over specific attributes

## 🎯 High-Risk Permissions Analyzed by ACLGuard

### 1. Admin Privileges

**What it means:**
- Full administrative access to the domain or forest
- Can create, modify, or delete any object
- Bypasses most security restrictions

**Common Groups:**
- `Domain Admins`: Full domain control
- `Enterprise Admins`: Full forest control
- `Schema Admins`: Can modify the AD schema
- `Group Policy Creator Owners`: Can create/modify GPOs

**Security Risk:**
- **🔴 CRITICAL**: Complete system compromise possible
- **Attack Vector**: Privilege escalation, lateral movement
- **Real-world Impact**: Okta breach, SolarWinds attack

### 2. Password Reset Permissions

**What it means:**
- Can reset passwords for other users
- Often includes unlocking locked accounts
- May include password policy modifications

**Common Groups:**
- `Account Operators`: Can manage user accounts
- `Help Desk`: Password reset for end users
- `Password Admins`: Dedicated password management

**Security Risk:**
- **🟠 HIGH**: Account takeover possible
- **Attack Vector**: Social engineering, insider threats
- **Real-world Impact**: Common in ransomware attacks

### 3. ACL Modification (WriteDACL)

**What it means:**
- Can modify access control lists
- Can grant permissions to other users
- Can change object ownership

**Common Groups:**
- `Backup Operators`: Can modify ACLs during backup operations
- `Server Operators`: Server management permissions
- `Print Operators`: Print server management

**Security Risk:**
- **🟡 MEDIUM-HIGH**: Permission escalation possible
- **Attack Vector**: ACL backdoors, privilege escalation
- **Real-world Impact**: Common persistence mechanism

### 4. Authentication Delegation

**What it means:**
- Can delegate authentication to other services
- Can impersonate users on behalf of services
- Can configure service principal names (SPNs)

**Common Groups:**
- `Delegation Admins`: Manage delegation settings
- `Trust Admins`: Manage domain trusts
- `Service Accounts`: Often have delegation rights

**Security Risk:**
- **🟠 HIGH**: Kerberos delegation attacks
- **Attack Vector**: Constrained/unconstrained delegation abuse
- **Real-world Impact**: Common in advanced persistent threats

### 5. Service Account Privileges

**What it means:**
- Accounts used by applications and services
- Often have elevated permissions
- May have "Password Never Expires" set

**Common Examples:**
- `SQL Service`: Database service accounts
- `IIS Service`: Web server accounts
- `Exchange Service`: Email server accounts

**Security Risk:**
- **🟡 MEDIUM**: Service account compromise
- **Attack Vector**: Service account abuse, privilege escalation
- **Real-world Impact**: Common in supply chain attacks

### 6. Secret Access Permissions

**What it means:**
- Can read sensitive attributes (passwords, certificates)
- Can write sensitive configuration data
- Access to encrypted data

**Common Scenarios:**
- `Read Secrets`: Can view password hashes
- `Write Secrets`: Can modify sensitive data
- `Certificate Access`: Can manage certificates

**Security Risk:**
- **🟠 HIGH**: Data exfiltration possible
- **Attack Vector**: Credential theft, data breach
- **Real-world Impact**: Common in data breaches

## 🎯 Risk Scoring Methodology

### Risk Calculation
ACLGuard uses a weighted scoring system:

```c
// Base risk scores
Admin Privileges:        +40 points
Authentication Delegation: +30 points
Write Secrets:           +35 points
Password Reset:          +25 points
Read Secrets:            +20 points
ACL Modification:        +20 points
Service Account:         +15 points

// Risk levels
0-19:   🟢 MINIMAL
20-39:  🔵 LOW
40-59:  🟡 MEDIUM
60-79:  🟠 HIGH
80-100: 🔴 CRITICAL
```

### Why These Scores?

**Admin Privileges (40 points):**
- Complete system control
- Can bypass all security measures
- Primary target for attackers

**Authentication Delegation (30 points):**
- Enables sophisticated attacks
- Difficult to detect
- Common in advanced threats

**Write Secrets (35 points):**
- Can modify critical data
- Enables persistence
- High impact on security

## 🚨 Real-World Attack Scenarios

### Scenario 1: Okta-Style Breach
1. **Initial Access**: Compromise service account
2. **Privilege Escalation**: Use service account to reset admin passwords
3. **Lateral Movement**: Use admin privileges to access other systems
4. **Data Exfiltration**: Access sensitive data with elevated permissions

### Scenario 2: SolarWinds-Style Attack
1. **Supply Chain**: Compromise software update mechanism
2. **Service Account Abuse**: Use service account with high privileges
3. **ACL Modification**: Create backdoors in access control lists
4. **Persistence**: Maintain access through modified permissions

### Scenario 3: Ransomware Attack
1. **Phishing**: Compromise user account
2. **Password Reset Abuse**: Use help desk privileges to reset admin passwords
3. **Domain Admin Access**: Gain full domain control
4. **Encryption**: Encrypt all accessible systems

## 🛡️ Mitigation Strategies

### For Admin Privileges
- **Principle of Least Privilege**: Only grant admin rights when necessary
- **Just-in-Time Access**: Temporary admin privileges
- **Multi-Factor Authentication**: Require MFA for admin accounts
- **Regular Auditing**: Monitor admin account usage

### For Password Reset Permissions
- **Approval Workflows**: Require approval for password resets
- **Audit Logging**: Log all password reset activities
- **Time Restrictions**: Limit password reset hours
- **Notification Systems**: Alert users of password resets

### For ACL Modification
- **Change Management**: Require approval for ACL changes
- **Baseline Monitoring**: Detect unexpected ACL modifications
- **Regular Reviews**: Periodic ACL audits
- **Automated Alerts**: Notify on suspicious changes

## 📊 Best Practices

### Regular Monitoring
- **Daily**: Check for new high-risk permissions
- **Weekly**: Review permission changes
- **Monthly**: Comprehensive permission audit
- **Quarterly**: Risk assessment review

### Documentation
- **Permission Justification**: Document why permissions are needed
- **Business Owner**: Identify who requested permissions
- **Review Date**: Set expiration dates for permissions
- **Risk Assessment**: Document security implications

### Automation
- **Automated Scanning**: Regular ACLGuard runs
- **SIEM Integration**: Feed results into security monitoring
- **Alert Systems**: Notify on high-risk changes
- **Reporting**: Generate management reports

## 🔍 Advanced Concepts

### Inheritance
- Permissions can be inherited from parent containers
- Understanding inheritance is crucial for effective analysis
- Blocking inheritance can create security gaps

### Delegation
- Granular permission delegation
- Can be more secure than group membership
- Requires careful management

### Trust Relationships
- Cross-domain permission implications
- Forest trust security considerations
- External trust risks

---

Understanding these ACL concepts is essential for effective Active Directory security. ACLGuard helps identify these risks, but proper security requires ongoing monitoring, regular audits, and a comprehensive security strategy.
