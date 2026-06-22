# Beginners Guide to ACLGuard

Welcome to ACLGuard! This guide is designed for newcomers to cybersecurity, Active Directory, and C programming who want to understand and use ACLGuard effectively.

## 🎯 What You'll Learn

By the end of this guide, you'll understand:
- What ACLGuard does and why it's important
- Basic Active Directory concepts
- How to build and run ACLGuard
- How to interpret the results
- Basic cybersecurity concepts

## 🔍 What is ACLGuard?

ACLGuard is a cybersecurity tool that helps identify security risks in Active Directory environments. Think of it as a "security scanner" that looks at user permissions and tells you which ones might be dangerous.

### Why is this important?
- **Security**: Helps prevent cyber attacks
- **Compliance**: Meets security audit requirements
- **Learning**: Teaches you about AD security
- **Career**: Demonstrates cybersecurity skills

## 🏗️ Understanding Active Directory

### What is Active Directory?
Active Directory (AD) is Microsoft's directory service that manages:
- **Users**: People who log into computers
- **Groups**: Collections of users with similar permissions
- **Computers**: Machines on the network
- **Permissions**: What each user/group can do

### Key Concepts

#### Users
- **Regular Users**: Normal employees (e.g., john.doe)
- **Administrators**: People with special privileges
- **Service Accounts**: Accounts used by software

#### Groups
- **Domain Users**: All regular users
- **Domain Admins**: People who can control everything
- **Help Desk**: People who can reset passwords

#### Permissions
- **Read**: Can look at information
- **Write**: Can change information
- **Delete**: Can remove information
- **Admin**: Can do anything

## 🚀 Getting Started

### Step 1: Install Prerequisites

#### On Windows (with WSL or Git Bash)
```bash
# Install WSL Ubuntu first, then:
sudo apt update
sudo apt install build-essential libldap2-dev libjson-c-dev
```

#### On Linux (Ubuntu/Debian)
```bash
sudo apt update
sudo apt install build-essential libldap2-dev libldap-2.4-2 liblber-dev libjson-c-dev
```

#### On Arch Linux
```bash
sudo pacman -S base-devel openldap openldap-devel gcc make json-c
```

### Step 2: Build ACLGuard
```bash
# Download the code
git clone https://github.com/yourusername/ACLGuard.git
cd ACLGuard

# Build the program
make clean && make
```

### Step 3: Test the Build
```bash
# Check if it works
./aclguard --help
```

You should see:
```
Usage: ./aclguard [options]
Options:
  --export-csv [filename]    Export results to CSV file
  --export-json [filename]   Export results to JSON file
  --help, -h                 Show this help message
```

## 🔧 Configuration

### Understanding Configuration
ACLGuard needs to know how to connect to your Active Directory server. This information goes in a configuration file.

### Create a Configuration File
Create a file called `config.env`:
```bash
# ACLGuard Configuration
export ACLGUARD_LDAP_URI="ldap://your-server:389"
export ACLGUARD_BIND_DN="your-username@yourdomain.local"
export ACLGUARD_BIND_PW="your-password"
export ACLGUARD_BASE_DN="dc=yourdomain,dc=local"
```

### Configuration Explained
- **LDAP_URI**: Where your AD server is located
- **BIND_DN**: Your username for connecting
- **BIND_PW**: Your password
- **BASE_DN**: Where to start looking for users

## 🏃‍♂️ Running ACLGuard

### Basic Run
```bash
# Load configuration and run
source config.env
./aclguard
```

### Export Results
```bash
# Save results to files
./aclguard --export-csv results.csv --export-json results.json
```

## 📊 Understanding the Output

### User Information
```
👤 User: john.doe (John Doe)
📧 Email: john.doe@company.com
👥 Groups: CN=Domain Users,CN=Users,DC=company,DC=local
    Permissions: None
⚠️  Risk Score: 0/100 🟢 MINIMAL
```

**What this means:**
- **User**: The username and display name
- **Email**: The person's email address
- **Groups**: What groups the user belongs to
- **Permissions**: What special permissions they have
- **Risk Score**: How dangerous their permissions are

### Risk Levels Explained

#### 🟢 MINIMAL (0-19 points)
- **What it means**: Normal user with basic permissions
- **Risk**: Very low
- **Example**: Regular employee who can only access their own files

#### 🔵 LOW (20-39 points)
- **What it means**: Some special permissions
- **Risk**: Low
- **Example**: User who can access shared folders

#### 🟡 MEDIUM (40-59 points)
- **What it means**: Significant permissions
- **Risk**: Medium
- **Example**: Help desk person who can reset passwords

#### 🟠 HIGH (60-79 points)
- **What it means**: Dangerous permissions
- **Risk**: High
- **Example**: Backup administrator who can modify security settings

#### 🔴 CRITICAL (80-100 points)
- **What it means**: Very dangerous permissions
- **Risk**: Critical
- **Example**: Domain administrator who can control everything

### Permission Types

#### Admin
- **What it means**: Can control the entire system
- **Why it's dangerous**: Can create new users, change passwords, access everything
- **Real-world impact**: If compromised, attacker controls everything

#### ResetPass
- **What it means**: Can reset other people's passwords
- **Why it's dangerous**: Can log in as anyone
- **Real-world impact**: Can impersonate any user

#### ModifyACL
- **What it means**: Can change who has access to what
- **Why it's dangerous**: Can give themselves more permissions
- **Real-world impact**: Can escalate their own privileges

## 🛡️ Security Concepts

### Why Permissions Matter
Think of permissions like keys to different rooms in a building:
- **Regular users**: Have keys to their own office
- **Help desk**: Have keys to reset other people's locks
- **Administrators**: Have master keys to everything

### Common Attack Scenarios

#### Scenario 1: Password Reset Abuse
1. **Attacker**: Compromises help desk account
2. **Action**: Resets admin password
3. **Result**: Gains full system control

#### Scenario 2: Permission Escalation
1. **Attacker**: Compromises user with ACL modification rights
2. **Action**: Gives themselves admin permissions
3. **Result**: Gains full system control

#### Scenario 3: Service Account Abuse
1. **Attacker**: Compromises service account
2. **Action**: Uses service account privileges
3. **Result**: Accesses sensitive systems

## 📈 Interpreting Results

### What to Look For

#### High-Risk Users
- Users with admin permissions
- Users who can reset passwords
- Users with service account privileges

#### Unusual Patterns
- Regular users with admin permissions
- Too many people with password reset rights
- Service accounts with excessive permissions

#### Risk Trends
- How many high-risk users exist
- Whether risk is concentrated or spread out
- If permissions match job roles

### Action Items

#### Immediate Actions
- **Review admin users**: Make sure they need admin access
- **Check password reset rights**: Limit to necessary personnel
- **Audit service accounts**: Ensure they have minimal permissions

#### Long-term Actions
- **Regular monitoring**: Run ACLGuard regularly
- **Permission reviews**: Periodically review user permissions
- **Training**: Educate users about security

## 🔧 Troubleshooting

### Common Problems

#### "Can't connect to server"
- **Check network**: Make sure you can reach the server
- **Check credentials**: Verify username and password
- **Check server**: Make sure AD server is running

#### "No users found"
- **Check base DN**: Make sure it's correct
- **Check permissions**: Make sure your account can read users
- **Check server**: Make sure AD server has users

#### "Build failed"
- **Check libraries**: Make sure all required libraries are installed
- **Check compiler**: Make sure GCC is installed
- **Check permissions**: Make sure you can write to the directory

### Getting Help
- **Read documentation**: Check other wiki pages
- **Check logs**: Look for error messages
- **Ask questions**: Use GitHub issues or forums

## 📚 Next Steps

### Learning Path
1. **Master basics**: Understand AD concepts
2. **Practice**: Use ACLGuard regularly
3. **Explore**: Try different configurations
4. **Learn more**: Study cybersecurity concepts

### Advanced Topics
- **LDAP programming**: Learn to write LDAP code
- **Security analysis**: Understand attack vectors
- **Tool development**: Create your own security tools
- **Career development**: Use skills in job applications

### Resources
- **Microsoft AD documentation**: Learn about Active Directory
- **Cybersecurity courses**: Take online courses
- **Practice labs**: Set up test environments
- **Community**: Join cybersecurity forums

## 🎯 Key Takeaways

1. **ACLGuard helps identify security risks** in Active Directory
2. **Permissions determine what users can do** and how dangerous they are
3. **Risk scores help prioritize** which issues to fix first
4. **Regular monitoring** is essential for security
5. **Understanding permissions** is crucial for cybersecurity

---

**Congratulations!** You now have a solid foundation for using ACLGuard. Remember, cybersecurity is a journey, not a destination. Keep learning, practicing, and exploring!

**Ready for more?** Check out the [Architecture Guide]( ARCHITECTURE.md) to understand how ACLGuard works under the hood!
