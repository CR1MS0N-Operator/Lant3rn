# ACLGuard Architecture (Legacy — C v1.0/v2.0)

> **Status: legacy documentation.** This page describes the original C implementation. The current architecture, including the Lantern Go rewrite target, graph model, and integration contracts, lives in the [root ARCHITECTURE.md](../ARCHITECTURE.md). This page is preserved for historical reference.

This document provides a comprehensive overview of ACLGuard's system architecture, design decisions, and technical implementation.

## 🏗️ System Overview

ACLGuard follows a modular, layered architecture designed for maintainability and extensibility:

```
┌─────────────────────────────────────────────────────────────┐
│                    ACLGuard v1.0                           │
├─────────────────────────────────────────────────────────────┤
│  Main Application Layer (main.c)                           │
├─────────────────────────────────────────────────────────────┤
│  Business Logic Layer                                      │
│  ├── LDAP Interface (ldap.c)                              │
│  ├── Permission Analysis (ldap.c)                         │
│  ├── Risk Assessment (ldap.c)                             │
│  └── Export Engine (export.c)                             │
├─────────────────────────────────────────────────────────────┤
│  Configuration Layer (config.c)                            │
├─────────────────────────────────────────────────────────────┤
│  Error Handling Layer (error_handler.c)                    │
├─────────────────────────────────────────────────────────────┤
│  Data Structures (types.h)                                 │
├─────────────────────────────────────────────────────────────┤
│  External Libraries                                        │
│  ├── OpenLDAP (libldap, liblber)                          │
│  └── JSON-C (libjson-c)                                   │
└─────────────────────────────────────────────────────────────┘
```

## 📁 Project Structure

### Source Code Organization

```
src/
├── main.c              # Application entry point and CLI
├── ldap.c              # LDAP operations and permission analysis
├── config.c            # Configuration management
├── export.c            # CSV/JSON export functionality
├── error_handler.c     # Centralized error handling
└── risk_engine.c       # Risk assessment engine (placeholder)

include/
├── types.h             # Core data structures
├── config.h            # Configuration definitions
├── aclguard_ldap.h     # LDAP function declarations
├── export.h            # Export function declarations
└── error_handler.h     # Error handling declarations
```

## 🔧 Core Components

### 1. Main Application (main.c)

**Responsibilities:**
- Command-line argument parsing
- Application flow control
- User interface and output formatting
- Integration of all components

**Key Functions:**
- `main()`: Application entry point
- `print_banner()`: ASCII art and branding
- `get_risk_level()`: Risk level formatting
- `display_user_permissions()`: Permission visualization

### 2. LDAP Interface (ldap.c)

**Responsibilities:**
- Active Directory connection management
- User enumeration and attribute retrieval
- Permission analysis based on group memberships
- Risk score calculation

**Key Functions:**
- `fetch_real_users()`: Main LDAP query function
- `analyze_user_permissions()`: Permission analysis engine
- LDAP connection lifecycle management

**LDAP Operations:**
```c
// Connection flow
ldap_initialize() → ldap_sasl_bind_s() → ldap_search_ext_s() → ldap_unbind_ext_s()
```

### 3. Permission Analysis Engine

**Analysis Categories:**
1. **Admin Privileges**: Domain Admins, Enterprise Admins, Schema Admins
2. **Password Reset**: Account Operators, Help Desk groups
3. **ACL Modification**: Backup Operators, Server Operators
4. **Authentication Delegation**: Delegation and Trust groups
5. **Service Accounts**: SQL, IIS, Exchange service accounts
6. **Secret Access**: Read/Write access to sensitive attributes

**Risk Scoring Algorithm:**
```c
// Risk calculation
if (isAdmin) risk += 40;
if (canResetPasswords) risk += 25;
if (canModifyACLs) risk += 20;
if (canDelegateAuth) risk += 30;
if (hasServiceAcct) risk += 15;
if (canReadSecrets) risk += 20;
if (canWriteSecrets) risk += 35;

// Cap at 100
if (risk > 100) risk = 100;
```

### 4. Export Engine (export.c)

**Supported Formats:**
- **CSV**: Comma-separated values for spreadsheet analysis
- **JSON**: Structured data for programmatic processing

**Export Schema:**
```json
{
  "username": "string",
  "cn": "string", 
  "email": "string",
  "groups": "string",
  "isAdmin": "boolean",
  "canResetPasswords": "boolean",
  "canModifyACLs": "boolean",
  "canDelegateAuth": "boolean",
  "hasServiceAcct": "boolean",
  "canReadSecrets": "boolean",
  "canWriteSecrets": "boolean",
  "risk": "integer"
}
```

## 🗃️ Data Structures

### ADUser Structure

```c
typedef struct {
    char *username;   // sAMAccountName or uid
    char *cn;         // Common Name
    char *dn;         // Distinguished Name
    char *mail;       // Email address
    char *memberOf;   // Group memberships (comma-separated)
    
    struct {
        int isAdmin;           // Domain Admin privileges
        int canResetPasswords; // Password reset permission
        int canModifyACLs;     // WriteDACL permission
        int canDelegateAuth;   // Authentication delegation
        int hasServiceAcct;    // Service account privileges
        int isPrivileged;      // Any privileged group membership
        int canReadSecrets;    // Read sensitive attributes
        int canWriteSecrets;   // Write sensitive attributes
    } perms;
    
    int risk;         // Risk score (0-100)
} ADUser;
```

### Configuration Structure

```c
typedef struct {
    char *ldap_uri;  // LDAP server URI
    char *bind_dn;   // Bind DN for authentication
    char *bind_pw;   // Bind password
    char *base_dn;   // Base DN for searches
} Config;
```

## 🔄 Application Flow

### 1. Initialization Phase
```
main() → load_env_config() → print_banner()
```

### 2. Data Collection Phase
```
fetch_real_users() → ldap_initialize() → ldap_sasl_bind_s() → ldap_search_ext_s()
```

### 3. Analysis Phase
```
analyze_user_permissions() → risk calculation → permission mapping
```

### 4. Output Phase
```
display_user_permissions() → export_to_csv() → export_to_json()
```

### 5. Cleanup Phase
```
ldap_unbind_ext_s() → free() → exit()
```

## 🔒 Security Considerations

### Design Principles
- **Minimal Privilege**: Only requests necessary LDAP attributes
- **Safe Defaults**: Conservative permission analysis
- **Error Handling**: Graceful failure without information leakage
- **Memory Management**: Proper cleanup of allocated resources

### LDAP Security
- **Authentication**: Uses SASL simple bind
- **Connection**: Unencrypted LDAP (not LDAPS)
- **Query Scope**: Limited to user objects and group memberships
- **Error Handling**: Generic error messages to prevent information disclosure

## 🚀 Performance Characteristics

### Time Complexity
- **LDAP Query**: O(n) where n = number of users
- **Permission Analysis**: O(m) where m = number of group memberships per user
- **Overall**: O(n × m) for complete analysis

### Space Complexity
- **User Storage**: O(n) for user data
- **Group Analysis**: O(m) for group membership strings
- **Overall**: O(n × m) for complete dataset

### Optimization Opportunities
- **Parallel Processing**: Multi-threaded LDAP queries
- **Caching**: Group membership caching
- **Streaming**: Large dataset processing
- **Indexing**: Optimized LDAP queries

## 🔧 Extensibility Points

### Adding New Permission Types
1. Extend `ADUser.perms` structure
2. Update `analyze_user_permissions()` function
3. Modify export functions
4. Update documentation

### Adding New Export Formats
1. Create new export function in `export.c`
2. Add command-line argument parsing
3. Update help documentation
4. Add format-specific error handling

### Adding New LDAP Sources
1. Extend configuration structure
2. Modify LDAP query logic
3. Update permission analysis rules
4. Test with different directory schemas

## 🧪 Testing Strategy

### Unit Testing
- Individual function testing
- Mock LDAP responses
- Edge case validation

### Integration Testing
- End-to-end workflow testing
- Real AD server testing
- Export format validation

### Performance Testing
- Large dataset processing
- Memory usage profiling
- Connection timeout handling

## 📈 Future Architecture Considerations

### v1.1 Enhancements
- **Multi-threading**: Parallel user processing
- **Configuration Files**: INI/JSON configuration support
- **Plugin System**: Extensible permission analyzers
- **Web Interface**: REST API and web dashboard

### Scalability Improvements
- **Distributed Processing**: Multiple AD server support
- **Database Backend**: Persistent storage for large environments
- **Real-time Monitoring**: Continuous permission monitoring
- **Alerting System**: Risk threshold notifications

---

This architecture provides a solid foundation for ACLGuard's current functionality while maintaining flexibility for future enhancements and extensions.
