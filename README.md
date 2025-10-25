# khwiTBRes - TokenBroker Hunter

```
  _    _             _ _________________          
 | |  | |           (_)_   _| ___ \ ___ \         
 | | _| |____      ___  | | | |_/ / |_/ /___  ___ 
 | |/ / '_ \ \ /\ / / | | | | ___ \    // _ \/ __|
 |   <| | | \ V  V /| | | | | |_/ / |\ \  __/\__ \
 |_|\_\_| |_|\_/\_/ |_| \_/ \____/\_| \_\___||___/
                                                                                                 
    Windows TokenBroker Cache Decryptor
    Office Master AppID Token Extractor
```

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Platform](https://img.shields.io/badge/Platform-Windows-blue.svg)](https://www.microsoft.com/windows)
[![PowerShell](https://img.shields.io/badge/PowerShell-5.1+-blue.svg)](https://github.com/PowerShell/PowerShell)

> **⚠️ LEGAL DISCLAIMER**: This tool is designed for authorized security testing and red team operations only. Use of this tool for attacking targets without prior mutual consent is illegal. The author is not responsible for any misuse or damage caused by this tool.

## 📋 Overview

**khwiTBRes** is a specialized Windows security research tool that decrypts and analyzes cached tokens from the Windows TokenBroker (`%LOCALAPPDATA%\Microsoft\TokenBroker\Cache`). It focuses on identifying and extracting **Office Master AppID tokens** (`d3590ed6-52b3-4102-aeff-aad2292ab01c`) commonly used by Microsoft Office applications.

This project was inspired by the excellent research of [**@_xpn_**](https://twitter.com/_xpn_) (WBAM/TBRES) on Windows token manipulation and DPAPI decryption techniques.

### 🎯 Key Features

- ✅ **DPAPI Decryption**: Automatically decrypts TBRES cache files using Windows Data Protection API
- ✅ **Office Master Detection**: Identifies tokens with Office Master AppID (`d3590ed6-52b*-4102-aeff-aad2292ab01c`)
- ✅ **Scope Extraction**: Parses and displays token scopes (Mail, Files, Calendar, Contacts, etc.)
- ✅ **Audience Detection**: Identifies Microsoft Graph and Outlook/Exchange tokens
- ✅ **Token Expiration**: Converts Windows timestamps to readable dates
- ✅ **PSRemoting Compatible**: ASCII banners work over PowerShell remoting sessions
- ✅ **Detailed Permissions**: Shows the first 5 most important scopes from wamcompat_scopes

### 🔍 Use Cases

- Red Team operations requiring Office/M365 token extraction
- Post-exploitation token harvesting on compromised Windows endpoints
- Security research on Windows authentication mechanisms
- Authorized penetration testing of Azure AD/M365 environments

---

## 🛠️ Components

### **khwiTBRes.exe** - TBRES Decryptor
C# executable that decrypts TokenBroker cache files and extracts token information.

### **BuildAndRun-khwiTBRes.ps1** - Build & Execution Script
PowerShell script that compiles the C# source and runs the decryptor automatically.

---

## 📦 Requirements

- **Operating System**: Windows 10/11 or Windows Server 2016+
- **PowerShell**: Version 5.1 or higher
- **.NET Framework**: 4.x (pre-installed on modern Windows)
- **C# Compiler**: `csc.exe` (included with .NET Framework)
- **Permissions**: Must run as the target user (not Administrator, due to DPAPI user-scope)

---

## 🚀 Quick Start

### Step 1: Decrypt and Extract Tokens

```powershell
# Compile and run the decryptor
.\BuildAndRun-khwiTBRes.ps1
```

**Output Example:**
```
###############################################
###   *** OFFICE MASTER TOKEN FOUND! ***   ###
###############################################
[*] TBRES Decrypted: 3952ad7220dd62e8cae4a98ac61eb6bb26f99e29.tbres.decrypted
    -> client_id: d3590ed6-52b3-4102-aeff-aad2292ab01c
    -> scope: https://outlook.office365.com//.default offline_access openid profile
    -> audience: https://outlook.office365.com [Outlook/Exchange]
    -> detailed_scopes: 52 permissions found
       - https://outlook.office365.com//Mail.ReadWrite
       - https://outlook.office365.com//Mail.Send
       - https://outlook.office365.com//Files.ReadWrite.All
       - https://outlook.office365.com//Calendar.ReadWrite
       - https://outlook.office365.com//Contacts.ReadWrite
    -> expires: 2025-10-26 14:38:29
###############################################

[*] === SUMMARY ===
[*] Total files: 22
[*] Successfully decrypted: 22
[*] Errors: 0
###############################################
### OFFICE MASTER TOKENS FOUND: 11
###############################################
```

### Step 2: Analyze Decrypted Tokens

Decrypted tokens are saved as `.decrypted` files in the current directory. You can:
- Use them for token replay attacks
- Extract JWT claims for analysis
- Validate token permissions and expiration

---

## 📖 Detailed Usage

### Build Options

```powershell
# Build and run automatically (default)
.\BuildAndRun-khwiTBRes.ps1

# Build only (don't execute)
.\BuildAndRun-khwiTBRes.ps1 -BuildOnly

# Show help
.\BuildAndRun-khwiTBRes.ps1 -Help
```

### Manual Execution

```powershell
# After building, run manually
.\khwiTBRes.exe

# Decrypted files are in current directory
Get-ChildItem *.decrypted
```

### Using Over PSRemoting

```powershell
# Works perfectly over PowerShell remoting!
Enter-PSSession -ComputerName TARGET-PC
cd C:\Path\To\Tool
.\BuildAndRun-khwiTBRes.ps1
```

ASCII banners (`###`) are visible even without color support.

---

## 🔬 Technical Details

### How It Works

1. **Token Cache Location**: `%LOCALAPPDATA%\Microsoft\TokenBroker\Cache\*.tbres`
2. **File Reading**: TBRES files are stored in Unicode (UTF-16LE) format
3. **JSON Extraction**: Extracts `ResponseBytes.Value` (base64-encoded encrypted blob)
4. **DPAPI Decryption**: Uses `ProtectedData.Unprotect()` with CurrentUser scope
5. **Token Parsing**: Extracts key fields:
   - `client_id` from JSON metadata
   - `scope` from JSON metadata
   - `wamcompat_scopes` for detailed permissions
   - `TokenExpiresOn` (Windows FileTime format)
   - `audience` derived from scope URLs

### Office Master AppID Variants

The tool detects both known variants:
- `d3590ed6-52b1-4102-aeff-aad2292ab01c` (older)
- `d3590ed6-52b3-4102-aeff-aad2292ab01c` (current)

### Supported Token Types

- **Outlook/Exchange**: `https://outlook.office365.com`
- **Microsoft Graph**: `https://graph.microsoft.com` or GUID `00000003-0000-0000-c000-000000000000`
- **OneDrive/SharePoint**: URLs in scope field
- **Office Applications**: Word, Excel, PowerPoint integrations

---

## 🛡️ OPSEC Considerations

### ✅ Safe for Red Team Operations
- No suspicious API calls or hooks
- Standard Windows DPAPI usage
- Native .NET Framework compilation
- Minimal footprint (single executable)

### ⚠️ Important Notes
- Must run as the **logged-in user** (DPAPI is user-scoped)
- Tokens expire - check the `expires` field
- Some EDR/AV may flag DPAPI usage on sensitive files

---

## 📁 Repository Structure

```
khwiTBRes/
├── BuildAndRun-khwiTBRes.ps1    # Main build & execution script
├── README.md                              # This file
├── LICENSE                                # MIT License
└── .gitignore                             # Git ignore rules
```
  
---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## ⚖️ Legal & Ethical Use

This tool is provided for **educational and authorized security testing purposes only**.

### ✅ Authorized Use
- Penetration testing with proper authorization
- Red team exercises with signed Rules of Engagement
- Security research in controlled lab environments
- Corporate security assessments with management approval

### ❌ Prohibited Use
- Unauthorized access to systems or data
- Theft of credentials or tokens
- Violation of computer fraud laws (CFAA, GDPR, etc.)
- Any illegal activity

**By using this tool, you agree to use it responsibly and ethically. The author assumes no liability for misuse.**

---

## 🐛 Known Issues

- DPAPI decryption requires running as the **original user** (not admin)
- Some tokens may have unusual formats that don't parse correctly
- Very large TBRES files (>1MB) may parse slowly

---

## 🤝 Contributing

Contributions are welcome! Please:
1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Open a Pull Request

---

## 📧 Contact

- **Author**: R3alM0m1X82
- **GitHub**: [https://github.com/R3alM0m1X82](https://github.com/R3alM0m1X82)
- **Project**: [https://github.com/R3alM0m1X82/khwiTBRes](https://github.com/R3alM0m1X82/khwiTBRes)

---

**⭐ If you find this tool useful, please consider starring the repository!**
