# DAY 1

## Maybe SOC-mas music, he thought, doesn't come from a store?
> - Learn how to investigate malicious link files.
> - Learn about OPSEC and OPSEC mistakes.
> - Understand how to track and attribute digital identities in cyber investigations.

> [!NOTE]  
> Operational Security (OPSEC) is a set of principals and tactics used to attempt to protect the security of an operator or operation.
> An example of this may be using code names instead of your real names, or using a proxy to conceal your IP address.

---

## Table of Contents

1. [Introduction](#introduction)
2. [Room Information](#room-information)
3. [Reconnaissance](#reconnaissance)
4. [Enumeration](#enumeration)
5. [Exploitation](#exploitation)
6. [Post-Exploitation](#post-exploitation)
7. [Flags](#flags)
8. [Conclusion](#conclusion)

---

## Introduction

Provide a brief introduction to the room:
- **Difficulty**: Easy / Medium / Hard
- **Focus Area**: Web, Networking, Forensics, etc.
- **Objective**: Describe what users will achieve by completing this room.

---

## Room Information

| Key Info            | Details                       |
|---------------------|-------------------------------|
| **IP Address**      | `10.10.XXX.XXX`              |
| **Creator**         | Author Name                  |
| **Category**        | e.g., CTF, Red Team, etc.    |
| **Tools Required**  | List tools (e.g., nmap, Burp) |
| **Skills Practiced**| List skills (e.g., pivoting, enumeration) |

---

## Reconnaissance

### Step 1: Ping the Target
```bash
ping 10.10.XXX.XXX
```
- Confirm the target is reachable.

### Step 2: Nmap Scan
Run a basic Nmap scan to identify open ports and services:
```bash
nmap -sC -sV -oN nmap/initial_scan.txt 10.10.XXX.XXX
```
- **Open Ports**:
  - Port 22: SSH
  - Port 80: HTTP
  - ...

### Step 3: Gather Service Information
- Identify versions and potential vulnerabilities for detected services.

---

## Enumeration

### Web Enumeration
1. Access the web server:
   ```
   http://10.10.XXX.XXX
   ```
2. Run Gobuster or Dirbuster:
   ```bash
gobuster dir -u http://10.10.XXX.XXX -w /path/to/wordlist.txt -t 50
   ```
3. Identify interesting directories and files:
   - `/admin`
   - `/uploads`

### Other Enumeration Steps
- Check SMB shares, FTP, etc., if applicable.

---

## Exploitation

### Vulnerability Identified
Describe the vulnerability identified and how it can be exploited:
- Example: SQL Injection on login page

### Exploit Steps
Provide step-by-step instructions to exploit the vulnerability:
```bash
sqlmap -u "http://10.10.XXX.XXX/login" --data="username=admin&password=admin"
```

### Gaining a Foothold
Explain how to establish an initial foothold, e.g., reverse shell, web shell.

---

## Post-Exploitation

### Privilege Escalation
Describe methods to escalate privileges:
- Check for SUID binaries:
  ```bash
  find / -perm -4000 2>/dev/null
  ```
- Exploit vulnerable software or misconfigurations.

### Persistence (Optional)
Discuss how to maintain access.

---

## Flags

### User Flag
- **Location**: `/home/user/user.txt`
- **Command**:
  ```bash
  cat /home/user/user.txt
  ```
- **Flag**: `THM{example_user_flag}`

### Root Flag
- **Location**: `/root/root.txt`
- **Command**:
  ```bash
  cat /root/root.txt
  ```
- **Flag**: `THM{example_root_flag}`

---

## Conclusion

Summarize the room walkthrough:
- Lessons learned.
- Tools used.
- Skills practiced.

---

## Disclaimer
> This walkthrough is intended for educational purposes only. Ensure you follow ethical hacking guidelines and only test systems you have permission to access.

---

## References
- [Tool Documentation](https://tool-docs-link)
- [Exploitation Resources](https://exploit-db.com)

