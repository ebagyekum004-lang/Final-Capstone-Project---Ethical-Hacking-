# Final-Capstone-Project---Ethical-Hacking-


# Final Capstone Project Report

**Ethical Hacking & Penetration Testing Assessment**

---

## Executive Summary

This report documents a controlled penetration testing engagement conducted against a simulated enterprise environment to identify, exploit, and assess common security vulnerabilities. The objective was to evaluate system resilience against real-world attack techniques and provide actionable remediation recommendations. The assessment covered web applications, web server configurations, SMB file-sharing services, and network traffic analysis. Multiple vulnerabilities were successfully identified and exploited, demonstrating risks related to improper input validation, insecure service configuration, weak access controls, and unencrypted data transmission.

---

## Scope Definition

### In Scope

* Web application hosted on **10.5.5.12**
* SMB servers within the **10.5.5.0/24** network
* Network traffic captured in **SA.pcap**
* Authorized use of exploitation and enumeration tools
* Credential testing and file access within the lab environment

### Out of Scope

* Denial-of-Service (DoS) attacks
* Privilege escalation beyond defined challenge objectives
* Attacks against systems outside the provided IP ranges
* Persistent malware deployment or system modification
* Any testing on production or unauthorized systems

---

## Penetration Testing Methodology

The assessment followed a structured penetration testing lifecycle aligned with industry standards such as **PTES** and **NIST SP 800-115**:

1. Planning and Authorization
2. Reconnaissance and Enumeration
3. Vulnerability Identification
4. Exploitation
5. Post-Exploitation Analysis
6. Remediation and Risk Evaluation

---

## Reconnaissance & Enumeration

Initial reconnaissance involved identifying active hosts, services, and exposed resources. Tools such as **Nmap**, **Nikto**, **Enum4Linux**, **SMB client utilities**, and **Wireshark** were used to enumerate open ports, running services, directory structures, SMB shares, and unencrypted network traffic. This phase revealed misconfigured services, accessible directories, and insecure communication channels.

---

## Key Activities Performed

* Exploited **SQL injection** vulnerabilities to extract database credentials and gain unauthorized system access
* Identified **web server misconfigurations** allowing directory listing and unauthorized file discovery
* Enumerated and accessed **unsecured SMB shares** without valid authentication
* Analyzed **PCAP traffic** to recover sensitive information transmitted in clear text
* Retrieved challenge flags by chaining reconnaissance findings with exploitation techniques
* Assessed security posture and documented weaknesses with supporting evidence

---

## Outcomes and Findings

The engagement successfully demonstrated how common security weaknesses can be exploited to compromise confidentiality and access sensitive data. Key outcomes included:

* Successful credential extraction via SQL injection
* Discovery of sensitive configuration files through directory indexing
* Unauthorized access to SMB shares and file upload capability
* Exposure of usernames, passwords, and files through unencrypted traffic analysis

Each vulnerability highlighted potential real-world risks such as data breaches, lateral movement, and credential compromise.

---

## Testing Environment

All testing was conducted in a **controlled laboratory environment** provided as part of the Ethical Hacking Capstone Project. No production systems were targeted, and all activities complied with ethical hacking principles and authorization guidelines.

---

## Conclusion

This penetration testing assessment demonstrates practical, hands-on experience with real-world attack vectors and defensive considerations. The project reflects a strong understanding of attacker methodologies while maintaining a focus on risk mitigation and security improvement. The techniques and remediation strategies applied align with modern enterprise security expectations and industry best practices.

---

## Recommended Next Steps

* Implement secure coding practices and parameterized queries
* Harden web server configurations and disable directory listing
* Enforce strong authentication and restrict SMB access
* Encrypt data in transit using TLS, VPNs, or IPsec
* Conduct regular security assessments and monitoring

---

**End of Report**



___


## Challenge 1: SQL Injection

This repository documents the successful identification and exploitation of a **SQL Injection vulnerability** within an authorized lab environment as part of the **Cisco Networking Academy Ethical Hacking Final Capstone Project**.

The objective of this challenge was to enumerate user account information from a vulnerable web application, recover and crack Bob Smith’s account credentials, and use those credentials to access a protected system and retrieve the Challenge 1 code.

All actions were conducted **strictly within scope**, under an approved **Pentesting Agreement**, and for **educational purposes only**.

---

## Objectives

The objectives of this challenge were to:

* Identify and exploit a SQL Injection vulnerability
* Enumerate database information and user credentials
* Crack a recovered password hash
* Use valid credentials to access a remote system
* Locate and retrieve the Challenge 1 code
* Propose effective SQL Injection remediation techniques

---

## Lab Environment

* **Attacker Machine:** Kali Linux
* **Vulnerable Web Application:** DVWA
* **DVWA Server IP:** 10.5.5.12
* **Target System IP:** 192.168.0.10
* **Database Type:** MySQL
* **Attack Type:** SQL Injection (Union-based)

---

## Tools Used

* Web Browser
* DVWA (Damn Vulnerable Web Application)
* SQL Injection payloads (manual input)
* Password hash cracking tool
* SSH
* Nmap

---

## Methodology & Results

### Step 1: Initial Setup and DVWA Configuration

The DVWA web application was accessed via a browser at:

```
http://10.5.5.12
```

The application was accessed using the default credentials:

* **Username:** admin
* **Password:** password

**Screenshot Placeholder:**

```markdown
![DVWA Login Page](images/dvwa_login.png)
```

After logging in, the DVWA security level was configured to **Low**:

* Navigate to **DVWA Security**
* Select **Low**
* Click **Submit**

At this security level, input sanitization is disabled, making the application vulnerable to SQL Injection.

**Screenshot Placeholder:**

```markdown
![DVWA Security Level Low](images/dvwa_security_low.png)
```

---

### Step 2: SQL Injection and Database Enumeration

The **SQL Injection** module was selected from the DVWA menu. The application presented a vulnerable input field labeled **User ID**.

**Screenshot Placeholder:**

```markdown
![SQL Injection Input Form](images/sql_injection_form.png)
```

Initial testing confirmed the presence of a SQL Injection vulnerability when crafted input altered application behavior.

**Screenshot Placeholders:**

```markdown
![SQLi Vulnerability Confirmation](images/sqli_test.png)
```

---

### Database Identification

The database name was successfully identified using a UNION-based SQL Injection technique.

**Screenshot Placeholder:**

```markdown
![Database Name Enumeration](images/database_name.png)
```

---

### Table and Column Enumeration

The database schema was enumerated to identify tables containing authentication data. The `users` table was identified as containing usernames and password hashes.

Column enumeration revealed fields related to usernames and passwords.

**Screenshot Placeholders:**

```markdown
![Table Enumeration](images/table_enum.png)
![Column Enumeration](images/column_enum.png)
```

---

### Credential Extraction

Usernames and password hashes were successfully retrieved from the `users` table, including **Bob Smith’s account**.

**Screenshot Placeholder:**

```markdown
![Credential Dump](images/credential_dump.png)
```

---

### Step 3: Password Hash Cracking

Bob Smith’s password hash was extracted and cracked using a password-cracking tool.

**Result:**
Bob Smith’s plaintext password was successfully recovered.

**Screenshot Placeholders:**

```markdown
![Password Hash](images/password_hash.png)
![Password Cracked](images/password_cracked.png)
```

---

### Step 4: Accessing the Target System

Using the recovered credentials, an SSH connection was established to the target system:

```
ssh smithy@192.168.0.10
```

A port scan confirmed that SSH was available on the target system.

**Screenshot Placeholders:**

```markdown
![Nmap Scan](images/nmap_ssh.png)
![SSH Login](images/ssh_login.png)
```

---

### Step 5: Locating the Challenge 1 Code

After logging in, directory contents were enumerated to locate the challenge file. The file containing the Challenge 1 code was identified and opened.

**Result:**
The file displayed the Challenge 1 flag/code.

**Screenshot Placeholder:**

```markdown
![Challenge File Contents](images/challenge_flag.png)
```

---

## Findings

* DVWA was vulnerable to SQL Injection at low security
* Improper input handling allowed full database enumeration
* User credentials were exposed and password hashes recovered
* Weak passwords enabled successful cracking
* Compromised credentials allowed unauthorized system access

---

## Remediation: Preventing SQL Injection Attacks

The following remediation techniques are recommended to prevent SQL Injection vulnerabilities:

1. **Prepared Statements (Parameterized Queries)**
2. **Principle of Least Privilege** for database accounts
3. **Strict Input Validation and Sanitization**
4. **Use of Stored Procedures**
5. **Secure Error Handling and Logging**

---

## Ethical Considerations

All activities were conducted:

* Within an **authorized Cisco NetAcad lab**
* Under a signed **Pentesting Agreement**
* For **educational and defensive purposes only**
* Without targeting real-world systems or users

Unauthorized SQL Injection attacks are illegal and unethical.

---

## Reflection

This challenge demonstrated how a single input validation flaw can lead to complete system compromise. The exercise reinforced the importance of secure coding practices and proactive vulnerability testing to protect applications from real-world attacks.

---


---

## Challenge 2: Web Server Vulnerabilities (Directory Listing)

This repository documents the identification and exploitation of **web server misconfigurations** that resulted in **directory listing vulnerabilities** on an HTTP server. The objective of this challenge was to perform reconnaissance, identify publicly accessible directories, and locate the **Challenge 2 flag file** stored within a vulnerable directory.

All activities were conducted **within an authorized lab environment** and in compliance with the **Cisco Networking Academy Ethical Hacking Pentesting Agreement**.

---

## Objectives

The objectives of this challenge were to:

* Identify web server misconfigurations
* Detect directory listing vulnerabilities
* Enumerate accessible directories using reconnaissance tools
* Locate sensitive files exposed through directory indexing
* Retrieve the Challenge 2 flag
* Propose remediation techniques for directory listing vulnerabilities

---

## Lab Environment

* **Attacker Machine:** Kali Linux
* **Target Server:** DVWA Web Server
* **Target IP Address:** 10.5.5.12
* **Protocol:** HTTP
* **Vulnerability Type:** Directory Listing / Web Server Misconfiguration

---

## Tools Used

* Web Browser
* Nikto (Web Server Scanner)
* Manual URL Manipulation

---

## Methodology & Results

### Step 1: Initial Setup and Application Configuration

The DVWA web application was accessed using a browser at:

```
http://10.5.5.12
```

The application was accessed using the default administrator credentials:

* **Username:** admin
* **Password:** password

**Screenshot Placeholder:**

```markdown
![DVWA Login](images/dvwa_login.png)
```

After authentication, the application security level was set to **Low** to simulate a vulnerable configuration.

* Navigate to **DVWA Security**
* Select **Low**
* Click **Submit**

**Screenshot Placeholder:**

```markdown
![DVWA Security Level Low](images/dvwa_security_low.png)
```

---

### Step 2: Web Server Reconnaissance

Reconnaissance was performed to identify misconfigurations and exposed directories on the web server using **Nikto**.

**Command:**

```bash
nikto -h 10.5.5.12
```

**Purpose:**
Detect web server vulnerabilities, including directory indexing and exposed paths.

**Result:**
Nikto identified two directories with directory listing enabled:

* `/config/`
* `/docs/`

**Screenshot Placeholder:**

```markdown
![Nikto Scan Results](images/nikto_scan.png)
```

---

### Step 3: Directory Enumeration via Browser

Manual URL manipulation was used to access the exposed directories through a web browser.

**Accessible Directories:**

```
http://10.5.5.12/config/
http://10.5.5.12/docs/
```

**Screenshot Placeholders:**

```markdown
![Config Directory Listing](images/config_directory.png)
![Docs Directory Listing](images/docs_directory.png)
```

The contents of each directory were reviewed to identify files related to the challenge.

---

### Step 4: Locating the Challenge 2 Flag File

During directory enumeration, the file **db_form.html** was identified as the file containing the Challenge 2 code.

* **File Name:** `db_form.html`
* **Directory:** `/config/`

The file was opened directly through the browser to view its contents.

**Screenshot Placeholder:**

```markdown
![Challenge 2 File](images/db_form_file.png)
```

**Result:**
The flag message contained in the file was successfully retrieved.

* **Challenge 2 Code:** `aWe-4975`

**Screenshot Placeholder:**

```markdown
![Challenge 2 Flag](images/challenge2_flag.png)
```

---

## Findings

* Directory indexing was enabled on the web server
* Sensitive directories were accessible without authentication
* File contents could be viewed through browser-based enumeration
* Misconfiguration exposed internal application files

---

## Remediation: Preventing Directory Listing Vulnerabilities

The following remediation techniques are recommended to prevent directory listing exploits:

### 1. Disable Directory Indexing

Explicitly disable directory listing in the web server configuration.

* **Apache:**
  Add `Options -Indexes` in the configuration file or `.htaccess`
* **IIS:**
  Disable directory browsing in IIS Manager or `web.config`

This ensures directories return an error instead of listing contents.

---

### 2. Use Default Index Files

Place a default index file (e.g., `index.html`, `index.php`) in all directories under the web root.

This prevents directory contents from being displayed when users access directory paths directly.

---

## Ethical Considerations

All actions in this challenge were conducted:

* Under an approved **Cisco NetAcad lab environment**
* Within the scope of a signed **Pentesting Agreement**
* For **educational and defensive purposes only**
* Without targeting real-world systems or users

Unauthorized exploitation of web server misconfigurations is illegal and unethical.

---

## Reflection

This challenge demonstrated how simple web server misconfigurations can expose sensitive files and application data. The exercise reinforced the importance of secure server configuration, routine vulnerability scanning, and proper access controls to prevent information disclosure.

---


---

## Challenge 3: Exploiting Open SMB Server Shares

This repository documents the discovery and exploitation of **unsecured SMB (Server Message Block) shared directories** within an internal network as part of the **Cisco Networking Academy Ethical Hacking Final Capstone Project**.

The objective of this challenge was to identify systems exposing SMB services, enumerate shared directories, determine which shares allow anonymous access, and locate the **Challenge 3 flag file**.

All activities were conducted **strictly within an authorized lab environment** and under the scope defined by the **Pentesting Agreement**.

---

## Objectives

The objectives of this challenge were to:

* Identify hosts running SMB services on the internal network
* Enumerate shared SMB directories
* Determine which shares allow anonymous or unauthenticated access
* Access exposed shares and retrieve the Challenge 3 file
* Propose remediation strategies to secure SMB services

---

## Lab Environment

* **Attacker Machine:** Kali Linux
* **Target Network:** 10.5.5.0/24
* **Target SMB Server:** 10.5.5.14
* **Protocol:** SMB (Ports 139, 445)

---

## Tools Used

* **Nmap:** Network discovery and SMB port scanning
* **Enum4Linux:** SMB share enumeration
* **SMBMap:** Anonymous access verification
* **SMBClient:** Manual interaction with SMB shares

---

## Methodology & Results

### Step 1: Scanning for SMB Services

A network scan was performed to identify hosts exposing SMB-related ports within the `10.5.5.0/24` network.

**Command:**

```bash
nmap -p139,445 10.5.5.0/24
```

**Purpose:**
Identify systems running SMB services by detecting open NetBIOS and Microsoft-DS ports.

**Result:**
The host `10.5.5.14` was identified with ports **139** and **445** open, indicating an active SMB server.

**Screenshot Placeholder:**

```markdown
![Nmap SMB Scan](images/nmap_smb_scan.png)
```

---

### Step 2: Enumerating SMB Shares

SMB share enumeration was performed against the identified host to list available shared directories.

**Command:**

```bash
enum4linux -S 10.5.5.14
```

**Purpose:**
Discover shared directories exposed by the SMB server.

**Result:**
Multiple SMB shares were identified on the target system.

**Screenshot Placeholder:**

```markdown
![Enum4Linux Share Enumeration](images/enum4linux_shares.png)
```

---

### Step 3: Identifying Anonymous Access

To determine which SMB shares were accessible without valid credentials, **SMBMap** was used.

**Command:**

```bash
smbmap -H 10.5.5.14
```

**Purpose:**
Identify shares that allow anonymous or guest access.

**Result:**
The following shares were listed on the SMB server:

* `homes`
* `workfiles`
* `print$`
* `IPC$`

Some of these shares were accessible without authentication, indicating a security misconfiguration.

**Screenshot Placeholder:**

```markdown
![SMBMap Anonymous Access](images/smbmap_access.png)
```

---

### Step 4: Accessing SMB Shares and Retrieving the Challenge File

An SMB client was used to access the exposed shares and navigate through the directory structure.

**Command:**

```bash
smbclient //10.5.5.14/workfiles
```

**Purpose:**
Access shared directories and locate the file containing the Challenge 3 code.

**Result:**
The challenge file was successfully located, downloaded, and opened locally.

**Screenshot Placeholders:**

```markdown
![SMBClient Access](images/smbclient_access.png)
![Challenge 3 File](images/challenge3_file.png)
```

---

## Findings

* SMB services were exposed on the internal network
* Multiple SMB shares were publicly discoverable
* Anonymous access was permitted on sensitive shares
* Exposed SMB shares allowed unauthorized file access

---

## Remediation: Securing SMB Services

The following remediation techniques are recommended to prevent unauthorized SMB access:

### 1. Network Segmentation and Firewall Rules

* Restrict SMB access to trusted IP addresses or VLANs
* Block SMB ports (139, 445) from untrusted networks
* Apply internal firewall rules to limit lateral movement

---

### 2. Disable Legacy SMB Versions and Enforce Strong Authentication

* Disable **SMBv1** to prevent legacy exploits
* Enforce modern authentication mechanisms (Kerberos / NTLMv2)
* Implement **Multi-Factor Authentication (MFA)** where possible

---

## Ethical Considerations

All actions in this challenge were conducted:

* Within an **authorized Cisco NetAcad lab environment**
* Under a signed **Pentesting Agreement**
* For **educational and defensive purposes only**
* Without targeting real-world systems or users

Unauthorized access to SMB shares is illegal and unethical.

---

## Reflection

This challenge demonstrated how improperly secured SMB shares can expose sensitive data and provide attackers with unauthorized access to internal resources. The exercise emphasized the importance of access control, network segmentation, and SMB hardening in enterprise environments.

---


---

## Challenge 4: Analyze a PCAP File to Discover Sensitive Information

This repository documents the analysis of a **packet capture (PCAP) file** to identify sensitive information transmitted over the network in **clear text**. The objective of this challenge was to analyze captured traffic, identify the target system and accessed resources, and retrieve the **Challenge 4 code** from an exposed file.

All activities were conducted **within an authorized lab environment** and in accordance with the **Cisco Networking Academy Ethical Hacking Pentesting Agreement**.

---

## Objectives

The objectives of this challenge were to:

* Analyze a PCAP file using Wireshark
* Identify the target IP address from captured traffic
* Extract URLs and file paths from network streams
* Locate and view the file containing the Challenge 4 code
* Understand the risks of transmitting data in clear text
* Propose remediation techniques to protect sensitive data

---

## Lab Environment

* **Attacker Machine:** Kali Linux
* **Analysis Tool:** Wireshark
* **PCAP File:** `SA.pcap`
* **Protocol(s) Observed:** HTTP / TCP
* **Vulnerability Type:** Clear-text data transmission

---

## Tools Used

* **Wireshark:** Packet capture analysis and TCP stream inspection
* **Web Browser:** Accessing discovered URLs

---

## Methodology & Results

### Step 1: PCAP File Analysis

The provided packet capture file (`SA.pcap`) was opened in **Wireshark** for analysis.

**Screenshot Placeholder:**

```markdown
![SA.pcap Opened in Wireshark](images/wireshark_open_pcap.png)
```

Captured packets were reviewed to identify communication between hosts, focusing on HTTP and TCP traffic.

---

### Step 2: Identifying Target IP Address and URLs

Packet inspection revealed the **IP address of the target system** and URLs accessed during the captured session.

Wireshark’s **Follow TCP Stream** feature was used to reconstruct application-layer conversations and reveal file paths and directory structures.

**Screenshot Placeholder:**

```markdown
![Follow TCP Stream](images/follow_tcp_stream.png)
```

---

### Step 3: Accessing Discovered Directories

The URLs identified in the TCP streams were accessed using a web browser to inspect the exposed directories on the target system.

**Screenshot Placeholders:**

```markdown
![Accessing Target Directory](images/browser_directory_access.png)
![Directory Contents](images/browser_directory_contents.png)
```

---

### Step 4: Locating the Challenge 4 File

Within the exposed directory, a file containing sensitive information was identified and opened.

**Observed File Contents:**

* Username
* Password
* Digital signatures

**Screenshot Placeholder:**

```markdown
![Challenge 4 File Contents](images/challenge4_file_contents.png)
```

---

### Step 5: Retrieving the Challenge 4 Code

The Challenge 4 flag was successfully identified from the file contents.

* **Challenge 4 Code:** `21z-1478K`

**Screenshot Placeholder:**

```markdown
![Challenge 4 Flag](images/challenge4_flag.png)
```

---

## Findings

* Sensitive data was transmitted in clear text
* Network traffic could be reconstructed using PCAP analysis
* File paths and credentials were exposed through HTTP traffic
* Lack of encryption enabled unauthorized data disclosure

---

## Remediation: Preventing Clear-Text Data Exposure

The following remediation techniques are recommended to prevent unauthorized viewing of sensitive data:

### 1. Encrypt Files Before Transmission

* Encrypt files using tools such as **PGP/GPG**, **AES**, or **BitLocker**
* Ensure only authorized recipients can decrypt the data
* Protects data even if network traffic is intercepted

---

### 2. Encrypt Network Traffic (IPsec / VPN)

* Implement **IPsec** to encrypt traffic between systems
* Use **VPN tunnels** to secure SMB and HTTP communications
* Prevents packet sniffing and traffic reconstruction

---

## Ethical Considerations

All actions in this challenge were conducted:

* Within an **authorized Cisco NetAcad lab**
* Under a signed **Pentesting Agreement**
* For **educational and defensive purposes only**
* Without targeting real-world users or networks

Unauthorized packet capture analysis is illegal and unethical.

---

## Reflection

This challenge demonstrated how unencrypted network traffic can expose sensitive information to attackers. The exercise reinforced the importance of encryption at both the file and network levels to protect confidentiality and prevent data leakage.

---

