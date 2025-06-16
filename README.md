## 📑 Table of Contents

- [Resources](#resources)
- [Kali setup](#kali-setup)
- [Penetration testing stages](#penetration-testing-stages)
- [Penetration testing report](#penetration-testing-report)
- [PWK-200 syallabus](#pwk-200-syallabus)
- [PWK-200 labs](#pwk-200-labs)  
  - [Information gathering](#information-gathering)

## 📚 Resources
- [OffSec student portal](https://help.offsec.com/hc/en-us/articles/9550819362964-Connectivity-Guide) 
- [OffSec Discord](https://discord.gg/offsec)
  - OffSec portal > Explorer > Discord > link OffSec account to discord
- [OffSec Study Plan and Exam FAQ](https://help.offsec.com/hc/en-us/sections/6970444968596-Penetration-Testing-with-Kali-Linux-PEN-200)
- PWK Labs  
  - Credentials (🔒 username:Eric.Wallows, password:EricLikesRunning800)
  - Flag format: `OS{68c1a60008e872f3b525407de04e48a3}`

## 🛠️ Kali setup
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

## PWK-200 syallabus
1. Password attacks
2. Windows privilege escalation
3. Common web application attacks
4. Information gathering
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

   - dd
6. Vulnerability scanning
7. Windows privilege escalation
8. Introduction to web applcation attacks
9. SQL injection attacks
10. Client-site attacks
11. Antivirus evasion
12. Fixing exploits
13. Locating public exploits
14. Linux privilege escalation
15. Port redirection and SSH tunneling
16. Tunneling through deep packet inspectation
17. The metassploit framework
18. Active directory introduction and enumeration
19. Attacking active drectiory authentication
20. Lateral movement in active directory
21. Assembling the pieces

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



