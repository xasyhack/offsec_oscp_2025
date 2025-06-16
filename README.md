## 📑 Table of Contents

- [Resources](#resources)
- [Kali setup](#kali-setup)
- [Penetration testing report](#penetration-testing-report)
- [PWK-200 syallabus](#pwk-200-syallabus)
- [Penetration testing stages](#penetration-testing-stages)
- [Usage](#usage)

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
   - `sudo updatedb` (run on first time only)
   - `locate universal.ovpn`
   - `cd /home/kali/Downloads`
   - `mkdir /home/kali/offsec`
   - `mv universal.ovpn /home/kali/offsec/universal.ovpn`
   - `cd ../offsec`
   - `sudo openvpn universal.ovpn`
   - output reads "Initialization Sequence Completed"
   - disconnect VPN by pressing Ctrl+C
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
 - [Sublime-syntax highlight]()
 - [CherryTree Kali]
 - [Obsidian-markdown editor]()
- taking screenshots

## Penetration testing stages
- scope: IP range, hosts, applications
- info gathering (passive or active): org infra, assets, personnel
- vulnerability detection
- initial foothold
- privilege escalation
- lateral movement
- report
- remediation

## PWK-200 syallabus
1. Password attacks
2. Windows privilege escalation
3. Common web application attacks
4. Information gathering
   - **OSINT**: public available info of a target
   - **Whois**: domain name info
     `whois megacorpone.com -h 192.168.50.251`: lookup personnel, name server
     `whois 38.100.193.70 -h 192.168.50.251`: reverse lookup
   - **google hacking**: uncover critical information, vulnerabilities, and misconfigured websites
     `site:mega.com filetype:txt`
     `site:mega.com -filetype:html` : exclude html page  
     `intitle: "index of" "parent directory"`: directory listing
   - [Google hacking database](https://www.exploit-db.com/google-hacking-database)
   - [faster google dorking](https://dorksearch.com/)
   - [Netcraft](https://searchdns.netcraft.com/): discover site tech, subdomains
   - [wappalzer](https://www.wappalyzer.com/websites/<domain>/)
   - **open-source code** search (small repo:GitHub, GitHub Gist, GitLab, SourceForge. larger repos: Gitrob, Gitleaks)
     `gitleaks detect --source https://github.com/username/repo.git`: scans for API keys, private keys, credentials
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

