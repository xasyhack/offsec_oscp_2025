## 📑 Table of Contents

- [Resources](#resources)
- [Kali setup](#kali-setup)
- [PWK-200 syallabus](#pwk-200-syallabus)
- [Usage](#usage)

## 📚 Resources
- [OffSec student portal](https://help.offsec.com/hc/en-us/articles/9550819362964-Connectivity-Guide) 
- [OffSec Discord](https://discord.gg/offsec)
- PWK Labs
 - Credentials (🔒 username:Eric.Wallows, password:EricLikesRunning800)

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

## PWK-200 syallabus
1. Password attacks
2. Windows privilege escalation
3. Common web application attacks
4. Information gathering
5. Vulnerability scanning
6. Windows privilege escalation
7. Introduction to web applcation attacks
8. SQL injection attacks
9. Client-site attacks
10. Antivirus evasion
11. Fixing exploits
12. Locating public exploits
13. Linux privilege escalation
14. Port redirection and SSH tunneling
15. Tunneling through deep packet inspectation
16. The metassploit framework
17. Active directory introduction and enumeration
18. Attacking active drectiory authentication
19. Lateral movement in active directory
20. Assembling the pieces

