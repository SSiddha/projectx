# ProjectX
Project X is a Bash automation script designed to perform intelligent enumeration and recon on a target system after an Nmap scan. It identifies common services based on open ports and launches specialized recon modules for each one, including bruteforce checks, default credential tests, enumeration scripts, and basic vulnerability scans.

🔍 Features
Port-aware scanning logic
Automatically detects open ports from Nmap output
Handles:

SSH (22) → Algorithm enum + Hydra bruteforce
Telnet (23) → Hydra bruteforce
HTTP/HTTPS (80/443) → Gobuster scan + filters
MySQL (3306) → Service detection, default creds, SQLi test
FTP (21) → Anonymous login check
SMTP (25) → VRFY enum + open relay test
SMB/RPC (139/445/135) → Enumeration + MS17-010 vuln check

Output organized in a dedicated logs/ directory
Interactive prompts for potentially noisy actions (e.g., bruteforce)
Ctrl+X is used as the interrupt key to avoid accidental exits

📁 Folder Structure
project-x/
├── script.sh                 # Main automation script
├── scan_results.txt         # Nmap output file (required input)
├── filters/
│   ├── filter_gobuster.sh   # Custom Gobuster output filter (optional)
│   └── filter_hydra.sh      # Custom Hydra output filter (optional)
└── logs/                    # Output directory for all scans

🚀 Usage
Ensure prerequisites are installed:
sudo apt install nmap hydra gobuster sqlmap rpcbind enum4linux

Run an Nmap scan manually:
nmap -sV -p- -oN scan_results.txt <TARGET_IP>

Run the script:
script.sh
When prompted during SSH/Telnet/MySQL enumeration, enter Y to run bruteforce or SQLi checks, or N to skip.

🧪 Supported Port Modules
Port	Service	Module Description
21	FTP	Anonymous login check
22	SSH	Algo enum + bruteforce (Hydra)
23	Telnet	Brute-force attack (Hydra)
25	SMTP	VRFY enum + Open relay test
80/443	HTTP/HTTPS	Gobuster + extension scan
135	RPC	rpcinfo + known vuln checks
139/445	SMB	Share enum + MS17-010 check + enum4linux
3306	MySQL	Version enum + default creds + optional SQLi

🧰 Custom Filters (Optional)
filters/filter_gobuster.sh
Parses Gobuster output and shows meaningful paths.

filters/filter_hydra.sh
Filters out successful bruteforce attempts from Hydra logs.

You can write your own filters to enhance readability and detect custom patterns.

🛑 Notes
This script uses Ctrl+X as the interrupt key (stty intr ^X) to avoid accidental Ctrl+C interrupts.
Brute-force modules (Hydra) and SQLMap scans are optional and interactive.

Default usernames are pulled from:
/usr/share/wordlists/metasploit/unix_users.txt
/usr/share/wordlists/seclists/Usernames/top-usernames-shortlist.txt

✅ Sample Workflow
nmap -sV -oN scan_results.txt 192.168.1.100
bash script.sh
# Choose 'Y' to run brute-force for SSH or Telnet when prompted
# Provide SQLi URL if MySQL is open and you wish to test SQLMap

📝 TODO (Future Enhancements)
Add DNS enumeration using Wfuzz
Parse results into JSON or HTML
Multithread certain recon tasks
Integrate ffuf for additional directory fuzzing

🧠 Inspiration
This tool is designed to streamline common post-scan recon tasks often performed manually during CTFs, internal assessments, or pentests. It provides both automation and control over noisy or intrusive tasks.

⚠️ Legal Notice
This tool is intended only for use in ethical hacking, penetration testing, or educational environments where you have explicit permission. Unauthorized use against systems you do not own or operate is illegal.

