# A Basic Intrusion Detection System Using Raw Sockets

This repo contains files that detect 4 types of network intrusions (ICMP Flooding, Port Syn Scan, Shellshock Exploit, XSS Attack).
I used Kali Linux for this project.

## How to use:
1. Download the 3 files in the repo.
2. Compile capture_analysis.c with: gcc capture_analysis.c -o executable
3. Turn run.sh into an executable using this command: chmod +x run.sh
4. capture_analysis.c requires sudo privileges to run. Since the python file is running it, we don't want it to prompt us to enter the password in the terminal.
   Run this command in the terminal: sudo visudo
   This opens the sudoers file. Type this at the end of the file: username ALL=(ALL) NOPASSWD: /absolute/path/to/executable
5. Run the shell file: ./run.sh
   This opens the gui file, where you can run the detection script.
6. To simulate the above mentioned attacks, you can run these commands from a different attacker system, that either runs Kali Linux or MacOS.
   1. icmp-flooding: ping -s 8000 <victim-IP>
   2. stealthy port syn-scan: sudo nmap -sS -p 1-1000 <victim-IP>
   3. shellshock exploit:
	    on victim (in a separate terminal tab): python3 -m http.server 8080
      on attacker: curl -H "User-Agent: () { :;}; echo; echo; /bin/bash -c 'ping -c 1 127.0.0.1'" http://<victim-IP>:8080/
   4. XSS attack:
	    on victim (in a separate terminal tab): python3 -m http.server 8080
      on attacker: curl "http://<victim-IP>:8080/?q=<script>alert(1)</script>"
