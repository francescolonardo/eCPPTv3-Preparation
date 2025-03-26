# Network Security 

## Scanning

### Introduction - Study Guide

(06/30) This is a good reference to PPS (Ports Protocols and Services): https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml.
(23/30) When the server responds to a SYN packet with a SA (SYN-ACK) packet, it means that the destination port is open.
(28/30) Instead, when the server responds with a RA (RST-ACK) packet, it means that the destination port is closed.

### Wireshark Introduction - Video

Wireshark display filters:
`ip.addr==192.168.1.1`, `ip.src==192.168.1.1`, `ip.dst==192.168.1.1`.
`arp`, `http`, `icmp`, `http or dns`.
`ip.addr==192.168.1.1 and (http or dns)`, `http and ip.src!=192.168.1.1`.
`tcp.port==22`, `tcp.flags.syn==1`, `tcp.flags.syn==1 and ip.addr==192.168.1.0/24`.
`tcp contains "elsfoo"`.

In order to see the whole communication we can click on a packet and select "Follow TCP Stream".

### Hping Basics - Video

`hping3 -S --scan 80,443 192.168.1.2`, `hping3 -S --scan 500-550 192.168.1.2`, `hping3 -S --scan 80,443,500-550 192.168.1.2`, `hping3 -S --scan '80,443,500-550,!525' 192.168.1.2`: to scan with a SA (SYN-ACK) packet to specific ports.
`hping3 -S --scan all 192.168.1.2`, `hping3 -S --scan known 192.168.1.2`: to scan all ports or just the known ones.
`hping3 -2 192.168.1.2`: to scan UDP ports.

TCP Christmas scan (a TCP packet with FIN, URG, PSH setted): `hping -F -U -P --scan 1-100 192.168.1.2`, to avoid certain firewalls. Ports that respond with RA packets are probably closed, else if they don't provide a response they can be open or filtered.
TCP Null scan (a TCP packet without any flags specified): `hping3 --scan 1-100 192.168.1.2`, to check ports that don't reply with RA flags. Ports that are not responding can be open or filtered.

### Detect Live Hosts and Port - Study Guide

(04/85) Based upon the type of discovery, the level of noise can vary.
(06/85) Penetration testing takes time if you want to do it correctly.
(14/85) Nmap host discovery techniques:
```
-sL: List Scan - simply list targets to scan
-sn: Ping Scan - disable port scan
-Pn: Treat all hosts as online - skip host discovery
-PS/PA/PU/PY [portlist]: TCP SYN/ACK, UDP or SCTP discovery
-PE/PP/PM: ICMP echo, timestamp, netmask request discovery
-PO [protocol list]: IP Protocol Ping
-n/-R: Never do DNS resolution/Always resolve
--dns-servers <servl[,serv2],...>: Specify custom DNS servers
--system-dns: Use OS's DNS resolver
--traceroute: Trace hop path to each host
```
(15/85) Nmap scan techniques:
```
-sS/sT/sA/sW/sM: TCP SYN/Connect()/ACK/Window/Maimon scans
-sU: UDP Scan
-sN/SF/SX: TCP Null, FIN, and Xmas scans
--scanflags <flags>: Customize TCP scan flags
-sI <zombie host[:probeport]>: Idle scan
-sY/sZ: SCTP INIT/COOKIE-ECHO scan
-sO: IP protocol scan
-b <FTP relay host>: FTP bounce scan
```
(16/85) `-sS` TCP SYN scan (half-open scan): is one of the most accurate and is not as obtrusive as other types of scans.
(21/85) Nmap port specification:
```
-p <port ranges>: Only scan specified ports
	Ex: -p22; -p1-65535; -p U:53,111,137, T:21-25, 80, 139, 8080,s:9
--exclude-ports <port ranges>: Exclude the specified ports
-F: Fast mode - Scan fewer ports than the default scan
-r: Scan ports consecutively - don't randomize
--top-ports <number>: Scan <number> most common ports
--port-ratio <ratio>: Scan ports more common than <ratio>
```
(25/85) `-sT` TCP Connect scan: relies on the underlying OS to establish a (full, less efficient) TCP connection.
(29/85) `-sU` UDP scan: to discover services that run over UDP (DNS, DHCP), slower but in some cases network administrators overlook the existence of UDP services. If the target replies with an UDP packet then the port is open, if replies with an ICMP port unreachable message then it is closed.
(35/85) `-sI` Idle scan: is a stealth technique that uses a third party host (hiding the scanning source) called zombie for its inactivity on the network. Indeed, we need to find a zombie with no other traffic that can disturb the IP fragmentation ID. We also need to use an open port on the zombie host.
We need to find a zombie (a host that assigns IP fragmentation ID incrementally): `nmap -O -v 192.168.1.2 -p 135`, `-O` is for OS fingerprinting. We can also use NSE.
After found a good zombie host, we send a TCP SYN packet by spoofing the zombie's IP address.
Then the target will respond to the zombie with a SYN-ACK if the port is open or a RST if it is closed.
While we send this packet we continue monitoring the IP ID of the zombie: if it increments by 2 (because the zombie answers with a RST to the SYN-ACK packet) then the port is open, else if it increments by 1 then the port is closed.
(43/85) If the IP ID is incremented by 2, then the port on the target is open.
(45/85) If the IP ID is incremented only by 1, then the port is closed.
(47/85) `nmap -sI -Pn 192.168.1.3:135 192.168.1.2 -p 23 --packet-trace`:
`192.168.1.3:135` is the zombie IP:port;
`192.168.1.2` is the target to scan;
`-Pn` prevents pings from our IP;
`--packet-trace` to print every packet sent and received by nmap.
(50/85) We can't see any communication between our IP and the target one (very stealthy method).
(52/85) `-n` Never do DNS resolution: to use everytime resolving IP addresses to hostnames is not required (less noise).
(53/85) `-b` FTP Bounce scan: is a stealth technique that exploits a vulnearble FTP server (hide the scanning source).
(55/85) `-sN`, `-sF`, `-sX` TCP Null, FIN, Xmas scan:
If a system compliant with the TCP RFC receives a packet that does not contain SYN RST ACK bits, it will return: RST if the port is closed, no response if it is open.
Nowdays IDS are set to look for this behavior.
(61/85) `-sA` TCP ACK scan: is used to determine filtered/unfiltered ports.
(67/85) `-sO` IP protocol scan: looks for ICMP protocol unreachable messages instead of ICMP port unreachable ones.
(70/85) Nmap output options:
```
-oN/-oX/-oS/-oG <file>: Output scan in normal, XML, s|<rIpt kIddi3, and Grepable format, respectively, to the given filename.
-oA <basename>: Output in the three major formats at once
-v: Increase verbosity level (use -vv or more for greater effect)
-d: Increase debugging level (use -dd or more for greater effect)
--reason: Display the reason a port is in a particular state
--open: Only show open (or possibly open) ports
--packet-trace: Show all packets sent and received
--iflist: Print host interfaces and routes (for debugging)
```
(73/85) NSE (Nmap Scripting Engine): allows to write scripts to automate networking tasks.
(76/85) Find an open port on the zombie host with hping: `hping3 -S --scan known 192.168.1.3`.
(75/85) Find a zombie (an host that assigns IP fragmentation ID incrementally with no other traffic on that port) with hping: `hping3 -S -r -p 135 192.168.1.3`, `-r` to display IP ID increments.
`hping3 -S -a 192.168.1.3 192.168.1.2 -p 23`, `-a` the packet must have the source IP address of the zombie host (IP spoofing).
We need to continue monitoring the IP fragmentation ID increments: `hping3 -S -r -p 135 192.168.1.3`, if the increments are by 2 then the port is open.

### Nmap Basics - Video

`-d` to enable the debugging mode.
`--disable-arp-ping` to avoid the use of ARP ping scans.
`-n` to disable DNS resolution.
`-Pn` to treat the target as online, without checking whether it is or not.
`-F` to enable the fast mode: scan fewer ports than the default scan.
`--top-ports 100` to scan the 100 most common TCP ports.
`--scanflags URG` to set arbitrary bits in the packet sent.

### Nmap NSE - Video

NSE scripts are stored in `/usr/share/nmap/scripts`.
`--script` to specify a script.
`--script-updatedb` to update the scripts database.

Script information:
`--script-help` to retrieve information about a script among the available default ones.
`nmap --script-help "smb*" and discovery` to search for all the smb* scripts into the discovery category.
`nmap --script-help whois-domain` to retrieve information about the whois (information gathering) script.

Script usage:
`nmap --script whois-domain <TargetDomain> -sn`.
`nmap --script smb-os-discovery -p <TargetPort> <TargetIP>`. Using also the default Nmap OS fingerprinting scan: `nmap -O -p <TargetPort> <TargetIP>`, we can see that in this case NSE is more efficient.
`nmap --script smb-enum-shares -p <TargetPort> <TargetIP>`: to enumerate all shares available on a target.
We can specify an entire category (can be noisy) of scripts to use: `nmap --script auth <TargetIP>`.

### Idle Scan Hping Nmap - Video

`nmap -script ipidseq -p <ZombiePort> <ZombieIP>`: to specifically identify if the IP ID is incremental with NSE.

Because of false negatives for determine the IP ID increments, we suggest to use both hping and nmap tools at the same time in the following way:
`hping3 -S -r -p <ZombiePort> <ZombieIP>` to check the IP ID increments (and continuing monitoring);
`nmap -S <ZombieIP> <TargetIP> -p <TargetPort> -Pn -n -e tap --disable-arp-ping` to perform the idle scan with nmap, where `-S` is to spoof the source IP address.

### Service and OS Detection - Study Guide

(03/26) Banner grabbing: grab the message (information like the version of the service) that a service sends back to a host when this tries to establish a connection to it.
(05/26) Downside: network administrator can edit the default banner.
(06/26) `ncat <TargetIP> <TargetPort>`.
(08/26) More accurate techniques: verify services responses with a database of known ones.
(09/26) `nmap -sV <TargetIP>`.
(12/26) Service/version detection:
```
-sV: Probe open ports to determine service/version info
--version-intensity <level>: 0 (light) 9 (all probes)
--version-light: Limit to most likely probes (intensity 2)
--version-all: Try every single probe (intensity 9)
--version-trace: Show detailed version scan activity
```
(13/26) (Active) OS fingerprinting with nmap: `nmap -O <TargetIP>`.
(19/26) (Active) Aggressive OS fingerprinting with nmap: `nmap -A <TargetIP>` (more accurate but very noisy scan).
(22/26) (Passive) OS fingerprinting with P0f: `p0f -i <NetworkInterface>`.

### Firewall IDS Evasion - Study Guide

(02/25) Firewall/IDS presence means exposing or incorrect results.
(04/25) IP Fragmentation evasion technique: to create difficulties for some IDS to detect what is happening in the scan. `nmap -sS -f <TargetIP>`. However, modern IDSs are able to rebuild the fragmented packets.
(09/25) Decoys evasion technique: uses spoofed IP addresses to confuse the analysts.
`nmap -sS -D <DecoyIP#1>,<DecoyIP#2>,ME <TargetIP> -p <TargetPort>`, where `ME` is a keyword indicating the attacker IP.
(14/25) Timing evasion technique: slows down (interspersing) the scan by blending it with other traffic into the firewall/IDS log, sending packets every X seconds.
`nmap -sS <TargetIP> -T1` sends a packet every 15 sec.
```
Option	Time
-TO		5 min
-T1		15 sec
-T2		0.4 sec
-T3		default
-T4		10 ms
-T5		5 ms
```
Timing and performance:
```
Options which take <time> are in seconds, or append 'ms' (milliseconds), 's' (seconds), 'm' (minutes), or 'h' (hours) to the value (e.g. 30m).
-T<0-5>: Set timing template (higher is faster)
--min-hostgroup/max-hostgroup <size>: Parallel host scan group sizes
--min-parallelism/max-parallelism <numprobes>: Probe parallelization
--min-rtt-timeout/max-rtt-timeout/initial-rtt-timeout <time>
--max-retries <tries>: Caps number of port scan probe retransmissions.
```
`hping3 -S <TargetIP> -p <TargetPort> -i u<MillisecNumber>`, similar for hping.
(20/25) Source ports evasion technique: bypasses misconfigured firewall/IDS that allow communications coming from specific ports. Sometimes DNS traffic is not filtered.
`nmap -sS --source-port <SourcePort> <TargetIP>` or `nmap -sS -g <SourcePort> <TargetIP>`.

### Advanced Port Scanning - Video

IP Fragmentation evasion technique:
`nmap -sS -f <TargetIP> -Pn -n --disable-arp-ping -p <TargetPort>`.
`hping3 -S -f <TargetIP> -p <TargetPort> -c 1`, same for hping.
Since sometimes firewall/IDS looks at packet length in order to identify a network scan, we can append random data in a packet's header:
`nmap -sS --data-length <BytesNumber> <TargetIP> -p <TargetPort>` to add extra bytes to our payload (and thus break the packet in more fragments). `-f -f` to change the default size of a single fragment, from 8 to 16 bytes.
`hping3 -S <TargetIP> -p <TargetPort> --data <BytesNumber> -c 1`, same for hping.

Decoys evasion technique:
`nmap -sS -D <DecoyIP#1>,<DecoyIP#2>,ME <TargetIP> -p <TargetPort>`.
`nmap -sS -D RND:<DecoysNumber> <TargetIP> -p <TargetPort>` to generate random decoys.
`hping3 -S --rand-source <TargetIP> -p <TargetPort> -c 1`, same for hping.
Modern networks apply filters to limit attacks that uses fake IP addresses to perform port scans. To avoid this we can specify a real IP address alive host as source of the scan: `hping3 -S -a <SpoofedIP> <TargetIP> -p <TargetPort>`.

Source ports evasion technique:
`hping3 -S -s <SourcePort> --scan known <TargetIP>`.

MAC address spoofing (to use when firewall/IDS has a MAC filter):
`nmap -sS --spoof-mac <Vendor> <TargetIP> -p <TargetPort>` (vendor MAC address), `nmap -sS --spoof-mac 0 <TargetIP> -p <TargetPort>` (random MAC address), `nmap -sS --spoof-mac <SpecificMACAddress> <TargetIP> -p <TargetPort>` (specific MAC address).
MAC address spoofing is not supported by hping.

Randomize hosts during the scan:
`nmap -sS -iL <HostsList> --randomize-hosts -p <TargetPort>`.
This technique has better results with a delay: `nmap -sS -iL <HostsList> --randomize-hosts -p <TargetPort> -T1`
`hping3 -S --rand-dest 192.168.1.x -p <TargetPort>`, similar for hping.

### Scanning - Lab

In this lab, you will learn to scan the target machines to discover exciting information about the running services, versions, OS, etc.

In this lab environment, the user will access a Kali GUI machine. A target machine running multiple services is provided to you. The IP address of the target machine is provided in a text file named target placed on the Desktop of the Kali machine (/root/Desktop/target).

Objective: Scan all target machines to find running services and versions.

The best tools for this lab are:
- Nmap

---

**Step 1**.

`cat /root/Desktop/target`:
```
Target 1 : 10.4.26.155
Target 2 : 10.4.26.192
Target 3 : 10.4.25.235
```

`nmap -PE -sn -n 10.4.24.0/21 -oX /root/Desktop/scan.xml`:
`-PE` to use the ICMP echo request (ping scan);
`-PR` to use different ping scan techniques;
`-sn` to disable the port scan after the host discovery;
`-n` to avoid DNS resolution;
`-oX` to output the results into an XML file.

`cat /root/Desktop/scan.xml`:
```
Starting Nmap 7.92 ( https://nmap.org ) at 2024-01-23 20:20 IST
Nmap scan report for 10.4.25.235 ←
Host is up (0.010s latency).
Nmap scan report for 10.4.26.192 ←
Host is up (0.0098s latency).
Nmap done: 2048 IP addresses (2 hosts up) scanned in 154.05 seconds
```

**Step 2**.

`nmap -Pn -n --disable-arp-ping 10.4.26.155`:
```
Starting Nmap 7.92 ( https://nmap.org ) at 2024-01-23 20:33 IST
Nmap scan report for 10.4.26.155
Host is up (0.0090s latency).
Not shown: 999 filtered tcp ports (no-response)
PORT     STATE SERVICE
3389/tcp open  ms-wbt-server

Nmap done: 1 IP address (1 host up) scanned in 8.30 seconds
```

`nmap -Pn -n --disable-arp-ping 10.4.26.192`:
```
Starting Nmap 7.92 ( https://nmap.org ) at 2024-01-23 20:34 IST
Nmap scan report for 10.4.26.192
Host is up (0.0090s latency).
Not shown: 993 filtered tcp ports (no-response)
PORT      STATE SERVICE
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
445/tcp   open  microsoft-ds
3389/tcp  open  ms-wbt-server
49154/tcp open  unknown
49155/tcp open  unknown
49159/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 4.91 seconds
```

`nmap -Pn -n --disable-arp-ping 10.4.25.235`:
```
Starting Nmap 7.92 ( https://nmap.org ) at 2024-01-23 20:39 IST
Nmap scan report for 10.4.25.235
Host is up (0.0090s latency).
Not shown: 993 filtered tcp ports (no-response)
PORT      STATE SERVICE
53/tcp    open  domain
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
3389/tcp  open  ms-wbt-server
49154/tcp open  unknown
49155/tcp open  unknown
49159/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 4.81 seconds
```

**Step 3**.

`nmap -sV -Pn 10.4.26.155 -p3389`:
```
Starting Nmap 7.92 ( https://nmap.org ) at 2024-01-23 21:24 IST
Nmap scan report for 10.4.26.155
Host is up (0.0086s latency).

PORT     STATE SERVICE       VERSION
3389/tcp open  ms-wbt-server Microsoft Terminal Services
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 6.56 seconds
```

`nmap -sV -Pn 10.4.26.192 -p135,139,445,3389,49154,49155,49159`:
```
Starting Nmap 7.92 ( https://nmap.org ) at 2024-01-23 21:30 IST
Nmap scan report for 10.4.26.192
Host is up (0.0090s latency).

PORT      STATE SERVICE            VERSION
135/tcp   open  msrpc              Microsoft Windows RPC
139/tcp   open  netbios-ssn        Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds       Microsoft Windows Server 2008 R2 - 2012 microsoft-ds
3389/tcp  open  ssl/ms-wbt-server?
49154/tcp open  msrpc              Microsoft Windows RPC
49155/tcp open  msrpc              Microsoft Windows RPC
49159/tcp open  msrpc              Microsoft Windows RPC
Service Info: OSs: Windows, Windows Server 2008 R2 - 2012; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 66.00 seconds
```

`nmap -sV -Pn 10.4.25.235 -p53,135,139,3389,49154,49155,49159`:
```
Starting Nmap 7.92 ( https://nmap.org ) at 2024-01-23 22:00 IST
Nmap scan report for 10.4.28.137
Host is up (0.0100s latency).

PORT      STATE SERVICE            VERSION
53/tcp    open  domain             Simple DNS Plus
135/tcp   open  msrpc              Microsoft Windows RPC
139/tcp   open  netbios-ssn        Microsoft Windows netbios-ssn
3389/tcp  open  ssl/ms-wbt-server?
49154/tcp open  msrpc              Microsoft Windows RPC
49155/tcp open  msrpc              Microsoft Windows RPC
49159/tcp open  msrpc              Microsoft Windows RPC
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 66.14 seconds
```

---
---
