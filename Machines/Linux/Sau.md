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

![image](https://github.com/Rogue-1/HTB/assets/105310322/d6883732-b52e-42ae-ad90-b7f701785ad8)


└──╼ [★]$ nc -lvnp 1234
Ncat: Version 7.93 ( https://nmap.org/ncat )
Ncat: Listening on :::1234
Ncat: Listening on 0.0.0.0:1234
Ncat: Connection from 10.129.229.26.
Ncat: Connection from 10.129.229.26:33344.
GET /test5 HTTP/1.1
Host: 10.10.14.78:1234
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.5
Dnt: 1
Sec-Gpc: 1
Upgrade-Insecure-Requests: 1
X-Do-Not-Forward: 1

