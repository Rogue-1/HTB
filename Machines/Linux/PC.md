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


└──╼ [★]$ telnet 10.129.85.76 50051
Trying 10.129.85.76...
Connected to 10.129.85.76.
Escape character is '^]'.
?�?� ?@Did not receive HTTP/2 settings before handshake timeoutConnection closed by foreign host.

https://github.com/fullstorydev/grpcui

└──╼ [★]$ go install github.com/fullstorydev/grpcui/cmd/grpcui@latest

└──╼ [★]$ chmod -R 777 go/

└──╼ [★]$ ./grpcui -plaintext 10.129.94.151:50051
gRPC Web UI available at http://127.0.0.1:32953/


![image](https://github.com/Rogue-1/HTB/assets/105310322/1798d19a-54b0-47d8-8efa-4114f991063c)

![image](https://github.com/Rogue-1/HTB/assets/105310322/e08a1923-efe7-4dcc-81f0-d6052dcd9eca)

![image](https://github.com/Rogue-1/HTB/assets/105310322/6a096f4e-55c8-41a7-b58a-7a4ca47692dd)

