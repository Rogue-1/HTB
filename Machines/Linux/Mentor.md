
```console
└─$ nmap -A -p- -T4 -Pn 10.10.11.193
Starting Nmap 7.93 ( https://nmap.org ) at 2022-12-16 10:29 CST
Nmap scan report for mentorquotes.htb (10.10.11.193)
Host is up (0.043s latency).
Not shown: 65533 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 c73bfc3cf9ceee8b4818d5d1af8ec2bb (ECDSA)
|_  256 4440084c0ecbd4f18e7eeda85c68a4f7 (ED25519)
80/tcp open  http    Apache httpd 2.4.52
|_http-title: MentorQuotes
| http-server-header: 
|   Apache/2.4.52 (Ubuntu)
|_  Werkzeug/2.0.3 Python/3.6.9
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 17.87 seconds
```

```console
└─$ sudo nmap -A --top-ports 100 -sU -T3 -Pn 10.10.11.193
[sudo] password for npayne: 
Starting Nmap 7.93 ( https://nmap.org ) at 2022-12-16 10:53 CST
Stats: 0:00:06 elapsed; 0 hosts completed (1 up), 1 undergoing UDP Scan
UDP Scan Timing: About 16.71% done; ETC: 10:54 (0:00:30 remaining)
Nmap scan report for mentorquotes.htb (10.10.11.193)
Host is up (0.044s latency).
Not shown: 98 closed udp ports (port-unreach)
PORT    STATE         SERVICE VERSION
68/udp  open|filtered dhcpc
161/udp open          snmp    SNMPv1 server; net-snmp SNMPv3 server (public)
| snmp-info: 
|   enterprise: net-snmp
|   engineIDFormat: unknown
|   engineIDData: a124f60a99b99c6200000000
|   snmpEngineBoots: 67
|_  snmpEngineTime: 10h59m05s
| snmp-sysdescr: Linux mentor 5.15.0-56-generic #62-Ubuntu SMP Tue Nov 22 19:54:14 UTC 2022 x86_64
|_  System uptime: 10h59m5.33s (3954533 timeticks)
Too many fingerprints match this host to give specific OS details
Network Distance: 2 hops
Service Info: Host: mentor

TRACEROUTE (using port 49188/udp)
HOP RTT      ADDRESS
1   58.15 ms 10.10.16.1
2   29.45 ms mentorquotes.htb (10.10.11.193)

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 214.82 seconds
```
```console
└─$ sudo nmap -sU -p 161 --script snmp-brute 10.10.11.193 --script-args 'snmp-
brute.communitiesdb=/usr/share/wordlists/SecLists/Discovery/SNMP/common-snmp-
community-strings.txt,snmp.version=v2c'
Starting Nmap 7.93 ( https://nmap.org ) at 2022-12-16 12:21 CST
Nmap scan report for mentorquotes.htb (10.10.11.193)
Host is up (0.039s latency).

PORT    STATE SERVICE
161/udp open  snmp
| snmp-brute: 
|_  public - Valid credentials

Nmap done: 1 IP address (1 host up) scanned in 2.11 seconds
```

```console
└─$ snmpwalk -v1 -c public 10.10.11.193                  
iso.3.6.1.2.1.1.1.0 = STRING: "Linux mentor 5.15.0-56-generic #62-Ubuntu SMP Tue Nov 22 19:54:14 UTC 2022 x86_64"
iso.3.6.1.2.1.1.2.0 = OID: iso.3.6.1.4.1.8072.3.2.10
iso.3.6.1.2.1.1.3.0 = Timeticks: (3991343) 11:05:13.43
iso.3.6.1.2.1.1.4.0 = STRING: "Me <admin@mentorquotes.htb>"
iso.3.6.1.2.1.1.5.0 = STRING: "mentor"
iso.3.6.1.2.1.1.6.0 = STRING: "Sitting on the Dock of the Bay"
iso.3.6.1.2.1.1.7.0 = INTEGER: 72
iso.3.6.1.2.1.1.8.0 = Timeticks: (0) 0:00:00.00
iso.3.6.1.2.1.1.9.1.2.1 = OID: iso.3.6.1.6.3.10.3.1.1
iso.3.6.1.2.1.1.9.1.2.2 = OID: iso.3.6.1.6.3.11.3.1.1
iso.3.6.1.2.1.1.9.1.2.3 = OID: iso.3.6.1.6.3.15.2.1.1
iso.3.6.1.2.1.1.9.1.2.4 = OID: iso.3.6.1.6.3.1
iso.3.6.1.2.1.1.9.1.2.5 = OID: iso.3.6.1.6.3.16.2.2.1
iso.3.6.1.2.1.1.9.1.2.6 = OID: iso.3.6.1.2.1.49
iso.3.6.1.2.1.1.9.1.2.7 = OID: iso.3.6.1.2.1.50
iso.3.6.1.2.1.1.9.1.2.8 = OID: iso.3.6.1.2.1.4
iso.3.6.1.2.1.1.9.1.2.9 = OID: iso.3.6.1.6.3.13.3.1.3
iso.3.6.1.2.1.1.9.1.2.10 = OID: iso.3.6.1.2.1.92
iso.3.6.1.2.1.1.9.1.3.1 = STRING: "The SNMP Management Architecture MIB."
iso.3.6.1.2.1.1.9.1.3.2 = STRING: "The MIB for Message Processing and Dispatching."
iso.3.6.1.2.1.1.9.1.3.3 = STRING: "The management information definitions for the SNMP User-based Security Model."
iso.3.6.1.2.1.1.9.1.3.4 = STRING: "The MIB module for SNMPv2 entities"
iso.3.6.1.2.1.1.9.1.3.5 = STRING: "View-based Access Control Model for SNMP."
iso.3.6.1.2.1.1.9.1.3.6 = STRING: "The MIB module for managing TCP implementations"
iso.3.6.1.2.1.1.9.1.3.7 = STRING: "The MIB module for managing UDP implementations"
iso.3.6.1.2.1.1.9.1.3.8 = STRING: "The MIB module for managing IP and ICMP implementations"
iso.3.6.1.2.1.1.9.1.3.9 = STRING: "The MIB modules for managing SNMP Notification, plus filtering."
iso.3.6.1.2.1.1.9.1.3.10 = STRING: "The MIB module for logging SNMP Notifications."
iso.3.6.1.2.1.1.9.1.4.1 = Timeticks: (0) 0:00:00.00
iso.3.6.1.2.1.1.9.1.4.2 = Timeticks: (0) 0:00:00.00
iso.3.6.1.2.1.1.9.1.4.3 = Timeticks: (0) 0:00:00.00
iso.3.6.1.2.1.1.9.1.4.4 = Timeticks: (0) 0:00:00.00
iso.3.6.1.2.1.1.9.1.4.5 = Timeticks: (0) 0:00:00.00
iso.3.6.1.2.1.1.9.1.4.6 = Timeticks: (0) 0:00:00.00
iso.3.6.1.2.1.1.9.1.4.7 = Timeticks: (0) 0:00:00.00
iso.3.6.1.2.1.1.9.1.4.8 = Timeticks: (0) 0:00:00.00
iso.3.6.1.2.1.1.9.1.4.9 = Timeticks: (0) 0:00:00.00
iso.3.6.1.2.1.1.9.1.4.10 = Timeticks: (0) 0:00:00.00
iso.3.6.1.2.1.25.1.1.0 = Timeticks: (3993371) 11:05:33.71
iso.3.6.1.2.1.25.1.2.0 = Hex-STRING: 07 E6 0C 10 11 03 02 00 2B 00 00 
iso.3.6.1.2.1.25.1.3.0 = INTEGER: 393216
iso.3.6.1.2.1.25.1.4.0 = STRING: "BOOT_IMAGE=/vmlinuz-5.15.0-56-generic root=/dev/mapper/ubuntu--vg-ubuntu--lv ro net.ifnames=0 biosdevname=0
"
iso.3.6.1.2.1.25.1.5.0 = Gauge32: 0
iso.3.6.1.2.1.25.1.6.0 = Gauge32: 231
iso.3.6.1.2.1.25.1.7.0 = INTEGER: 0
End of MIB
```         
```console
└─$ ffuf -w /usr/share/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt -u http://mentorquotes.htb -H "HOST: FUZZ.mentorquotes.htb"  -v -fs 0 -fc 302  -mc all -c

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.5.0 Kali Exclusive <3
________________________________________________

 :: Method           : GET
 :: URL              : http://mentorquotes.htb
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt
 :: Header           : Host: FUZZ.mentorquotes.htb
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: all
 :: Filter           : Response status: 302
 :: Filter           : Response size: 0
________________________________________________

[Status: 404, Size: 22, Words: 2, Lines: 1, Duration: 29ms]
| URL | http://mentorquotes.htb
    * FUZZ: api
```

```console
└─$ feroxbuster -u http://api.mentorquotes.htb -w /usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt -x txt,html,php,pdf,git -q

307      GET        0l        0w        0c http://api.mentorquotes.htb/admin => http://api.mentorquotes.htb/admin/
405      GET        1l        3w       31c http://api.mentorquotes.htb/admin/backup
200      GET       31l       62w      969c http://api.mentorquotes.htb/docs
307      GET        0l        0w        0c http://api.mentorquotes.htb/users => http://api.mentorquotes.htb/users/
405      GET        1l        3w       31c http://api.mentorquotes.htb/users/add
```












```console
HOST-RESOURCES-MIB::hrSWRunParameters.556 = STRING: "-d -s"
HOST-RESOURCES-MIB::hrSWRunParameters.559 = ""
HOST-RESOURCES-MIB::hrSWRunParameters.591 = ""
HOST-RESOURCES-MIB::hrSWRunParameters.696 = ""
HOST-RESOURCES-MIB::hrSWRunParameters.745 = ""
HOST-RESOURCES-MIB::hrSWRunParameters.746 = ""
HOST-RESOURCES-MIB::hrSWRunParameters.766 = ""
HOST-RESOURCES-MIB::hrSWRunParameters.768 = ""
HOST-RESOURCES-MIB::hrSWRunParameters.781 = ""
HOST-RESOURCES-MIB::hrSWRunParameters.782 = ""
HOST-RESOURCES-MIB::hrSWRunParameters.805 = STRING: "-1 -4 -v -i -pf /run/dhclient.eth0.pid -lf /var/lib/dhcp/dhclient.eth0.leases -I -df /var/lib/dhcp/dhclient6.eth0.leases eth0"
HOST-RESOURCES-MIB::hrSWRunParameters.900 = STRING: "--system --address=systemd: --nofork --nopidfile --systemd-activation --syslog-only"
HOST-RESOURCES-MIB::hrSWRunParameters.905 = STRING: "--foreground"
HOST-RESOURCES-MIB::hrSWRunParameters.906 = STRING: "/usr/bin/networkd-dispatcher --run-startup-triggers"
HOST-RESOURCES-MIB::hrSWRunParameters.907 = STRING: "--no-debug"
HOST-RESOURCES-MIB::hrSWRunParameters.908 = STRING: "-n -iNONE"
HOST-RESOURCES-MIB::hrSWRunParameters.909 = ""
HOST-RESOURCES-MIB::hrSWRunParameters.910 = ""
HOST-RESOURCES-MIB::hrSWRunParameters.911 = ""
HOST-RESOURCES-MIB::hrSWRunParameters.936 = ""
HOST-RESOURCES-MIB::hrSWRunParameters.1209 = STRING: "-f -P"
HOST-RESOURCES-MIB::hrSWRunParameters.1212 = STRING: "-LOw -u Debian-snmp -g Debian-snmp -I -smux mteTrigger mteTriggerConf -f"
HOST-RESOURCES-MIB::hrSWRunParameters.1226 = ""
HOST-RESOURCES-MIB::hrSWRunParameters.1238 = STRING: "-o -p -- \\u --noclear tty1 linux"
HOST-RESOURCES-MIB::hrSWRunParameters.1241 = ""
HOST-RESOURCES-MIB::hrSWRunParameters.1268 = STRING: "-k start"
HOST-RESOURCES-MIB::hrSWRunParameters.1332 = STRING: "-H fd:// --containerd=/run/containerd/containerd.sock"
HOST-RESOURCES-MIB::hrSWRunParameters.1682 = STRING: "/usr/local/bin/login.sh"
HOST-RESOURCES-MIB::hrSWRunParameters.1746 = STRING: "-proto tcp -host-ip 172.22.0.1 -host-port 5432 -container-ip 172.22.0.4 -container-port 5432"
HOST-RESOURCES-MIB::hrSWRunParameters.1760 = STRING: "-namespace moby -id 96e44c5692920491cdb954f3d352b3532a88425979cd48b3959b63bfec98a6f4 -address /run/containerd/containerd.sock"
HOST-RESOURCES-MIB::hrSWRunParameters.1778 = ""
HOST-RESOURCES-MIB::hrSWRunParameters.1856 = STRING: "-proto tcp -host-ip 172.22.0.1 -host-port 8000 -container-ip 172.22.0.3 -container-port 8000"
HOST-RESOURCES-MIB::hrSWRunParameters.1874 = STRING: "-namespace moby -id 3fc9258f43cfcdf21c24d95c26ea4628b127b0401f97786d3288c5fed1f3949d -address /run/containerd/containerd.sock"
HOST-RESOURCES-MIB::hrSWRunParameters.1898 = STRING: "-m uvicorn app.main:app --reload --workers 2 --host 0.0.0.0 --port 8000"
HOST-RESOURCES-MIB::hrSWRunParameters.1904 = ""
HOST-RESOURCES-MIB::hrSWRunParameters.1905 = ""
HOST-RESOURCES-MIB::hrSWRunParameters.1906 = ""
HOST-RESOURCES-MIB::hrSWRunParameters.1907 = ""
HOST-RESOURCES-MIB::hrSWRunParameters.1908 = ""
HOST-RESOURCES-MIB::hrSWRunParameters.1909 = ""
HOST-RESOURCES-MIB::hrSWRunParameters.1976 = STRING: "-proto tcp -host-ip 172.22.0.1 -host-port 81 -container-ip 172.22.0.2 -container-port 80"
HOST-RESOURCES-MIB::hrSWRunParameters.1996 = STRING: "-namespace moby -id 589fe567a7f2d67c58c3b0f5f24b893d9488947799a37748e0fd3dc4839c0198 -address /run/containerd/containerd.sock"
HOST-RESOURCES-MIB::hrSWRunParameters.2017 = STRING: "main.py"
HOST-RESOURCES-MIB::hrSWRunParameters.2038 = STRING: "-c from multiprocessing.semaphore_tracker import main;main(4)"
HOST-RESOURCES-MIB::hrSWRunParameters.2039 = STRING: "-c from multiprocessing.spawn import spawn_main; spawn_main(tracker_fd=5, pipe_handle=7) --multiprocessing-fork"
HOST-RESOURCES-MIB::hrSWRunParameters.2080 = ""
HOST-RESOURCES-MIB::hrSWRunParameters.2106 = STRING: "/usr/local/bin/login.py kj23sadkj123as0-d213"
```
