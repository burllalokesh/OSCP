##Grep Commands

```
# Search current directory recursively
grep -rni "password\|passwd\|pwd\|secret\|credential" . 2>/dev/null

# Config files specifically
grep -rni "password" /var/www/html/ 2>/dev/null

# Look for password in common locations
grep -rni "password" /home/*/.* 2>/dev/null

# Search for passwords in Windows-style files (if Wine/mixed env)
grep -rni "password" /opt/ /srv/ 2>/dev/null

```
##Hash cat 

```
find out the hash type with Hash analyzer , find the -m value to give in below command in the hashcat website

hashcat -m 1410 -a 0 hash.txt /usr/share/wordlists/rockyou.txt

##With rules for better coverage:
hashcat -m 1410 -a 0 hash.txt /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule
```

##SSH 
```
ssh root@IP

Internal port tunneling (Pivoting)

ssh sedric@10.129.5.48 -L 5555:127.0.0.1:54321
```
