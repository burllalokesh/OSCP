## Web Enumeration

```
gobuster dir -u http://10.10.10.121/ -w /usr/share/seclists/Discovery/Web-Content/common.txt
```
## Sub domaim enumaration

```
gobuster dns -d inlanefreight.com -w /usr/share/SecLists/Discovery/DNS/namelist.txt
```

## Banner Grabbing / Web Server Headers
```
curl -IL https://www.inlanefreight.com
```
