##Enumeration Methodology
```
https://academy.hackthebox.com/storage/modules/112/enum-method33.png

**Domain Information

Certificate Transparency 
curl -s https://crt.sh/\?q\=inlanefreight.com\&output\=json | jq .

filtered by the unique subdomains
curl -s https://crt.sh/\?q\=inlanefreight.com\&output\=json | jq . | grep name | cut -d":" -f2 | grep -v "CN=" | cut -d'"' -f2 | awk '{gsub(/\\n/,"\n");}1;' | sort -u

Company Hosted Servers
for i in $(cat subdomainlist);do host $i | grep "has address" | grep inlanefreight.com | cut -d" " -f1,4;done

DNS Records
dig any inlanefreight.com

