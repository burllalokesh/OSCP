Pterodactyl

IP : 10.129.5.102

##Nmap Scan
```
nmap -sV -sC -A 10.129.5.102
Starting Nmap 7.94SVN ( https://nmap.org ) at 2026-02-26 06:25 CST
Nmap scan report for 10.129.5.102
Host is up (0.43s latency).
Not shown: 967 filtered tcp ports (no-response), 29 filtered tcp ports (admin-prohibited)
PORT     STATE  SERVICE    VERSION
22/tcp   open   ssh        OpenSSH 9.6 (protocol 2.0)
| ssh-hostkey: 
|   256 a3:74:1e:a3:ad:02:14:01:00:e6:ab:b4:18:84:16:e0 (ECDSA)
|_  256 65:c8:33:17:7a:d6:52:3d:63:c3:e4:a9:60:64:2d:cc (ED25519)
80/tcp   open   http       nginx 1.21.5
|_http-title: Did not follow redirect to http://pterodactyl.htb/
|_http-server-header: nginx/1.21.5
443/tcp  closed https
8080/tcp closed http-proxy
Aggressive OS guesses: Linux 5.0 (92%), Linux 5.0 - 5.4 (92%), Linux 4.15 - 5.8 (89%), HP P2000 G3 NAS device (89%), Linux 5.3 - 5.4 (89%), Linux 2.6.32 (89%), Linux 2.6.32 - 3.1 (88%), Linux 5.0 - 5.5 (88%), Linux 5.1 (88%), Ubiquiti AirOS 5.5.9 (88%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops

TRACEROUTE (using port 443/tcp)
HOP RTT       ADDRESS
1   512.33 ms 10.10.16.1
2   512.35 ms 10.129.5.102

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 52.73 seconds
```

