# Screen capture
shift+cmd+4
^+shift+cmd+4

# Delete file in finder
cmd+delete

# Show hide file in finder
shif+cmd+.

# Show or move all open windows
Control+down

#Telnet
nc -vz 192.168.119.132 12201

# traceroute
traceroute -n 150.171.22.12

# Route Print
netstat -rln -f inet

# flush dns
sudo dscacheutil -flushcache

# ip address
ifconfig | grep -v "inet6" | grep "inet" | grep -v "127.0.0.1"

# mount smb
tpdir=$(mktemp -d)
mount -t smbfs //v-guminyu@products/PUBLIC/Products/OS/WindowsServer2016/MSIT/ITEasyInstaller/ $tpdir

# copy smb
# ...
tpdir=$(mktemp -d)
mount -t smbfs //v-guminyu@products/PUBLIC/ $tpdir
cp -v $tpdir/Products/ISO/OS/Windows_Server_2022_Standard_and_Datacenter/20348.1726.230505-1231.fe_release_svc_refresh_SERVER_VOL_x64FRE_en-us.iso ~/downloads
umount $tpdir && rmdir $tpdir

ditto

# chech destination mss
lsof -i -n -Tf

# find max mtu
ping -g 1350 -G 1520 -h 10 -D andrewbaker.ninja

# web access
curl -v https://chat.openai.com

# gateway
netstat -nr | grep default

