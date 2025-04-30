# remove ssh host
## ssh-keygen -R 'mygu@k2.omygu.com'

sudo tunnel mode

# change root password
sudo passwd root

sudo apt-get update && sudo apt-get upgrade

sudo reboot

sudo apt-get install traceroute

##################################
traceroute -n rm2.omygu.com
ping rm2.omygu.com
##################################

# change ip to static
sudo nano /etc/netplan/50-cloud-init.yaml

# Install strongswan
sudo apt install strongswan strongswan-pki libcharon-extra-plugins libcharon-extauth-plugins libstrongswan-extra-plugins libtss2-tcti-tabrmd0 charon-systemd strongswan-swanctl -y

#### Prepare for VPN
sudo timedatectl set-timezone Asia/Shanghai
	
# Change ssh port:
sudo nano /etc/ssh/sshd_config
	
#modify sysctl.conf
sudo nano /etc/sysctl.conf
	
#modify rc.local
sudo nano /etc/rc.local

# reload
sudo sysctl -p

# 3. update swanctl.conf------------------
sudo nano /etc/swanctl/swanctl.conf

#   3.1 change IKE port------------------
sudo nano /etc/strongswan.conf

# 4. update updown.sh------------------
sudo mkdir /usr/libexec/ipsec
sudo nano /usr/libexec/ipsec/updown.sh
sudo chmod +x /usr/libexec/ipsec/updown.sh

sudo nano /usr/libexec/ipsec/updown_raspberryPi.sh
sudo chmod +x /usr/libexec/ipsec/updown_raspberryPi.sh

# 5. Enable strongswan service
sudo systemctl enable strongswan
sudo systemctl disable strongswan

# 6. add delay for strongswan.service start------------------
sudo mkdir /etc/systemd/system/strongswan.service.d
sudo nano /etc/systemd/system/strongswan.service.d/override.conf

# 7. Start strongswan service
sudo systemctl start strongswan
sudo systemctl stop strongswan
sudo systemctl restart strongswan


sudo systemctl status strongswan
sudo journalctl -xe
sudo journalctl -xeu strongswan.service
journalctl -u strongswan --since "10 minutes ago"

123KJHHYGvtfre56jh

sudo swanctl --list-sas

######---Start---iptables---######
sudo iptables-save

sudo /usr/sbin/iptables -t nat -A POSTROUTING -s 192.168.119.0/24 ! -d 192.168.0.0/16 -j SNAT --to 144.168.58.227
sudo /usr/sbin/iptables -t nat -D POSTROUTING -s 192.168.119.47/32 ! -d 192.168.0.0/16 -j SNAT --to 144.168.58.227

sudo iptables -t nat -v -L POSTROUTING -n --line-number
sudo ip route list table express
sudo ip rule
sudo iptables -v -L FORWARD -n --line-number
======---End---iptables---======


######---Start---install cloudflare---##########
apt list --installed

# Add cloudflare gpg key
curl https://pkg.cloudflareclient.com/pubkey.gpg | sudo gpg --yes --dearmor --output /usr/share/keyrings/cloudflare-warp-archive-keyring.gpg

# Add this repo to your apt repositories
echo "deb [arch=amd64 signed-by=/usr/share/keyrings/cloudflare-warp-archive-keyring.gpg] https://pkg.cloudflareclient.com/ $(lsb_release -cs) main" | sudo tee /etc/apt/sources.list.d/cloudflare-client.list

# Install
sudo apt-get update && sudo apt-get install cloudflare-warp
######---End---install cloudflare---##########



######---Start---Wireguard--##########
######---Start---Wireguard---##########

sudo apt install wireguard

# 01. A new interface can be added via ip-link(8), which should automatically handle module loading:
# sudo ip link add dev wg0 type wireguard

# 02. An IP address and peer can be assigned with ifconfig(8) or ip-address(8)
# sudo ip address add dev wg0 192.168.222.1/28

# 3. gen key
cd /etc/wireguard
# set the permissions for the directory with the following command. Note that you need to be logged in with the root account to do this.
umask 077
sudo wg genkey | tee privatekey | wg pubkey > publickey

# 4. configruation
sudo nano /etc/wireguard/postup.sh
sudo nano /etc/wireguard/postdown.sh

sudo chmod +x /etc/wireguard/postup.sh
sudo chmod +x /etc/wireguard/postdown.sh

sudo nano /etc/wireguard/wg0.conf
#sudo wg setconf wg0 home_k0_wg0.conf

# 5. Finally, the interface can then be activated with ifconfig(8) or ip-link(8):
# sudo ip link set up dev wg0

# shwo config
sudo wg show
sudo wg showconf wg0

# enable services
sudo systemctl enable wg-quick@wg0
sudo systemctl disable wg-quick@wg0

sudo systemctl start wg-quick@wg0
sudo systemctl stop wg-quick@wg0

sudo systemctl status wg-quick@wg0

# 6. add delay for wg-quick@wg0.service.d start------------------
sudo mkdir /etc/systemd/system/wg-quick@wg0.service.d
sudo nano /etc/systemd/system/wg-quick@wg0.service.d/override.conf

# start wg0
wg-quick up wg0
wg-quick down wg0

######---End---Wireguard--##########
######---End---Wireguard---##########


journalctl -xeu wg-quick@wg0.service

#===network====
ip link help bridge
sudo bridge -s vlan show
sudo apt install bridge-utils
sudo brctl delbr docker0




sudo nano /etc/strongswan.d/charon-logging.conf