# sha-dc-01
ssh "sha\shadmin@192.168.119.132" -p 12201
scp -P 12201 -r '/Users/mygu/Library/CloudStorage/OneDrive-MG/WorkData/My Documents/0 MS/_DevOps' 'sha\shadmin@192.168.119.132:/C:/_DevOps'

# K0 - Bandwagon
ssh root@k0.omygu.com -p 27584 -i ~/.ssh/k0-root-key

ssh root@k0.omygu.com -p 27584
xs7spF2nUpwV

# K2 - Azure
ssh mygu@k2.omygu.com -p 8850 -i "/Users/mygu/Library/CloudStorage/OneDrive-Personal/_ssh/k2/k2.omygu.com_mygu.pem"

# Raspberry Pi
ssh mygu@192.168.129.129


##################################
traceroute -n rm2.omygu.com
ping rm2.omygu.com
##################################

##########
#### copy user cert to local ####
scp -P 27584 root@k0.omygu.com:/root/.ssh/ssh_root_user-cert.pub ~/.ssh
scp -P 27584 root@k0.omygu.com:/root/.ssh/ssh_root_user.pub ~/.ssh

scp mygu@192.168.129.129:/home/mygu/swanctl.conf /Users/mygu/Desktop
scp -P 27584 -i ~/.ssh/k0-root-key root@k0.omygu.com:/etc/swanctl/swanctl.conf ~/Desktop

scp -P 27584 root@k0.omygu.com:/root/.ssh/ssh_root_user ~/.ssh

ssh root@k0.omygu.com -p 27584 -i ~/.ssh/ssh_root_user-cert.pub
ssh root@k0.omygu.com -p 27584 -i ~/.ssh/ssh_root_user.pub


scp -P 27584 root@k0.omygu.com:/etc/ssh/id_rsa-cert.pub  /users/mygu/downloads

#========= Convert key to pem ==================
ssh-keygen -f ~/downloads/id_rsa.pub -e -m pem > ~/downloads/k0-root-pub.pem
ssh-keygen -f ~/downloads/k0-root-key -p -N "" -m pem > ~/downloads/k0-root.key

#================Routeros ssh exec command==================
/system ssh-exec address=k0.omygu.com user=root port=27584 command="ls"


ssh mygu@genymotion.eastasia.cloudapp.azure.com -p 22 -i ~/.ssh/mygu_genymotion.pem

# install ssh on windows
Get-WindowsCapability -Online | Where-Object Name -like 'OpenSSH*'
Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0 
