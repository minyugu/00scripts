### CA Certificate ###
# Generate the CA key (cert_ca) for signing user and host ssh keys
ssh-keygen -t rsa -b 4096 -f ~/.ssh/k0_ssh_ca
ls ~/.ssh

# Signing the CA’s Host Certificate
ssh-keygen -s ~/.ssh/k0_ssh_ca -I mygu@omygu.com -h -n k0.omygu.com -V +52w ~/.ssh/k0_ssh_ca.pub
ssh-keygen -Lf ~/.ssh/k0_ssh_ca-cert.pub

cat /etc/ssh/k0_ssh_ca.pub
cat ~/.ssh/k0_ssh_ca-cert.pub

# Copy the publice key to /etc/ssh/  
cp -pr ~/.ssh/k0_ssh_ca.pub /etc/ssh/

# Add CA public key (cert_ca.pub) as Trusted Key in the ssh server machines
nano /etc/ssh/sshd_config
# (Add the following lines)
…
TrustedUserCAKeys /etc/ssh/k0_ssh_ca.pub
…

###########
#### Host Certificate ###
# Creating SSH Host Certificates
ssh-keygen -t rsa -b 4096 -f ~/.ssh/k0_ssh_host

# create the host certificate from the host public key and sign the certificate using the host CA’s private key
ssh-keygen -s ~/.ssh/k0_ssh_ca -I mygu@omygu.com -h -n k0.omygu.com -V +52w ~/.ssh/k0_ssh_host.pub
ssh-keygen -Lf ~/.ssh/k0_ssh_host-cert.pub

# Copy the publice key to /etc/ssh/  
cp -pr ~/.ssh/k0_ssh_host-cert.pub /etc/ssh/
cp -pr ~/.ssh/k0_ssh_host.pub /etc/ssh/
cp -pr ~/.ssh/k0_ssh_host /etc/ssh/
#cp -pr ~/.ssh/k0_ssh_ca /etc/ssh/

# Add Host key in the ssh server machines
nano /etc/ssh/sshd_config
…
HostCertificate  /etc/ssh/k0_ssh_host-cert.pub
…

systemctl restart sshd

###########
#### Creating SSH User Certificates ####
ssh-keygen -t rsa -b 4096 -f ~/.ssh/ssh_root_user

# Signing the User Certificate
ssh-keygen -s ~/.ssh/k0_ssh_ca -I mygu@omygu.com -n root -V +4w ~/.ssh/ssh_root_user.pub
ssh-keygen -Lf ~/.ssh/ssh_root_user-cert.pub

ssh-keygen -s ~/.ssh/k0_ssh_ca -I user_root -n root -V +52w ~/.ssh/ssh_root_user.pub


#############
#### client trust #####
ssh-rsa-cert-v01@openssh.com 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 root@k0.omygu.com








ssh-keygen -s /etc/ssh/ssh_host_rsa_key -I mygu@omygu.com -h -n k0.omygu.com -V +52w /etc/ssh/ssh_host_rsa_key.pub

ssh-keygen -trsa
cp -pr ~/.ssh/id_rsa* /etc/ssh
cp /etc/ssh/id_rsa-cert.pub ~/.ssh

ssh-keygen -s /etc/ssh/ssh_host_rsa_key -I user_root -n root -V +52w /etc/ssh/id_rsa.pub

ls ~/.ssh
#=========================================================
nano ~/.ssh/authorized_keys
cat ~/.ssh/id_rsa.pub > ~/.ssh/authorized_keys


