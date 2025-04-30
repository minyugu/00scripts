ssh mygu@kgfw03.omygu.com
curl -sSL https://get.docker.com | sh
sudo usermod -aG docker mygu
sudo docker pull portainer/portainer-ce:linux-arm
sudo docker run -d -p 9988:9000 --name=portainer --restart=always -v /var/run/docker.sock:/var/run/docker.sock -v portainer_data:/data portainer/portainer-ce:linux-arm



sudo docker ps -a -f status=exited
sudo docker stop portainer
sudo docker rm -v portainer
sudo docker ps -a
sudo docker container ls

sudo lsof -i -P -n | grep LISTEN
resolvectl status


sudo systemctl stop docker.socket
sudo systemctl stop docker

#=====remove docker service

sudo ip link set docker0 up
sudo ip link set docker0 down

sudo apt-get purge docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin docker-ce-rootless-extras

sudo rm -rf /var/lib/docker
sudo rm -rf /var/lib/containerd
