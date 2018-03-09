#! /bin/bash

#constants
RED='\e[31m'
GREEN='\e[32m'
NC='\033[0m' # No Color
KO="${RED}[KO]${NC}"
OK="${GREEN}[OK]${NC}"

#checking piveleges
if (( $EUID != 0 )); then
  echo -e "Root ${KO}"
  echo "Please run this script with sudo"
  exit
fi
echo -e "Root ${OK}"

#installation
sudo apt-get install openssh-server -y >& /dev/null
echo -e "openssh-server ${OK}"
#configuration serveur ssh
cfg="/etc/ssh/sshd_config"
sudo cp ${cfg} ${cfg}.factory-defaults #backup settings
cat $cfg | sed -e "s/'PermitRootLogin .*$'/'PermitRootLogin no$'/" > ${cfg}.temp  #No root login
cat ${cfg}.temp | grep 'PasswordAuthentication yes' >& /dev/null #If login by password allowed
if (( $? -ne 0 )); then
  cat $cfg.temp | sed -e 's/PasswordAuthentication .*$/PasswordAuthentication no$/g' > $cfg.temp #if yes, set no
fi
cat $cfg.temp | sed -e 's/PermitEmptyPasswords no .*$/PermitEmptyPasswords no$/g' > $cfg.temp #no empty PermitEmptyPasswords
cat $cfg.temp | sed -e 's/PubkeyAuthentication no .*$/PubkeyAuthentication yes$/g' > $cfg.temp #yes to login by key
mv ${cfg}.temp ${cfg} #Copy the new file over the original file
sudo /etc/init.d/ssh restart #restart with new config

#run in new PID namecpace
echo "Starting server"
sudo service ssh start
pid=`pgrep sshd | cut -d' ' -f1`
echo "It's PID = $pid"

sudo setcap cap_chown,cap_dac_override,cap_dac_read_search,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_ipc_lock,cap_ipc_owner,cap_sys_rawio,cap_sys_chroot,cap_sys_ptrace,cap_sys_admin,cap_sys_boot,cap_sys_nice,cap_sys_resource,cap_sys_time,cap_sys_tty_config,cap_mknod,cap_lease,cap_audit_write,cap_audit_control,cap_mac_override,cap_mac_admin,cap_syslog,cap_wake_alarm,cap_block_suspend,cap_audit_read,cap_sys_pacct=-ep /usr/sbin/sshd
sudo setcap cap_chown,cap_dac_override,cap_dac_read_search,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_ipc_lock,cap_ipc_owner,cap_sys_rawio,cap_sys_chroot,cap_sys_ptrace,cap_sys_admin,cap_sys_boot,cap_sys_nice,cap_sys_resource,cap_sys_time,cap_sys_tty_config,cap_mknod,cap_lease,cap_audit_write,cap_audit_control,cap_mac_override,cap_mac_admin,cap_syslog,cap_wake_alarm,cap_block_suspend,cap_audit_read,cap_sys_pacct=-ep /usr/bin/ssh
sudo setcap cap_fowner,cap_fsetid,cap_linux_immutable,cap_net_admin,cap_net_bind_service,cap_net_broadcast,cap_net_raw,cap_setfcap,cap_sys_module,cap_sys_time=+eip /usr/sbin/sshd
sudo setcap cap_fowner,cap_fsetid,cap_linux_immutable,cap_net_admin,cap_net_bind_service,cap_net_broadcast,cap_net_raw,cap_setfcap,cap_sys_module,cap_sys_time=+eip /usr/bin/ssh

#separater le reseaux
sudo ip netns add sshServerL3
sudo ip netns exec sshServerL3 ip link set lo up
sudo ip link add veth0 type veth peer name veth1
sudo ip link set veth1 netns sshServerL3
sudo ip netns exec sshServerL3 ip addr add 192.168.2.2/24 dev veth1
sudo ip netns exec sshServerL3 ip link set dev veth1 up
sudo ip addr add 192.168.2.1/24 dev veth0
sudo ip link set dev veth0 up
sudo ip netns exec sshServerL3 route add default gw 192.168.2.1
sudo iptables -t nat -A POSTROUTING -o enp0s3 -j MASQUERADE
sudo sysctl -w net.ipv4.ip_forward=1

#limiter l'acces a CPU et RAM
#RAM
chem=/sys/fs/cgroup/memory/limServer/
mkdir $chem
#sudo echo ${pid} > $chem/cgroup.procs >& /dev/null
sudo echo ${pid} > $chem/tasks >& /dev/null
sud echo $(( 1024 * 1024 * 1024 )) > $chem/memory.limit_in_bytes
#CPU
chem=/sys/fs/cgroup/cpu/limServer/
mkdir $chem
sudo echo ${pid} > $chem/tasks >& /dev/null
#1024 * 0.4 ~ 410
sudo echo 410 > $chem/cpu.shares    #setting 40 to our group
