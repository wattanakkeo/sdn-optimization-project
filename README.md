# sdn-optimization-project

This is a software defined networking traffic optimization project running on the Ryu framework. We created a custom switch that maps the shortest path based on the current network topology with Dijkstra's algorithm.

# How to set up
1. Update the system\
sudo apt update && sudo apt upgrade -y
2. Install Mininet
sudo apt install mininet -y
3. Install Open vSwitch
sudo apt install openvswitch-switch -y
4. Install python and pip
sudo apt install python3 python3-pip -y
5. Install Ryu
pip3 install ryu
6. Then clone this repository
git clone https://github.com/wattanakkeo/sdn-optimization-project.git
