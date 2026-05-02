# sdn-optimization-project

This is a software defined networking traffic optimization project running on the Ryu framework. We created a custom switch that maps the shortest path based on the current network topology with Dijkstra's algorithm.

# How to set up
1. Update the system by using:\
sudo apt update\
AND\
sudo apt upgrade -y
3. Install Mininet using:\
sudo apt install mininet -y
4. Install Open vSwitch using:\
sudo apt install openvswitch-switch -y
5. Install python and pip:\
sudo apt install python3 python3-pip -y
7. Install Ryu:\
pip3 install ryu
8. Then clone this repository:\
git clone https://github.com/wattanakkeo/sdn-optimization-project.git
