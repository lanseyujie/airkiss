# AirKiss

WeChat AirKiss Library for Golang.

## Usage

```shell
# prepare
sudo apt install -y libpcap-dev iw
sudo service NetworkManager stop
sudo ip link set <interface> down
sudo iw dev <interface> set type monitor
sudo ip link set <interface> up
sudo iw dev <interface> set channel <channel>
sudo iw dev <interface> info

# recover
sudo ip link set <interface> down
sudo iw dev <interface> set type managed
sudo ip link set <interface> up
sudo iwlist <interface> scanning
sudo service NetworkManager start
```
