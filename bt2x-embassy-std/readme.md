
# Embassy `std` Example

This example can be used to debug the updater code on a target that is easier to debug (locally).

## Setup

First, create the tap0 interface. You only need to do this once.

```sh
sudo ip tuntap add name tap0 mode tap user $USER
sudo ip link set tap0 up
sudo ip addr add 192.168.69.100/24 dev tap0
sudo ip -6 addr add fe80::100/64 dev tap0
sudo ip -6 addr add fdaa::100/64 dev tap0
sudo ip -6 route add fe80::/64 dev tap0
sudo ip -6 route add fdaa::/64 dev tap0
```

Then you can connect to the OTA server if it's running in the docker setup.
