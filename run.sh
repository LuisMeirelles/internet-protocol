#!/bin/bash

cargo build

sudo setcap cap_net_admin=eip target/debug/internet-protocol

./target/debug/internet-protocol &

pid=$!

sudo ip addr add 192.168.0.1/24 dev tun0
sudo ip link set up dev tun0

trap 'kill $pid' SIGINT SIGTERM

wait $pid
