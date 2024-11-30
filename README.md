# l3fwd

A simple L3 forwarding acceleration POC. It's an alternative implementation of the host chain. When I deploy a full-mesh network, I found that MLX's host chain has issues with opening circuits. So I run FRR and use the l3fwd program to accelerate forwarding, check https://github.com/edgesite/l3fwd/tree/main/lab for details. Compared to MLX's host chain, this program achieves high-performance forwarding on generic hardware and can integrate with common routing programs (such as FRR).

This program reads /32 routes from the kernel routing table, synthesizes srcmac, dstmac, and ifindex, and installs them into the BPF map. When receiving packets with known destination addresses, it bypasses the kernel network stack and directly redirects them.

## Known Issues

- On virtio-net, the program only works under xdpgeneric mode.

## Dependencies

- `apt install clang llvm libbpf-dev linux-headers-$(uname -r)`
- `go get github.com/cilium/ebpf/cmd/bpf2go`

## Build

```sh
sysctl net.ipv4.ip_forward=1
sysctl net.ipv4.conf.default.rp_filter=0
go generate
GOARCH=amd64 go run ./ ens20
```
