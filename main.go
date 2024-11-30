//go:build linux && amd64

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang l3fwd xdp/l3fwd.c
package main

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

type RouteInfo struct {
	SrcMAC  [6]byte
	DstMAC  [6]byte
	Ifindex uint32
}

func ipToUint32(ip net.IP) uint32 {
	ip = ip.To4()
	return binary.BigEndian.Uint32(ip)
}

func listRoutes() ([]netlink.Route, error) {
	return netlink.RouteList(nil, netlink.FAMILY_V4)
}

func installRoutes(objs *l3fwdObjects, routes []netlink.Route) error {
	neighborMap := make(map[int][]netlink.Neigh)
	linkMap := make(map[int]netlink.Link)
	lookupLink := func(route netlink.Route) error {
		if _, ok := linkMap[route.LinkIndex]; !ok {
			link, err := netlink.LinkByIndex(route.LinkIndex)
			if err != nil {
				return fmt.Errorf("getting link: %v", err)
			}
			linkMap[route.LinkIndex] = link
		}
		return nil
	}
	lookupNeighbors := func(route netlink.Route) error {
		if _, ok := neighborMap[route.LinkIndex]; !ok {
			neigh, err := netlink.NeighList(route.LinkIndex, netlink.FAMILY_V4)
			if err != nil {
				return fmt.Errorf("listing neighbors: %v", err)
			}
			neighborMap[route.LinkIndex] = neigh
		}
		return nil
	}

	for _, route := range routes {
		if route.Dst == nil || route.Dst.Mask.String() != "ffffffff" {
			continue // Only process /32 routes
		}

		if err := lookupLink(route); err != nil {
			log.Printf("ensuring link: %v", err)
			continue
		}
		if err := lookupNeighbors(route); err != nil {
			log.Printf("ensuring neighbors: %v", err)
			continue
		}

		var nh *netlink.Neigh
		neighbors := neighborMap[route.LinkIndex]
		for _, neigh := range neighbors {
			if neigh.IP.Equal(route.Gw) {
				nh = &neigh
				break
			}
		}

		if nh == nil {
			log.Printf("no neighbor found for route %v", route.Dst)
			continue
		}

		key := ipToUint32(route.Dst.IP)

		fmt.Printf("link: %v\n", linkMap[route.LinkIndex].Attrs().HardwareAddr)
		info := RouteInfo{}
		copy(info.SrcMAC[:], linkMap[route.LinkIndex].Attrs().HardwareAddr)
		copy(info.DstMAC[:], nh.HardwareAddr)
		info.Ifindex = uint32(route.LinkIndex)

		if err := objs.RouteMap.Put(&key, &info); err != nil {
			log.Printf("installing route %v: %v", route.Dst, err)
			continue
		}
		log.Printf("installed route %v: DMAC %02x, SMAC %02x", route.Dst, info.DstMAC, info.SrcMAC)
	}

	return nil
}

func debugTrace() {
	f, err := os.Open("/sys/kernel/debug/tracing/trace_pipe")
	if err != nil {
		log.Printf("opening trace_pipe: %v", err)
		return
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		fmt.Println(scanner.Text())
	}
}

func main() {
	if len(os.Args) != 2 {
		log.Fatalf("Usage: %s <interface>", os.Args[0])
	}
	ifaceName := os.Args[1]

	objs := l3fwdObjects{}
	if err := loadL3fwdObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %v", err)
	}
	defer objs.Close()

	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		log.Fatalf("getting interface: %v", err)
	}

	l, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.L3fwd,
		Interface: iface.Index,
		Flags:     link.XDPAttachFlags(link.XDPGenericMode),
	})
	if err != nil {
		log.Fatalf("attaching XDP: %v", err)
	}
	defer l.Close()

	// Read debug logs
	go debugTrace()

	// Install existing routes
	routes, err := listRoutes()
	if err != nil {
		log.Fatalf("listing routes: %v", err)
	}
	if err := installRoutes(&objs, routes); err != nil {
		log.Fatalf("installing routes: %v", err)
	}

	// Subscribe to route updates
	updates := make(chan netlink.RouteUpdate)
	done := make(chan struct{})
	defer close(done)

	if err := netlink.RouteSubscribe(updates, done); err != nil {
		log.Fatalf("subscribing to routes: %v", err)
	}

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)

	log.Printf("Listening for route updates on %s...", ifaceName)

	for {
		select {
		case update := <-updates:
			if update.Route.Dst == nil || update.Route.Dst.Mask.String() != "ffffffff" {
				continue // Only process /32 routes
			}

			key := ipToUint32(update.Route.Dst.IP)

			switch update.Type {
			case unix.RTM_NEWROUTE:
				if err := installRoutes(&objs, []netlink.Route{update.Route}); err != nil {
					log.Printf("updating routes: %v", err)
				}
			case unix.RTM_DELROUTE:
				if err := objs.RouteMap.Delete(&key); err != nil && err != ebpf.ErrKeyNotExist {
					log.Printf("deleting route: %v", err)
				}
			}

		case sig := <-sigs:
			log.Printf("Received signal %v", sig)
			return
		}
	}
}
