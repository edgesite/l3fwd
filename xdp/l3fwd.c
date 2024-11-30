#include <bpf/bpf_endian.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <asm/byteorder.h>
#include <bpf/bpf_helpers.h>

struct route_key {
    __u32 dst_ip;
};

struct route_info {
    unsigned char dst_mac[ETH_ALEN];
    unsigned char src_mac[ETH_ALEN];
    __u32 ifindex;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct route_key);
    __type(value, struct route_info);
    __uint(max_entries, 10000);
} routes SEC(".maps");

SEC("xdp")
int l3fwd(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    
    struct ethhdr *eth = data;
    if ((void*)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *iph = (void*)(eth + 1);
    if ((void*)(iph + 1) > data_end)
        return XDP_PASS;

    struct route_key key = {
        .dst_ip = iph->daddr,
    };

    struct route_info *info = bpf_map_lookup_elem(&routes, &key);
    if (!info) {
        // bpf_printk("l3fwd: No route info found for destination IP: %pI4", &iph->daddr);
        return XDP_PASS;
    }

    if (info->ifindex != ctx->ingress_ifindex) {
        __builtin_memcpy(eth->h_source, info->src_mac, ETH_ALEN);   
        __builtin_memcpy(eth->h_dest, info->dst_mac, ETH_ALEN);
        // bpf_printk("l3fwd: redirecting %pI4 to interface %d, src interface %d", &iph->daddr, info->ifindex, ctx->ingress_ifindex);
        // bpf_printk("l3fwd: rewritten SMAC: %x:%x:%x:%x:%x:%x", eth->h_source[0], eth->h_source[1], eth->h_source[2], eth->h_source[3], eth->h_source[4], eth->h_source[5]);
        // bpf_printk("l3fwd: rewritten DMAC: %x:%x:%x:%x:%x:%x", eth->h_dest[0], eth->h_dest[1], eth->h_dest[2], eth->h_dest[3], eth->h_dest[4], eth->h_dest[5]);

        long rc = bpf_redirect(info->ifindex, 0);
        // bpf_printk("l3fwd: redirect res=%ld", rc);
        return rc;
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
