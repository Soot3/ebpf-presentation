#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <arpa/inet.h>
#include <netinet/in.h>

// Define a structure to store packet information
struct packet_info {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8 protocol;
    __u32 size;
    __u64 timestamp;
};

// Define BPF map for sharing data with userspace
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
    __uint(max_entries, 1024);
} packet_events SEC(".maps");

// Create a simple counter to track total packets
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u64));
    __uint(max_entries, 4);
} packet_counters SEC(".maps");

SEC("xdp_observer")
int packet_observer(struct xdp_md *ctx) {
    // Pointers to the start and end of packet data
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    
    // Get packet size
    __u32 packet_size = (__u32)(data_end - data);
    
    // Parse Ethernet header
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) {
        return XDP_PASS;  // Pass packet if Ethernet header is invalid
    }
    
    // Check if it's an IP packet
    if (eth->h_proto != htons(ETH_P_IP)) {
        // Not an IP packet, just pass it along
        return XDP_PASS;
    }
    
    // Parse IP header
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end || ip->ihl < 5) {
        return XDP_PASS;  // Pass packet if IP header is invalid
    }
    
    // Initialize packet_info structure
    struct packet_info pinfo = {};
    pinfo.src_ip = ip->saddr;
    pinfo.dst_ip = ip->daddr;
    pinfo.protocol = ip->protocol;
    pinfo.size = packet_size;
    pinfo.timestamp = bpf_ktime_get_ns();
    
    // Process different protocols
    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (void *)(ip + 1);
        if ((void *)(tcp + 1) > data_end) {
            return XDP_PASS;  // Pass packet if TCP header is invalid
        }
        pinfo.src_port = ntohs(tcp->source);
        pinfo.dst_port = ntohs(tcp->dest);
        
        // Update TCP packet counter
        __u32 tcp_key = 1;
        __u64 *tcp_count = bpf_map_lookup_elem(&packet_counters, &tcp_key);
        if (tcp_count) {
            __sync_fetch_and_add(tcp_count, 1);
        }
    } 
    else if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = (void *)(ip + 1);
        if ((void *)(udp + 1) > data_end) {
            return XDP_PASS;  // Pass packet if UDP header is invalid
        }
        pinfo.src_port = ntohs(udp->source);
        pinfo.dst_port = ntohs(udp->dest);
        
        // Update UDP packet counter
        __u32 udp_key = 2;
        __u64 *udp_count = bpf_map_lookup_elem(&packet_counters, &udp_key);
        if (udp_count) {
            __sync_fetch_and_add(udp_count, 1);
        }
    }
    
    // Update total packet counter
    __u32 total_key = 0;
    __u64 *total_count = bpf_map_lookup_elem(&packet_counters, &total_key);
    if (total_count) {
        __sync_fetch_and_add(total_count, 1);
    }
    
    // Send packet info to userspace via perf event
    bpf_perf_event_output(ctx, &packet_events, BPF_F_CURRENT_CPU, 
                         &pinfo, sizeof(pinfo));
    
    // Always pass the packet - we're only observing, not filtering
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";