#include "queue.h"
#include "lib.h"
#include "protocols.h"

#include <arpa/inet.h>
#include <string.h>

#define R_TABLE_MAX_ENTRIES 80000
#define ARP_TABLE_MAX_ENTRIES 80000
#define ETHERTYPE_IP 0x0800
#define ETHERTYPE_ARP 0x0806
#define ICMP_PROTOCOL 1
#define TIME_EXCEEDED_TYPE 11
#define TIME_EXCEEDED_CODE 0
#define DEST_UNREACHABLE_TYPE 3
#define DEST_UNREACHABLE_CODE 0
#define ARP_TABLE_FILE "arp_table.txt"

// Compare function for qsort -- sort by prefix and mask (descending) 
int cmpfunc(const void *a, const void *b)
{
	struct route_table_entry *entry1 = (struct route_table_entry *)a;
	struct route_table_entry *entry2 = (struct route_table_entry *)b;

	if (entry1->prefix < entry2->prefix)
		return 1;
	else if (entry1->prefix > entry2->prefix)
		return -1;
	else if (entry1->mask < entry2->mask)
		return 1;
	else if (entry1->mask > entry2->mask)
		return -1;

	return 0;
}

// Search for the best route in the routing table
struct route_table_entry *get_best_route(u_int32_t ip, struct route_table_entry *r_table, int r_table_size)
{
	for (int i = 0; i < r_table_size; i++)
		if ((ip & r_table[i].mask) == r_table[i].prefix)
			return &r_table[i];

	return NULL;
}

// Get the MAC address from the ARP table
u_int8_t *get_mac_from_arp_table(struct arp_table_entry *arp_table, int arp_table_size, u_int32_t ip)
{
	for (int i = 0; i < arp_table_size; i++)
		if (arp_table[i].ip == ip)
			return arp_table[i].mac;

	return NULL;
}

// Sends an ICMP packet with the given type and code -- In our case: "Time exceeded" and "Destination unreachable"
void send_icmp_packet(int interface, struct ether_header *eth_hdr, struct iphdr *ip_hdr, int type, int code) {
	// Get the MAC address of the interface
	uint8_t *interface_mac = malloc(6 * sizeof(uint8_t));
	get_interface_mac(interface, interface_mac);

	// Get the IP address of the interface
	in_addr_t interface_ip = inet_addr(get_interface_ip(interface));
	
	struct ether_header *icmp_eth_hdr = malloc(sizeof(struct ether_header));
	struct iphdr *icmp_ip_hdr = malloc(sizeof(struct iphdr));
	struct icmphdr *icmp_icmp_hdr = malloc(sizeof(struct icmphdr));

	// Create the ICMP packet
	icmp_eth_hdr->ether_type = htons(ETHERTYPE_IP);
	memcpy(icmp_eth_hdr->ether_shost, interface_mac, 6);
	memcpy(icmp_eth_hdr->ether_dhost, eth_hdr->ether_shost, 6);

	// Create the IP header
	icmp_ip_hdr->version = 4; 
	icmp_ip_hdr->ihl = 5; 
	icmp_ip_hdr->tos = 0; 
	icmp_ip_hdr->tot_len = htons(sizeof(struct iphdr) + sizeof(struct icmphdr));
	icmp_ip_hdr->id = 0;
	icmp_ip_hdr->frag_off = 0;
	icmp_ip_hdr->ttl = 64;
	icmp_ip_hdr->protocol = ICMP_PROTOCOL;
	icmp_ip_hdr->saddr = interface_ip;
	icmp_ip_hdr->daddr = ip_hdr->saddr;
	icmp_ip_hdr->check = 0;
	icmp_ip_hdr->check = checksum((uint16_t *)icmp_ip_hdr, sizeof(struct iphdr));

	// Create the ICMP header
	icmp_icmp_hdr->type = type;
	icmp_icmp_hdr->code = code;
	icmp_icmp_hdr->checksum = 0;
	icmp_icmp_hdr->checksum = checksum((uint16_t *)icmp_icmp_hdr, sizeof(struct icmphdr));

	// Create the packet
	char *icmp_packet = malloc(sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr));
	memcpy(icmp_packet, icmp_eth_hdr, sizeof(struct ether_header));
	memcpy(icmp_packet + sizeof(struct ether_header), icmp_ip_hdr, sizeof(struct iphdr));
	memcpy(icmp_packet + sizeof(struct ether_header) + sizeof(struct iphdr), icmp_icmp_hdr, sizeof(struct icmphdr));

	// Add the first 64 bits of the original packet
	memcpy(icmp_packet + sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr), ip_hdr + sizeof(struct iphdr), 64);

	// Compute length of the packet
	size_t icmp_packet_len = sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr) + 64;
				
	// Send the packet
	send_to_link(interface, icmp_packet, icmp_packet_len); 

	// Free the allocated memory for interface_mac and the ICMP packet
	free(interface_mac);
	free(icmp_eth_hdr);
	free(icmp_ip_hdr);
	free(icmp_icmp_hdr);
	free(icmp_packet);
}

int main(int argc, char *argv[])
{
	char buf[MAX_PACKET_LEN];

	// Do not modify this line
	init(argc - 2, argv + 2);

	// Initialize the routing table
	struct route_table_entry *r_table = malloc(sizeof(struct route_table_entry) * R_TABLE_MAX_ENTRIES);
	int r_table_size = read_rtable(argv[1], r_table);

	// Sort the routing table by the mask and prefix (descending)
	qsort(r_table, r_table_size, sizeof(struct route_table_entry), cmpfunc);

	// Initialize the ARP table
	struct arp_table_entry *arp_table = malloc(sizeof(struct arp_table_entry) * ARP_TABLE_MAX_ENTRIES);
	int arp_table_size = parse_arp_table(ARP_TABLE_FILE, arp_table);

	while (1) {
		fprintf(stderr, "Waiting for packets...\n");

		int interface;
		size_t len;

		interface = recv_from_any_link(buf, &len);
		DIE(interface < 0, "recv_from_any_links");

		struct ether_header *eth_hdr = (struct ether_header *) buf;
		/* Note that packets received are in network order,
		any header field which has more than 1 byte will need to be conerted to
		host order. For example, ntohs(eth_hdr->ether_type). The oposite is needed whens
		sending a packet on the link, */

		fprintf(stderr, "Received packet on interface %d\n", interface);

		// Check if the packet has the right size, if not drop it
		if (len < sizeof(struct ether_header)) {
			fprintf(stderr, "Packet too short\n");
			continue;
		}

		// Get the MAC address of the interface
		uint8_t *interface_mac = malloc(6 * sizeof(uint8_t));
		get_interface_mac(interface, interface_mac);

		// Get the IP address of the interface
		in_addr_t interface_ip = inet_addr(get_interface_ip(interface));

		// If the packet is not for the router, forward it => Check the type of the packet(ARP/IP)
		switch (ntohs(eth_hdr->ether_type)) 
		{
		case ETHERTYPE_IP:
			// Get the IP header
			struct iphdr *ip_hdr = (struct iphdr *)(buf + sizeof(struct ether_header));

			fprintf(stderr, "Received IP packet\n");

			// Check if the router is the actual destination
			if (ip_hdr->daddr == interface_ip) {
				// Check if the packet is an ICMP packet
				if (ip_hdr->protocol == ICMP_PROTOCOL) {
					fprintf(stderr, "Received ICMP packet\n");

					// Get the ICMP header
					struct icmphdr *icmp_hdr = (struct icmphdr *)(buf + sizeof(struct ether_header) + sizeof(struct iphdr));

					// Check if the ICMP packet is an echo request
					if (icmp_hdr->type == 8) {
						fprintf(stderr, "Received ICMP echo request\n");

						// Swap the MAC addresses
						memcpy(eth_hdr->ether_shost, eth_hdr->ether_dhost, 6);
						memcpy(eth_hdr->ether_dhost, interface_mac, 6);

						// Swap the IP addresses
						uint32_t aux_ip = ip_hdr->saddr;
						ip_hdr->saddr = ip_hdr->daddr;
						ip_hdr->daddr = aux_ip;

						// Update the IP checksum
						ip_hdr->check = 0;
						ip_hdr->check = checksum((uint16_t *)ip_hdr, sizeof(struct iphdr));

						// Create the ICMP echo reply
						icmp_hdr->type = 0;
						icmp_hdr->checksum = 0;
						icmp_hdr->checksum = checksum((uint16_t *)icmp_hdr, sizeof(struct icmphdr));

						// Send the packet
						send_to_link(interface, buf, sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr));
					}
				}

				// Free the allocated memory for interface_mac
				free(interface_mac);
			} else {
				// The router is not the destination, so we need to forward the packet

				fprintf(stderr, "Forwarding packet...\n");

				// Verify the checksum
				uint16_t old_checksum = ip_hdr->check;
				ip_hdr->check = 0;
				uint16_t new_checksum = htons(checksum((uint16_t *)ip_hdr, sizeof(struct iphdr)));
				ip_hdr->check = new_checksum;

				// If the checksums don't match, drop the packet
				if (old_checksum != new_checksum) {
					fprintf(stderr, "Checksums don't match\n");

					// Free the allocated memory for interface_mac
					free(interface_mac);

					continue;
				}

				// Check the TTL
				if (ip_hdr->ttl <= 1) {
					fprintf(stderr, "TTL is 0 or 1, so we send ICMP packet with type \"Time exceeded\"\n");

					// Send an ICMP packet with "Time exceeded"
					send_icmp_packet(interface, eth_hdr, ip_hdr, TIME_EXCEEDED_TYPE, TIME_EXCEEDED_CODE);
					
					// Free the allocated memory for interface_mac
					free(interface_mac);

					continue;
				} 

				fprintf(stderr, "TTL is greater than 1, so we decrement it and forward the packet\n");

				// Decrement the TTL
				ip_hdr->ttl--;

				fprintf(stderr, "Finding the best route...\n");
				
				// Find the best route
				struct route_table_entry *best_route = NULL;
				best_route = get_best_route(ip_hdr->daddr, r_table, r_table_size);

				// Check if the route doesn't exists
				if (best_route == NULL) {
					fprintf(stderr, "The route doesn't exist, so we ned an ICMP type \"Destination ureachable\"\n");

					// Send an ICMP packet with "Destination unreachable"
					send_icmp_packet(interface, eth_hdr, ip_hdr, DEST_UNREACHABLE_TYPE, DEST_UNREACHABLE_CODE);
					
					// Free the allocated memory for interface_mac
					free(interface_mac);

					continue;
				}

				fprintf(stderr, "The best route is found, so we update the packet and send it\n");

				// Update the IP checksum with the formula from LAB 4
				ip_hdr->check = ~(~old_checksum + ~((uint16_t)ip_hdr->ttl + 1) + (uint16_t)ip_hdr->ttl) - 1;

				// Update the MAC addresses
				memcpy(eth_hdr->ether_shost, interface_mac, 6);
				memcpy(eth_hdr->ether_dhost, get_mac_from_arp_table(arp_table, arp_table_size, best_route->next_hop), 6);

				fprintf(stderr, "Forwarding the packet...\n");

				// Send the packet
				send_to_link(best_route->interface, buf, len);

				// Free the allocated memory for interface_mac
				free(interface_mac);
			}

			break;
		
		case ETHERTYPE_ARP:
			// NOT IMPLEMENTED => TOO MANY HOMEWORKS :(
			break;

		default:
			break;
		}
	}

	// Free the allocated memory
	free(r_table);
	free(arp_table);
}

