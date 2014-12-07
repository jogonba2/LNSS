#define string_htons(A) (htons(atoi(A)))
#define string_addr(A)  (inet_addr(A))
#define MAX(a,b) ( (a) >= (b) ? (a) : (b) )
#define MIN(a,b) ( (a) <= (b) ? (a) : (b) )

// Show info of header creation //
#define SHOW_CREATED_IP_HEADER(ip_hdr) (fprintf(stdout,"|****************** IP HEADER *******************|\n\
														| version=%d | ihl=%d | tos=%d | length=%d       |\n\
														|------------|--------|--------|-----------------|\n\
														| identification=%d   |x=%d|D=%d|M=%d|offset=%d  |\n\
														|---------------------|--------------------------|\n\
														| ttl=%d |protocol=%d |       checksum=%d        |\n\
														|---------------------|--------------------------|\n\
														| source_address=%d                              |\n\
														|------------------------------------------------|\n\
														| remote_address=%d                              |\n\
														|------------------------------------------------|\n\
														| optional=%d                                    |\n\
														|------------------------------------------------|\n",\
														ip_hdr->version,ip_hdr->ihl,ip_hdr->tos,ip_hdr->total_length,\
														ip_hdr->identification,ip_hdr->zero_flag,ip_hdr->do_not_fragments,\
														ip_hdr->more_fragments,ip_hdr->fragment_offset,\
														ip_hdr->ttl,ip_hdr->protocol,ip_hdr->checksum,\
														ip_hdr->source_address,ip_hdr->remote_address,\
														ip_hdr->optional))
					
#define SHOW_CREATED_TCP_HEADER(tcp_hdr) (fprintf(stdout,"|***************** TCP HEADER *******************************************|\
														  | source port=%d      | destination port=%d      						   |\n\
														  |------------|--------|--------|-----------------------------------------|\n\
														  |              sequence number=%d                                        |\n\
														  |---------------------|--------------------------------------------------|\n\
														  |              acknowledgment=%d                                         |\n\
														  |---------------------|--------------------------------------------------|\n\
														  |offset=%d|reserved=%d|C=%d|E=%d|U=%d|A=%d|P=%d|R=%d|S=%d|F=%d|window=%d |\n\
														  |---------------------|--------------------------------------------------|\n\
														  |    checksum=%d      |  urg pointer=%d          						   |\n\
														  |------------------------------------------------------------------------|\n\
														  |                tcp options=%d                  						   |\n\
														  |------------------------------------------------------------------------|\n\n",\
														  tcp_hdr->source_port,tcp_hdr->remote_port,\
														  tcp_hdr->num_sequence,tcp_hdr->ack_number,\
														  tcp_hdr->offset,tcp_hdr->reserved,tcp_hdr->flag_reduced,\
														  tcp_hdr->flag_echo,tcp_hdr->flag_urg,tcp_hdr->flag_ack,\
														  tcp_hdr->flag_push,tcp_hdr->flag_rst,tcp_hdr->flag_syn,\
														  tcp_hdr->flag_fin,tcp_hdr->window,tcp_hdr->checksum,\
														  tcp_hdr->urg_pointer,tcp_hdr->tcp_options))

#define SHOW_CREATED_UDP_HEADER(tcp_hdr) (fprintf(stdout,"| UDP HEADER |\n"))
#define SHOW_CREATED_ICMP_HEADER(icmp_hdr) (fprintf(stdout,"| ICMP HEADER |\n"))
#define SHOW_CREATED_IGMP_HEADER(icmp_hdr) (fprintf(stdout,"| IGMP HEADER |\n"))
// ... //



// Add your macros //
