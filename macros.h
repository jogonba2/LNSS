#define string_htons(A) (htons(atoi(A)))
#define string_addr(A)  (inet_addr(A))
#define MAX(a,b) ( (a) >= (b) ? (a) : (b) )
#define MIN(a,b) ( (a) <= (b) ? (a) : (b) )

// Show info of header creation //
#define SHOW_CREATED_IP_HEADER(ip_hdr) (fprintf(stdout,"%c,%d,%d\n",ip_hdr->protocol,ip_hdr->source_address,ip_hdr->remote_address))
#define SHOW_CREATED_TCP_HEADER(tcp_hdr) (fprintf(stdout,"Rest...\n"))
#define SHOW_CREATED_UDP_HEADER(tcp_hdr) (fprintf(stdout,"Rest...\n"))
// ... //



// Add your macros //
