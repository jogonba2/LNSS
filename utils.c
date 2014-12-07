#include "utils.h"
#include <time.h>
#include <stdlib.h>
#include <arpa/inet.h>


unsigned short checksum_md5(unsigned short *buffer, int length)
{
    unsigned long sum;
    for(sum=0; length>0; length--){
        sum += *buffer++;
        sum = (sum >> 16) + (sum & 0xffff);
        sum += (sum >> 16);
    }
    return (unsigned short)(~sum);
}


unsigned char* generate_random_ip_v4(){
	char first_byte = (rand()%254)&0xFF;
	char scond_byte = (rand()%254)&0xFF;
	char third_byte = (rand()%254)&0xFF;
	char fourt_byte = (rand()%254)&0xFF;
	uint32_t ip = ((((((((0x00000000|first_byte)<<8)|scond_byte)<<8)|third_byte)<<8)|fourt_byte)<<8)|0x13;
    struct in_addr ip_addr;
    ip_addr.s_addr = ip;
	char* addr = inet_ntoa(ip_addr);
	return addr;
}

unsigned char* generate_random_valid_port(){
	char* res = 0x00;
	//sprintf(res,"%d",(rand()%65535)&0xFFFF);
	return res;
}

