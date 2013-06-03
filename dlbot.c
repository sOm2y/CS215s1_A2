// standard includes
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>

// networking includes
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netdb.h>

#define STUDENT_SPECIFY 0
#define DNS_IP "8.8.8.8"

char* resolve_name(char* hostname);
void retrieve_data(char* inetaddr, char* hostname, char* requestpath);
void convert_host_format(unsigned char* dns, unsigned char* host);
void hexdump(char* data, int sz);

int main(int argc, char** argv) {
	if (argc != 2) err(1, "Example Usage: %s www.ietf.org/rfc/rfc1149.txt", argv[0]);

	char path[80];
	strcpy(path, strchr(argv[1], '/'));

	char host[80];
	strcpy(host, strtok(argv[1], "/"));

	char* host_ip = resolve_name(host);
	retrieve_data(host_ip, host, path);

	printf("\n\n");
	return 0;
}

/*
 * [NB:1] you need htons(3) to convert your local integer format to the network integer format.
 *
 * [NB:2]  The DNS host format precedes each section (bit between dots) with the number of characters in that section.
 * So "tools.ietf.org" becomes "\x05tools\x04ietf\x03org", the function convert_host_format will do that for you.
 */
void convert_host_format(unsigned char* dns, unsigned char* host) {
	int lock = 0, i;

	strcat((char*) host, ".");

	for (i = 0; i < (int) strlen((char*) host); i++) {
		if (host[i] == '.') {
			*dns++ = i - lock;
			for (; lock < i; lock++) {
				*dns++ = host[lock];
			}
			lock++; //or lock=i+1;
		}
	}
	*dns++ = '\0';
}


/*
 * You may find this useful while doing the DNS packet.
 */
void hexdump(char* data, int sz) {
	int i;
	for (i = 0; i < sz; i++) {
		printf("%02hhx", *(data + i));
		if ((i+1) % 16 == 0) {
			printf("\n");
		} else if (i != (sz - 1)) {
			printf(":");
		}
	}
}

/**
 *
 * BEGIN STUDENT MODIFIABLE CODE.
 *
 * You must configure these two functions, the first makes a DNS query and
 *
 */
#define STRING ""
#define VALUE 0
char* resolve_name(char* hostname) {
	int socketid;
	struct sockaddr_in socket_info;
	char* return_ip = malloc(sizeof(char) * 18);

	if ((socketid = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0) err(1, "socket(2) failed");

	// configure the socket_info
	memset((char *) &socket_info, 0, sizeof(socket_info));
	socket_info.sin_family = AF_INET;
	socket_info.sin_port = htons(53);
	if (inet_aton(DNS_IP, &socket_info.sin_addr) == 0) err(1, "inet_aton(3) failed");

	char buffer[2046]; // input and output buffer

	// header
	uint16_t header[6] = { // [NB:1]
			htons(0x6f0c), // 2 byte ID: this is arbitrary
			htons(0x8180), // flags (you have to work these out, try doing it in hex)
			htons(1), // number of questions
			htons(4), // number of answers
			htons(9), // number of nameservers
			htons(10) // number of additional records
			};

	char converted_name[80]; // you need to store the name in here. [NB:2]
	convert_host_format(converted_name, hostname);

	// construct the buffer
	memcpy(buffer, header, sizeof(header)); // copy the header into the
	memcpy(buffer + sizeof(header), converted_name, strlen(converted_name)); // copy the string after the header (including the null)
	*(buffer + sizeof(header) + strlen(converted_name) + 1) = 0x00; // append the query type after the string (CNAME)
	*(buffer + sizeof(header) + strlen(converted_name) + 2) = 0x01;
	*(buffer + sizeof(header) + strlen(converted_name) + 3) = 0x00; // append the address type after the query type (AN)
	*(buffer + sizeof(header) + strlen(converted_name) + 4) = 0x01;

	int buffer_size = sizeof(header) + strlen(converted_name) + 5;

	// send the packet
	sendto(socketid, (char*) buffer, buffer_size, 0, (struct sockaddr*) &socket_info, sizeof(socket_info));
	// get the response
	socklen_t len = sizeof socket_info;
	recvfrom(socketid, (char*) buffer, 2046, 0, (struct sockaddr*) &socket_info, sizeof(socket_info));

	// as long as your work out the offset of the first return address, you don't need to
	// hint: %hhu prints an unsigned 8 bit number
	sprintf(return_ip,"%hhu.%hhu.%hhu.%hhu", buffer[VALUE], buffer[VALUE], buffer[VALUE], buffer[VALUE]);

	close(socketid);
	return return_ip;
}

#define HTTP_BUF_LEN 2096
void retrieve_data(char* inetaddr, char* hostname, char* requestpath) {
	int socketid;
	struct sockaddr_in socket_info;
	char buffer[HTTP_BUF_LEN];

	if ((socketid = socket(AF_INET, SOCK_STREAM, 0)) < 0) err(1, "socket(2) failed");

	memset((char *) &socket_info, 0, sizeof(socket_info));
	socket_info.sin_family = AF_INET;
	socket_info.sin_port = htons(80);
	if (inet_aton(inetaddr, &socket_info.sin_addr.s_addr) == 0) err(1, "inet_aton(3) failed");

	if (connect(socketid, (struct sockaddr*) &socket_info, sizeof(socket_info)) != 0) err(1, "connect(2) failed");

	const char* request_format_string = STRING;
	sprintf(buffer, request_format_string, requestpath, hostname);
	send(socketid, buffer, strlen(buffer), 0);

	int bytes_read;
	int strip_header = 1;
	while ((bytes_read = recv(socketid, buffer, sizeof(buffer), 0)) > 0) {
		if (strip_header) {
			char* end_of_header = strstr(buffer, STRING);
			printf("%s", end_of_header);
			strip_header = 0;
		} else {
			printf("%s", buffer);
		}
	}

	close(socketid);
}

