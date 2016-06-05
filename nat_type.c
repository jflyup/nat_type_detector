#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include <sys/time.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h> 

#define DEFAULT_STUN_SERVER_PORT 3478
#define DEFAULT_LOCAL_PORT 34780

static const char* STUN_SERVER = "stun.ideasip.com";

typedef enum {
	Blocked,
	OpenInternet,
	FullCone,
	RestricNAT,
	RestricPortNAT,
	SymmetricNAT,
	error,
} nat_type_t;

static const char* nat_types[] = {
	"blocked",
	"open internet",
	"full cone",
	"restricted NAT",
	"Port-restricted cone",
	"symmetric NAT",
	"error"
};

// define stun address families
const static uint8_t  IPv4Family = 0x01;
const static uint8_t  IPv6Family = 0x02;

// The following are codepoints used in the requested transport header, they
// are the same values used in the IPv4 and IPv6 headers
const static uint32_t RequestedTransportUdp = 17;
const static uint32_t RequestedTransportTcp = 6;

// define  flags  
const static uint32_t ChangeIpFlag   = 0x04;
const static uint32_t ChangePortFlag = 0x02;


// Message Type - from RFC5389
//
//        0                   1                   2                   3
//        0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//       |0 0|     STUN Message Type     |         Message Length        |
//       |   |M|M|M|M|M|C|M|M|M|C|M|M|M|M|                               |
//       |   |1|1|9|8|7|1|6|5|4|0|3|2|1|0|                               |
//       |   |1|0| | | | | | | | | | | | |                               |
//       |   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               |
//
// M11 through M0 represent a 12-bit encoding of the method
// C1 through C0 represent a 2 bit encoding of the class.
// 2-bit Class Values are: 00=Request, 01=Indicaiton, 
//                         10=Success Response, 11=Error Response
//

const static uint16_t StunClassRequest            = 0x0000;
const static uint16_t StunClassIndication         = 0x0010;
const static uint16_t StunClassSuccessResponse    = 0x0100;
const static uint16_t StunClassErrorResponse      = 0x0110; 

// define types for a stun message - RFC5389
const static uint16_t BindRequest                 = 0x0001;
const static uint16_t BindResponse				  = 0x0101;
const static uint16_t SharedSecretMethod          = 0x0002;  // deprecated by RFC5389 (used for backwards compatibility to RFC3489 only)

const static uint16_t ResponseAddress  = 0x0002;
const static uint16_t ChangeRequest    = 0x0003; /* CHANGE-REQUEST, and CHANGED-ADDRESS, that have been
												 removed from rfc5389.*/
// const static constants cannot be used in case label
#define MappedAddress 0x0001
#define SourceAddress 0x0004
#define ChangedAddress 0x0005
const static uint16_t MessageIntegrity = 0x0008;
const static uint16_t ErrorCode        = 0x0009;
const static uint16_t UnknownAttribute = 0x000A;
const static uint16_t ReflectedFrom    = 0x000B;
const static uint16_t Realm            = 0x0014;
const static uint16_t Nonce            = 0x0015;
const static uint16_t XorMappedAddress = 0x0020;

const static uint32_t StunMagicCookie  = 0x2112A442; // introduced since rfc 5389

typedef struct { uint32_t longpart[4]; }  UInt128;
typedef struct { uint32_t longpart[3]; }  UInt96;

#ifndef htonll
uint64_t htonll(uint64_t v) {
	union { uint32_t lv[2]; uint64_t llv; } u;
	u.lv[0] = htonl(v >> 32);
	u.lv[1] = htonl(v & 0xFFFFFFFFULL);
	return u.llv;
}
#endif

char* encode16(char* buf, uint16_t data)
{
	uint16_t ndata = htons(data);
	memcpy(buf, (void*)(&ndata), sizeof(uint16_t));
	return buf + sizeof(uint16_t);
}

char* encode32(char* buf, uint32_t data)
{
	uint32_t ndata = htonl(data);
	memcpy(buf, (void*)(&ndata), sizeof(uint32_t));

	return buf + sizeof(uint32_t);
}

char* encode64(char* buf, const uint64_t data)
{
	uint64_t ndata = htonll(data);
	memcpy(buf, (void*)(&ndata), sizeof(uint64_t));

	return buf + sizeof(uint64_t);
}

char* encodeAtrUInt32(char* ptr, uint16_t type, uint32_t value)
{
	ptr = encode16(ptr, type);
	ptr = encode16(ptr, 4);
	ptr = encode32(ptr, value);
	return ptr;
}

char* encodeAtrUInt64(char* ptr, uint16_t type, uint64_t value)
{
	ptr = encode16(ptr, type);
	ptr = encode16(ptr, 8);
	ptr = encode64(ptr, value);
	return ptr;
}

char* encode(char* buf, const char* data, unsigned int length)
{
	memcpy(buf, data, length);
	return buf + length;
}

typedef struct 
{
	uint32_t magicCookie; // rfc 5389
	UInt96 tid;
} Id;

typedef struct 
{
	uint16_t msgType;
	uint16_t msgLength; // message length not including header
	union
	{
		UInt128 magicCookieAndTid;
		Id id;
	};
} StunHeader;

typedef struct
{
	uint16_t type;
	uint16_t length;
} StunAtrHdr;

typedef struct
{
	uint8_t family;
	uint16_t port;
	union
	{
		uint32_t ipv4;  // in host byte order
		UInt128 ipv6; // in network byte order
	} addr;
} StunAtrAddress;

int stunParseAtrAddress( char* body, unsigned int hdrLen, StunAtrAddress* result )
{
	if (hdrLen != 8 /* ipv4 size */ && hdrLen != 20 /* ipv6 size */ )
	{
		return -1;
	}
	body++;  // Skip pad
	result->family = *body++;

	uint16_t nport;
	memcpy(&nport, body, 2); body+=2;
	result->port = ntohs(nport);

	if (result->family == IPv4Family)
	{		
		uint32_t naddr;
		memcpy(&naddr, body, sizeof(uint32_t)); body+=sizeof(uint32_t);
		result->addr.ipv4 = ntohl(naddr);
		// Note:  addr.ipv4 is stored in host byte order
		return 0;
	}
	else if (result->family == IPv6Family)
	{
		printf("ipv6 is not implemented yet");
		return -1;
	}
	else
	{
		return -1;
	}

	return -1;
}

void gen_random_string(char *s, const int len) {
	static const char alphanum[] =
		"0123456789"
		"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
		"abcdefghijklmnopqrstuvwxyz";

	int i = 0;
	for (; i < len; ++i) {
		s[i] = alphanum[rand() % (sizeof(alphanum) - 1)];
	}

	s[len] = 0;
}

int send_bind_request(int sock, const char* remote_host, uint16_t remote_port, uint32_t change_ip, uint32_t change_port, StunAtrAddress* addr_array)
{
	char* buf = malloc(512);
	char* ptr = buf;

	StunHeader h;
	h.msgType = StunClassRequest | BindRequest; //This unfortunate encoding is due to assignment of values in [RFC3489]
	//h.id.magicCookie = htonl(StunMagicCookie); // no magic cookie in rfc 3478
	//
	gen_random_string((char*)&h.magicCookieAndTid, 16);

	ptr = encode16(ptr, h.msgType);
	char* lengthp = ptr;
	ptr = encode16(ptr, 0);
	ptr = encode(ptr, (const char*)&h.id, sizeof(h.id));

	if (change_ip || change_port)
	{
		ptr = encodeAtrUInt32(ptr, ChangeRequest, change_ip | change_port);

		// message length
		encode16(lengthp, ptr - buf - sizeof(StunHeader));
	}

	// todo
	/**
	* It is RECOMMENDED that the server check the Binding Request for a
	* MESSAGE-INTEGRITY attribute
	**/

	struct sockaddr_in remote_addr;
    	struct hostent *server = gethostbyname(remote_host);
	if (server == NULL) {
		fprintf(stderr, "no such host as %s\n", remote_host);
		return -1;
	}
	remote_addr.sin_family = AF_INET;
	memcpy(&remote_addr.sin_addr.s_addr, server->h_addr_list[0], server->h_length);
	remote_addr.sin_port = htons(3478); 

	if (-1 == sendto(sock, buf, ptr - buf, 0, (struct sockaddr *)&remote_addr, sizeof(remote_addr)))
	{
		return -1;
	}

	socklen_t fromlen = sizeof remote_addr;

	struct timeval tv;
	tv.tv_sec = 1;
	tv.tv_usec = 0;
	setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv));

	int recv_bytes = recvfrom(sock, buf, 512, 0, (struct sockaddr *)&remote_addr, &fromlen);

	if (recv_bytes < sizeof(StunHeader))
	{
		return -1;
	}

	StunHeader reply_header;
	memcpy(&reply_header, buf, sizeof(StunHeader));

	uint16_t msg_type = ntohs(reply_header.msgType);

	//if (msg_type == )

	char* body = buf + sizeof(StunHeader);
	uint16_t size = ntohs(reply_header.msgLength);

	StunAtrHdr* attr;
	unsigned int attrLen;
	unsigned int attrLenPad;  
	int atrType;

	while (size > 0)
	{
		attr = (StunAtrHdr*)(body);

		attrLen = ntohs(attr->length);
		// attrLen may not be on 4 byte boundary, in which case we need to pad to 4 bytes when advancing to next attribute
		attrLenPad = attrLen % 4 == 0 ? 0 : 4 - (attrLen % 4);  
		atrType = ntohs(attr->type); // SDP::SdpNtohx

		if ( attrLen + attrLenPad + 4 > size ) 
		{
			return -1;
		}

		body += 4; // skip the length and type in attribute header
		size -= 4;

		switch (atrType)
		{
		case MappedAddress:
			if (stunParseAtrAddress(body, attrLen, addr_array))
			{
				return -1;
			}
			break;
		case ChangedAddress:
			if (stunParseAtrAddress( body, attrLen, addr_array + 1))
			{
				return -1;
			}
			break;
		case SourceAddress:
			if (stunParseAtrAddress( body, attrLen, addr_array + 2))
			{
				return -1;
			}
			break;
		default:
			// ignore
			break;

		}
		body += attrLen+attrLenPad;
		size -= attrLen+attrLenPad;
	}
	
	free(buf);
	return 0;
}

nat_type_t detect_nat_type(const char* stun_host, uint16_t stun_port, const char* local_host, uint16_t local_port)
{
	int s;
	if((s = socket(AF_INET, SOCK_DGRAM, 0)) <= 0)  
	{  
		return error;  
	}

	int reuse_addr = 1;

	setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (const char*)&reuse_addr, sizeof(reuse_addr));

	struct sockaddr_in local_addr;
	local_addr.sin_family = AF_INET;
	if (local_host)
		local_addr.sin_addr.s_addr = inet_addr(local_host);
	else
		local_addr.sin_addr.s_addr = inet_addr("0.0.0.0");

	local_addr.sin_port = htons(DEFAULT_LOCAL_PORT);  
	bind(s, (struct sockaddr *)&local_addr, sizeof(local_addr));

	if (!stun_host)
		stun_host = STUN_SERVER;

	// 0 for mapped addr, 1 for changed addr, 2 for source addr
	StunAtrAddress bind_result[3];

	memset(bind_result, 0, sizeof(StunAtrAddress) * 3);
	if (send_bind_request(s, stun_host, stun_port, 0, 0, bind_result))
	{
		return Blocked;
	}
	
	uint32_t ext_ip = bind_result[0].addr.ipv4;
	uint32_t ext_port = bind_result[0].port;
	uint32_t changed_ip = bind_result[1].addr.ipv4;
	uint32_t changed_port = bind_result[1].port;
	uint32_t source_ip = bind_result[2].addr.ipv4;
	uint32_t source_port = bind_result[2].port;

	// some implementations of stun server don't offer source address.
	if (ext_ip == source_ip)
	{
		return OpenInternet;
	}
	else if (send_bind_request(s, stun_host, stun_port, ChangeIpFlag, ChangePortFlag, bind_result))
	{
		// some servers don't have second ip
		struct in_addr addr = {changed_ip};
		char* alt_host = inet_ntoa(addr);
		memset(bind_result, 0, sizeof(StunAtrAddress) * 3);
		if (send_bind_request(s, alt_host, changed_port, 0, 0, bind_result))
		{
			return RestricNAT;
		}
	}

	return FullCone;	
}

int main()
{
	nat_type_t type = detect_nat_type(NULL, DEFAULT_STUN_SERVER_PORT, NULL, DEFAULT_LOCAL_PORT);

	printf("%s\n", nat_types[type]);
}
