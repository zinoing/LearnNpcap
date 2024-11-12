#ifdef _MSC_VER
/*
 * we do not want the warnings about the old deprecated and unsecure CRT functions
 * since these examples can be compiled under *nix as well
 */
#define _CRT_SECURE_NO_WARNINGS
#endif

#include <pcap.h>
#include <stdio.h>
#include <time.h>

#pragma comment(lib, "wpcap")
#pragma comment(lib, "ws2_32.lib")

#include <tchar.h>
#include <winsock.h>

 /* Ethernet Header의 정보를 받아오기 위한 custom struct 정의 */
#pragma pack(push, 1) // 1바이트 경계로 정렬 시작
typedef struct EtherHeader {
	unsigned char dstMax[6];
	unsigned char srcMax[6];
	unsigned short type;
} EtherHeader;

typedef struct IpHeader {
	unsigned char verIhl;
	unsigned char tos;
	unsigned short legnth;
	unsigned short id;
	unsigned short fragOffset;
	unsigned char ttl;
	unsigned char protocol;
	unsigned short checksum;
	unsigned char srcIp[4];
	unsigned char dstIp[4];
} IpHeader;

typedef struct TcpHeader {
	unsigned short srcPort;
	unsigned short dstPort;
	unsigned int seq;
	unsigned int ack;
	unsigned char data;
	unsigned char flags;
	unsigned short windowSize;
	unsigned short checksum;
	unsigned short urgent;
} TcpHeader;
#pragma pack(pop)// 이전의 정렬 방식으로 복원

BOOL LoadNpcapDlls()
{
	_TCHAR npcap_dir[512];
	UINT len;
	len = GetSystemDirectory(npcap_dir, 480);
	if (!len) {
		fprintf(stderr, "Error in GetSystemDirectory: %x", GetLastError());
		return FALSE;
	}
	_tcscat_s(npcap_dir, 512, _T("\\Npcap"));
	if (SetDllDirectory(npcap_dir) == 0) {
		fprintf(stderr, "Error in SetDllDirectory: %x", GetLastError());
		return FALSE;
	}
	return TRUE;
}

/* prototype of the packet handler */
void packet_handler(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data);

int main()
{
	pcap_if_t* alldevs;
	pcap_if_t* d;
	int inum;
	int i = 0;
	pcap_t* adhandle;
	char errbuf[PCAP_ERRBUF_SIZE];

	/* Load Npcap and its functions. */
	if (!LoadNpcapDlls())
	{
		fprintf(stderr, "Couldn't load Npcap\n");
		exit(1);
	}

	/* Retrieve the device list */
	/*
	pcap_findalldevs는 NIC와 관련한 정보들 반환
	*/
	if (pcap_findalldevs(&alldevs, errbuf) == -1)
	{
		fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
		exit(1);
	}

	/* Print the list */
	for (d = alldevs; d; d = d->next)
	{
		printf("%d. %s", ++i, d->name);
		if (d->description)
			printf(" (%s)\n", d->description);
		else
			printf(" (No description available)\n");
	}

	if (i == 0)
	{
		printf("\nNo interfaces found! Make sure Npcap is installed.\n");
		return -1;
	}

	printf("Enter the interface number (1-%d):", i);
	scanf("%d", &inum);

	if (inum < 1 || inum > i)
	{
		printf("\nInterface number out of range.\n");
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}

	/* Jump to the selected adapter */
	for (d = alldevs, i = 0; i < inum - 1; d = d->next, i++);

	/* Open the device */
	/* Open the adapter */
	if ((adhandle = pcap_open_live(d->name,	// name of the device
		65536,			// portion of the packet to capture. 
		// 65536 grants that the whole packet will be captured on all the MACs.
		1,				// promiscuous mode (nonzero means promiscuous)
		1000,			// read timeout
		errbuf			// error buffer
	)) == NULL)
	{
		fprintf(stderr, "\nUnable to open the adapter. %s is not supported by Npcap\n", d->name);
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}

	printf("\nlistening on %s...\n", d->description);

	/* At this point, we don't need any more the device list. Free it */
	pcap_freealldevs(alldevs);

	/* start the capture */
	pcap_loop(adhandle, 0, packet_handler, NULL);

	pcap_close(adhandle);
	return 0;
}


/* Callback function invoked by libpcap for every incoming packet */
void packet_handler(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data)
{
	struct tm* ltime;
	char timestr[16];
	time_t local_tv_sec;

	/*
	 * unused parameters
	 */
	(VOID)(param);
	(VOID)(pkt_data);

	/* convert the timestamp to readable format */
	local_tv_sec = header->ts.tv_sec;
	ltime = localtime(&local_tv_sec);
	strftime(timestr, sizeof timestr, "%H:%M:%S", ltime);

	EtherHeader* pEther = (EtherHeader*)pkt_data; // 강제 형변환

	if (ntohs(pEther->type) != 0x0800) // IP 프로토콜이 IPv4인 것만 분석하도록 함
		return;

	printf("%s,%.6d len:%-5d, " // 이더넷 헤더의 최대 길이는 기본적으로 1514 바이트이다. 그러나 이보다 크게 출력이 될 수도 있는데 이는 NIC 옵션으로 NPU를 사용했기 때문이다.
		"SRC: %02X-%02X-%02X-%02X-%02X-%02X -> " // 출발지 MAC의 주소는 6바이트의 고정 크기를 가지고 있어, 이를 다음과 같이 16진수로 표현 가능하다. 
		"DST: %02X-%02X-%02X-%02X-%02X-%02X " // 도착지 MAC의 주소도 위와 동일한 특징을 지니고 있다.
		"type: %04X\n", // type의 경우는 2바이트의 크기를 지니고 있어 04X로 표현한다.	0800일 경우 IPV4이고 0806은 ARP를 뜻한다.
		timestr, header->ts.tv_usec, header->len,
		pEther->srcMax[0], pEther->srcMax[1], pEther->srcMax[2],
		pEther->srcMax[3], pEther->srcMax[4], pEther->srcMax[5],
		pEther->dstMax[0], pEther->dstMax[1], pEther->dstMax[2],
		pEther->dstMax[3], pEther->dstMax[4], pEther->dstMax[5],
		ntohs(pEther->type)); // Intel CPU는 기본적으로 little endian 방식을 채택하고 있어 이를 big endian을 little endian 방식으로 바꾸어줄 함수 ntohs()를 사용한다.

	IpHeader* pIpHeader = (EtherHeader*)(pkt_data + sizeof(EtherHeader));

	if (pIpHeader->protocol != 6) // IP 프로토콜이 6인 것만 분석하도록 함
		return;

	int ipLen = (pIpHeader->legnth & 0x0F) * 4;
	TcpHeader* pTcpHeader = (TcpHeader*)(pkt_data + sizeof(EtherHeader) + ipLen);

	printf("Ipv%d, IHL: %d, Total length: %d\n",
		(pIpHeader->verIhl & 0xF0) >> 4,
		(pIpHeader->verIhl & 0x0F) * 4, // IHL 필드는 IP 헤더의 길이를 32비트(4바이트) 워드 단위로 표현하기 때문에 4를 곱한다
		ntohs(pIpHeader->legnth)); // total length도 앞선 type과 마찬가지로 네트워크 순서를 주의한다.

	if (pIpHeader->fragOffset & htons((short)0x2000) || // htons((short)0x2000)일 경우 0x0020으로 00100000 00000000
		ntohs(pIpHeader->fragOffset) & htons((unsigned short)0xFF1F) > 0) // (unsigned short)0xFF1F)일 경우 11111111 00011111
	{
		printf("ID: %04X, Flags: %04X, Offset:%d, Protocol: 0x%02X\n",
			ntohs(pIpHeader->id),
			ntohs(pIpHeader->fragOffset & htons((short)0xE000)),
			ntohs(pIpHeader->fragOffset & htons((unsigned short)0xFF1F)) * 8,
			pIpHeader->protocol);

		printf("%d.%d.%d.%d:%d -> %d.%d.%d.%d:%d\n",
			pIpHeader->srcIp[0], pIpHeader->srcIp[1],
			pIpHeader->srcIp[2], pIpHeader->srcIp[3],
			pTcpHeader->srcPort,
			pIpHeader->dstIp[0], pIpHeader->dstIp[1],
			pIpHeader->dstIp[2], pIpHeader->dstIp[3],
			pTcpHeader->dstPort
		);
	}

}
