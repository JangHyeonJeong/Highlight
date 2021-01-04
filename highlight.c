#define _CRT_SECURE_NO_WARNINGS    //���� ���� ���� ������ ���� ����
#define HAVE_STRUCT_TIMESPEC //mysql ���� ���� ����

#include <my_global.h>
#include <winsock2.h>
#include <mysql.h>
#include <stdio.h>    
#include <string.h>
#include <stdlib.h> 
#include <ctype.h>
#include "pcre.h"

#pragma comment(lib, "libmysql.lib")

#ifdef _DEBUG
#pragma comment(lib, "pcred.lib")
#pragma comment(lib, "pcrecppd.lib")
#else
#pragma comment(lib, "pcre.lib")
#pragma comment(lib, "pcrecpp.lib")
#endif

#define DB_HOST "127.0.0.1"
#define DB_USER "test"
#define DB_PASS "12345"
#define DB_NAME "convert"


int Parsing(FILE *fp, char *rule, int pos);
int extract_value(char *str, int i);
int extract_keyword(char *str, int i);

char value[10000];
char *keyword;

char fname[256];
FILE *fp = 0;
int signatue_id;

void ViewMac(unsigned char *mac);
void ViewIP(char *buf, int ethernet_size, int packet_size, char *rule, int pos);
void packetpayload(char *buf, int underlayer_size, int correspondinglayer_size, int packet_size, char *rule, int pos);
void Viewpayload(unsigned char *payload, int underlayer_size, int correspondinglayer_size, int packet_size, char *rule, int pos);
int ParseTCP(uchar* base, int underlayer_size, int packet_size, char *rule, int pos);
void ParseUDP(uchar* base, int underlayer_size, int packet_size, char *rule, int pos);
int ViewHTTP(uchar *vpdata, int tcphdr_size, int packet_size, int UI_NEXT, int source_port, char *rule, int pos);
void maching_pcap(char keyword, char *rule, int pos);
int ViewHTTP_Request(uchar *vpdata, int tcphdr_size, int UI_NEXT, int packet_size, char *rule, int pos);
int ViewHTTP_Response(uchar *vpdata, int tcphdr_size, int UI_NEXT, int packet_size, char *rule, int pos);
static unsigned char hexdigit2int(unsigned char xd);
int pcre_matching(const char* subject, const char* pattern, int x);
int pcre_opt_matching(const char* subject, const char* pattern, const char* opt, int opt_count);
int save_json(int start, int end);

void main() {
	printf("���� ��:");
	gets_s(fname, sizeof(fname));
	memset(value, 0, 10000);
	//printf("MySQL version: %s\n", mysql_get_client_info());MYSQL
	MYSQL       *connection = NULL, conn;
	MYSQL_RES   *sql_result;
	MYSQL_ROW   sql_row;
	int  query_stat;
	int i = 0;
	int n;
	char sid[11];
	char *rule_full_set;


	mysql_init(&conn);
	connection = mysql_real_connect(&conn, DB_HOST, DB_USER, DB_PASS, DB_NAME, 3306, (char *)NULL, 0);
	if (connection == NULL)
	{
		fprintf(stderr, "Mysql connection error : %s", mysql_error(&conn));
		return 1;
	}

	query_stat = mysql_query(connection, "select * from rule_table;");
	if (query_stat != 0)
	{
		fprintf(stderr, "Mysql query error : %s", mysql_error(&conn));
		return 1;
	}
	sql_result = mysql_store_result(connection);//��� ��� ����� �������� �ѹ��� �� �޾ƿ�


	printf("sid �Է� : ");
	scanf_s("%s", &sid, sizeof(sid));

	// DB�� sid�� int ������ ���� �Ǿ��־ ���ڿ��� �о��
	while ((sql_row = mysql_fetch_row(sql_result)) != NULL)
	{

		//strcmp : �� ���ڿ��� ��ġ�ϸ� 0��ȯ
		if (strcmp(sid, sql_row[0]) == 0) {
			//printf("\n\n %s : %s \n", sql_row[0], sql_row[1]);
			signatue_id = atoi(sql_row[0]);
			
			rule_full_set = malloc(1000);
			memset(rule_full_set, 0, 1000);

			strcpy(rule_full_set, sql_row[1]);

			mysql_free_result(sql_result); //result�� ���� �޸�(memory)�� �ִ� ������ ��� ����
			mysql_close(&conn);

			while (strncmp((rule_full_set + i), ")", 1)) {

				if (strncmp((rule_full_set + i), "msg:", 4) == 0)
				{
					while (1)
					{
						if (strncmp((rule_full_set + i), ";", 1) == 0)
						{
							i++;
							break;
						}
						i++;
					}
				}
				//printf("%s \n", (rule_full_set + i));
				if (strncmp((rule_full_set + i), "content:", 8) == 0)
				{
					i = extract_value(rule_full_set, i, &value) - 1;
					extract_keyword(rule_full_set, i);
					maching_pcap(keyword, rule_full_set,i);
				}

				if (strncmp((rule_full_set + i), "pcre:\"/", 7) == 0)
				{
					i = extract_value(rule_full_set, i, &value) - 1;
					extract_keyword(rule_full_set, i);
					maching_pcap(keyword, rule_full_set, i);
				}

				i++;
			}

			printf("��");
		}

	}

	free(rule_full_set);

}

static unsigned char hexdigit2int(unsigned char xd)
{
	if (xd <= '9')
		return xd - '0';
	xd = tolower(xd);
	if (xd == 'a')
		return 10;
	if (xd == 'b')
		return 11;
	if (xd == 'c')
		return 12;
	if (xd == 'd')
		return 13;
	if (xd == 'e')
		return 14;
	if (xd == 'f')
		return 15;
	return 0;
}

// content�� ���� ����
int extract_value(char *str, int i)
{
	int n = 0;
	//printf("\n �� = %s \n\n", str+i);
	int x;
	while (1)
	{
		if (strncmp(str + i, "content:", 8) == 0) {
			i += 9;
			char str_rule[10000] = "";
			
			//printf(" %s \n", (str + i));
			while (strncmp((str + i + n), ";", 1)) n++;

			// str_rule : content�� ��
			strncpy(str_rule, (str + i), n - 1);

			char hex[3];
			const char *src = hex;

			for (x = 0; x < strlen(str_rule); x++)
			{
				// 16���� ��Ī�� ���� ��� �ƽ�Ű ������ ��ȯ
				if (strncmp(str_rule + x, "|", 1) == 0)
				{
					strncpy(value, str_rule, x);

					x += 1;
					while (1)
					{
						strncpy(hex, str_rule + x, 2);
						hex[2] = '\0';
						const char *src = hex;
						char text[sizeof hex + 1], *dst = text;
						while (*src != '\0')
						{
							const unsigned char high = hexdigit2int(*src++);
							const unsigned char low = hexdigit2int(*src++);
							*dst++ = (high << 4) | low;
						}
						*dst = '\0';
						strcat(value, text);

						x += 2;
						if (strncmp(str_rule + x++, "|", 1) == 0) break;
					}
				}

			}
			if (x == strlen(str_rule)) strcpy(value, str_rule);
			//printf("value :%s \n", value);
			//free(value);
			return (i + n + 1); // content�� ���� ���� ��ġ�� �̵�
		}
		else if (strncmp(str + i, "pcre:\"/", 7) == 0) {

			//printf("pcre ��Ī \n");
			i += 7;
			char* str_pattern;
			str_pattern = malloc(strlen(str));
			memset(str_pattern, 0, strlen(str));

			for (n = 0; ; n++)
			{
				if (strncmp((str + i + n), "\";", 2) == 0 || strncmp((str + i + n), "/", 1) == 0) break;

			}

			if (strncmp((str + i + n), "/\";", 3) == 0) // pcre �ɼ��� ���°��
			{
				strncpy(str_pattern, (str + i - 7), n + 7);
				//printf("str_pattern :%s \n", str_pattern);
				memset(value, 0, 10000);
				strcat(value, str_pattern);
				//printf("value :%s \n", value);
				return (i + n + 4); // pcre keyword�� ���� ���� ��ġ�� �̵�

			}
			// pcre �ɼ� �ִ°��
			if ((strncmp((str + i + n), "/i", 2) == 0) || (strncmp((str + i + n), "/s", 2) == 0) || (strncmp((str + i + n), "/m", 2) == 0))
			{
				while (1)
				{
					if (strncmp((str + i + n), ";", 1) == 0) break;
					n++;
				}
				strncpy(str_pattern, (str + i - 7), n + 7);
				memset(value, 0, 10000);
				strcat(value, str_pattern);
				//printf("value :%s \n", value);

				return (i + n + 5); // pcre keyword�� ���� ���� ��ġ�� �̵�

			}


		}
		i++;
	}

}

int extract_keyword(char *str, int i)
{
	i += 1;
	int n = 1;
	keyword = malloc(100);
	memset(keyword, 0, 100);

	while (1)
	{
		if (strncmp((str + i - strlen(value) - 11 - n), ";", 1) == 0)
		{

			for (int x = 1; x <= strlen(str); x++)
			{
				if (*(str + i - strlen(value) - 11 - n - x) == NULL) return 0;
				if (strncmp((str + i - strlen(value) - 11 - n - x), ";", 1) == 0 || strncmp((str + i - strlen(value) - 11 - n - x), " ", 1) == 0)
				{
					strncpy(keyword, (str + i - strlen(value) - 10 - n - x), x);
					
					//keyword DB�� ��Ī
					MYSQL       *connection = NULL, conn;
					MYSQL_RES   *sql_result;
					MYSQL_ROW   sql_row;
					int  query;

					mysql_init(&conn);

					connection = mysql_real_connect(&conn, DB_HOST, DB_USER, DB_PASS, DB_NAME, 3306, (char *)NULL, 0);
					if (connection == NULL)
					{
						fprintf(stderr, "Mysql connection error : %s", mysql_error(&conn));
						return 1;
					}

					query = mysql_query(connection, "select * from keyword_table;");
					if (query != 0)
					{
						fprintf(stderr, "Mysql query error : %s", mysql_error(&conn));
						return 1;
					}

					sql_result = mysql_store_result(connection);//��� ��� ����� �������� �ѹ��� �� �޾ƿ�


					while ((sql_row = mysql_fetch_row(sql_result)) != NULL)
					{
						// content �տ� ���� Ű���� �̸�
						if (strncmp(keyword, sql_row[0], strlen(sql_row[0])) == 0) {
							mysql_free_result(sql_result); //result�� ���� �޸�(memory)�� �ִ� ������ ��� ����
							mysql_close(&conn);
							//printf("keyword =%s \n",keyword);
							return 0;
						}
					}
					// content �ڿ� ���� Ű���� �̸�
					memset(keyword, 0, strlen(keyword));
					break;
				}

			}
			break;
		}
		n++;
	}

	// content �ڿ� ���� Ű���� �̸�
	while (1)
	{
		if (*(str + i + n) == NULL) return 0;
		if (strncmp((str + i + n), ";", 1) == 0 || strncmp((str + i + n), "(", 1) == 0) break;
		n++;
	}
	//printf("n =%d\n", n);
	
	//���� ����
	while (1)
	{
		if (strncmp((str + i), " ", 1) == 0)	i++;
		else break;
	}
	strncpy(keyword, (str + i), n +1);
	//printf("keyword =%s \n",keyword);
}

#include "packetheader.h"
#define MAX_PACKET  5000000
pcap_header headers[MAX_PACKET];//��Ŷ ������� �����ҹ迭
int pcnt; //��Ŷ ����

void maching_pcap(char keyword, char *rule, int pos)
{
	//char fname[256];
	FILE *fp = 0;
	//printf("���� ��:");
	//gets_s(fname, sizeof(fname));
	fopen_s(&fp, fname, "rb");//���޹��� ������ �б�/���̳ʸ����� ����
	Parsing(fp,rule,pos);//�м��ϱ�
	fclose(fp);//���� �ݱ�
}

void ParsingEthernet(FILE *fp, char *rule, int pos);
int Parsing(FILE *fp, char *rule, int pos)
{
	pcap_file_header pfh;
	fread(&pfh, sizeof(pfh), 1, fp);//pcap ���� ��� �б�    
	if (pfh.magic != MAGIC) //������ �ٸ���
	{
		printf("this file format is not correct \n");
		return -1;
	}
	printf("version:%d.%d\n", pfh.version_major, pfh.version_minor);//pcap ��� ���� ���

	switch (pfh.linktype)//��ũ Ÿ�Կ� ����
	{
	case 1:ParsingEthernet(fp, rule, pos); break; //Ethernet ������� �м�
	case 6:printf("Not support Token Ring\n"); break;
	case 10:printf("Not support FDDI\n"); break;
	case 0:printf("Not support Loopback\n"); break;
	default:printf("Unknown\n"); break;
	}
	return 0;
}

int ViewPacketHeader(pcap_header *ph);
void ViewEthernet(char *buf, int packet_size, char *rule, int pos);
void ParsingEthernet(FILE *fp, char *rule, int pos)
{
	char buf[65536];
	int packet_size;
	pcap_header *ph = headers;//ph�� ��Ŷ ����� ���� ��ġ�� �ʱ�ȭ
	int i = 0;
	while (feof(fp) == 0) //������ ���� �ƴϸ� �ݺ�
	{
		if (fread(ph, sizeof(pcap_header), 1, fp) != 1)//��Ŷ ��� �б⸦ �����ϸ�
		{
			break;//���� Ż��
		}
		if (pcnt == MAX_PACKET)
		{
			break;//���� Ż��
		}
		packet_size = ViewPacketHeader(ph); //��Ŷ ��� ���� ���
		fread(buf, 1, ph->caplen, fp); //��Ŷ �б�
		
		ViewEthernet(buf, packet_size, rule, pos); //�̴��� ���� ���
		ph++;//ph�� ���� ��ġ�� �̵�
	}
}


int ViewPacketHeader(pcap_header *ph)
{
	pcnt++;//��Ŷ ������ 1 ����
	printf("\n\nNo:%d time:%08d:%06d caplen:%u length:%u \n",
		pcnt, ph->ts.tv_sec, ph->ts.tv_usec, ph->caplen, ph->len);
	return ph->caplen;
}


void ViewEthernet(char *buf, int packet_size, char *rule, int pos)
{
	ethernet *ph = (ethernet *)buf; //��Ŷ ���۸� ethernet ����ü �����ͷ� �� ��ȯ
	printf("===========ETHERNET Header==============\n");
	printf("dest mac:0x");
	ViewMac(ph->dest_mac);//MAC �ּ� ���
	printf("  src mac:0x");
	ViewMac(ph->src_mac);//MAC �ּ� ���
						 //Link Ÿ���� ���(2����Ʈ �̻����ʹ� network byte order -> host byte order �� ��ȯ�ؾ� ��
	printf("  type:%#x\n", ntohs(ph->type));


	switch (ntohs(ph->type))
	{
	case 0x800: ViewIP(buf + sizeof(ethernet), sizeof(ethernet), packet_size, rule, pos); break;
		//case 0x806:ViewARP(buf + sizeof(ethernet));  break; //ARP ���� ���
	default:printf("Not support Protocol\n"); break;
	}
}

void ViewMac(unsigned char *mac)
{
	int i;
	for (i = 0; i < MAC_ADDR_LEN; ++i)
	{
		printf("%02x ", mac[i]);
	}
}


ushort ip_checksum(ushort *base, int len);
void ViewIP(char *buf, int ethernet_size, int packet_size, char *rule, int pos)
{
	IN_ADDR addr;
	iphdr *ip = (iphdr *)buf; //��Ŷ ���۸� IP ����ü �����ͷ� ����ȯ

	int iphdr_size = (int)(ip->hlen);
	iphdr_size = iphdr_size * 4; // bytes ������ ����

	printf("\n=========== IPv4 Header ==============\n");

	addr.s_addr = ip->src_address;

	printf("src:%s, ", inet_ntoa(addr));

	addr.s_addr = ip->dst_address;
	printf("dst:%s\n", inet_ntoa(addr));

	printf("header length:%d bytes, ", ip->hlen * 4);
	printf("version:%d, ", ip->version);
	printf("total length:%d bytes\n", ntohs(ip->tlen));
	printf("id:%d, ", ntohs(ip->id));
	if (DONT_FRAG(ip->frag))
	{
		printf("Don't Fragment\n");
	}
	else
	{
		if (MORE_FRAG(ip->frag) == 0)
		{
			printf("last fragment, ");
		}
		printf("offset:%d ", FRAG_OFFSET(ip->frag));
	}
	if (ip_checksum((ushort *)buf, iphdr_size) == 0)
	{
		printf("checksum is correct, ");
	}
	else
	{
		printf("checksum is not correct, ");
	}
	printf("TTL:%d\n", ip->ttl);

	//L3 ������ payload
	//packetpayload(ip, ethernet_size, iphdr_size, packet_size);

	switch (ip->protocol)
	{
	case 1: printf("\nICMP\n"); break;
	case 2: printf("\nIGMP\n"); break;
	case 6: {
		printf("\nTCP\n");
		ParseTCP(buf + iphdr_size, ethernet_size + iphdr_size, packet_size, rule, pos);
		break;
	}
	case 17: {
		printf("\nUDP\n");
		ParseUDP(buf + iphdr_size, ethernet_size + iphdr_size, packet_size, rule, pos);
		break;
	}
	case 89: printf("\nOSPF\n"); break;
	default: printf("\nNot support\n"); break;
	}
}


ushort ip_checksum(ushort *base, int len)
{
	int nleft = len;
	int sum = 0;
	u_short *w = base;
	u_short answer = 0;
	while (nleft>1)
	{
		sum += *w;
		w++;
		nleft -= 2;
	}

	if (nleft == 1)
	{
		*(ushort *)(&answer) = *(uchar *)w;
		sum += answer;
	}
	sum = (sum >> 16) + (sum & 0xFFFF);
	sum += (sum >> 16);
	answer = ~sum;
	return (answer);
}

int ParseTCP(uchar* base, int underlayer_size, int packet_size, char *rule, int pos)
{
	TCPHeader* th = (TCPHeader*)base;
	printf("\n=========== TCP Header ==============\n");
	printf("\tsrc port:%u\n\tdest port:%u\n\tseq no:%u\n\tack no:%u\n",
		ntohs(th->src_port), ntohs(th->dst_port), ntohl(th->seqno), ntohs(th->ackno));
	printf("\t");
	if (th->syn) printf("SYN ");
	if (th->ack) printf("ACK ");
	if (th->fin) printf("FIN ");
	if (th->rst) printf("RST ");
	if (th->psh) printf("PSH ");
	if (th->urg) printf("URG ");
	printf("\n");
	printf("\twindow size:%u\n", ntohs(th->winsize));
	printf("\turg pointer:%u\n", ntohs(th->upoint));

	int tcphdr_size = (int)(th->hdlen);
	tcphdr_size = tcphdr_size / 4; // bytes ������ ����
								   //printf("TCP ��� ũ�� : %d \n", tcphdr_size);
	
	// port number 80�������� payload�� ���� ��Ŷ�� ����(http ��Ŷ�� ���)
	if ((ntohs(th->src_port) == 80 || ntohs(th->dst_port) == 80) && (packet_size != (tcphdr_size + underlayer_size)))
		ViewHTTP(th, tcphdr_size, packet_size, (packet_size - underlayer_size), (ntohs(th->src_port)), rule, pos);

	//L4(TCP)������ payload
	
	else packetpayload(th, underlayer_size, tcphdr_size, packet_size, rule, pos);

	

}

void ParseUDP(uchar* base, int underlayer_size, int packet_size, char *rule, int pos)
{
	UDPHeader* th = (UDPHeader*)base;
	printf("\n=========== UDP Header ==============\n");
	printf("\tsrc port:%u\n\tdest port:%u\n\tlen:%u\n",
		ntohs(th->src_port), ntohs(th->dst_port), ntohs(th->len));
	//L4(UDP)������ payload
	packetpayload(th, underlayer_size, (sizeof(UDPHeader)), packet_size, rule, pos);
}

void packetpayload(char *buf, int underlayer_size, int correspondinglayer_size, int packet_size, char *rule, int pos)
{
	packet_payload *ph = (packet_payload *)buf;

	Viewpayload(ph->payload, underlayer_size, correspondinglayer_size, packet_size, rule, pos);
}

void Viewpayload(unsigned char *payload, int underlayer_size, int correspondinglayer_size, int packet_size, char *rule, int pos)
{
	int i,x,y;
	//printf("payload : ");

	for (i = correspondinglayer_size; i < (packet_size - underlayer_size); ++i)
	{
		//printf("%02x ", payload[i]);
		//printf("value :%s \n", value);
		// payload üũ

		if (strncmp(value, "pcre:\"/", 7) == 0)
		{
			char* subject;
			char* pattern;
			int z,w,re;
			w = strlen(value) - 6;
			subject = malloc((packet_size - underlayer_size - correspondinglayer_size) +1);
			memset(subject, 0, (packet_size - underlayer_size - correspondinglayer_size) + 1);
			pattern = malloc(w);
			memset(pattern, 0, w);
	
			for (z = 0; z < (packet_size - underlayer_size - correspondinglayer_size); z++)
			{
				subject[z] = payload[i];
				i++;
			}
			
			
			//pcre�� ��Ī�� payload
			
			strncpy(pattern, value + 7, strlen(value) - 7);
			printf("pcre : %s \n\n", pattern);
			if (strlen(subject) != 0)
			{
				re = pcre_matching(subject, pattern, 0);
				if (re >= 1)
				{
					//printf("payload %s \n", subject);
					save_json(0, 0);
					
				}
				else printf("��Ī X \n\n");
			}
	
		}
		if (payload[i] == value[0])
		{
			
			for (x = 0; x < strlen(value); x++)
			{
				if (payload[i] != value[x]) break;
				i++;
			}
			if (x == (strlen(value)))
			{
				save_json(underlayer_size + i, underlayer_size + i + x - 1);
				
				// ���� ���� �ȳ����� ��� �̾ �˻�
				while (strncmp((rule + pos), ")", 1)) 
				{
					if (strncmp((rule + pos), "content:", 8) == 0)
					{
						pos = extract_value(rule, pos, &value) - 1;
						extract_keyword(rule, pos);
						Viewpayload(payload, underlayer_size, i+x, packet_size, rule, pos);
					}
					pos++;
				}
				
				save_json(0, 0);
			}
		}
		
	}

}

int ViewHTTP(uchar *vpdata, int tcphdr_size, int packet_size, int UI_NEXT, int source_port, char *rule, int pos)
{
	int a = 1;
	int init_pos = pos;
	pos = extract_value(rule, 0, &value) - 1;
	extract_keyword(rule, pos);

	char data[100];
	const unsigned char *ucp_data = vpdata;
	if (source_port != 80)
	{
		if (*(vpdata + tcphdr_size) == 0x00) return 0; // payload�� 00 ���� �����ϸ� ���� ��Ŷ����
		if (*(vpdata + tcphdr_size) == 0x47 || *(vpdata + tcphdr_size) == 0x50 || *(vpdata + tcphdr_size) == 0x48
			|| *(vpdata + tcphdr_size) == 0x44 || *(vpdata + tcphdr_size) == 0x54 || *(vpdata + tcphdr_size) == 0x4F
			|| *(vpdata + tcphdr_size) == 0x43)
		{
			a = ViewHTTP_Request(vpdata, tcphdr_size, UI_NEXT, packet_size, rule, init_pos);
		}
	}

	else if(source_port == 80)
	{
		
		if (*(vpdata + tcphdr_size) == 0x00) return 0; // payload�� 00 ���� �����ϸ� ���� ��Ŷ����
		if (*(vpdata + tcphdr_size) == 0x48) ViewHTTP_Response(vpdata, tcphdr_size, UI_NEXT, packet_size, rule, init_pos);
	}

	if (a == 0) return 0;


	

	//return vpdata;

}

int ViewHTTP_Request(uchar *vpdata, int tcphdr_size, int UI_NEXT, int packet_size, char *rule, int pos)
{

	const unsigned char *ucp_data = vpdata;
	int i, x = 0;
	int w = 0;
	int count;
	int start;
	char data[10];
	char header[30][5000] = { 0, };
	while ((UI_NEXT - tcphdr_size) != 0)
	{

		int z, y;

		sprintf(data, "%c", *(ucp_data + tcphdr_size));
		//putchar(*(ucp_data + tcphdr_size));

		char *method; // http_method ����
		method = malloc(20);
		memset(method, 0, 20);

		for (z = 0;; z++)
		{
			method[z] = *(ucp_data + tcphdr_size);
			ucp_data++;
			if (strncmp((ucp_data + tcphdr_size), " ", 1) == 0) break;

		}
		//printf("http_method ���� :%s\n\n", method);

		char *URI; // http_uri ����
		URI = malloc(1000);
		memset(URI, 0, 1000);
		ucp_data++;
		for (z = 0;; z++)
		{
			URI[z] = *(ucp_data + tcphdr_size);
			ucp_data++;
			if (strncmp((ucp_data + tcphdr_size), " ", 1) == 0) break;

		}
		//printf("http_uri ���� :%s\n\n", URI);

		char *pro; // http_protocol ����
		pro = malloc(20);
		memset(pro, 0, 20);
		ucp_data++;
		for (z = 0;; z++)
		{
			pro[z] = *(ucp_data + tcphdr_size);
			ucp_data++;
			if (strncmp((ucp_data + tcphdr_size), "\n", 1) == 0) break;

		}
		//printf("http_protocol ���� :%s\n\n", pro);

		char *req_line; // http_request_line ����
		req_line = malloc(strlen(method) + strlen(URI) + strlen(pro));
		memset(req_line, 0, (strlen(method) + strlen(URI) + strlen(pro)));

		strcpy(req_line, method);
		strcat(req_line, " ");
		strcat(req_line, URI);
		strcat(req_line, " ");
		strcat(req_line, pro);

		//printf("http_request_line ���� :%s\n\n", req_line);

		for (i = 0; ; i++)
		{

			ucp_data++;

			if (strncmp((ucp_data + tcphdr_size + 1), "\n", 1) == 0) break;
			for (z = 0;; z++)
			{
				if (w + z == UI_NEXT - tcphdr_size - 11) break;

				header[i][z] = *(ucp_data + tcphdr_size);
				ucp_data++;

				if (strncmp((ucp_data + tcphdr_size), "\n", 1) == 0) break;
				if (strcmp((ucp_data + tcphdr_size), "") == 0) break;
			}

			//printf("header ���� :%s\n", header[i]);
			w += strlen(header[i]);

			if (w + z == UI_NEXT - tcphdr_size - 11) break;
			if ((UI_NEXT - tcphdr_size) == 0) break;
			if (strcmp((ucp_data + tcphdr_size), "") == 0) break;
		}

		if (strncmp(keyword, "http_method;", 12) == 0)
		{
			for (x = 0; x < strlen(value); x++)
			{
				if (method[x] != value[x]) break;
			}

			if (x == (strlen(value)))
			{
				start = packet_size - UI_NEXT + tcphdr_size;
				save_json(start, start + x - 1);

			}
			else return 0;

		}

		else if (strncmp(keyword, "http_uri;", 9) == 0)
		{
			for (x = 0; x < strlen(URI); x++)
			{

				if (URI[x] == value[0])
				{

					for (y = 1; y < strlen(value); y++) if (URI[x + y] != value[y]) break;
					if (y == (strlen(value))) break;
				}

			}

			if (y == (strlen(value)))
			{
				start = packet_size - UI_NEXT + tcphdr_size + strlen(method) + x + 1;
				save_json(start, start + y - 1);
			}
			else return 0;
		}

		else if (strncmp(keyword, "http_protocol;", 14) == 0)
		{
			for (x = 0; x < strlen(pro); x++)
			{

				if (pro[x] == value[0])
				{

					for (y = 1; y < strlen(value); y++) if (pro[x + y] != value[y]) break;


					if (y == (strlen(value))) break;
				}

			}

			if (y == (strlen(value)))
			{
				start = packet_size - UI_NEXT + tcphdr_size + strlen(method) + strlen(URI) + x + 2;
				save_json(start, start + y - 1);
			}
			else return 0;
		}

		else if (strncmp(keyword, "http_request_line;", 18) == 0)
		{
			for (x = 0; x < strlen(req_line); x++)
			{

				if (req_line[x] == value[0])
				{

					for (y = 1; y < strlen(value); y++) if (req_line[x + y] != value[y]) break;


					if (y == (strlen(value))) break;
				}

			}

			if (y == (strlen(value)))
			{
				start = packet_size - UI_NEXT + tcphdr_size + x;
				save_json(start, start + y - 1);
			}
			else return 0;
		}

		else if (strncmp(keyword, "http_accept;", 12) == 0)
		{
			for (count = 0; count < i; count++)
			{
				if (strncmp(header[count], "Accept:", 7) == 0)
				{
					for (x = 0; x < strlen(header[count]); x++)
					{
						if (header[count][x] == value[0])
						{
							for (y = 1; y < strlen(value); y++) if (header[count][x + y] != value[y]) break;
							if (y == (strlen(value))) break;
						}
					}
					if (y == (strlen(value))) break;
				}
			}
			if (y == (strlen(value)))
			{

				start = packet_size - UI_NEXT + tcphdr_size + strlen(req_line) + 2 * (count + 1) + (x - count - 1);

				for (x = 0; x < count; x++) {
					start += strlen(header[x]);

				}

				save_json(start, start + y - 1);
			}
			else return 0;
		}

		else if (strncmp(keyword, "http_referer;", 13) == 0)
		{
			for (count = 0; count < i; count++)
			{
				if (strncmp(header[count], "Referer:", 8) == 0)
				{
					for (x = 0; x < strlen(header[count]); x++)
					{
						if (header[count][x] == value[0])
						{
							for (y = 1; y < strlen(value); y++) if (header[count][x + y] != value[y]) break;
							if (y == (strlen(value))) break;
						}
					}
					if (y == (strlen(value))) break;
				}
			}
			if (y == (strlen(value)))
			{

				start = packet_size - UI_NEXT + tcphdr_size + strlen(req_line) + 2 * (count + 1) + (x - count - 1);
				for (x = 0; x < count; x++) {
					start += strlen(header[x]);
				}

				save_json(start, start + y - 1);
			}
			else return 0;
		}

		else if (strncmp(keyword, "http_accept_lang;", 17) == 0)
		{
			for (count = 0; count < i; count++)
			{
				if (strncmp(header[count], "Accept-Language:", 16) == 0)
				{
					for (x = 0; x < strlen(header[count]); x++)
					{
						if (header[count][x] == value[0])
						{
							for (y = 1; y < strlen(value); y++) if (header[count][x + y] != value[y]) break;
							if (y == (strlen(value))) break;
						}
					}
					if (y == (strlen(value))) break;
				}
			}
			if (y == (strlen(value)))
			{

				start = packet_size - UI_NEXT + tcphdr_size + strlen(req_line) + 2 * (count + 1) + (x - count - 1);
				for (x = 0; x < count; x++) {

					start += strlen(header[x]);
				}
				save_json(start, start + y - 1);
			}
			else return 0;
		}

		else if (strncmp(keyword, "http_user_agent;", 16) == 0)
		{
			for (count = 0; count < i; count++)
			{
				if (strncmp(header[count], "User-Agent:", 11) == 0)
				{
					for (x = 0; x < strlen(header[count]); x++)
					{
						if (header[count][x] == value[0])
						{
							for (y = 1; y < strlen(value); y++) if (header[count][x + y] != value[y]) break;
							if (y == (strlen(value))) break;
						}
					}
					if (y == (strlen(value))) break;
				}
			}
			if (y == (strlen(value)))
			{

				start = packet_size - UI_NEXT + tcphdr_size + strlen(req_line) + 2 * (count + 1) + (x - count - 1);
				for (x = 0; x < count; x++) {

					start += strlen(header[x]);
				}
				save_json(start, start + y - 1);
			}
			else return 0;
		}

		else if (strncmp(keyword, "http_accept_enc;", 16) == 0)
		{
			for (count = 0; count < i; count++)
			{
				if (strncmp(header[count], "Accept-Encoding:", 16) == 0)
				{
					for (x = 0; x < strlen(header[count]); x++)
					{
						if (header[count][x] == value[0])
						{
							for (y = 1; y < strlen(value); y++) if (header[count][x + y] != value[y]) break;
							if (y == (strlen(value))) break;
						}
					}
					if (y == (strlen(value))) break;
				}
			}
			if (y == (strlen(value)))
			{

				start = packet_size - UI_NEXT + tcphdr_size + strlen(req_line) + 2 * (count + 1) + (x - count - 1);
				for (x = 0; x < count; x++) {

					start += strlen(header[x]);
				}
				save_json(start, start + y - 1);
			}
			else return 0;
		}

		else if (strncmp(keyword, "http_host;", 10) == 0)
		{
			for (count = 0; count < i; count++)
			{
				if (strncmp(header[count], "Host:", 5) == 0)
				{
					for (x = 0; x < strlen(header[count]); x++)
					{
						if (header[count][x] == value[0])
						{
							for (y = 1; y < strlen(value); y++) if (header[count][x + y] != value[y]) break;
							if (y == (strlen(value))) break;
						}
					}
					if (y == (strlen(value))) break;
				}
			}
			if (y == (strlen(value)))
			{

				start = packet_size - UI_NEXT + tcphdr_size + strlen(req_line) + 2 * (count + 1) + (x - count - 1);
				for (x = 0; x < count; x++) {

					start += strlen(header[x]);
				}
				save_json(start, start + y - 1);
			}
			else return 0;
		}

		else if (strncmp(keyword, "http_connection;", 16) == 0)
		{
			for (count = 0; count < i; count++)
			{
				if (strncmp(header[count], "Connection:", 11) == 0)
				{
					for (x = 0; x < strlen(header[count]); x++)
					{
						if (header[count][x] == value[0])
						{
							for (y = 1; y < strlen(value); y++) if (header[count][x + y] != value[y]) break;
							if (y == (strlen(value))) break;
						}
					}
					if (y == (strlen(value))) break;
				}
			}

			if (y == (strlen(value)))
			{

				start = packet_size - UI_NEXT + tcphdr_size + strlen(req_line) + 2 * (count + 1) + (x - count - 1);
				for (x = 0; x < count; x++) {

					start += strlen(header[x]);
				}
				printf("start:%d\n", start);
				save_json(start, start + y - 1);
			}
			else return 0;
		}

		else if (strncmp(keyword, "http_cookie;", 12) == 0)
		{
			for (count = 0; count < i; count++)
			{
				if (strncmp(header[count], "Cookie:", 7) == 0)
				{
					for (x = 0; x < strlen(header[count]); x++)
					{
						if (header[count][x] == value[0])
						{
							for (y = 1; y < strlen(value); y++) if (header[count][x + y] != value[y]) break;
							if (y == (strlen(value))) break;
						}
					}
					if (y == (strlen(value))) break;
				}
			}

			if (y == (strlen(value)))
			{

				start = packet_size - UI_NEXT + tcphdr_size + strlen(req_line) + 2 * (count + 1) + (x - count - 1);
				for (x = 0; x < count; x++) {

					start += strlen(header[x]);
				}
				printf("start:%d\n", start);
				save_json(start, start + y - 1);
			}
			else return 0;
		}

		else return 0;
		// ���� ���� �ȳ����� ��� �̾ �˻�
		while (strncmp((rule + pos), ")", 1))
		{

			if (strncmp((rule + pos), "content:", 8) == 0)
			{

				pos = extract_value(rule, pos, &value) - 1;
				extract_keyword(rule, pos);
				if (ViewHTTP_Request(vpdata, tcphdr_size, UI_NEXT, packet_size, rule, pos) == 0) return 0;
			}
			pos++;
		}

		if (strncmp((rule + pos), ")", 1) == 0) printf("����Ǿ����ϴ�.\n\n"); save_json(0, 0);

		return 0;
	}
	return 0;
}

int ViewHTTP_Response(uchar *vpdata, int tcphdr_size, int UI_NEXT, int packet_size, char *rule, int pos)
{
	
	const unsigned char *ucp_data = vpdata;
	int x = 0;
	int start = 0;
	char data[10];
	char header[30][200] = { 0, };
	while ((UI_NEXT - tcphdr_size) != 0)
	{
		
		int i,z, y, count,w;

		sprintf(data, "%c", *(ucp_data + tcphdr_size));
		//putchar(*(ucp_data + tcphdr_size));
		
		char *pro; // http_protocol ����
		pro = malloc(20);
		memset(pro, 0, 20);
		for (z = 0;; z++)
		{
			pro[z] = *(ucp_data + tcphdr_size);
			ucp_data++;
			if (strncmp((ucp_data + tcphdr_size), " ", 1) == 0) break;

		}
		//printf("http_protocol ���� :%s\n", pro);
		
		ucp_data++;

		char *stat_code; // http_stat_code ����
		stat_code = malloc(20);
		memset(stat_code, 0, 20);
		for (z = 0;; z++)
		{
			stat_code[z] = *(ucp_data + tcphdr_size);
			ucp_data++;
			if (strncmp((ucp_data + tcphdr_size), " ", 1) == 0) break;

		}
		//printf("http_stat_code ���� :%s\n", stat_code);

		ucp_data++;

		char *stat_msg; // http_stat_msg ����
		stat_msg = malloc(20);
		memset(stat_msg, 0, 20);
		for (z = 0;; z++)
		{
			stat_msg[z] = *(ucp_data + tcphdr_size);
			ucp_data++;
			if (strncmp((ucp_data + tcphdr_size), "\n", 1) == 0) break;

		}
		//printf("http_stat_msg ���� :%s\n", stat_msg);

		char *res_line; // http_response_line ����

		res_line = malloc(strlen(pro) + strlen(stat_code) + strlen(stat_msg));
		memset(res_line, 0, (strlen(pro) + strlen(stat_code) + strlen(stat_msg)));

		strcpy(res_line, pro);
		strcat(res_line, " ");
		strcat(res_line, stat_code);
		strcat(res_line, " ");
		strcat(res_line, stat_msg);
		//printf("http_response_line ���� :%s\n",res_line); 
		
		
		for (i = 0; ; i++)
		{
			ucp_data++;
			if (strncmp((ucp_data + tcphdr_size +1), "\n", 1) == 0) break;
			for (z = 0;; z++)
			{
				header[i][z] = *(ucp_data + tcphdr_size);
				ucp_data++;
				if (strncmp((ucp_data + tcphdr_size), "\n", 1) == 0) break;

			}
			
			//printf("header ���� :%s\n", header[i]);
			
			if ((UI_NEXT - tcphdr_size) == 0) break;
		}

		if (strncmp(keyword, "http_protocol;", 14) == 0)
		{
			for (x = 0; x < strlen(pro); x++)
			{
				if (pro[x] == value[0])
				{
					for (y = 1; y < strlen(value); y++) if (pro[x + y] != value[y]) break;
					if (y == (strlen(value))) break;
				}
			}

			if (y == (strlen(value)))
			{
				start = packet_size - UI_NEXT + tcphdr_size + x;
				save_json(start, start + y - 1);
			}
			else return 0;
		}

		else if (strncmp(keyword, "http_stat_code;", 15) == 0)
		{
			for (x = 0; x < strlen(stat_code); x++)
			{
				if (stat_code[x] == value[0])
				{
					for (y = 1; y < strlen(value); y++) if (stat_code[x + y] != value[y]) break;
					if (y == (strlen(value))) break;
				}
			}

			if (y == (strlen(value)))
			{
				start = packet_size - UI_NEXT + tcphdr_size + strlen(pro) + x + 1;
				save_json(start, start + y - 1);
			}
			else return 0;
		}

		else if (strncmp(keyword, "http_stat_msg;", 14) == 0)
		{
			for (x = 0; x < strlen(stat_msg); x++)
			{
				if (stat_msg[x] == value[0])
				{
					for (y = 1; y < strlen(value); y++) if (stat_msg[x + y] != value[y]) break;
					if (y == (strlen(value))) break;
				}
			}

			if (y == (strlen(value)))
			{
				start = packet_size - UI_NEXT + tcphdr_size + strlen(pro) + strlen(stat_code) + x + 2;
				save_json(start, start + y - 1);
			}
			else return 0;
		}

		else if (strncmp(keyword, "http_response_line;", 19) == 0)
		{
			for (x = 0; x < strlen(res_line); x++)
			{
				if (res_line[x] == value[0])
				{
					for (y = 1; y < strlen(value); y++) if (res_line[x + y] != value[y]) break;
					if (y == (strlen(value))) break;
				}
			}

			if (y == (strlen(value)))
			{
				start = packet_size - UI_NEXT + tcphdr_size + x;
				save_json(start, start + y - 1);
			}
			else return 0;
		}

		else if (strncmp(keyword, "http_content_type;", 18) == 0)
		{
			for (count = 0; count < i; count++)
			{
				if (strncmp(header[count], "Content-Type:", 13) == 0)
				{
					for (x = 0; x < strlen(header[count]); x++)
					{
						if (header[count][x] == value[0])
						{
							for (y = 1; y < strlen(value); y++) if (header[count][x + y] != value[y]) break;
							if (y == (strlen(value))) break;
						}
					}
					if (y == (strlen(value))) break;
				}
			}
			if (y == (strlen(value)))
			{
				start = packet_size - UI_NEXT + tcphdr_size + strlen(res_line) + 2*(count+1)+ 12;
				for (x = 0; x < count; x++) {
					start += strlen(header[x]);
				}
				
				save_json(start, start + y - 1);
			}
			else return 0;
		}
	
		else if (strncmp(keyword, "http_content_len;", 17) == 0)
		{
			for (count = 0; count < i; count++)
			{
				if (strncmp(header[count], "Content-Length:", 15) == 0)
				{
					for (x = 0; x < strlen(header[count]); x++)
					{
						if (header[count][x] == value[0])
						{
							for (y = 1; y < strlen(value); y++) if (header[count][x + y] != value[y]) break;
							if (y == (strlen(value))) break;
						}
					}
					if (y == (strlen(value))) break;
				}
			}
			if (y == (strlen(value)))
			{
				start = packet_size - UI_NEXT + tcphdr_size + strlen(res_line) + 2 * (count + 1) + 12;
				for (x = 0; x < count; x++) {
					start += strlen(header[x]);
				}

				save_json(start, start + y - 1);
			}
			else return 0;
		}
		else return 0;
		// ���� ���� �ȳ����� ��� �̾ �˻�
		while (strncmp((rule + pos), ")", 1))
		{

			if (strncmp((rule + pos), "content:", 8) == 0)
			{

				pos = extract_value(rule, pos, &value) - 1;
				extract_keyword(rule, pos);
				if (ViewHTTP_Response(vpdata, tcphdr_size, UI_NEXT, packet_size, rule, pos) == 0) return 0;
			}
			pos++;
		}

		if (strncmp((rule + pos), ")", 1) == 0) printf("����Ǿ����ϴ�.\n\n"); save_json(0, 0);
		
		return 0;
	}
	return 0;
}

int pcre_matching(const char* subject, const char* pattern, int x)
{
	const char* err;
	char* patt;
	int err_offset;
	int match_offsets[128];
	const char** groups;
	int i;
	pcre* regex;

	while (1)
	{
		
		if (x == (strlen(pattern))) break;
		
		if (strncmp(pattern + x, "/", 1) == 0)
		{
			return pcre_opt_matching(subject, pattern, pattern + x+1, 2);
		}
		x++;
	}

	if (x == (strlen(pattern)))
	{
		regex = pcre_compile(pattern, 0, &err, &err_offset, NULL);
		// Create Regex
		pcre_extra* regex_aux = pcre_study(regex, 0, &err); // Regex match
		int result = pcre_exec(regex, regex_aux, subject, strlen(subject), 0, 0, match_offsets, 128); // Retrieve matched strings
		pcre_get_substring_list(subject, match_offsets, result, &groups);
		pcre_free_study(regex_aux);
		pcre_free(regex);
		return result;
	}

}

int pcre_opt_matching(const char* subject, const char* pattern, const char* opt, int opt_count)
{
	const char* err;
	char* patt;
	int err_offset;
	int match_offsets[128];
	const char** groups;
	int i, x, result;
	x = 0;
	pcre* regex;

	while (1)
	{

		if (x == (strlen(pattern))) break;

		//��ҹ��� ���� X
		if ((strncmp(pattern + x + 1, "/", 1) == 0) && (strncmp(opt, "i", 1) == 0))
		{
			patt = malloc(x + 2);
			memset(patt, 0, x + 2);
			strncpy(patt, pattern, x+1);
			regex = pcre_compile(patt, PCRE_CASELESS, &err, &err_offset, NULL);
			pcre_extra* regex_aux = pcre_study(regex, 0, &err); // Regex match 
			result = pcre_exec(regex, regex_aux, subject, strlen(subject), 0, 0, match_offsets, 128); // Retrieve matched strings 
			pcre_get_substring_list(subject, match_offsets, result, &groups);
			pcre_free_study(regex_aux);
			pcre_free(regex);;
			opt_count++;
			if (strlen(opt) !=2) pcre_opt_matching(subject, pattern, pattern + x + opt_count, opt_count);
			return result;
		}
		
		if ((strncmp(pattern + x + 1, "/", 1) == 0) && (strncmp(opt, "s", 1) == 0))
		{
			patt = malloc(x + 2);
			memset(patt, 0, x + 2);
			strncpy(patt, pattern, x+1);
			regex = pcre_compile(patt, PCRE_DOTALL, &err, &err_offset, NULL);
			pcre_extra* regex_aux = pcre_study(regex, 0, &err); // Regex match 
			result = pcre_exec(regex, regex_aux, subject, strlen(subject), 0, 0, match_offsets, 128); // Retrieve matched strings 
			pcre_get_substring_list(subject, match_offsets, result, &groups);
			pcre_free_study(regex_aux);
			pcre_free(regex);
			
			opt_count++;
			if (strlen(opt) != 2) pcre_opt_matching(subject, pattern, pattern + x + opt_count, opt_count);
			return result;
		}

		if ((strncmp(pattern + x + 1, "/", 1) == 0) && (strncmp(opt, "m", 1) == 0))
		{
			patt = malloc(x + 2);
			memset(patt, 0, x + 2);
			strncpy(patt, pattern, x+1);
			regex = pcre_compile(patt, PCRE_MULTILINE, &err, &err_offset, NULL);
			pcre_extra* regex_aux = pcre_study(regex, 0, &err); // Regex match 
			result = pcre_exec(regex, regex_aux, subject, strlen(subject), 0, 0, match_offsets, 128); // Retrieve matched strings 
			pcre_get_substring_list(subject, match_offsets, result, &groups);
			pcre_free_study(regex_aux);
			pcre_free(regex);
			opt_count++;
			if (strlen(opt) != 2) pcre_opt_matching(subject, pattern, pattern + x + opt_count, opt_count);
			return result;
		}
		x++;
	}
	return 0;
}

int cnt,temp = 0;
int start_byte[20][2] = { 0, };
int end_byte[20][2] = { 0, };
FILE *jfp = 0;

int save_json(int start, int end)
{

	if (temp != pcnt) cnt =0;
	temp = pcnt;
	printf("start:%d\n", start);
	/*
	printf("\n����Ƚ�� = %d\n", cnt);
	printf("\n��Ŷ��ȣ = %d\n", pcnt);
	printf("\n���� = %d\n", start);
	printf("�� = %d\n", end);
	printf("Ÿ�� value :");
	for (int w = 0; w < strlen(value); w++) printf("%02x ", value[w]);
	printf("\n\n");
	*/
	start_byte[cnt][0] = start;
	end_byte[cnt][0] = end;
	
	if (start == 0 && end == 0)
	{
		
		for (cnt = 0; ; cnt++)
		{// JSON ������ ���缭 fprintf �Լ��� �� ���
			if (cnt == 0)
			{
				strcat(fname, ".json");
				jfp = fopen(fname, "w");    // ���� ���� ���� ����
				fprintf(jfp, "{\n");
				fprintf(jfp, "  \"Packet_No\": %d,\n", pcnt);
				fprintf(jfp, "  \"Sid\": %d", signatue_id);

			}

			if (start_byte[cnt][0] == NULL)
			{
				fprintf(jfp, ",\n  \"Start_Byte\": [");
				for (int x = 0; x <= cnt; x++)
				{
					if (start_byte[x][0] == 0) break;
					fprintf(jfp, "%d", start_byte[x][0]);
					
					if (x != cnt && (start_byte[x + 1][0] != 0)) fprintf(jfp, ", ");
				}
				fprintf(jfp, "]");

				fprintf(jfp, ",\n  \"End_Byte\": [");
				for (int x = 0; x <= cnt; x++)
				{
					if (end_byte[x][0] == 0) break;
					fprintf(jfp, "%d", end_byte[x][0]);
					
					if (x!=cnt && (end_byte[x+1][0] != 0)) fprintf(jfp, ", ");
				}
				fprintf(jfp, "]");

				fprintf(jfp, "\n");
				fprintf(jfp, "}\n");
				fclose(jfp);    // ���� �ݱ�
				exit(1);
			}

				//fprintf(jfp, "  \"End_Byte\": %d", end_byte[cnt][0]);

		}
	}
	
	else
	{
		cnt++;
		return 0;
	}
}