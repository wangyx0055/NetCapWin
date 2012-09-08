/*
*	���ߣ�lyz
*	����ʱ�䣺2011.03.14
*	�����£�2011.04.10 16��00
*	��ϵ��ʽ��leeicoding@gmail.com || QQ:498168146
*
*/
/*************************************************************
*			���˱�������Ȩ��
*	��������������ѧϰĿ��ʹ�á����ơ��޸ġ�������
*	��������������������
*ע�⣺	�κγ�����ҵ��Ŀ��ʹ�ñ����룬���뾭ԭ��������ͬ�⡣
*	�緢��δ������ͬ��ͰѴ˴���������ҵ����
*	���߽������޹���ɽ�Ĳ�и̬�ȶ������ף�
*/

#include "iostream"
#include "mem.h"

#define HAVE_REMOTE
#include "pcap.h"
#include "pcap-bpf.h"

#include "capturepacket.h"
#include "setting.h"

using namespace std;

extern void pri(pcap_if_t *);
extern int postToProcess(u_char*,int,int);
extern int getMac(const unsigned char *);
extern DWORD WINAPI addPacket(LPVOID , int,char*);

int getTime(const struct pcap_pkthdr *, char *);



int capturePacket(pcap_if_t*,char [] ,u_int);
void packet_handler(u_char *, const struct pcap_pkthdr *, const u_char *);

int getAdapter(LPVOID lpParameter)
{
    pcap_if_t *allDevs;
    char errbuf[PCAP_ERRBUF_SIZE];
    int ret;

    ret = pcap_findalldevs_ex((char*)PCAP_SRC_IF_STRING, NULL, &allDevs, errbuf);

    if(ret == -1)
    {
        fprintf(stderr,"��ȡ�������б�ʧ�ܡ�������Ϣ��%s\n",errbuf);
    }

    pri(allDevs);
/********************************************************************/
    capturePacket(allDevs->next,(char*)"",0);
/********************************************************************/

    pcap_freealldevs(allDevs);

    return 0;
}

int capturePacket(pcap_if_t* adapter,char setfilter[],u_int netmask)
{
    pcap_t *adhandle;
    int ret;
    struct bpf_program fcode;
    pcap_dumper_t *dumpfile;

    char errbuf[PCAP_ERRBUF_SIZE];

    /*��������*/
    adhandle = pcap_open(adapter->name,
                    65536,
                    PCAP_OPENFLAG_PROMISCUOUS,
                    1000,
                    NULL,
                    errbuf);
    if(adhandle == NULL)
    {
        fprintf(stderr,"��������ʧ��\n");
        pcap_freealldevs(adapter);
        return -1;
    }
    /*��ȡ��ַ���룬��������Ĭ��ΪC����*/
    if(adapter->addresses != NULL || netmask == 0)
        netmask=((struct sockaddr_in *)(adapter->addresses->netmask))->sin_addr.S_un.S_addr;
    else
        netmask=0xffffff;

    ret = pcap_compile(adhandle, &fcode, setfilter, 1, netmask);
    if(ret < 0)
    {
        fprintf(stderr,"����������ʧ�ܣ�\n");
        pcap_freealldevs(adapter);
        return -1;
    }else puts("����������ɹ���");
    ret = pcap_setfilter(adhandle,&fcode);
    if(ret < 0)
    {
        fprintf(stderr,"����������ʧ�ܣ�\n");
        pcap_freealldevs(adapter);
        return -1;
    }else puts("���������óɹ���\n");

    system("pause");
    system("cls");
    puts("��ʼ����...");

    dumpfile = pcap_dump_open(adhandle, "log.pcap");

    pcap_loop(adhandle, 0, packet_handler, (unsigned char *)dumpfile);

    return 0;
}

void packet_handler(u_char *dumpfile, const struct pcap_pkthdr *header, const u_char *pkt_data)
{
    u_short *pap_type;                          //�����б��Ƿ���PAP
    u_short *pppoe_type;                        //�����б��Ƿ���PPPoE
    u_char *userpwd;                            //�����û�������
    u_char *packet_type;                        //�ж�u_char��������
    u_short *packet_d_type;                     //�ж�˫�ֽڱ�ʶ���İ�
    u_short *err_type;                          //�жϴ�������
    int userpwd_len;                            //�û�������
    char timestr[16];




    pap_type = (u_short *)(pkt_data + 20);     //ȡ���ݰ�����
    pppoe_type = (u_short*)(pkt_data + 12);
    userpwd = (u_char *)(pkt_data + 27);        //ȡ�û�����

    err_type = (u_short*)(pkt_data +25);        //ȡ��������

    userpwd_len = header->len - 27;

    getTime(header,timestr);


/********************************************************/
/*              ȡ��Ч�İ�����LIST                      */
/********************************************************/
                    /*PAP��*/
    if(ntohs(0x23c0) == ntohs(*pap_type) )         //PAP������
    {
        packet_type = (u_char*)(pkt_data + 22);     //ȡPAP����
        if(ntohs(0x03) ==  ntohs(*packet_type))
        {   //��֤ʧ�� NAK��
            addPacket((LPVOID)pkt_data,IS_PAP_NAK,timestr);
            pcap_dump(dumpfile, header, pkt_data);
        }
         if(ntohs(0x02) == ntohs(*packet_type))
        {   //ͨ����֤ ACK��
            addPacket((LPVOID)pkt_data,IS_PAP_ACK,timestr);
            pcap_dump(dumpfile, header, pkt_data);
        }
        if(ntohs(0x01) == ntohs(*packet_type))
        {   //�˰������û�������Ϊ  REQUEST��
            addPacket((LPVOID)pkt_data,IS_PAP_REQUEST,timestr);
            pcap_dump(dumpfile, header, pkt_data);
        }

    }
                    /*PPPoE��*/
    if(ntohs(0x6388) == ntohs(*pppoe_type))
    {
        packet_type = (u_char*)(pkt_data + 15);
        if(ntohs(0x09) == ntohs(*packet_type))
        {   //�㲥 REQUEST Active Discovery Initination PADI��
            addPacket((LPVOID)pkt_data,IS_PPPOE_PADI,timestr);
            pcap_dump(dumpfile, header, pkt_data);
        }
        else if(ntohs(0x07) == ntohs(*packet_type))
        {   //ͨ����֤ Active Discovery Offer  PIDO��
            addPacket((LPVOID)pkt_data,IS_PPPOE_PADO,timestr);
            pcap_dump(dumpfile, header, pkt_data);
        }
        else if(ntohs(0x19) == ntohs(*packet_type))
        {   //Active Discovery Request DISR��
            addPacket((LPVOID)pkt_data,IS_PPPOE_PADR,timestr);
            pcap_dump(dumpfile, header, pkt_data);
        }
        else packet_d_type = (u_short*)(pkt_data + 15); //˫�ֽڱ�ʶ��������
        if(ntohs(0x8f1a) ==  ntohs(*packet_d_type))
        {   //Active Discovery Session PADS��
            addPacket((LPVOID)pkt_data,IS_PPPOE_PADS,timestr);
            pcap_dump(dumpfile, header, pkt_data);
        }
    }

}

int getTime(const struct pcap_pkthdr *header, char *timestr)
{
    time_t local_tv_sec;
    struct tm *ltime;

    local_tv_sec = header->ts.tv_sec;
    ltime=localtime(&local_tv_sec);
    strftime(timestr, 22, "%H:%M:%S", ltime);

    return 0;
}
