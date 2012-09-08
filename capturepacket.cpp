/*
*	作者：lyz
*	创建时间：2011.03.14
*	最后更新：2011.04.10 16：00
*	联系方式：leeicoding@gmail.com || QQ:498168146
*
*/
/*************************************************************
*			个人保留所有权利
*	本代码仅允许出于学习目的使用、复制、修改、发布。
*	此声明必须完整保留。
*注意：	任何出于商业化目的使用本代码，必须经原作者书面同意。
*	如发现未经书面同意就把此代码用于商业化。
*	作者将会以愚公移山的不懈态度斗争到底！
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
        fprintf(stderr,"获取适配器列表失败。错误信息：%s\n",errbuf);
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

    /*打开适配器*/
    adhandle = pcap_open(adapter->name,
                    65536,
                    PCAP_OPENFLAG_PROMISCUOUS,
                    1000,
                    NULL,
                    errbuf);
    if(adhandle == NULL)
    {
        fprintf(stderr,"打开适配器失败\n");
        pcap_freealldevs(adapter);
        return -1;
    }
    /*获取地址掩码，无掩码则默认为C类网*/
    if(adapter->addresses != NULL || netmask == 0)
        netmask=((struct sockaddr_in *)(adapter->addresses->netmask))->sin_addr.S_un.S_addr;
    else
        netmask=0xffffff;

    ret = pcap_compile(adhandle, &fcode, setfilter, 1, netmask);
    if(ret < 0)
    {
        fprintf(stderr,"过滤器编译失败！\n");
        pcap_freealldevs(adapter);
        return -1;
    }else puts("过滤器编译成功！");
    ret = pcap_setfilter(adhandle,&fcode);
    if(ret < 0)
    {
        fprintf(stderr,"过滤器设置失败！\n");
        pcap_freealldevs(adapter);
        return -1;
    }else puts("过滤器设置成功！\n");

    system("pause");
    system("cls");
    puts("开始监听...");

    dumpfile = pcap_dump_open(adhandle, "log.pcap");

    pcap_loop(adhandle, 0, packet_handler, (unsigned char *)dumpfile);

    return 0;
}

void packet_handler(u_char *dumpfile, const struct pcap_pkthdr *header, const u_char *pkt_data)
{
    u_short *pap_type;                          //用于判别是否是PAP
    u_short *pppoe_type;                        //用于判别是否是PPPoE
    u_char *userpwd;                            //保存用户名密码
    u_char *packet_type;                        //判断u_char包的类型
    u_short *packet_d_type;                     //判断双字节标识符的包
    u_short *err_type;                          //判断错误类型
    int userpwd_len;                            //用户名长度
    char timestr[16];




    pap_type = (u_short *)(pkt_data + 20);     //取数据包类型
    pppoe_type = (u_short*)(pkt_data + 12);
    userpwd = (u_char *)(pkt_data + 27);        //取用户名段

    err_type = (u_short*)(pkt_data +25);        //取错误类型

    userpwd_len = header->len - 27;

    getTime(header,timestr);


/********************************************************/
/*              取有效的包加入LIST                      */
/********************************************************/
                    /*PAP包*/
    if(ntohs(0x23c0) == ntohs(*pap_type) )         //PAP包特征
    {
        packet_type = (u_char*)(pkt_data + 22);     //取PAP类型
        if(ntohs(0x03) ==  ntohs(*packet_type))
        {   //认证失败 NAK包
            addPacket((LPVOID)pkt_data,IS_PAP_NAK,timestr);
            pcap_dump(dumpfile, header, pkt_data);
        }
         if(ntohs(0x02) == ntohs(*packet_type))
        {   //通过认证 ACK包
            addPacket((LPVOID)pkt_data,IS_PAP_ACK,timestr);
            pcap_dump(dumpfile, header, pkt_data);
        }
        if(ntohs(0x01) == ntohs(*packet_type))
        {   //此包含有用户名密码为  REQUEST包
            addPacket((LPVOID)pkt_data,IS_PAP_REQUEST,timestr);
            pcap_dump(dumpfile, header, pkt_data);
        }

    }
                    /*PPPoE包*/
    if(ntohs(0x6388) == ntohs(*pppoe_type))
    {
        packet_type = (u_char*)(pkt_data + 15);
        if(ntohs(0x09) == ntohs(*packet_type))
        {   //广播 REQUEST Active Discovery Initination PADI包
            addPacket((LPVOID)pkt_data,IS_PPPOE_PADI,timestr);
            pcap_dump(dumpfile, header, pkt_data);
        }
        else if(ntohs(0x07) == ntohs(*packet_type))
        {   //通过认证 Active Discovery Offer  PIDO包
            addPacket((LPVOID)pkt_data,IS_PPPOE_PADO,timestr);
            pcap_dump(dumpfile, header, pkt_data);
        }
        else if(ntohs(0x19) == ntohs(*packet_type))
        {   //Active Discovery Request DISR包
            addPacket((LPVOID)pkt_data,IS_PPPOE_PADR,timestr);
            pcap_dump(dumpfile, header, pkt_data);
        }
        else packet_d_type = (u_short*)(pkt_data + 15); //双字节标识符包类型
        if(ntohs(0x8f1a) ==  ntohs(*packet_d_type))
        {   //Active Discovery Session PADS包
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
