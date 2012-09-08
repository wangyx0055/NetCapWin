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
#include "stdio.h"
#include "stdlib.h"
#include "string.h"
#include "windows.h"
#include "iostream"

#include "processer.h"
#include "setting.h"
#include "capturepacket.h"

#define BUF_MAX_SIZE 655
#define LOCK 1
#define UNLOCK 0

using namespace std;

LISTPACKET buf[BUF_MAX_SIZE];
volatile UINT64 buf_used = 0;
int p_of_add=0;

HANDLE *hThreadDelPacket;

int getPAPRequest(DATA_OF_PAP *,const u_char *);
int PAP_processer(LISTPACKET *);
int pppoeProcesser(LISTPACKET *);
int getMAC(unsigned char *,unsigned char *,const unsigned char *);
int getACNAME(unsigned char *, const unsigned char *);
int getCOOKIE(unsigned char *, const unsigned char *);
extern DWORD WINAPI getAdapter(LPVOID lpParameter);
extern int dbconnector(void* ,int);
extern int initdb();


DWORD WINAPI addPacket(LPVOID lpParameter,int packetType,char *timestr)
{
    const unsigned char *data = (const unsigned char *)lpParameter;

    if(buf_used == BUF_MAX_SIZE-1)
    {
        cout<<"���治��,�˰���������"<<endl;
        return 0;
    }
        /*Ѱ��δʹ�õ�buf�ռ�*/
    while(buf[p_of_add].lock == LOCK)
    {
        p_of_add = (p_of_add+1)%BUF_MAX_SIZE;
    }
    if(buf[p_of_add].lock == UNLOCK && buf[p_of_add].packetType == 0)
    {
        buf[p_of_add].lock=LOCK;
        buf[p_of_add].packetType = packetType;
        buf[p_of_add].data=data;
        buf_used++;
        strcpy(buf[p_of_add].time,timestr);
        cout<<"that:"<<buf[p_of_add].packetType<<endl;
    }
    return 0;
}

DWORD WINAPI delPacket(LPVOID lpParameter)
{
    int p=0;

    while(1)
    {

        if(buf[p].lock == UNLOCK)
        {
            p = (p+1)%BUF_MAX_SIZE;
            continue;
        }
        else if(buf[p].lock == LOCK && buf[p].packetType != 0)
        {
/********************************************************************/
                    /*�����ﴦ�����ݰ�*/
                    cout<<"this:"<<buf[p].packetType<<endl;
        switch(buf[p].packetType )
        {
            case IS_PAP_REQUEST :cout <<"����һ��PAP_REQUEST��"<<buf[p].packetType<<endl;
                                PAP_processer(&buf[p]);
                                break;
            case IS_PAP_ACK :    cout <<"����һ��PAP_ACK��"<<buf[p].packetType<<endl;
                                PAP_processer(&buf[p]);
                                break;
            case IS_PAP_NAK :    cout <<"����һ��PAP_NAK��"<<buf[p].packetType<<endl;
                                PAP_processer(&buf[p]);
                                break;
            /****************************************************/
            case IS_PPPOE_PADI : cout <<"����һ��PPPOE_PADI��"<<buf[p].packetType<<endl;
                                pppoeProcesser(&buf[p]);
                                break;
            case IS_PPPOE_PADO : cout <<"����һ��PPPOE_PADO��"<<buf[p].packetType<<endl;
                                pppoeProcesser(&buf[p]);
                                break;
            case IS_PPPOE_PADR : cout <<"����һ��PPPOE_PADR��"<<buf[p].packetType<<endl;
                                pppoeProcesser(&buf[p]);
                                break;
            case IS_PPPOE_PADS : cout <<"����һ��PPPOE_PADS��"<<buf[p].packetType<<endl;
                                pppoeProcesser(&buf[p]);
                                break;
            default :break;
        }

/********************************************************************/
            buf[p].data=NULL;
            buf[p].packetType=0;
            buf[p].lock=UNLOCK;
            buf_used--;

            if(buf_used == 0)
            {
                cout<< "����Ϊ��"<<endl;
                //_sleep(1000);
            }
        }
    p = (p+1)%BUF_MAX_SIZE;
    }
    return 0;
}

int initpro()
{
    HANDLE hThreadDelPacket;
    initdb();
    hThreadDelPacket = CreateThread(NULL,0,delPacket,NULL,0,NULL);

    return 0;
}

int PAP_processer(LISTPACKET *list)
{
 /******************************************/
    DATA_OF_PAP packet;
/*******************************************/

    packet.packet_type = list->packetType;
    memcpy(packet.time,list->time,16);
    if(list->packetType == IS_PAP_REQUEST);
    {
        getPAPRequest(&packet,list->data);
        getMAC(packet.srcMAC,packet.dstMAC,list->data);

        packet.dstMAC[MAC_SIZE]='\0';
        dbconnector(&packet,packet.packet_type);
        return 0;
    }
    if(list->packetType == IS_PAP_ACK);
    {
        getMAC(packet.srcMAC,packet.dstMAC,list->data);

        packet.dstMAC[MAC_SIZE]='\0';
        dbconnector(&packet,packet.packet_type);
        return 0;
    }
    if(list->packetType == IS_PAP_NAK);
    {
        getMAC(packet.srcMAC,packet.dstMAC,list->data);
        packet.dstMAC[MAC_SIZE]='\0';
        dbconnector(&packet,packet.packet_type);
        return 0;
    }
    return 0;
}

int getPAPRequest(DATA_OF_PAP *pk,const u_char *pkt_data)
{
    unsigned char *user;
    int user_len;
    int pwd_len;

    unsigned char ch;


    user = (u_char *)(pkt_data + 27);        //ȡ�û�����

    ch = *(user -1);
    user_len = ch;
    ch = *(user + user_len);
    pwd_len = ch;

    memcpy(pk->user,user,user_len);
    pk->user[user_len] = '\0';
    memcpy(pk->pwd,(user+1+user_len),pwd_len);
    pk->pwd[pwd_len] = '\0';

    return 0;
}

int getMAC(unsigned char *srcMAC,unsigned char *dstMAC,const unsigned char *pkt_data)
{
    char mac[12];

    memcpy(dstMAC,pkt_data,6);
    for(int i=0;i<6;i++)
        sprintf((mac+i*2),"%.2x ",*(dstMAC+i));

    memcpy(dstMAC,mac,12);
    *(dstMAC+12) = '\0';

 /********************************************************************/
    memcpy(srcMAC,(pkt_data+6),6);
    for(int i=0;i<6;i++)
        sprintf(mac+i*2,"%.2x ",*(srcMAC+i));

    memcpy(srcMAC,mac,12);
    *(srcMAC+12) = '\0';

    return 0;
}

int pppoeProcesser(LISTPACKET *list)
{
/*********************************************/
    DATA_OF_PPPOE packet;
/*********************************************/
    packet.packetType = list->packetType;
    memcpy(packet.time,list->time,16);

    if(list->packetType == IS_PPPOE_PADO)
    {
        getMAC(packet.srcMAC,packet.dstMAC,list->data);
        getACNAME(packet.AC_name,list->data);
        getCOOKIE(packet.AC_cookie,list->data);
        dbconnector(&packet,IS_PPPOE_PACKET);

    }
    if(list->packetType == IS_PPPOE_PADI)
    {
        getMAC(packet.srcMAC,packet.dstMAC,list->data);
        packet.AC_name[0]='\0';
        packet.AC_cookie[0]='\0';
        dbconnector(&packet,IS_PPPOE_PACKET);
        return 0;
    }
    if(list->packetType == IS_PPPOE_PADR)
    {
        getMAC(packet.srcMAC,packet.dstMAC,list->data);
        packet.AC_name[0]='\0';
        packet.AC_cookie[0]='\0';
        dbconnector(&packet,IS_PPPOE_PACKET);
        return 0;
    }
    if(list->packetType == IS_PPPOE_PADS)
    {
        getMAC(packet.srcMAC,packet.dstMAC,list->data);
        packet.AC_name[0]='\0';
        packet.AC_cookie[0]='\0';
        dbconnector(&packet,IS_PPPOE_PACKET);
        return 0;
    }

    return 0;
}

int getACNAME(unsigned char *ACNAME, const unsigned char *data)
{
    u_char *p;
    int len;

    p = (u_char*)(data+39);
    len = *p;
    memcpy(ACNAME,p+1,len);
    *(ACNAME+len) = '\0';

    return 0;
}

int getCOOKIE(unsigned char *COOKIE, const unsigned char *data)
{
    u_char *p;
    char ck[28];
    int len;

    p = (u_char*)(data+68);
    len = *p;

    memcpy(COOKIE,p+1,len);

    for(int i=0;i<28;i++)
        sprintf((ck+i*2),"%.2x ",*(COOKIE+i));

    memcpy(COOKIE,ck,28);
    *(COOKIE+28) = '\0';

    return 0;
}
