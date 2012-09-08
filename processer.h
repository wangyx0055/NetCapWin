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
#ifndef PROCESSER_H_INCLUDED
#define PROCESSER_H_INCLUDED

#define MAC_SIZE 15
#define MAX_USER_SIZE 30
#define MAX_PWD_SIZE 30
#define MAX_AC_NAME_MAX 25
#define MAX_COOKIE_SIZE 28
#define MAX_TIME_SIZE 16


typedef struct listPadket
{
    const unsigned char *data;
    int packetType;
    char time[MAX_TIME_SIZE];
    int lock;
}LISTPACKET;


typedef struct data_of_pap
{
    int packet_type;
    unsigned char time[MAX_TIME_SIZE];
    unsigned char user[MAX_USER_SIZE];
    unsigned char pwd[MAX_PWD_SIZE];
    unsigned char srcMAC[MAC_SIZE];
    unsigned char dstMAC[MAC_SIZE];
}DATA_OF_PAP;

typedef struct data_of_pppoe
{
    unsigned int packetType;
    unsigned char time[MAX_TIME_SIZE];
    unsigned char AC_name[MAX_AC_NAME_MAX];
    int *q;
    unsigned char AC_cookie[MAX_COOKIE_SIZE];
    int *p;
    unsigned char dstMAC[MAC_SIZE];
    unsigned char srcMAC[MAC_SIZE];

}DATA_OF_PPPOE;
#endif // PROCESSER_H_INCLUDED
