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
