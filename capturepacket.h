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
#ifndef CAPTUREPACKET_H_INCLUDED
#define CAPTUREPACKET_H_INCLUDED

typedef struct pap_header{
    u_char type;
    u_char length;
    u_short pro;
    u_char *data;
}pap_header;

typedef struct pppoe
{
    u_char vertype;
    u_char code;
    u_short session_id;
    u_short len;
    u_short pap;
}pppoe;

typedef struct ethdr
{
    u_char eh_dst[6];
    u_char eh_src[6];
    u_short eh_type;
}ether;
#endif // CAPTUREPACKET_H_INCLUDED
