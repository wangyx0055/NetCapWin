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
