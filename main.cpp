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
#define HAVE_REMOTE
#include "pcap.h"
#include <iostream>


using namespace std;

extern int getAdapter(LPVOID lpParameter);
extern int initpro();

int main()
{
    initpro();
    getAdapter(NULL);
    return 0;
}

void pri(pcap_if_t *dev)
{
    pcap_if_t *d;
    d=dev;
    while(d != NULL)
    {
        if(d->addresses != NULL)
            printf("%s\n%s\n",d->description,d->name);
        d=d->next;
    }
}
