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
