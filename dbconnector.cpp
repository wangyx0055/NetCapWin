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
#include <iostream>
#include <winsock.h>
#include <stdio.h>

#include "capturepacket.h"
#include "processer.h"
#include "setting.h"

#include "mysql.h"

using namespace std;

MYSQL *con;

int initdb()
{
    con = mysql_init(NULL);//��ʼ��

    if (!mysql_real_connect(con, "127.0.0.1", "root", "root", "nic", 3306, NULL, 0))//���ӣ�
    {
        fprintf(stderr, "%s\n", mysql_error(con));
        return 0;
    }
    return 0;
}

int dbconnector(void *pk,int pktype)
{

    char sqltext[500]="";

    if(!con)
        initdb();

    if(pktype/10 == IS_PAP_PACKET/10 )
    {
        DATA_OF_PAP *packet=(DATA_OF_PAP*)pk;
        packet->dstMAC[MAC_SIZE]='\0';

        //if(packet->packet_type == IS_PAP_REQUEST)
        sprintf(sqltext,"insert into paptb values('%s','%s','%s','%s',%d,'%s');",
                packet->dstMAC,
                packet->srcMAC,
                packet->user,
                packet->pwd,
                pktype,
                packet->time
                );
        if(packet->packet_type == IS_PAP_NAK)
        {
            sprintf(sqltext,"insert into paptb values('%s','%s','%s','%s',%d,'%s');",
                packet->dstMAC,
                packet->srcMAC,
                "null",
                "null",
                pktype,
                packet->time
                );
        }
        if(packet->packet_type == IS_PAP_ACK)
        {
            sprintf(sqltext,"insert into paptb values('%s','%s','%s','%s',%d,'%s');",
                packet->dstMAC,
                packet->srcMAC,
                "null",
                "null",
                pktype,
                packet->time
                );
        }
        printf("sqltext:%s\n",sqltext);
    }else if(pktype/10  == IS_PPPOE_PACKET/10)
    {
        DATA_OF_PPPOE *packet=(DATA_OF_PPPOE*)pk;
        packet->AC_name[MAX_AC_NAME_MAX]='\0';
        packet->AC_cookie[MAX_COOKIE_SIZE]='\0';

        sprintf(sqltext,"insert into pppoetb values('%s','%s','%s','%s',%d,'%s');",
                packet->dstMAC,
                packet->srcMAC,
                packet->AC_name,
                packet->AC_cookie,
                packet->packetType,
                packet->time
                );
        //printf("sqltext:%s\n",sqltext);
    }


/*********************ִ��SQL���*******************************/
    if (mysql_query( con, sqltext))
    {
        //ִ��SQL������
        fprintf(stderr, "%s\n", mysql_error(con));;
        mysql_close( con ) ;
        return FALSE ;
    }
/**************************************************************/

    //mysql_close(con);
    return 0;
}
