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
    con = mysql_init(NULL);//初始化

    if (!mysql_real_connect(con, "127.0.0.1", "root", "root", "nic", 3306, NULL, 0))//连接，
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


/*********************执行SQL语句*******************************/
    if (mysql_query( con, sqltext))
    {
        //执行SQL语句出错
        fprintf(stderr, "%s\n", mysql_error(con));;
        mysql_close( con ) ;
        return FALSE ;
    }
/**************************************************************/

    //mysql_close(con);
    return 0;
}
