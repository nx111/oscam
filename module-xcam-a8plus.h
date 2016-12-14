/*************************************************************************
* Copyright (c) 2005, TIARTOP
* All rights reserved.
* 
* 文件名称： CccamClient.h
* 
* 摘    要： CCCAM Client实现
* 
* 当前版本： 1.0
*
* 作    者： 田龙
*
* 完成日期： 2010年04月13日
*************************************************************************/

#if !defined(__AFX_XCAM_SERVER_H__INCLUDED_)
#define __AFX_XCAM_SERVER_H__INCLUDED_

#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <unistd.h>
#include <time.h>
#include <stdlib.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <net/route.h>
#include <linux/if_ether.h>
#include <netpacket/packet.h>


#include <linux/ioctl.h>
#include <errno.h>
#include <fcntl.h>
#include <time.h>

/////////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////////

typedef  unsigned int UINT;
typedef  int           BOOL;

#define SOCKET		int



//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////


BOOL XCAM_Init(int nPort);

//启动运行
BOOL XCAM_Start();

BOOL XCAM_Stop();

BOOL XCAM_Reset();




#endif //__AFX_XCAM_SERVER_H__INCLUDED_






