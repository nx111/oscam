#if !defined(__AFX_XCAM_SERVER_H__INCLUDED_)
#define __AFX_XCAM_SERVER_H__INCLUDED_

typedef  unsigned int UINT;
//typedef  int           BOOL;

#define SOCKET		int


int XCAM_Init(int nPort);
int XCAM_Start(void);
int XCAM_Stop(void);
int XCAM_Reset(void);

#endif //__AFX_XCAM_SERVER_H__INCLUDED_

