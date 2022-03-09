#pragma once
#include <windows.h>
class CMyInlineHook
{
public:
	CMyInlineHook(void);
	BOOL Hook(PVOID pOriginalAddr, PVOID pNewAddr, int nSize = 5);
	BOOL UnHook();
	BOOL WriteBytes(LPVOID endereco, LPCVOID valor, int size);
private:
	PVOID m_pNewAddr;
	PVOID M_pOriginalAddr;
	BYTE  m_byOriginalCode[8];
	BYTE  m_byJmpAsmCode[8];
	int   m_nSize;
};