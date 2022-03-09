#define _CRT_SECURE_NO_WARNINGS

#include <Windows.h>
#include <iostream>
#include <fstream>
#include <time.h>
#include <string>
#include <sstream>
#include <thread>
#include <iomanip>
#include <vector>
#include "asm.h"



extern void WriteLog(std::string text);

typedef struct _packet {
	WORD size;
	//WORD Opcode;
	BYTE packetmessage[4000] = { 0 };
};


const char* string_to_hex(const char *str, char *hex, size_t maxlen)
{
	static const char* const lut = "0123456789ABCDEF";

	if (str == NULL) return NULL;
	if (hex == NULL) return NULL;
	if (maxlen == 0) return NULL;

	size_t len = strlen(str);

	char *p = hex;

	for (size_t i = 0; (i < len) && (i < (maxlen - 1)); ++i)
	{
		const unsigned char c = str[i];
		*p++ = lut[c >> 4];
		*p++ = lut[c & 15];
	}

	*p++ = 0;

	return hex;
}


template<typename TInputIter>
std::string make_hex_string(TInputIter first, TInputIter last, bool use_uppercase = true, bool insert_spaces = false)
{
	std::ostringstream ss;
	ss << std::hex << std::setfill('0');
	if (use_uppercase)
		ss << std::uppercase;
	while (first != last)
	{
		ss << std::setw(2) << static_cast<int>(*first++);
		if (insert_spaces && first != last)
			ss << " ";
	}
	return ss.str();
}

template<typename TInputIter>
std::string make_hex_stringx(TInputIter first, TInputIter last,int size, bool use_uppercase = true, bool insert_spaces = false)
{
	int i = 0;
	std::ostringstream ss;
	ss << std::hex << std::setfill('0');
	if (use_uppercase)
		ss << std::uppercase;
	while (i < size)
	{
		ss << std::setw(2) << static_cast<int>(*first++);
		if (insert_spaces && first != last)
			ss << " ";
		i++;
	}
	return ss.str();
}





void PacketHandlerThread(int packetx) {
	packetx -= 2;
	auto packet = (_packet*)packetx;
	
	auto from_array = make_hex_stringx(std::begin(packet->packetmessage), std::end(packet->packetmessage),packet->size+2, true, true);

	WriteLog("Size: " + std::to_string(packet->size) + " - Packet: " + from_array);


	HANDLE CurrentThread = GetCurrentThread();
	CloseHandle(CurrentThread);
}

void _stdcall PacketHandler(int user,int packet) {
	std::thread thread(PacketHandlerThread, packet);
	thread.detach();
}




DWORD PacketHook_exit = 0x00474920;
DWORD PacketHook_handled = 0x00474925;
__declspec(naked) void naked_PacketHook() {
	__asm {
		add edx, 02

		pushad
		pushfd
		push edx
		push ebx
		call PacketHandler
		popfd
		popad

		mov ecx, ebx
		jmp PacketHook_exit

		processed :
		popfd
		popad
		mov ecx, ebx
		jmp PacketHook_handled
	}
}





void PacketHandlerHook() {
	CMyInlineHook HookObj;
	HookObj.Hook((PVOID)0x0047491B, naked_PacketHook, 5);
}