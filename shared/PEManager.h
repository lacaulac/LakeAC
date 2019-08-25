#pragma once
#include <Windows.h>
#include <algorithm>
#include <iterator>
#include <boost/uuid/detail/md5.hpp>
#include <boost/algorithm/hex.hpp>
#include <vector>

typedef struct {
	unsigned int p1, p2, p3, p4;
} md5_hash;

#define DEFAULT_BLOCK_SIZE 256

class PEManager
{
public:
	static IMAGE_DOS_HEADER* GetDOSHeader(HMODULE modHandle);
	static IMAGE_NT_HEADERS64* GetPEHeader(HMODULE modHandle);
	static IMAGE_NT_HEADERS64* GetPEHeader(IMAGE_DOS_HEADER* dosHeader);
	static IMAGE_SECTION_HEADER* GetSectionHeader(char* segmentName, IMAGE_NT_HEADERS64* peHeader);
	static IMAGE_SECTION_HEADER* GetSectionHeader(char* segmentName, IMAGE_DOS_HEADER* dosHeader);
	static IMAGE_SECTION_HEADER* GetSectionHeader(char* segmentName, HMODULE modHandle);
	static md5_hash HashMD5(void* source, size_t size);
	static std::vector<md5_hash> hashSection(HMODULE modHandle, char* segmentName, size_t blockSize);
	static std::vector<md5_hash> hashSection(HMODULE modHandle, char* segmentName);
	static std::vector<md5_hash> hashSection(HMODULE modHandle, const char* segmentName);
};

