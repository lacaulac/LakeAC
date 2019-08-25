#include "PEManager.h"

IMAGE_DOS_HEADER* PEManager::GetDOSHeader(HMODULE modHandle)
{
	return (IMAGE_DOS_HEADER*)modHandle;
}

IMAGE_NT_HEADERS64* PEManager::GetPEHeader(HMODULE modHandle)
{
	return GetPEHeader(GetDOSHeader(modHandle));
}

IMAGE_NT_HEADERS64* PEManager::GetPEHeader(IMAGE_DOS_HEADER* dosHeader)
{
	return (IMAGE_NT_HEADERS64*)((ULONGLONG)dosHeader + (ULONGLONG)dosHeader->e_lfanew);
}

IMAGE_SECTION_HEADER* PEManager::GetSectionHeader(char* sectionName, IMAGE_NT_HEADERS64* peHeader)
{
	ULONGLONG segmentTableAddress = (ULONGLONG)peHeader + peHeader->FileHeader.SizeOfOptionalHeader + sizeof(IMAGE_NT_HEADERS64) - (peHeader->FileHeader.NumberOfSections * sizeof(IMAGE_SECTION_HEADER));
	IMAGE_SECTION_HEADER* textSeg = NULL;
	for (int i = 0; i < peHeader->FileHeader.NumberOfSections; i++)
	{
		textSeg = (IMAGE_SECTION_HEADER*)(segmentTableAddress + (i * sizeof(IMAGE_SECTION_HEADER)));
		if (strcmp((char*)textSeg->Name, ".text") == 0)
			return textSeg;
	}
	return nullptr;
}

IMAGE_SECTION_HEADER* PEManager::GetSectionHeader(char* sectionName, IMAGE_DOS_HEADER* dosHeader)
{
	return GetSectionHeader(sectionName, GetPEHeader(dosHeader));
}

IMAGE_SECTION_HEADER* PEManager::GetSectionHeader(char* sectionName, HMODULE modHandle)
{
	return GetSectionHeader(sectionName, GetPEHeader((IMAGE_DOS_HEADER*)modHandle));
}

md5_hash PEManager::HashMD5(void* source, size_t size)
{
	boost::uuids::detail::md5 hash;
	hash.process_bytes(source, size);
	boost::uuids::detail::md5::digest_type tmp;
	md5_hash t;
	hash.get_digest(tmp);
	memcpy(&t, tmp, 16);
	return t;
}

std::vector<md5_hash> PEManager::hashSection(HMODULE modHandle, char* segmentName, size_t blockSize)
{
	std::vector<md5_hash> tmp;
	IMAGE_SECTION_HEADER* segInfo = GetSectionHeader(segmentName, modHandle);
	if(segInfo == NULL)
		return tmp;
	void* segment = segInfo->VirtualAddress + modHandle;
	int amountOfSubSegments = (segInfo->SizeOfRawData - (segInfo->SizeOfRawData % blockSize)) / blockSize;
	for (int i = 0; i < amountOfSubSegments; i++)
	{
		tmp.push_back(HashMD5((void*)((BYTE*)segment + (i * blockSize)), blockSize));
	}
	return tmp;
}

std::vector<md5_hash> PEManager::hashSection(HMODULE modHandle, char* segmentName)
{
	return hashSection(modHandle, segmentName, DEFAULT_BLOCK_SIZE);
}

std::vector<md5_hash> PEManager::hashSection(HMODULE modHandle, const char* segmentName)
{
	return hashSection(modHandle, (char*)segmentName, DEFAULT_BLOCK_SIZE);
}
