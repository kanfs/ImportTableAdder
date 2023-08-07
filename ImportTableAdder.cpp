/* UESTC - kanfs - 2023.3.16 */
#define _CRT_SECURE_NO_WARNINGS
#include<Windows.h>
#include<winnt.h>
#include<stdio.h>


PCHAR readFile(WCHAR* file_path, DWORD* fileSize);    //读取目标exe文件 返回文件缓存指针

PVOID addNewSection(PCHAR pFileBuffer, DWORD sectionSize, DWORD* bufferSize, PCHAR dllName, PCHAR functionName); //新增Section并在新Section中写入导入表

size_t RVAtoFileOffset(/*虚拟内存相对偏移地址*/size_t rva, PCHAR pFileBuffer);  //根据相对虚拟地址返回文件偏移地址

VOID buildNewImageSectionHeader(PIMAGE_SECTION_HEADER newSection, DWORD fileAlignment, DWORD sectionSize, DWORD fileOffsetAddress); //初始化新SectionHeader信息

VOID writeFile(WCHAR* newFilePath, PCHAR pFileBuffer,DWORD* bufferSize);           //将修改后的pe文件缓存写入新文件中


// dll需要预先载入到C:/Windows/SysWOW64/ 目录下 且functionName需要确保dll中声明并实现

int main()
{
	WCHAR filePath[] = L"C:/Users/kanfs/Desktop/Virus/TestVirus/Debug/TestVirus.exe";
	CHAR dllName[] = "mydll.dll";
	WCHAR newFilePath[] = L"C:/Users/kanfs/Desktop/Virus/TestVirus/Debug/TestVirus_x.exe";
	CHAR functionName[] = "GetImageLoadAddress";

	if (GetFileAttributesW(filePath) == INVALID_FILE_ATTRIBUTES)
	{
		printf("无法打开目标文件,请检查路径或关闭相关进程\n");
		getchar();
		return 0;
	}


	DWORD fileSize = 0;

	PCHAR pFileBuffer;
	if ((pFileBuffer = readFile(filePath, &fileSize)) == NULL)
	{
		printf("读取文件异常\n");
		getchar();
		return 0;
	}

	pFileBuffer =(PCHAR) addNewSection(pFileBuffer, 0x200, &fileSize, dllName, functionName);

	writeFile(newFilePath, pFileBuffer,&fileSize);
	free(pFileBuffer);
	getchar();
	return 0;
}


PCHAR readFile(WCHAR* file_path, DWORD* fileSize)
{
	//打开文件
	FILE* pFile = NULL;
	pFile = _wfopen(file_path, L"rb");
	if (pFile == NULL)
	{
		printf("fopen失败\n");
		return NULL;
	}
	//获取文件长度
	fseek(pFile, 0, SEEK_END);			
	DWORD size = ftell(pFile);
	fseek(pFile, 0, SEEK_SET);		

	//申请文件数据存储缓冲区 读取文件数据
	PCHAR pFileBuffer = (PCHAR)malloc(size);
	if (!pFileBuffer)
	{
		printf("分配文件缓冲失败\n");
		fclose(pFile);
		return NULL;
	}
	fread(pFileBuffer, size, 1, pFile);
	fclose(pFile);

	//判断是否为PE文件格式
	if (*(PSHORT)pFileBuffer != IMAGE_DOS_SIGNATURE)
	{
		printf("Error: MZ \r\n");
		fclose(pFile);
		free(pFileBuffer);
		return NULL;
	}

	if (*(PDWORD)(pFileBuffer + *(PDWORD)(pFileBuffer + 0x3C)) != IMAGE_NT_SIGNATURE)
	{
		printf("Error: PE \r\n");
		fclose(pFile);
		free(pFileBuffer);
		return NULL;
	}

	*fileSize = size;
	return pFileBuffer;
}

PVOID addNewSection(PCHAR pFileBuffer, DWORD sectionSize, DWORD* bufferSize, PCHAR dllName, PCHAR functionName)
{
	if (!dllName || !functionName)
	{
		printf("dll和函数名不能为空\n");
		return NULL;
	}

	//获取各个ImageHeader指针方便后续操作
	PIMAGE_DOS_HEADER pImageDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
	PIMAGE_NT_HEADERS pImageNtHeader = (PIMAGE_NT_HEADERS)(pFileBuffer + pImageDosHeader->e_lfanew);
	PIMAGE_FILE_HEADER pImageFileHeader = (PIMAGE_FILE_HEADER)((PUCHAR)pImageNtHeader + 4);
	PIMAGE_OPTIONAL_HEADER pImageOptionHeader = (PIMAGE_OPTIONAL_HEADER)((PUCHAR)pImageFileHeader + IMAGE_SIZEOF_FILE_HEADER);
	PIMAGE_SECTION_HEADER pImageSectionHeader = (PIMAGE_SECTION_HEADER)((PUCHAR)pImageOptionHeader + pImageFileHeader->SizeOfOptionalHeader);

	//获取原导入表指针 并修改导入表描述符目录size（新填一个导入表描述符）
	//pImageOptionHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT]对应导入表目录 
	PIMAGE_IMPORT_DESCRIPTOR pOldImports = (PIMAGE_IMPORT_DESCRIPTOR)(pFileBuffer +
		RVAtoFileOffset(pImageOptionHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress, pFileBuffer));
	pImageOptionHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size += sizeof(IMAGE_IMPORT_DESCRIPTOR);

	
	printf("导入表RVA:%p\n", pOldImports);

	//获取原导入表dll个数
	DWORD dllCount = 0;
	PIMAGE_IMPORT_DESCRIPTOR temp = pOldImports;
	for (; temp->Name; temp++) dllCount++;
	printf("dll数量:%d\n", dllCount);

	//填充新SectionHeader   
	DWORD oldLastSectionHeaderIndex = pImageFileHeader->NumberOfSections - 1;
	DWORD newSectionHeaderIndex = pImageFileHeader->NumberOfSections;
	DWORD fileOffsetAddress = pImageSectionHeader[oldLastSectionHeaderIndex].PointerToRawData + pImageSectionHeader[oldLastSectionHeaderIndex].SizeOfRawData;
	buildNewImageSectionHeader(&pImageSectionHeader[newSectionHeaderIndex], pImageOptionHeader->FileAlignment, sectionSize, fileOffsetAddress);

	//对旧文件最后一个Section大小做修正
	DWORD oldSize = 0, newSize = 0;
	DWORD oldSectionEndFileOffset = //末尾Section的文件偏移地址
		pImageSectionHeader[oldLastSectionHeaderIndex].PointerToRawData + pImageSectionHeader[oldLastSectionHeaderIndex].SizeOfRawData;
	

	
	DWORD externSpaceNeeded = // 需要扩展的空间大小
		pImageSectionHeader[newSectionHeaderIndex].PointerToRawData - oldSectionEndFileOffset;
	oldSize = oldSectionEndFileOffset;
	pImageSectionHeader[oldLastSectionHeaderIndex].SizeOfRawData += externSpaceNeeded;
	pImageSectionHeader[oldLastSectionHeaderIndex].Misc.VirtualSize += externSpaceNeeded;
	

	//改写导入表RVA
	pImageSectionHeader[newSectionHeaderIndex].VirtualAddress=
		((pImageSectionHeader[oldLastSectionHeaderIndex].Misc.VirtualSize+pImageSectionHeader[oldLastSectionHeaderIndex].VirtualAddress)
		/ pImageOptionHeader->SectionAlignment + 1)* pImageOptionHeader->SectionAlignment;
	printf("pImageSectionHeader[newSectionHeaderIndex].VirtualAddress:0x%x\n", pImageSectionHeader[newSectionHeaderIndex].VirtualAddress);
	pImageOptionHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress = pImageSectionHeader[newSectionHeaderIndex].VirtualAddress;
	

	//修改内存镜像大小
	pImageOptionHeader->SizeOfImage =
		((pImageSectionHeader[newSectionHeaderIndex].VirtualAddress + pImageSectionHeader[newSectionHeaderIndex].Misc.VirtualSize)
			/ pImageOptionHeader->SectionAlignment + 1) * pImageOptionHeader->SectionAlignment;
	memset(&pImageSectionHeader[newSectionHeaderIndex + 1], 0, IMAGE_SIZEOF_SECTION_HEADER);
	pImageFileHeader->NumberOfSections++;
	

	
	//重新分配缓冲区  复制旧的FileBuffer 
	DWORD oldBufferSize = *bufferSize;
	printf("%d\n%d\n%d\n ", pImageSectionHeader[newSectionHeaderIndex].PointerToRawData, pImageSectionHeader[newSectionHeaderIndex].SizeOfRawData, oldSectionEndFileOffset);
	*bufferSize +=( pImageSectionHeader[newSectionHeaderIndex].PointerToRawData + pImageSectionHeader[newSectionHeaderIndex].SizeOfRawData-oldSectionEndFileOffset);
	printf("NewBufferSize:%d Bytes\n", *bufferSize);
	 PUCHAR pNewFileBuffer = (PUCHAR)malloc(*bufferSize);
	 if (!pNewFileBuffer)
	 {
		 printf("AddNewSection malloc Fail \r\n");
		 free(pFileBuffer);
		 return NULL;
	 }
	 printf("malloc %d Bytes for new exe\n", *bufferSize);
	 memset(pNewFileBuffer, 0, *bufferSize);
	 memcpy(pNewFileBuffer, pFileBuffer, oldBufferSize);

	 DWORD RVA = pImageOptionHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
	 DWORD FileOffset = pImageSectionHeader[newSectionHeaderIndex].PointerToRawData;

	 //拷贝旧的导入表到新的区段
	 DWORD oldImportTableSize = dllCount * sizeof(IMAGE_IMPORT_DESCRIPTOR);
	 memcpy(pNewFileBuffer + FileOffset, pOldImports, oldImportTableSize);
	 memcpy(pNewFileBuffer + FileOffset + oldImportTableSize, pOldImports, sizeof(IMAGE_IMPORT_DESCRIPTOR));
	 memset(pNewFileBuffer + FileOffset + oldImportTableSize + sizeof(IMAGE_IMPORT_DESCRIPTOR), 0, sizeof(IMAGE_IMPORT_DESCRIPTOR));

	 //对新的导入表项做初始化 IMAGE_IMPORT_DESCRIPTOR各项都是dword=>指向对应值的RVA
	 PIMAGE_IMPORT_DESCRIPTOR pNewImport = (PIMAGE_IMPORT_DESCRIPTOR)(pNewFileBuffer + FileOffset + oldImportTableSize);
	 DWORD firstThunkOffset = oldImportTableSize + sizeof(IMAGE_IMPORT_DESCRIPTOR) * 3;
	 printf("pImageSectionHeader[newSectionHeaderIndex].VirtualAddress:0x%x\n", pImageSectionHeader[newSectionHeaderIndex].VirtualAddress);
	 pNewImport->FirstThunk = RVA + firstThunkOffset;                //函数名地址
	 pNewImport->OriginalFirstThunk = RVA + firstThunkOffset;        //函数指针地址
	 pNewImport->Name = RVA + firstThunkOffset + sizeof(DWORD) * 2;  //dll名地址
	 memcpy(pNewFileBuffer + FileOffset + firstThunkOffset + sizeof(DWORD) * 2, dllName, strlen(dllName));

	 //再import_by_name中加入目标函数 在函数名地址指向位置写入函数名
	 DWORD importByNameOffset = firstThunkOffset + sizeof(DWORD) * 2 + strlen(dllName) + sizeof(DWORD);
	 PIMAGE_IMPORT_BY_NAME pImageImportByName = (PIMAGE_IMPORT_BY_NAME)malloc(40);
	 memset(pImageImportByName, 0, 40);
	 pImageImportByName->Hint = 1;
	 memcpy(pImageImportByName->Name, functionName, strlen(functionName));
	 memcpy(pNewFileBuffer + FileOffset + importByNameOffset, pImageImportByName, 40);
	 DWORD firstThunkRVA = (DWORD)pImageSectionHeader[newSectionHeaderIndex].VirtualAddress + importByNameOffset;


	 memcpy(pNewFileBuffer + FileOffset +firstThunkOffset, &firstThunkRVA, sizeof(DWORD*));
	 memcpy(pNewFileBuffer + FileOffset+ pImageSectionHeader[newSectionHeaderIndex].SizeOfRawData,
		 (PCHAR)pFileBuffer+oldSectionEndFileOffset, oldBufferSize-oldSectionEndFileOffset);
	 free(pFileBuffer);
	 return pNewFileBuffer;
}

size_t RVAtoFileOffset(size_t rva, PCHAR pFileBuffer)
{
	PIMAGE_DOS_HEADER pImageDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
	PIMAGE_NT_HEADERS pImageNtHeader = (PIMAGE_NT_HEADERS)(pFileBuffer + pImageDosHeader->e_lfanew);

	DWORD sectionCount = pImageNtHeader->FileHeader.NumberOfSections;
	DWORD sectionAlignment = pImageNtHeader->OptionalHeader.SectionAlignment;
	
	PIMAGE_SECTION_HEADER pImageSectionHeader = IMAGE_FIRST_SECTION(pImageNtHeader);
	DWORD sectionOffset = 0;//距离命中节的起始虚拟地址的偏移值
	for (DWORD i = 0; i < sectionCount; i++)
	{
		//模拟内存对齐机制
		DWORD blockCount = pImageSectionHeader[i].SizeOfRawData / sectionAlignment;
		blockCount += pImageSectionHeader[i].SizeOfRawData % sectionAlignment ? 1 : 0;
		DWORD beginVA = pImageSectionHeader[i].VirtualAddress;
		DWORD endVA = pImageSectionHeader[i].VirtualAddress + blockCount * sectionAlignment;

		//如果目标rva在第i个区段中 
		if (beginVA <= rva && rva < endVA)
		{
			sectionOffset = rva - beginVA;
			return pImageSectionHeader[i].PointerToRawData + sectionOffset;
		}
		if (rva < beginVA )
		{
			return rva;
		}
	}
	return 0;
}

VOID buildNewImageSectionHeader(PIMAGE_SECTION_HEADER pNewSectionHeader, DWORD fileAlignment, DWORD sectionSize, DWORD fileOffsetAddress)
{
	CHAR sectionName[] = ".new";
	memcpy(pNewSectionHeader->Name, sectionName, strlen(sectionName));
	pNewSectionHeader->Misc.VirtualSize = 0x1000;
	pNewSectionHeader->Characteristics = 0xC0000040;
	pNewSectionHeader->NumberOfRelocations = 0;
	pNewSectionHeader->NumberOfLinenumbers = 0;
	pNewSectionHeader->PointerToLinenumbers = 0;
	pNewSectionHeader->PointerToRelocations = 0;
	pNewSectionHeader->PointerToRawData = (fileOffsetAddress / fileAlignment + 1) * fileAlignment;
	pNewSectionHeader->SizeOfRawData = (sectionSize / fileAlignment + 1) * fileAlignment;
	return;
}


VOID writeFile(WCHAR* newFilePath, PCHAR pFileBuffer,DWORD* bufferSize)
{
	HANDLE hFile = NULL;

	hFile=CreateFileW(newFilePath, GENERIC_WRITE, 0, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE || hFile==NULL )
	{
		printf("无法写入新文件路径 Error:%d\n",GetLastError());
		return;
	}
	DWORD writtenBytes = 0;
	if (!WriteFile(hFile, pFileBuffer, *bufferSize, &writtenBytes, NULL))	printf("写入新文件失败\n");
	if (writtenBytes != *bufferSize)											printf("写入新文件不全\n");
	else																		printf("写入新文件成功\n");

	CloseHandle(hFile);
	return;

}
