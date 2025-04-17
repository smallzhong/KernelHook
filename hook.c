#include "hook.h"
#include "stdio.h"

NTSTATUS makeWriteableMapping(void* const addr, unsigned int size, PMDL* my_mdl, PVOID* my_addr)
{
	PMDL mdl = IoAllocateMdl(addr, size, FALSE, FALSE, NULL);
	if (!mdl)
	{
		*my_mdl = NULL, * my_addr = NULL;
		return STATUS_MEMORY_NOT_ALLOCATED;
	}

	BOOLEAN locked = FALSE;
	__try
	{
		MmProbeAndLockPages(mdl, KernelMode, IoReadAccess);
		locked = TRUE;

		PVOID mapped = MmMapLockedPagesSpecifyCache(mdl, KernelMode, MmCached, NULL, FALSE, NormalPagePriority);
		if (mapped)
		{
			NTSTATUS status = MmProtectMdlSystemAddress(mdl, PAGE_READWRITE);
			if (!NT_SUCCESS(status))
			{
				MmUnmapLockedPages(mapped, mdl);
				MmUnlockPages(mdl);
				IoFreeMdl(mdl);

				*my_mdl = NULL, * my_addr = NULL;
				return STATUS_MEMORY_NOT_ALLOCATED;
			}

			*my_mdl = mdl, * my_addr = mapped;
			return STATUS_SUCCESS;
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		if (locked)
		{
			MmUnlockPages(mdl);
		}
	}

	IoFreeMdl(mdl);

	*my_mdl = NULL, * my_addr = NULL;
	return STATUS_MEMORY_NOT_ALLOCATED;
}

VOID freeMapping(PMDL my_mdl, PVOID my_addr)
{
	if (my_addr)
	{
		MmUnmapLockedPages(my_addr, my_mdl);
	}

	if (my_mdl)
	{
		MmUnlockPages(my_mdl);
		IoFreeMdl(my_mdl);
	}
}

BOOLEAN writeToKernel(PVOID dest, PVOID src, ULONG64 size)
{
	KdPrintEx((77, 0, "writeToKernel %llx %llx %llx\r\n", dest, src, size));
	PMDL my_mdl = NULL;
	PVOID my_addr = NULL;
	NTSTATUS status = makeWriteableMapping(dest, size, &my_mdl, &my_addr);
	if (!NT_SUCCESS(status))
	{
		return FALSE;
	}

	memcpy(my_addr, src, size);

	freeMapping(my_mdl, my_addr);
	return TRUE;
}

int get_hook_len(ULONG64 Addr, ULONG64 size, BOOLEAN isX64)
{
	PUCHAR tempAddr = Addr;
	int totalSize = 0;
	int len = 0;

	if (isX64)
	{
		do
		{
			len = insn_len_x86_64((ULONG64)tempAddr);

			tempAddr = tempAddr + len;

			totalSize += len;

		} while (totalSize < size);
	}
	else
	{
		do
		{
			len = insn_len_x86_32((ULONG64)tempAddr);

			tempAddr = tempAddr + len;

			totalSize += len;

		} while (totalSize < size);
	}

	return totalSize;
}

ULONG64 allocateMemory(ULONG64 size)
{
	// �����޸��ڴ���䷽ʽʹ�������
	return ExAllocatePool(NonPagedPool, size);
}

VOID freeMemory(ULONG64 addr)
{
	//return ExFreePool(addr);
}

// 36��hookhandler��ƫ��
// 67��origin��ַ��ƫ��
UCHAR handler_shellcode[] =
{
0x54                            // push rsp    
,0x41,0x57                         // push r15                           
,0x41,0x56                       // push r14                           
,0x41,0x55                         // push r13                           
,0x41,0x54                         // push r12                           
,0x41,0x53                         // push r11                           
,0x41,0x52                         // push r10                           
,0x41,0x51                         // push r9                            
,0x41,0x50                         // push r8                            
,0x57                            // push rdi                           
,0x56                            // push rsi                           
,0x55                            // push rbp                                             
,0x53                            // push rbx                           
,0x52                            // push rdx                           
,0x51                            // push rcx                           
,0x50                            // push rax          
,0x9C                            // pushfq
,0x48,0x8B,0xCC                       // mov rcx,rsp                        
,0x48,0x81,0xEC,0x00,0x01,0x00,0x00              // sub rsp,100        

// call hookhandler
,0xEB,0x08 // jmp (��������Ĵ���)
,0x00,0x00 // add byte ptr ds : [rax] ,al |
,0x00,0x00 // add byte ptr ds : [rax] ,al |
,0x00,0x00 // add byte ptr ds : [rax] ,al |
,0x00,0x00 // add byte ptr ds : [rax] ,al |
,0xFF,0x15,0xF2,0xFF,0xFF,0xFF // call qword ptr ds : [7FF9AAEA069B] |

,0x48,0x81,0xC4,0x00,0x01,0x00,0x00 // add rsp,100 |

// ���rax=1��˵����Ҫֱ�ӷ��أ�����ֵ����rcx�С�����jmp��ԭ��Ҫִ�еĴ��봦����ִ�С�
,0x3C,0x00 // cmp al,0
,0x75,0x0E // jne (��������14���ֽ�)
,0xFF,0x25,0x00,0x00,0x00,0x00 // jmp qword ptr ds : [7FF9AAEA06FA] 
,0x00,0x00 // add byte ptr ds : [rax] ,al 
,0x00,0x00 // add byte ptr ds : [rax] ,al 
,0x00,0x00 // add byte ptr ds : [rax] ,al 
,0x00,0x00 // add byte ptr ds : [rax] ,al 

,0x9D                            // pop rflags
,0x58                            // pop rax   
,0x59                            // pop rcx                            
,0x5A                            // pop rdx                            
,0x5B                            // pop rbx                                                    
,0x5D                            // pop rbp                            
,0x5E                            // pop rsi                            
,0x5F                            // pop rdi                            
,0x41,0x58                         // pop r8                             
,0x41,0x59                         // pop r9                             
,0x41,0x5A                         // pop r10                            
,0x41,0x5B                         // pop r11                            
,0x41,0x5C                         // pop r12                            
,0x41,0x5D                         // pop r13                            
,0x41,0x5E                         // pop r14                            
,0x41,0x5F                         // pop r15
,0x5C                            // pop rsp    
,0xC3							   // ret
};

UCHAR resume_code[] =
{
0x9D                              // pop rflags
,0x58                             // pop rcx                    
,0x59                            // pop rcx                            
,0x5A                            // pop rdx                            
,0x5B                            // pop rbx                                                   
,0x5D                            // pop rbp                            
,0x5E                            // pop rsi                            
,0x5F                            // pop rdi                            
,0x41,0x58                         // pop r8                             
,0x41,0x59                         // pop r9                             
,0x41,0x5A                         // pop r10                            
,0x41,0x5B                         // pop r11                            
,0x41,0x5C                         // pop r12                            
,0x41,0x5D                         // pop r13                            
,0x41,0x5E                         // pop r14                            
,0x41,0x5F                         // pop r15
,0x5C                            // pop rsp     
};

static phook_record head = NULL;
static ULONG64 record_ct = 0;

VOID
my_AppendTailList(
	_Inout_ PLIST_ENTRY ListHead,
	_Inout_ PLIST_ENTRY ListToAppend
)
{
	PLIST_ENTRY ListEnd = ListHead->Blink;

	RtlpCheckListEntry(ListHead);
	RtlpCheckListEntry(ListToAppend);
	ListHead->Blink->Flink = ListToAppend;
	ListHead->Blink = ListToAppend->Blink;
	ListToAppend->Blink->Flink = ListHead;
	ListToAppend->Blink = ListEnd;
	return;
}



ULONG64 get_module_base_by_an_addr_in_this_module(ULONG64 virt_addr)
{
	ULONG uNeedSize = 0;

	NTSTATUS status = STATUS_SUCCESS;
	PRTL_PROCESS_MODULES pSysInfo = NULL;
	status = ZwQuerySystemInformation(SystemModuleInformation, NULL, 0, &uNeedSize);
	if (status != STATUS_INFO_LENGTH_MISMATCH)
	{
		return NULL;
	}
	if (uNeedSize == 0)
	{
		return NULL;
	}

	pSysInfo = (PRTL_PROCESS_MODULES)ExAllocatePool(NonPagedPool, uNeedSize);
	if (pSysInfo == NULL)
	{
		return NULL;
	}

	status = ZwQuerySystemInformation(SystemModuleInformation, pSysInfo, uNeedSize, &uNeedSize);
	if (!NT_SUCCESS(status))
	{
		return NULL;
	}

	for (int i = 0; i < pSysInfo->NumberOfModules; i++)
	{
		PRTL_PROCESS_MODULE_INFORMATION pModuleInfo = &pSysInfo->Modules[i];
		if (MmIsAddressValid(pModuleInfo) && pModuleInfo != NULL)
		{
			ULONG64 moduleStart = (ULONG64)pModuleInfo->ImageBase;
			ULONG64 moduleEnd = (ULONG64)pModuleInfo->ImageBase + pModuleInfo->ImageSize;

			if (virt_addr < moduleEnd && virt_addr >= moduleStart)
			{
				return moduleStart;
			}
		}
	}

	return NULL;
}

PUCHAR get_blank_space_in_module(ULONG64 virt_addr_in_this_module, ULONG64 size_needed)
{
	ULONG64 moduleBase = get_module_base_by_an_addr_in_this_module(virt_addr_in_this_module);
	if (moduleBase == NULL)
	{
		return STATUS_NOT_FOUND;
	}

	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)moduleBase;

	PIMAGE_NT_HEADERS pNts = (PIMAGE_NT_HEADERS)((PUCHAR)moduleBase + pDos->e_lfanew);

	PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pNts);

	for (int i = 0; i < pNts->FileHeader.NumberOfSections; i++)
	{
		char bufName[9] = { 0 };
		RtlMoveMemory(bufName, pSection->Name, 8);

		// TODO:�����������ȫ��
		if (_stricmp(bufName, ".text") == 0)
		{
			ULONG64 blank_space_start_addr = moduleBase + pSection->VirtualAddress + pSection->Misc.VirtualSize;
			ULONG64 blank_space_end_addr = moduleBase + pSection->VirtualAddress + pSection->SizeOfRawData;

			// TODO:���������һ�������档��ʱ���ñ����ѵ��߼���
			ULONG64 cur_addr = blank_space_start_addr;
			while (TRUE)
			{
				// ��ַ���Ϸ�����û����ô��ռ���
				if (!MmIsAddressValid(cur_addr) || cur_addr + size_needed >= blank_space_end_addr || !MmIsAddressValid(cur_addr + size_needed))
				{
					return NULL;
				}

				for (int i = 0; i < size_needed; i++)
				{
					ULONG64 t_addr = cur_addr + i;
					if (!MmIsAddressValid(t_addr))
					{
						return NULL;
					}

					if (*(PUCHAR)t_addr != 0x00)
					{
						cur_addr += 16;
						continue;
					}
				}

				// �ߵ�����˵����ַȫ���Ϸ�������ȫΪ0��
				break;
			}

			if (cur_addr + size_needed > moduleBase + pSection->VirtualAddress + pSection->SizeOfRawData)
			{
				return NULL;
			}
			if (!MmIsAddressValid(cur_addr) || !MmIsAddressValid(cur_addr + size_needed))
			{
				return NULL;
			}
			return cur_addr;
		}

		pSection++;
	}

	return NULL;
}

// TODO���жϺ�������
// ǰ������ģ�����ͺ���������������callback�ĵ�ַ�����ĸ������ģ���Ӧ���±�

NTSTATUS hook_by_addr(ULONG64 funcAddr, ULONG64 callbackFunc, OUT ULONG64* record_number)
{
	if (!funcAddr || !MmIsAddressValid(funcAddr))
	{
		return STATUS_NOT_FOUND;
	}

	ULONG64 handler_addr = allocateMemory(PAGE_SIZE);
	if (!handler_addr)
		return STATUS_MEMORY_NOT_ALLOCATED;
	RtlMoveMemory(handler_addr, handler_shellcode, sizeof(handler_shellcode));
	char bufcode[] = { 0xFF, 0x25, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, };

	// ��ȡ��Ҫpatch��ָ���
	ULONG64 inslen = get_hook_len(funcAddr, sizeof(bufcode), TRUE);
	ULONG64 shellcode_origin_addr = allocateMemory(PAGE_SIZE);
	if (!shellcode_origin_addr)
		return STATUS_MEMORY_NOT_ALLOCATED;


	/*
	ԭʼ����
	ff 25 xxxxxx(����ԭ��)
	*/
	RtlMoveMemory(shellcode_origin_addr, resume_code, sizeof(resume_code));
	RtlMoveMemory(shellcode_origin_addr + sizeof(resume_code), funcAddr, inslen);

	// ʹ��zydis�ҳ�ʹ������Ե�ַ�����
	ZyanU64 runtime_address = funcAddr;

	// ���������Ե�ַ�����ʱ�����˶೤�Ĵ��롣��������дff25��ʱ��Ҫ����ε�ַҲ��������
	ULONG64 resolve_relative_code_len = 0;

	// ����ȷ��ABC���Ƿ���ʹ������Ե�ַ�Ĵ���ı�ǡ�����еĻ��ں��滹Ҫ�ټ���һ��ebjmp��������resolve��Ե�ַ�Ĵ�������ԭʼ��ff25jmp����
	BOOLEAN relative_addr_used_in_abc = FALSE;

	ZyanUSize cur_disasm_offset = 0;
	ZydisDisassembledInstruction instruction;
	while (ZYAN_SUCCESS(ZydisDisassembleIntel(
		/* machine_mode:    */ ZYDIS_MACHINE_MODE_LONG_64,
		/* runtime_address: */ runtime_address,
		/* buffer:          */ shellcode_origin_addr + sizeof(resume_code) + cur_disasm_offset,
		/* length:          */ inslen - cur_disasm_offset,
		/* instruction:     */ &instruction
	))) {
		KdPrintEx((77, 0, "%llx %s\n", runtime_address, instruction.text));


		// �ж��Ƿ�����Ե�ַ
		if (instruction.info.attributes & ZYDIS_ATTRIB_IS_RELATIVE)
		{
			// ���flag��������flag�����˵Ļ�����Ҫ����һ��ebjmp��������ff25����ԭ��������Ĵ��봦��
			if (relative_addr_used_in_abc == FALSE)
			{
				relative_addr_used_in_abc = TRUE;
				// ��Ӧ���ǵ�һ�Σ�Ӧ��Ϊ0
				//ASSERT(resolve_relative_code_len == 0);
				if (resolve_relative_code_len != 0)
				{
					KdPrintEx((77, 0, "resolve_relative_code_len != 0\r\n"));
					return STATUS_INTERNAL_ERROR;
				}
				UCHAR t_ebjmp[2] = { 0xeb, 0x00 };
				// ABC�����ټ���һ��ebjmp��������������resolve�Ĵ���
				RtlMoveMemory(shellcode_origin_addr + sizeof(resume_code) + inslen + resolve_relative_code_len, t_ebjmp, sizeof(t_ebjmp));
				// ����resolve�Ĵ���ĳ���+=2
				resolve_relative_code_len += sizeof(t_ebjmp);
			}

			KdPrintEx((77, 0, "ZYDIS_ATTRIB_IS_RELATIVE\r\n"));
			KdPrintEx((77, 0, "���ָ�����Ϣ��%llx", funcAddr + cur_disasm_offset));
			for (int i = 0; i < instruction.info.length; i++)
				KdPrintEx((77, 0, " %02hhx", *(PUCHAR)(funcAddr + cur_disasm_offset + i)));
			KdPrintEx((77, 0, " %s\r\n", instruction.text));
			// һ�ֽ������ת
			if (instruction.info.length == 2 && (
				(*(PUCHAR)runtime_address <= 0x7f && *(PUCHAR)runtime_address >= 0x70) ||
				*(PUCHAR)runtime_address == 0xe0 ||
				*(PUCHAR)runtime_address == 0xe1 ||
				*(PUCHAR)runtime_address == 0xe2 ||
				*(PUCHAR)runtime_address == 0xe3 ||
				*(PUCHAR)runtime_address == 0xeb
				))
			{
#define OPCODE_LENGTH 1
#define OFFSET_TYPE CHAR
				do
				{
					// 1.ȷ������ָ��ԭ��Ҫ��ת���ĸ���ַ
					ULONG64 original_jx_addr = funcAddr + cur_disasm_offset + instruction.info.length + *(PULONG)(runtime_address + OPCODE_LENGTH); // ��һ����ַ+offset
					KdPrintEx((77, 0, "original_jx_addr = %llx\r\n", original_jx_addr));

					// 1.1.�ж�����ָ����ת�ĵ�ַ�ǲ��������Ǹ��Ƶ�buffer��Χ�ڣ�����eb 02�����������������ȥ�Ļ�Ҳ�����Ӧ�ò�ȥ�޸�����
					if (original_jx_addr >= funcAddr && original_jx_addr < funcAddr + inslen)
					{
						// ���ȷʵ�ڷ�Χ�ڣ���ȥ�޸ģ�ֱ��break
						break;
					}
					// 2.����ff25jmp��д������

					// ��������ff25�ĵ�ַ���ں�������jcc��ת�ĵ�ַ��ʱ������õ�
					ULONG64 t_ff25jmp_addr = shellcode_origin_addr + sizeof(resume_code) + inslen + resolve_relative_code_len;

					*(PULONG64)&bufcode[6] = original_jx_addr;
					RtlMoveMemory(shellcode_origin_addr + sizeof(resume_code) + inslen + resolve_relative_code_len, bufcode, sizeof(bufcode));
					resolve_relative_code_len += sizeof(bufcode); // resolve�Ĵ��볤��+=sizeof bufcode

					// 3.����jcc��ת�ĵ�ַ����֤���ܹ���ȷ��ת���ղŹ����ff25jmp��
					KdPrintEx((77, 0, "runtime_address = %llx\r\n", runtime_address));
					ULONG64 t_dummy = t_ff25jmp_addr - (shellcode_origin_addr + sizeof(resume_code) + cur_disasm_offset + instruction.info.length);
					OFFSET_TYPE offset_for_jx = *(OFFSET_TYPE*)(&t_dummy);
					if (offset_for_jx < 0 || offset_for_jx == 0)
					{
						KdPrintEx((77, 0, "offset_for_jx < 0 || offset_for_jx == 0\r\n"));
						return STATUS_INTERNAL_ERROR;
					}
					// д��jcc��ת�ĵ�ַ��ȥ��
					*(OFFSET_TYPE*)(shellcode_origin_addr + sizeof(resume_code) + cur_disasm_offset + OPCODE_LENGTH) = offset_for_jx;
					KdPrintEx((77, 0, "%llx\r\n", shellcode_origin_addr));
					KdPrintEx((77, 0, "%llx\r\n", shellcode_origin_addr + sizeof(resume_code) + cur_disasm_offset));
				} while (0);
			}
			// һЩ��̫���ܳ��ֵĴ�����Чǰ׺�Ķ��������в�����UB��Ϊ��
			else if (instruction.info.length == 3 && (
				(*(PUCHAR)runtime_address >= 0x40 && *(PUCHAR)runtime_address <= 0x4f) ||
				*(PUCHAR)runtime_address == 0x26 ||
				*(PUCHAR)runtime_address == 0x2e ||
				*(PUCHAR)runtime_address == 0x36 ||
				*(PUCHAR)runtime_address == 0x3e ||
				*(PUCHAR)runtime_address == 0x64 ||
				*(PUCHAR)runtime_address == 0x65 ||
				*(PUCHAR)runtime_address == 0x66 ||
				*(PUCHAR)runtime_address == 0x67 ||
				*(PUCHAR)runtime_address == 0xf2 ||
				*(PUCHAR)runtime_address == 0xf3
				) && (
					(*(PUCHAR)(runtime_address + 1) <= 0x7f && *(PUCHAR)(runtime_address + 1) >= 0x70) ||
					*(PUCHAR)(runtime_address + 1) == 0xe0 ||
					*(PUCHAR)(runtime_address + 1) == 0xe1 ||
					*(PUCHAR)(runtime_address + 1) == 0xe2 ||
					*(PUCHAR)(runtime_address + 1) == 0xe3 ||
					*(PUCHAR)(runtime_address + 1) == 0xeb
					))
			{
#define OPCODE_LENGTH 2
#define OFFSET_TYPE CHAR
				do
				{
					// 1.ȷ������ָ��ԭ��Ҫ��ת���ĸ���ַ
					ULONG64 original_jx_addr = funcAddr + cur_disasm_offset + instruction.info.length + *(PCHAR)(runtime_address + OPCODE_LENGTH); // ��һ����ַ+offset
					KdPrintEx((77, 0, "original_jx_addr = %llx\r\n", original_jx_addr));

					// 1.1.�ж�����ָ����ת�ĵ�ַ�ǲ��������Ǹ��Ƶ�buffer��Χ�ڣ�����eb 02�����������������ȥ�Ļ�Ҳ�����Ӧ�ò�ȥ�޸�����
					if (original_jx_addr >= funcAddr && original_jx_addr < funcAddr + inslen)
					{
						// ���ȷʵ�ڷ�Χ�ڣ���ȥ�޸ģ�ֱ��break
						break;
					}
					// 2.����ff25jmp��д������

					// ��������ff25�ĵ�ַ���ں�������jcc��ת�ĵ�ַ��ʱ������õ�
					ULONG64 t_ff25jmp_addr = shellcode_origin_addr + sizeof(resume_code) + inslen + resolve_relative_code_len;

					*(PULONG64)&bufcode[6] = original_jx_addr;
					RtlMoveMemory(shellcode_origin_addr + sizeof(resume_code) + inslen + resolve_relative_code_len, bufcode, sizeof(bufcode));
					resolve_relative_code_len += sizeof(bufcode); // resolve�Ĵ��볤��+=sizeof bufcode

					// 3.����jcc��ת�ĵ�ַ����֤���ܹ���ȷ��ת���ղŹ����ff25jmp��
					KdPrintEx((77, 0, "runtime_address = %llx\r\n", runtime_address));
					ULONG64 t_dummy = t_ff25jmp_addr - (shellcode_origin_addr + sizeof(resume_code) + cur_disasm_offset + instruction.info.length);
					OFFSET_TYPE offset_for_jx = *(OFFSET_TYPE*)(&t_dummy);
					if (offset_for_jx < 0 || offset_for_jx == 0)
					{
						KdPrintEx((77, 0, "offset_for_jx < 0 || offset_for_jx == 0\r\n"));
						return STATUS_INTERNAL_ERROR;
					}
					// д��jcc��ת�ĵ�ַ��ȥ��
					*(OFFSET_TYPE*)(shellcode_origin_addr + sizeof(resume_code) + cur_disasm_offset + OPCODE_LENGTH) = offset_for_jx;
					KdPrintEx((77, 0, "%llx\r\n", shellcode_origin_addr));
					KdPrintEx((77, 0, "%llx\r\n", shellcode_origin_addr + sizeof(resume_code) + cur_disasm_offset));
				} while (0);
			}
			// 0x0f 0x8x xx xx xx xx ���ֽ������ת
			else if (instruction.info.length == 6 && *(PUCHAR)runtime_address == 0x0f && *(PCUCHAR)(runtime_address + 1) <= 0x8f && *(PCUCHAR)(runtime_address + 1) >= 0x80)
			{
#define OPCODE_LENGTH 2
#define OFFSET_TYPE LONG
				do
				{
					// 1.ȷ������ָ��ԭ��Ҫ��ת���ĸ���ַ
					ULONG64 original_jx_addr = funcAddr + cur_disasm_offset + instruction.info.length + *(PCHAR)(runtime_address + OPCODE_LENGTH); // ��һ����ַ+offset
					KdPrintEx((77, 0, "original_jx_addr = %llx\r\n", original_jx_addr));

					// 1.1.�ж�����ָ����ת�ĵ�ַ�ǲ��������Ǹ��Ƶ�buffer��Χ�ڣ�����eb 02�����������������ȥ�Ļ�Ҳ�����Ӧ�ò�ȥ�޸�����
					if (original_jx_addr >= funcAddr && original_jx_addr < funcAddr + inslen)
					{
						// ���ȷʵ�ڷ�Χ�ڣ���ȥ�޸ģ�ֱ��break
						break;
					}
					// 2.����ff25jmp��д������

					// ��������ff25�ĵ�ַ���ں�������jcc��ת�ĵ�ַ��ʱ������õ�
					ULONG64 t_ff25jmp_addr = shellcode_origin_addr + sizeof(resume_code) + inslen + resolve_relative_code_len;

					*(PULONG64)&bufcode[6] = original_jx_addr;
					RtlMoveMemory(shellcode_origin_addr + sizeof(resume_code) + inslen + resolve_relative_code_len, bufcode, sizeof(bufcode));
					resolve_relative_code_len += sizeof(bufcode); // resolve�Ĵ��볤��+=sizeof bufcode

					// 3.����jcc��ת�ĵ�ַ����֤���ܹ���ȷ��ת���ղŹ����ff25jmp��
					KdPrintEx((77, 0, "runtime_address = %llx\r\n", runtime_address));
					ULONG64 t_dummy = t_ff25jmp_addr - (shellcode_origin_addr + sizeof(resume_code) + cur_disasm_offset + instruction.info.length);
					OFFSET_TYPE offset_for_jx = *(OFFSET_TYPE*)(&t_dummy);
					if (offset_for_jx < 0 || offset_for_jx == 0)
					{
						KdPrintEx((77, 0, "offset_for_jx < 0 || offset_for_jx == 0\r\n"));
						return STATUS_INTERNAL_ERROR;
					}
					// д��jcc��ת�ĵ�ַ��ȥ��
					*(OFFSET_TYPE*)(shellcode_origin_addr + sizeof(resume_code) + cur_disasm_offset + OPCODE_LENGTH) = offset_for_jx;
					KdPrintEx((77, 0, "%llx\r\n", shellcode_origin_addr));
					KdPrintEx((77, 0, "%llx\r\n", shellcode_origin_addr + sizeof(resume_code) + cur_disasm_offset));
				} while (0);
			}
			// 0xe8(0xe9) xx xx xx xx ���ֽ������ת
			else if (instruction.info.length == 5 && (*(PUCHAR)runtime_address == 0xe8 || *(PUCHAR)runtime_address == 0xe9))
			{
#define OPCODE_LENGTH 1
#define OFFSET_TYPE LONG
				do
				{
					// 1.ȷ������ָ��ԭ��Ҫ��ת���ĸ���ַ
					ULONG64 original_jx_addr = funcAddr + cur_disasm_offset + instruction.info.length + *(PULONG)(runtime_address + OPCODE_LENGTH); // ��һ����ַ+offset
					KdPrintEx((77, 0, "original_jx_addr = %llx\r\n", original_jx_addr));

					// 1.1.�ж�����ָ����ת�ĵ�ַ�ǲ��������Ǹ��Ƶ�buffer��Χ�ڣ�����eb 02�����������������ȥ�Ļ�Ҳ�����Ӧ�ò�ȥ�޸�����
					if (original_jx_addr >= funcAddr && original_jx_addr < funcAddr + inslen)
					{
						// ���ȷʵ�ڷ�Χ�ڣ���ȥ�޸ģ�ֱ��break
						break;
					}
					// 2.����ff25jmp��д������

					// ��������ff25�ĵ�ַ���ں�������jcc��ת�ĵ�ַ��ʱ������õ�
					ULONG64 t_ff25jmp_addr = shellcode_origin_addr + sizeof(resume_code) + inslen + resolve_relative_code_len;

					*(PULONG64)&bufcode[6] = original_jx_addr;
					RtlMoveMemory(shellcode_origin_addr + sizeof(resume_code) + inslen + resolve_relative_code_len, bufcode, sizeof(bufcode));
					resolve_relative_code_len += sizeof(bufcode); // resolve�Ĵ��볤��+=sizeof bufcode

					// 3.����jcc��ת�ĵ�ַ����֤���ܹ���ȷ��ת���ղŹ����ff25jmp��
					KdPrintEx((77, 0, "runtime_address = %llx\r\n", runtime_address));
					ULONG64 t_dummy = t_ff25jmp_addr - (shellcode_origin_addr + sizeof(resume_code) + cur_disasm_offset + instruction.info.length);
					OFFSET_TYPE offset_for_jx = *(OFFSET_TYPE*)(&t_dummy);
					if (offset_for_jx < 0 || offset_for_jx == 0)
					{
						KdPrintEx((77, 0, "offset_for_jx < 0 || offset_for_jx == 0\r\n"));
						return STATUS_INTERNAL_ERROR;
					}
					// д��jcc��ת�ĵ�ַ��ȥ��
					*(OFFSET_TYPE*)(shellcode_origin_addr + sizeof(resume_code) + cur_disasm_offset + OPCODE_LENGTH) = offset_for_jx;
					KdPrintEx((77, 0, "%llx\r\n", shellcode_origin_addr));
					KdPrintEx((77, 0, "%llx\r\n", shellcode_origin_addr + sizeof(resume_code) + cur_disasm_offset));
				} while (0);
			}
			// ��������������ֽ�disp��Ե�ַ
			else if (instruction.info.raw.disp.size == 0x20)
			{
				// 1.��ģ���ڲ���һ���������ŵ�ǰ����+ff25jmp����ĵ�ַ
				PUCHAR module_blank_area = get_blank_space_in_module(funcAddr, instruction.info.length + sizeof(bufcode));
				if (module_blank_area == 0)
				{
					return STATUS_INTERNAL_ERROR;
				}

				writeToKernel(module_blank_area, runtime_address, instruction.info.length);

				// 2.����ת�����ĵ�ַд��bufcode����ת��ַ����
				ULONG64 addr_to_jmp_back = shellcode_origin_addr + sizeof(resume_code) + cur_disasm_offset + instruction.info.length;
				*(PULONG64)&bufcode[6] = addr_to_jmp_back;

				// �޸�module_blank_area��fff25jmp����ת��ַΪ��һ��ָ��ĵ�ַ������ӵ�module_blank_area��
				writeToKernel(module_blank_area + instruction.info.length, bufcode, sizeof(bufcode));

				// TODO:��������ж�һ���Ƿ���2GB�ڣ�����ڵĻ��Ͳ������������ȥ�Ĵ�����
				// 3.������Ե�ַ��ȡ��Ե�ַ��Ӧ�ľ��Ե�ַ
				LONG cur_offset = *(PLONG)(runtime_address + instruction.info.raw.disp.offset);
				ULONG64 resolved_addr = runtime_address + instruction.info.length + cur_offset;

				// 4.��������checkһ�ּ�����������������67:0005 00000000���ִ��롣
				CHAR disasm_text_buf[96] = { 0 };
				// TODO:sprintf����ȫ���Ժ���Ի��ɰ�ȫ�ĺ�����
				sprintf(disasm_text_buf, "%llX", resolved_addr);
				if (strstr(instruction.text, disasm_text_buf) == 0)
				{
					// ֻ��һ�ִ�����ܵ����������runtime_address+length+disp�õ���Եĵ�ַ�� 67:0005 00000000 ���ִ���һ��address-size override prefix�Ĵ��롣����eipѰַ���������ִ���Ҳ̫�����ˣ��������Ժ��ԣ�û�б�����������д�����
					return STATUS_INTERNAL_ERROR;
				}

				// 5.����disp����Ե�ַ������ָ��ͬһ��������
				// ����Ե�ַ��Ӧ�ľ��Ե�ַ��ȥ��һ��ָ�����ʼ��ַ
				ULONG64 t_dummy = resolved_addr - ((ULONG64)module_blank_area + instruction.info.length);
				// ���룬������
				writeToKernel((ULONG64)module_blank_area + instruction.info.raw.disp.offset, &t_dummy, sizeof(LONG));

				// 6.shellcode��ff25������jmp��module_blank_area����ӵ�����ֽ�disp�Ĵ����ִ�С�
				*(PULONG64)&bufcode[6] = module_blank_area;
				RtlMoveMemory(shellcode_origin_addr + sizeof(resume_code) + inslen + resolve_relative_code_len, bufcode, sizeof(bufcode));
				resolve_relative_code_len += sizeof(bufcode); // resolve�Ĵ��볤��+=sizeof bufcode

				// 7.�޸�shellcode�еĶ�Ӧ���룬���eb xx������һ�����µ�ff25shellcode��
				ULONG64 ff25shellcode_addr = shellcode_origin_addr + sizeof(resume_code) + inslen + resolve_relative_code_len - sizeof(bufcode);
				t_dummy = ff25shellcode_addr - (shellcode_origin_addr + sizeof(resume_code) + cur_disasm_offset + 2);
				if (*(PCHAR)&t_dummy <= 0)
				{
					return STATUS_INTERNAL_ERROR;
				}

				// 8.����eb xx
				*(PUCHAR)(shellcode_origin_addr + sizeof(resume_code) + cur_disasm_offset) = 0xEB;
				*(PCHAR)(shellcode_origin_addr + sizeof(resume_code) + cur_disasm_offset + 1) = *(PCHAR)&t_dummy;
				// TODO:���������90����CC֮��ģ����ﲻ����
			}
			else
			{
				return STATUS_INTERNAL_ERROR;
			}
		}


		cur_disasm_offset += instruction.info.length;
		runtime_address += instruction.info.length;
	}

	// �Ѻ����Ǹ�������ת��ԭ�����Ǹ�jmp��eb�޸�һ��
	if (resolve_relative_code_len > 0x79)
	{
		KdPrintEx((77, 0, "resolve_relative_code_len > 0x79\r\n"));
		return STATUS_INTERNAL_ERROR;
	}
	ULONG64 t_dummy = resolve_relative_code_len - 2;
	*(PCHAR)(shellcode_origin_addr + sizeof(resume_code) + inslen + 1) = *(PCHAR)(&t_dummy);
	// ��ff25 jmp����ԭ����ַ�Ĵ��뿽����ABC�ĺ���
	*(PULONG64)&bufcode[6] = funcAddr + inslen;
	RtlMoveMemory(shellcode_origin_addr + sizeof(resume_code) + inslen + resolve_relative_code_len, bufcode, sizeof(bufcode));

	// �޸�handler_shellcode+0x28������HookHandler
	// �޸�handler_shellcode+0x43������
	*(PULONG64)(handler_addr + 37) = callbackFunc;
	*(PULONG64)(handler_addr + 68) = shellcode_origin_addr;

	if (!head)
	{
		head = allocateMemory(PAGE_SIZE);
		InitializeListHead(&head->entry);
	}

	// �����¼
	phook_record record = allocateMemory(PAGE_SIZE);
	record->num = record_ct;
	*record_number = record_ct;
	record_ct++;
	record->addr = funcAddr;
	record->len = inslen;
	record->handler_addr = handler_addr;
	record->shellcode_origin_addr = shellcode_origin_addr;
	RtlMoveMemory(&record->buf, funcAddr, inslen);
	//InsertHeadList(&head->entry, &record->entry);
	InitializeListHead(&record->entry);
	my_AppendTailList(&head->entry, &record->entry);

	// patchԭ����
	*(PULONG64)&bufcode[6] = handler_addr;
	writeToKernel(funcAddr, bufcode, sizeof(bufcode));

	//freeMemory(handler_addr);
	//freeMemory(shellcode_origin_addr);

	return STATUS_SUCCESS;
}

ULONG64 KeFlushEntireTb();

NTSTATUS reset_hook(ULONG64 record_number)
{
	if (!head)
	{
		return STATUS_NOT_FOUND;
	}
	phook_record cur = head->entry.Flink;
	while (cur != head)
	{
		if (cur->num == record_number)
		{
			writeToKernel(cur->addr, &cur->buf, cur->len);
			freeMemory(cur->handler_addr);
			freeMemory(cur->shellcode_origin_addr);
			RemoveEntryList(&cur->entry);
			freeMemory(cur);
			//KdPrintEx((77, 0, "%llx�����hook\r\n", record_number));
			KeFlushEntireTb();
			return STATUS_SUCCESS;
		}

		cur = cur->entry.Flink;
	}


	return STATUS_NOT_FOUND;
}

// prehandler��ʽ��������
// cmp XXX
// jnz ��������ԭ����code������ԭʼ�߼���Ȼ�����ص�ԭ��λ��  ; ��һЩ���������ж�
// jmp [eip]  ; һ��ff25 jmp��offset��0
// 00 00
// 00 00
// 00 00
// 00 00
// @��������ԭ����code������ԭʼ�߼���Ȼ�����ص�ԭ��λ��
// ; ������ԭʼ�߼��ɺ���Ĵ����Զ����룬�����ֶ�д��
// 
// 
// ע�������п��ܻᵼ��eflags�ĸı䡣�����Ҫ���ı�eflags����Ҫ��ջ���ٱ���һ��eflags��
// ��hook��һ���ǳ�Ƶ�������õĺ���ʱ����������prehandler����prehandler�н���Ԥ�������ĳ������������Ҫ�󣬾Ͳ���������ı���context��handler��ȥ��
// ��һ��������hook��ţ��ڶ���������prehandler�����Ƶĵ�ַ��������������prehandler������Ĵ�С�����ĸ�������prehandler����jmp��Ŀ���ַ��ƫ�ƣ������滻��
// ������handler_addr+0x600��λ�á����Ҫȷ��prehandler_buf_sizeС��0x400
NTSTATUS set_fast_prehandler(ULONG64 record_number, PUCHAR prehandler_buf, ULONG64 prehandler_buf_size, ULONG64 jmp_addr_offset)
{
	if (!head)
	{
		return STATUS_NOT_FOUND;
	}

	if (prehandler_buf_size > 0x350)
	{
		return STATUS_NO_MEMORY;
	}

	phook_record cur = head->entry.Flink;
	BOOLEAN flag = FALSE;

	while (cur != head)
	{
		if (cur->num == record_number)
		{
			flag = TRUE;
			PUCHAR prehook_buf_addr = (PUCHAR)(cur->handler_addr + 0x600);
			// �Ȱ�prehandler������+0x600��λ��
			RtlMoveMemory(prehook_buf_addr, prehandler_buf, prehandler_buf_size);
			// ���Ȼ�ȡhook����Ǹ�ff25��ת�ĵ�ַ��
			PULONG64 phook_point_jmp_addr = (PULONG64)((ULONG64)cur->addr + 6);
			ULONG64 hook_point_jmp_addr = *phook_point_jmp_addr;
			// Ȼ��������ת�ĵ�ַ���뵽prehandler��Ӧ��jmp_addr_offset��
			PULONG64 pPrehandlerJmpAddr = (PULONG64)((ULONG64)prehook_buf_addr + jmp_addr_offset);
			*pPrehandlerJmpAddr = hook_point_jmp_addr;

			// ���ѱ�����ֽڿ�����prehandler�����
			RtlMoveMemory(prehook_buf_addr + prehandler_buf_size, cur->buf, cur->len);
			// ��ff25��ת��ԭ�����Ĵ��뿽�����������
			UCHAR t_ff25_jmp_buf[] = {
				0xff, 0x25, 0x00, 0x00, 0x00, 0x00, // jmp qword ptr ds : [7FF806EA0974] 
				0x00, 0x00, // add byte ptr ds : [rax] ,al 
				0x00, 0x00, // add byte ptr ds : [rax] ,al 
				0x00, 0x00, // add byte ptr ds : [rax] ,al 
				0x00, 0x00, // add byte ptr ds : [rax] ,al 
			};



			ULONG64 t_jmp_back_addr = cur->addr + cur->len;


			RtlMoveMemory(t_ff25_jmp_buf + 6, &t_jmp_back_addr, sizeof(ULONG64));
			RtlMoveMemory(prehook_buf_addr + prehandler_buf_size + cur->len, t_ff25_jmp_buf, sizeof t_ff25_jmp_buf);
			// ͨ��ԭ�Ӳ�����ԭʼ��hook���ff25��ת��λ�ý�����Ӧ���޸ģ���Ϊprehandler�ĵ�ַ
			//InterlockedExchange64(phook_point_jmp_addr, prehook_buf_addr);
			writeToKernel(phook_point_jmp_addr, &prehook_buf_addr, sizeof(PUCHAR));

			break;
		}
		cur = cur->entry.Flink;
	}

	if (!flag) return STATUS_NOT_FOUND;
	else return STATUS_SUCCESS;
}