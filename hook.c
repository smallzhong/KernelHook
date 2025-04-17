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
	// 可以修改内存分配方式使其更隐蔽
	return ExAllocatePool(NonPagedPool, size);
}

VOID freeMemory(ULONG64 addr)
{
	//return ExFreePool(addr);
}

// 36是hookhandler的偏移
// 67是origin地址的偏移
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
,0xEB,0x08 // jmp (跳过后面的代码)
,0x00,0x00 // add byte ptr ds : [rax] ,al |
,0x00,0x00 // add byte ptr ds : [rax] ,al |
,0x00,0x00 // add byte ptr ds : [rax] ,al |
,0x00,0x00 // add byte ptr ds : [rax] ,al |
,0xFF,0x15,0xF2,0xFF,0xFF,0xFF // call qword ptr ds : [7FF9AAEA069B] |

,0x48,0x81,0xC4,0x00,0x01,0x00,0x00 // add rsp,100 |

// 如果rax=1，说明需要直接返回，返回值放在rcx中。否则jmp到原来要执行的代码处进行执行。
,0x3C,0x00 // cmp al,0
,0x75,0x0E // jne (跳过后面14个字节)
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

		// TODO:这个函数不安全。
		if (_stricmp(bufName, ".text") == 0)
		{
			ULONG64 blank_space_start_addr = moduleBase + pSection->VirtualAddress + pSection->Misc.VirtualSize;
			ULONG64 blank_space_end_addr = moduleBase + pSection->VirtualAddress + pSection->SizeOfRawData;

			// TODO:这里可以用一个表来存。暂时先用暴力搜的逻辑。
			ULONG64 cur_addr = blank_space_start_addr;
			while (TRUE)
			{
				// 地址不合法或者没有那么大空间了
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

				// 走到这里说明地址全部合法，并且全为0。
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

// TODO：判断函数长度
// 前两个是模块名和函数名，第三个是callback的地址，第四个是这个模块对应的下标

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

	// 获取需要patch的指令长度
	ULONG64 inslen = get_hook_len(funcAddr, sizeof(bufcode), TRUE);
	ULONG64 shellcode_origin_addr = allocateMemory(PAGE_SIZE);
	if (!shellcode_origin_addr)
		return STATUS_MEMORY_NOT_ALLOCATED;


	/*
	原始代码
	ff 25 xxxxxx(跳回原来)
	*/
	RtlMoveMemory(shellcode_origin_addr, resume_code, sizeof(resume_code));
	RtlMoveMemory(shellcode_origin_addr + sizeof(resume_code), funcAddr, inslen);

	// 使用zydis找出使用了相对地址的语句
	ZyanU64 runtime_address = funcAddr;

	// 用来解决相对地址问题的时候用了多长的代码。后面重新写ff25的时候要把这段地址也给跳过。
	ULONG64 resolve_relative_code_len = 0;

	// 用来确定ABC中是否有使用了相对地址的代码的标记。如果有的话在后面还要再加上一个ebjmp跳过用来resolve相对地址的代码跳到原始的ff25jmp处。
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


		// 判断是否有相对地址
		if (instruction.info.attributes & ZYDIS_ATTRIB_IS_RELATIVE)
		{
			// 标记flag，如果这个flag设置了的话后面要加上一个ebjmp跳到最后的ff25跳回原函数代码的代码处。
			if (relative_addr_used_in_abc == FALSE)
			{
				relative_addr_used_in_abc = TRUE;
				// 这应该是第一次，应该为0
				//ASSERT(resolve_relative_code_len == 0);
				if (resolve_relative_code_len != 0)
				{
					KdPrintEx((77, 0, "resolve_relative_code_len != 0\r\n"));
					return STATUS_INTERNAL_ERROR;
				}
				UCHAR t_ebjmp[2] = { 0xeb, 0x00 };
				// ABC后面再加上一个ebjmp，用来跳过用来resolve的代码
				RtlMoveMemory(shellcode_origin_addr + sizeof(resume_code) + inslen + resolve_relative_code_len, t_ebjmp, sizeof(t_ebjmp));
				// 用来resolve的代码的长度+=2
				resolve_relative_code_len += sizeof(t_ebjmp);
			}

			KdPrintEx((77, 0, "ZYDIS_ATTRIB_IS_RELATIVE\r\n"));
			KdPrintEx((77, 0, "这个指令的信息：%llx", funcAddr + cur_disasm_offset));
			for (int i = 0; i < instruction.info.length; i++)
				KdPrintEx((77, 0, " %02hhx", *(PUCHAR)(funcAddr + cur_disasm_offset + i)));
			KdPrintEx((77, 0, " %s\r\n", instruction.text));
			// 一字节相对跳转
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
					// 1.确定这条指令原来要跳转到哪个地址
					ULONG64 original_jx_addr = funcAddr + cur_disasm_offset + instruction.info.length + *(PULONG)(runtime_address + OPCODE_LENGTH); // 后一条地址+offset
					KdPrintEx((77, 0, "original_jx_addr = %llx\r\n", original_jx_addr));

					// 1.1.判断这条指令跳转的地址是不是在我们复制的buffer范围内，比如eb 02。这样如果还是跳回去的话也会出错，应该不去修改他。
					if (original_jx_addr >= funcAddr && original_jx_addr < funcAddr + inslen)
					{
						// 如果确实在范围内，不去修改，直接break
						break;
					}
					// 2.构造ff25jmp并写到后面

					// 保存这条ff25的地址，在后面修正jcc跳转的地址的时候可以用到
					ULONG64 t_ff25jmp_addr = shellcode_origin_addr + sizeof(resume_code) + inslen + resolve_relative_code_len;

					*(PULONG64)&bufcode[6] = original_jx_addr;
					RtlMoveMemory(shellcode_origin_addr + sizeof(resume_code) + inslen + resolve_relative_code_len, bufcode, sizeof(bufcode));
					resolve_relative_code_len += sizeof(bufcode); // resolve的代码长度+=sizeof bufcode

					// 3.修正jcc跳转的地址，保证其能够正确跳转到刚才构造的ff25jmp处
					KdPrintEx((77, 0, "runtime_address = %llx\r\n", runtime_address));
					ULONG64 t_dummy = t_ff25jmp_addr - (shellcode_origin_addr + sizeof(resume_code) + cur_disasm_offset + instruction.info.length);
					OFFSET_TYPE offset_for_jx = *(OFFSET_TYPE*)(&t_dummy);
					if (offset_for_jx < 0 || offset_for_jx == 0)
					{
						KdPrintEx((77, 0, "offset_for_jx < 0 || offset_for_jx == 0\r\n"));
						return STATUS_INTERNAL_ERROR;
					}
					// 写到jcc跳转的地址中去。
					*(OFFSET_TYPE*)(shellcode_origin_addr + sizeof(resume_code) + cur_disasm_offset + OPCODE_LENGTH) = offset_for_jx;
					KdPrintEx((77, 0, "%llx\r\n", shellcode_origin_addr));
					KdPrintEx((77, 0, "%llx\r\n", shellcode_origin_addr + sizeof(resume_code) + cur_disasm_offset));
				} while (0);
			}
			// 一些不太可能出现的带了无效前缀的短跳，其中部分是UB行为。
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
					// 1.确定这条指令原来要跳转到哪个地址
					ULONG64 original_jx_addr = funcAddr + cur_disasm_offset + instruction.info.length + *(PCHAR)(runtime_address + OPCODE_LENGTH); // 后一条地址+offset
					KdPrintEx((77, 0, "original_jx_addr = %llx\r\n", original_jx_addr));

					// 1.1.判断这条指令跳转的地址是不是在我们复制的buffer范围内，比如eb 02。这样如果还是跳回去的话也会出错，应该不去修改他。
					if (original_jx_addr >= funcAddr && original_jx_addr < funcAddr + inslen)
					{
						// 如果确实在范围内，不去修改，直接break
						break;
					}
					// 2.构造ff25jmp并写到后面

					// 保存这条ff25的地址，在后面修正jcc跳转的地址的时候可以用到
					ULONG64 t_ff25jmp_addr = shellcode_origin_addr + sizeof(resume_code) + inslen + resolve_relative_code_len;

					*(PULONG64)&bufcode[6] = original_jx_addr;
					RtlMoveMemory(shellcode_origin_addr + sizeof(resume_code) + inslen + resolve_relative_code_len, bufcode, sizeof(bufcode));
					resolve_relative_code_len += sizeof(bufcode); // resolve的代码长度+=sizeof bufcode

					// 3.修正jcc跳转的地址，保证其能够正确跳转到刚才构造的ff25jmp处
					KdPrintEx((77, 0, "runtime_address = %llx\r\n", runtime_address));
					ULONG64 t_dummy = t_ff25jmp_addr - (shellcode_origin_addr + sizeof(resume_code) + cur_disasm_offset + instruction.info.length);
					OFFSET_TYPE offset_for_jx = *(OFFSET_TYPE*)(&t_dummy);
					if (offset_for_jx < 0 || offset_for_jx == 0)
					{
						KdPrintEx((77, 0, "offset_for_jx < 0 || offset_for_jx == 0\r\n"));
						return STATUS_INTERNAL_ERROR;
					}
					// 写到jcc跳转的地址中去。
					*(OFFSET_TYPE*)(shellcode_origin_addr + sizeof(resume_code) + cur_disasm_offset + OPCODE_LENGTH) = offset_for_jx;
					KdPrintEx((77, 0, "%llx\r\n", shellcode_origin_addr));
					KdPrintEx((77, 0, "%llx\r\n", shellcode_origin_addr + sizeof(resume_code) + cur_disasm_offset));
				} while (0);
			}
			// 0x0f 0x8x xx xx xx xx 四字节相对跳转
			else if (instruction.info.length == 6 && *(PUCHAR)runtime_address == 0x0f && *(PCUCHAR)(runtime_address + 1) <= 0x8f && *(PCUCHAR)(runtime_address + 1) >= 0x80)
			{
#define OPCODE_LENGTH 2
#define OFFSET_TYPE LONG
				do
				{
					// 1.确定这条指令原来要跳转到哪个地址
					ULONG64 original_jx_addr = funcAddr + cur_disasm_offset + instruction.info.length + *(PCHAR)(runtime_address + OPCODE_LENGTH); // 后一条地址+offset
					KdPrintEx((77, 0, "original_jx_addr = %llx\r\n", original_jx_addr));

					// 1.1.判断这条指令跳转的地址是不是在我们复制的buffer范围内，比如eb 02。这样如果还是跳回去的话也会出错，应该不去修改他。
					if (original_jx_addr >= funcAddr && original_jx_addr < funcAddr + inslen)
					{
						// 如果确实在范围内，不去修改，直接break
						break;
					}
					// 2.构造ff25jmp并写到后面

					// 保存这条ff25的地址，在后面修正jcc跳转的地址的时候可以用到
					ULONG64 t_ff25jmp_addr = shellcode_origin_addr + sizeof(resume_code) + inslen + resolve_relative_code_len;

					*(PULONG64)&bufcode[6] = original_jx_addr;
					RtlMoveMemory(shellcode_origin_addr + sizeof(resume_code) + inslen + resolve_relative_code_len, bufcode, sizeof(bufcode));
					resolve_relative_code_len += sizeof(bufcode); // resolve的代码长度+=sizeof bufcode

					// 3.修正jcc跳转的地址，保证其能够正确跳转到刚才构造的ff25jmp处
					KdPrintEx((77, 0, "runtime_address = %llx\r\n", runtime_address));
					ULONG64 t_dummy = t_ff25jmp_addr - (shellcode_origin_addr + sizeof(resume_code) + cur_disasm_offset + instruction.info.length);
					OFFSET_TYPE offset_for_jx = *(OFFSET_TYPE*)(&t_dummy);
					if (offset_for_jx < 0 || offset_for_jx == 0)
					{
						KdPrintEx((77, 0, "offset_for_jx < 0 || offset_for_jx == 0\r\n"));
						return STATUS_INTERNAL_ERROR;
					}
					// 写到jcc跳转的地址中去。
					*(OFFSET_TYPE*)(shellcode_origin_addr + sizeof(resume_code) + cur_disasm_offset + OPCODE_LENGTH) = offset_for_jx;
					KdPrintEx((77, 0, "%llx\r\n", shellcode_origin_addr));
					KdPrintEx((77, 0, "%llx\r\n", shellcode_origin_addr + sizeof(resume_code) + cur_disasm_offset));
				} while (0);
			}
			// 0xe8(0xe9) xx xx xx xx 四字节相对跳转
			else if (instruction.info.length == 5 && (*(PUCHAR)runtime_address == 0xe8 || *(PUCHAR)runtime_address == 0xe9))
			{
#define OPCODE_LENGTH 1
#define OFFSET_TYPE LONG
				do
				{
					// 1.确定这条指令原来要跳转到哪个地址
					ULONG64 original_jx_addr = funcAddr + cur_disasm_offset + instruction.info.length + *(PULONG)(runtime_address + OPCODE_LENGTH); // 后一条地址+offset
					KdPrintEx((77, 0, "original_jx_addr = %llx\r\n", original_jx_addr));

					// 1.1.判断这条指令跳转的地址是不是在我们复制的buffer范围内，比如eb 02。这样如果还是跳回去的话也会出错，应该不去修改他。
					if (original_jx_addr >= funcAddr && original_jx_addr < funcAddr + inslen)
					{
						// 如果确实在范围内，不去修改，直接break
						break;
					}
					// 2.构造ff25jmp并写到后面

					// 保存这条ff25的地址，在后面修正jcc跳转的地址的时候可以用到
					ULONG64 t_ff25jmp_addr = shellcode_origin_addr + sizeof(resume_code) + inslen + resolve_relative_code_len;

					*(PULONG64)&bufcode[6] = original_jx_addr;
					RtlMoveMemory(shellcode_origin_addr + sizeof(resume_code) + inslen + resolve_relative_code_len, bufcode, sizeof(bufcode));
					resolve_relative_code_len += sizeof(bufcode); // resolve的代码长度+=sizeof bufcode

					// 3.修正jcc跳转的地址，保证其能够正确跳转到刚才构造的ff25jmp处
					KdPrintEx((77, 0, "runtime_address = %llx\r\n", runtime_address));
					ULONG64 t_dummy = t_ff25jmp_addr - (shellcode_origin_addr + sizeof(resume_code) + cur_disasm_offset + instruction.info.length);
					OFFSET_TYPE offset_for_jx = *(OFFSET_TYPE*)(&t_dummy);
					if (offset_for_jx < 0 || offset_for_jx == 0)
					{
						KdPrintEx((77, 0, "offset_for_jx < 0 || offset_for_jx == 0\r\n"));
						return STATUS_INTERNAL_ERROR;
					}
					// 写到jcc跳转的地址中去。
					*(OFFSET_TYPE*)(shellcode_origin_addr + sizeof(resume_code) + cur_disasm_offset + OPCODE_LENGTH) = offset_for_jx;
					KdPrintEx((77, 0, "%llx\r\n", shellcode_origin_addr));
					KdPrintEx((77, 0, "%llx\r\n", shellcode_origin_addr + sizeof(resume_code) + cur_disasm_offset));
				} while (0);
			}
			// 如果代码中有四字节disp相对地址
			else if (instruction.info.raw.disp.size == 0x20)
			{
				// 1.在模块内部找一个能用来放当前代码+ff25jmp代码的地址
				PUCHAR module_blank_area = get_blank_space_in_module(funcAddr, instruction.info.length + sizeof(bufcode));
				if (module_blank_area == 0)
				{
					return STATUS_INTERNAL_ERROR;
				}

				writeToKernel(module_blank_area, runtime_address, instruction.info.length);

				// 2.把跳转回来的地址写到bufcode的跳转地址里面
				ULONG64 addr_to_jmp_back = shellcode_origin_addr + sizeof(resume_code) + cur_disasm_offset + instruction.info.length;
				*(PULONG64)&bufcode[6] = addr_to_jmp_back;

				// 修改module_blank_area的fff25jmp的跳转地址为下一条指令的地址，并添加到module_blank_area中
				writeToKernel(module_blank_area + instruction.info.length, bufcode, sizeof(bufcode));

				// TODO:这里可以判断一下是否在2GB内，如果在的话就不用添加跳来跳去的代码了
				// 3.根据相对地址获取相对地址对应的绝对地址
				LONG cur_offset = *(PLONG)(runtime_address + instruction.info.raw.disp.offset);
				ULONG64 resolved_addr = runtime_address + instruction.info.length + cur_offset;

				// 4.这里用来check一种极其特殊的情况，类似67:0005 00000000这种代码。
				CHAR disasm_text_buf[96] = { 0 };
				// TODO:sprintf不安全，以后可以换成安全的函数。
				sprintf(disasm_text_buf, "%llX", resolved_addr);
				if (strstr(instruction.text, disasm_text_buf) == 0)
				{
					// 只有一种代码会跑到这里，不能用runtime_address+length+disp得到相对的地址。 67:0005 00000000 这种带了一个address-size override prefix的代码。。用eip寻址，但是这种代码也太奇葩了，基本可以忽略，没有编译器会这样写代码的
					return STATUS_INTERNAL_ERROR;
				}

				// 5.修正disp的相对地址，让其指向同一个函数。
				// 用相对地址对应的绝对地址减去下一条指令的起始地址
				ULONG64 t_dummy = resolved_addr - ((ULONG64)module_blank_area + instruction.info.length);
				// 填入，修正。
				writeToKernel((ULONG64)module_blank_area + instruction.info.raw.disp.offset, &t_dummy, sizeof(LONG));

				// 6.shellcode的ff25，用来jmp到module_blank_area进行拥有四字节disp的代码的执行。
				*(PULONG64)&bufcode[6] = module_blank_area;
				RtlMoveMemory(shellcode_origin_addr + sizeof(resume_code) + inslen + resolve_relative_code_len, bufcode, sizeof(bufcode));
				resolve_relative_code_len += sizeof(bufcode); // resolve的代码长度+=sizeof bufcode

				// 7.修改shellcode中的对应代码，变成eb xx跳到上一步放下的ff25shellcode。
				ULONG64 ff25shellcode_addr = shellcode_origin_addr + sizeof(resume_code) + inslen + resolve_relative_code_len - sizeof(bufcode);
				t_dummy = ff25shellcode_addr - (shellcode_origin_addr + sizeof(resume_code) + cur_disasm_offset + 2);
				if (*(PCHAR)&t_dummy <= 0)
				{
					return STATUS_INTERNAL_ERROR;
				}

				// 8.填入eb xx
				*(PUCHAR)(shellcode_origin_addr + sizeof(resume_code) + cur_disasm_offset) = 0xEB;
				*(PCHAR)(shellcode_origin_addr + sizeof(resume_code) + cur_disasm_offset + 1) = *(PCHAR)&t_dummy;
				// TODO:后面可以填90或者CC之类的，这里不填了
			}
			else
			{
				return STATUS_INTERNAL_ERROR;
			}
		}


		cur_disasm_offset += instruction.info.length;
		runtime_address += instruction.info.length;
	}

	// 把后面那个用来跳转到原来的那个jmp的eb修复一下
	if (resolve_relative_code_len > 0x79)
	{
		KdPrintEx((77, 0, "resolve_relative_code_len > 0x79\r\n"));
		return STATUS_INTERNAL_ERROR;
	}
	ULONG64 t_dummy = resolve_relative_code_len - 2;
	*(PCHAR)(shellcode_origin_addr + sizeof(resume_code) + inslen + 1) = *(PCHAR)(&t_dummy);
	// 把ff25 jmp跳回原来地址的代码拷贝到ABC的后面
	*(PULONG64)&bufcode[6] = funcAddr + inslen;
	RtlMoveMemory(shellcode_origin_addr + sizeof(resume_code) + inslen + resolve_relative_code_len, bufcode, sizeof(bufcode));

	// 修改handler_shellcode+0x28，跳到HookHandler
	// 修改handler_shellcode+0x43，跳到
	*(PULONG64)(handler_addr + 37) = callbackFunc;
	*(PULONG64)(handler_addr + 68) = shellcode_origin_addr;

	if (!head)
	{
		head = allocateMemory(PAGE_SIZE);
		InitializeListHead(&head->entry);
	}

	// 保存记录
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

	// patch原函数
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
			//KdPrintEx((77, 0, "%llx已清除hook\r\n", record_number));
			KeFlushEntireTb();
			return STATUS_SUCCESS;
		}

		cur = cur->entry.Flink;
	}


	return STATUS_NOT_FOUND;
}

// prehandler格式类似如下
// cmp XXX
// jnz 重新运行原来的code，运行原始逻辑，然后跳回到原来位置  ; 对一些参数进行判断
// jmp [eip]  ; 一个ff25 jmp，offset填0
// 00 00
// 00 00
// 00 00
// 00 00
// @重新运行原来的code，运行原始逻辑，然后跳回到原来位置
// ; 这后面的原始逻辑由后面的代码自动填入，不用手动写。
// 
// 
// 注意这里有可能会导致eflags的改变。如果需要不改变eflags还需要在栈上再保存一份eflags。
// 在hook了一个非常频繁被调用的函数时，可以设置prehandler，在prehandler中进行预处理，如果某个参数不符合要求，就不跳到后面的保存context的handler中去了
// 第一个参数是hook编号，第二个参数是prehandler二进制的地址，第三个参数是prehandler汇编代码的大小，第四个参数是prehandler里面jmp的目标地址的偏移，用来替换。
// 拷贝到handler_addr+0x600的位置。因此要确保prehandler_buf_size小于0x400
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
			// 先把prehandler拷贝到+0x600的位置
			RtlMoveMemory(prehook_buf_addr, prehandler_buf, prehandler_buf_size);
			// 首先获取hook点的那个ff25跳转的地址，
			PULONG64 phook_point_jmp_addr = (PULONG64)((ULONG64)cur->addr + 6);
			ULONG64 hook_point_jmp_addr = *phook_point_jmp_addr;
			// 然后把这个跳转的地址填入到prehandler相应的jmp_addr_offset中
			PULONG64 pPrehandlerJmpAddr = (PULONG64)((ULONG64)prehook_buf_addr + jmp_addr_offset);
			*pPrehandlerJmpAddr = hook_point_jmp_addr;

			// 最后把保存的字节拷贝到prehandler的最后
			RtlMoveMemory(prehook_buf_addr + prehandler_buf_size, cur->buf, cur->len);
			// 把ff25跳转回原函数的代码拷贝到最后的最后
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
			// 通过原子操作对原始的hook点的ff25跳转的位置进行相应的修改，改为prehandler的地址
			//InterlockedExchange64(phook_point_jmp_addr, prehook_buf_addr);
			writeToKernel(phook_point_jmp_addr, &prehook_buf_addr, sizeof(PUCHAR));

			break;
		}
		cur = cur->entry.Flink;
	}

	if (!flag) return STATUS_NOT_FOUND;
	else return STATUS_SUCCESS;
}