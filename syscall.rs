#![allow(warnings)]
#![allow(unused_must_use)]

use goblin::pe::PE;
use pelite::image::UNWIND_INFO;
use pelite::pe32::msvc::FuncInfo;
use pelite::pe64::exports::Export;
use pelite::pe64::{Pe, PeView};
use std::arch::asm;
use std::fs;
use std::io::BufReader;
use std::mem::MaybeUninit;
use std::ops::{Sub, SubAssign};

pub fn calculate_offset(pe: &PE, rva: usize) -> usize {
    for section in &pe.sections {
        let start = section.virtual_address as usize;
        let end = start + section.virtual_size as usize;
        // println!("start: {:?}  end: {:?}", start, end);
        if start <= rva && rva <= end {
            return rva - start + section.pointer_to_raw_data as usize;
        }
    }
    0
}

pub unsafe fn get_fun_rva(dll_base: *const u8, func_name: &str) -> usize {
    unsafe {
        let view = PeView::module(dll_base);
        let exports = view.exports().unwrap();
        let by = exports.by().unwrap();
        if let Ok(Export::Symbol(addr)) = by.name(func_name) {
            println!("{} address: 0x{:x?}", func_name, addr);
            return *addr as usize;
        } else {
            println!("{} not found", func_name);
            return 0;
        }
    }
}

struct ImageEntry {
    pub start: u32,
    pub end: u32,
    pub unwind_rva: u32,
}

unsafe fn calcular_bytes_frame(unwind_info_va: usize, count_of_codes: u8) -> Option<u32> {
    if count_of_codes == 0 {
        return Some(8); // O return 8, dependiendo de cómo lo tengas en tu código actual
    }

    let codes_ptr = (unwind_info_va + 4) as *const UnwindCode;
    let codes = unsafe { std::slice::from_raw_parts(codes_ptr, count_of_codes as usize) };

    let mut total_bytes: u32 = 0;
    let mut i = 0;

    while i < codes.len() {
        let code = codes[i];
        let op_code = code.unwind_op();
        let op_info = code.op_info();

        match op_code {
            0 => {
                total_bytes += 8;
                i += 1;
            }
            2 => {
                total_bytes += (op_info as u32 * 8) + 8; //
                i += 1;
            }
            1 => {
                if op_info == 0 {
                    if i + 1 < codes.len() {
                        let siguiente_slot = unsafe { *(codes_ptr.add(i + 1) as *const u16) };
                        total_bytes += (siguiente_slot as u32) * 8;
                    }
                    i += 2;
                } else if op_info == 1 {
                    if i + 2 < codes.len() {
                        let low = unsafe { *(codes_ptr.add(i + 1) as *const u16) } as u32;
                        let high = unsafe { *(codes_ptr.add(i + 2) as *const u16) } as u32;
                        let siguiente_dword = low | (high << 16);
                        total_bytes += siguiente_dword;
                    } else {
                    }
                    i += 3;
                }
            }
            4 | 8 => {
                i += 2;
            }
            5 | 9 => {
                i += 3;
            }
            3 => {
                return None;
            }
            10 => {
                total_bytes += if op_info == 0 { 40 } else { 48 };
                i += 1;
            }
            _ => {
                return None;
            }
        }
    }
    Some(total_bytes) // O total_bytes + 8, según lo que tengas
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct UnwindInfo {
    pub version_flags: u8,
    pub size_of_prolog: u8,
    pub count_of_codes: u8,
    pub frame_register: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct UnwindCode {
    pub code_offset: u8,
    pub unwind_op_and_info: u8,
}
impl UnwindCode {
    pub fn unwind_op(&self) -> u8 {
        self.unwind_op_and_info & 0x0F
    }

    pub fn op_info(&self) -> u8 {
        (self.unwind_op_and_info >> 4) & 0x0F
    }

    pub unsafe fn frame_offset(&self) -> u16 {
        unsafe { *(self as *const UnwindCode as *const u16) }
    }
}

unsafe fn get_unwind_info(dll_base: *const u8, func_rva: u32) -> usize {
    unsafe {
        let view = PeView::module(dll_base);
        let section = view.section_headers();
        for sec in section {
            let name = sec.name().unwrap_or("Unknown");
            // println!("section name: {}", name);
            // println!("virtual address: 0x{:x?}", sec.VirtualAddress);
            // println!("virtual size: 0x{:x?}", sec.VirtualSize);
            // println!("pointer to raw data: 0x{:x?}", sec.PointerToRawData);
            // println!("size of raw data: 0x{:x?}", sec.SizeOfRawData);
            // println!("-----------------------------------");
            if name == ".pdata" {
                let pdata_start = dll_base.add(sec.VirtualAddress as usize);
                let pdata_size = sec.VirtualSize as usize;
                let entry_count = pdata_size / 12;
                for i in 0..entry_count {
                    let pdata_slice = std::slice::from_raw_parts(pdata_start.add(i * 12), 12);
                    // println!("pdata slice: {:?}", pdata_slice);
                    let start_rva = u32::from_le_bytes([
                        pdata_slice[0],
                        pdata_slice[1],
                        pdata_slice[2],
                        pdata_slice[3],
                    ]);
                    let end_rva = u32::from_le_bytes([
                        pdata_slice[4],
                        pdata_slice[5],
                        pdata_slice[6],
                        pdata_slice[7],
                    ]);
                    let unwind_rva = u32::from_le_bytes([
                        pdata_slice[8],
                        pdata_slice[9],
                        pdata_slice[10],
                        pdata_slice[11],
                    ]);
                    // println!("start:{:?} and end:{:?}, rva:{:?}", start_rva, end_rva, func_rva);
                    if func_rva >= start_rva && func_rva <= end_rva {
                        // println!("found function in pdata entry: start: 0x{:x?}, end: 0x{:x?}, unwind_rva: 0x{:x?}", start_rva, end_rva, unwind_rva);
                        let image_entry = ImageEntry {
                            start: start_rva,
                            end: end_rva,
                            unwind_rva: unwind_rva,
                        };
                        // println!("image entry: start: 0x{:x?}, end: 0x{:x?}, unwind_rva: 0x{:x?}", image_entry.start, image_entry.end, image_entry.unwind_rva);
                        let unwind_addr = dll_base.add(unwind_rva as usize);
                        let unwind_slice = std::slice::from_raw_parts(unwind_addr, 12);
                        // println!("unwind slice: {:?}", unwind_slice);
                        let unwind_info = std::ptr::read(unwind_addr as *const UnwindInfo);
                        // println!("unwind info: {:?}", unwind_info);

                        let mut current_unwind_info_va = unwind_addr as usize;
                        let mut total_offset_bytes: u32 = 0;
                        let mut current_unwind_info: UnwindInfo;

                        loop {
                            current_unwind_info =
                                std::ptr::read(current_unwind_info_va as *const UnwindInfo);
                            total_offset_bytes += unsafe {
                                match calcular_bytes_frame(
                                    current_unwind_info_va,
                                    current_unwind_info.count_of_codes,
                                ) {
                                    Some(bytes) => bytes,
                                    None => 0,
                                }
                            };
                            if current_unwind_info.version_flags & 0xF8 == 0x20 {
                                let mut unwind_extension_ptr;
                                if current_unwind_info.count_of_codes % 2 != 0 {
                                    unwind_extension_ptr = unwind_addr.add(
                                        4 + (current_unwind_info.count_of_codes as usize + 1) * 2,
                                    );
                                } else {
                                    unwind_extension_ptr = unwind_addr
                                        .add(4 + (current_unwind_info.count_of_codes as usize) * 2);
                                }

                                let extension =
                                    std::ptr::read(unwind_extension_ptr as *const ImageEntry);
                                let safe_unwind_rva = extension.unwind_rva & !1;
                                current_unwind_info_va =
                                    dll_base as usize + safe_unwind_rva as usize;
                                continue;
                            } else {
                                break;
                            }
                        }
                        return total_offset_bytes as usize;
                    }
                }
            }
        }
        0
    }
}

//从文件读取ssn
pub unsafe fn get_ssn(sys_name: &str) -> u32 {
    let buffer = fs::read("C:\\Windows\\System32\\ntdll.dll").unwrap();
    let pe = PE::parse(&buffer).unwrap();
    let mut rva = 0;

    for export in &pe.exports {
        if let Some(name) = export.name {
            if name == sys_name {
                print!("{:?}: ", name);
                rva = export.rva;
                println!("0x{:?}", rva);
            }
        }
    }
    // unsafe {
    // let ntdll_base = get_ntdll_base();
    // let func_in_byte = std::slice::from_raw_parts(ntdll_base.wrapping_add(rva as usize), 16);
    // println!("the first 16 bytes of NtQuerySystemTime: {:?}", func_in_byte);
    // }
    // 0

    let file_offset = calculate_offset(&pe, rva);
    // println!("offset in file: 0x{:x?}", file_offset);
    let func_in_byte = &buffer[file_offset + 4..file_offset + 12];
    // println!("the first 16 bytes of NtQuerySystemTime: {:x?}", func_in_byte);
    let ssn_in_byte: [u8; 4] = [
        func_in_byte[0],
        func_in_byte[1],
        func_in_byte[2],
        func_in_byte[3],
    ];
    let ssn = u32::from_le_bytes(ssn_in_byte);
    if ssn > 0x200 {
        println!("[warning] didn't find correct ssn of {:}", sys_name);
        return 0x200;
    }
    println!("ssn = 0x{:x?}", ssn);
    ssn
}

pub unsafe fn get_ntdll_base() -> *const u8 {
    let ntdll_base: *const u8;
    std::arch::asm!(
        // PEB
        "mov rax, gs:[0x60]",
        // PEB_LDR_DATA
        "mov rax, [rax + 0x18]",
        // InLoadOrderModuleList 头部
        "mov rax, [rax + 0x10]",
        // 链表的 Flink
        "mov rax, [rax]",
        // DllBase 位于正开头偏移 0x30 处
        "mov {out_ptr}, [rax + 0x30]",
        out_ptr = out(reg) ntdll_base,
    );
    // println!("ntdll base addr: 0x{:x?}", ntdll_base as u32);
    ntdll_base
}

pub unsafe fn get_kernel32_base() -> *const u8 {
    let dll_base: *const u8;
    std::arch::asm!(
        "mov rax, gs:[0x60]",
        "mov rax, [rax + 0x18]",
        "mov rax, [rax + 0x10]",
        "mov rax, [rax]",
        "mov rax, [rax]",
        "mov {out_ptr}, [rax + 0x30]",
        out_ptr = out(reg) dll_base,
    );
    println!("kernel base addr: 0x{:x?}", dll_base as u32);
    dll_base
}

//在内存中查找ntdll并寻找其中的syscall地址
pub unsafe fn syscall_addr() -> usize {
    let ntdll_base: *const u8 = get_ntdll_base();
    println!("ntdll base addr: 0x{:x?}", ntdll_base as u32);
    let offset = 1444768;
    let memory_slice = std::slice::from_raw_parts(ntdll_base.wrapping_add(offset), 4096);
    for i in 0..memory_slice.len() {
        if i != memory_slice.len() - 1 && memory_slice[i] == 0xf && memory_slice[i + 1] == 0x5 {
            let syscall_addr = ntdll_base.wrapping_add(offset + i);
            // for j in 0..128 {
            //     print!("0x{:x?}", memory_slice[i+j]);
            // }
            println!(
                "found syscall instruction at address: 0x{:x?}",
                syscall_addr as u32
            );
            let slice = std::slice::from_raw_parts(syscall_addr as *const u8, 12);
            println!("the first byte: 0x{:x?}", slice[0]);
            return syscall_addr as usize;
            break;
        }
    }
    0
}

// need to improve robustness
pub unsafe fn jmp_addr() -> usize {
    let ntdll_base: *const u8 = get_ntdll_base();
    // println!("ntdll base addr: 0x{:x?}", ntdll_base as u32);
    let offset = 0;
    let memory_slice = std::slice::from_raw_parts(ntdll_base.wrapping_add(offset), 0x2000000);
    for i in 0..memory_slice.len() {
        if i != memory_slice.len() - 3
            && memory_slice[i] == 0xff
            && (memory_slice[i + 1] == 0xd6
                || memory_slice[i + 1] == 0xd7
                || memory_slice[i + 1] == 0xd4)
        {
            let syscall_addr = ntdll_base.wrapping_add(offset + i);
            // for j in 0..128 {
            //     print!("0x{:x?}", memory_slice[i+j]);
            // }
            println!(
                "found jmp instruction at address: 0x{:x?}",
                syscall_addr as u32
            );
            let slice = std::slice::from_raw_parts(syscall_addr.sub(1) as *const u8, 3);
            println!("byte: {:x?}", slice);
            let _ = get_unwind_info(ntdll_base, (offset + i) as u32);
            return (offset + i - 1) as usize;
            break;
        }
    }
    println!("didn't find proper jmp addr");
    0
}

#[derive(Debug)]
pub struct StackData {
    pub total_offset: usize,
    pub func_1: usize,
    pub pos_1: usize,
    pub func_2: usize,
    pub pos_2: usize,
    pub func_3: usize,
    pub pos_3: usize,
    pub syscall_addr: usize,
}

pub unsafe fn prepare_stack_data() -> StackData {
    println!("preparing stack data...");
    unsafe {
        let func_1 = "RtlUserThreadStart";
        let func_2 = "BaseThreadInitThunk";
        let ntdll_base = get_ntdll_base();
        let func_rva = get_fun_rva(ntdll_base, func_1);
        let offset = get_unwind_info(ntdll_base, func_rva as u32);
        // println!("offset: 0x{:x?}", offset);
        let kernel32_base = get_kernel32_base();
        let func_2_rva = get_fun_rva(kernel32_base, func_2);
        let offset_2 = get_unwind_info(kernel32_base, func_2_rva as u32);
        // println!("offset_2: 0x{:x?}", offset_2);
        let func_3_rva;
        unsafe {
            func_3_rva = jmp_addr();
        }
        let buffer = std::slice::from_raw_parts(ntdll_base.add(func_3_rva), 3);
        // println!("func_3 {:?} {:x?}", func_3_rva,buffer);
        let offset_3 = get_unwind_info(ntdll_base, func_3_rva as u32);
        let pos_3 = 0;
        let pos_2 = pos_3 + offset_3 + 8;
        let pos_1 = pos_2 + offset_2 + 8;

        StackData {
            total_offset: pos_1 + offset + 8,
            func_1: ntdll_base.add(func_rva + 0x21) as usize,
            pos_1: pos_1,
            func_2: kernel32_base.add(func_2_rva + 0x14) as usize,
            pos_2: pos_2,
            func_3: ntdll_base.add(func_3_rva) as usize,
            pos_3: pos_3,
            syscall_addr: syscall_addr(),
        }
    }
}

//用找到的ssn和syscall指令地址执行syscall
pub unsafe fn execute(ssn: u32, param: [usize; 11], stack_data: *const StackData) -> i32 {
    println!("excuting...");
    // let buffer  = std::slice::from_raw_parts(addr as *const u8, 2);
    // println!("{:?}", buffer);

    let output: i32;
    asm! {
        "xor r11, r11",
        "mov rsi, [rsp]",
        "mov [rsp], r11",
        "mov r11,[r15 + 0x0]",
        "mov rdi, rsp",
        "sub rsp, r11",

        "mov r14, [r13 + 0x20]", // args 5
        "mov [rsp + 0x28], r14",

        "mov r14, [r13 + 0x28]", // args 6
        "mov [rsp + 0x30], r14",

        "mov r14, [r13 + 0x30]", // args 7
        "mov [rsp + 0x38], r14",

        "mov r14, [r13 + 0x38]", // args 8
        "mov [rsp + 0x40], r14",

        "mov r14, [r13 + 0x40]", // args 9
        "mov [rsp + 0x48], r14",

        "mov r14, [r13 + 0x48]", // args 10
        "mov [rsp + 0x50], r14",

        "mov r14, [r13 + 0x50]", // args 11
        "mov [rsp + 0x58], r14",

        "mov rcx, [r15 + 0x8]",
        "mov r11,[r15 + 0x10]",
        "mov [rsp + r11], rcx",  // func 1

        "mov rcx, [r15 + 0x18]",
        "mov r11,[r15 + 0x20]",
        "mov [rsp + r11], rcx",  // func 2

        "mov rcx, [r15 + 0x28]",
        "mov r11,[r15 + 0x30]",
        "mov [rsp + r11], rcx",  // func 3

        "lea r12, [rip+2f]",
        // "mov r10, rcx",
        "mov rcx, [r15 + 0x38]",
        "jmp rcx",
        // "syscall",
        "2:",
        "mov rsp, rdi",
        "mov [rsp], rsi",
        in("eax") ssn,
        // syscall_addr = in(reg) addr,
        // in("rsi") syscall_addr,
        in("r15") stack_data,
        // stack_data = in(reg) stack_data,
        in("r13") &param,  //  the input params will stay in the same
        // in("r14") param[5],
        inout("r10") param[0] => _,  // the input params might be modified
        inout("rdx") param[1] => _,
        inout("r8") param[2] => _,
        inout("r9") param[3] => _,
        lateout("rax") output,
        clobber_abi("win64")
    }
    println!("core {:x?}", output);
    output
}

pub unsafe fn syscall(sys_name: &str, param: [usize; 11]) -> i32 {
    let mut ssn = get_ssn(sys_name);
    if ssn == 0x200 {
        // ssn = 0x5a;
        panic!("no such syscall")
    }
    let stack_data = prepare_stack_data();
    let stack_data_ptr = &stack_data as *const StackData;
    execute(ssn, param, stack_data_ptr)
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union LARGE_INTEGER {
    pub u: LARGE_INTEGER_u,
    pub QuadPart: i64, // 时间戳数值
}

#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct LARGE_INTEGER_u {
    pub LowPart: u32,
    pub HighPart: i32,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_excute() {
        unsafe {
            let mut ssn = get_ssn("NtQuerySystemTime");
            ssn = 0x5A;

            // let slice = std::slice::from_raw_parts(base as *const u8, 12);
            let mut buffer = MaybeUninit::<LARGE_INTEGER>::uninit();
            let stack_data = prepare_stack_data();
            let stack_data_ptr = &stack_data as *const StackData;
            let mut param = [0; 11];
            param[0] = buffer.as_mut_ptr() as usize;
            execute(ssn, param, stack_data_ptr);
            let time_ptr = param[0] as *mut LARGE_INTEGER;
            let time = *time_ptr;
            println!("time: {:?}", time.QuadPart);
        }
    }

    #[test]
    fn test_syscall() {
        unsafe {
            let mut buffer = MaybeUninit::<LARGE_INTEGER>::uninit();
            let mut param = [0; 11];
            param[0] = buffer.as_mut_ptr() as usize;
            syscall("NtQuerySystemTime", param);
            let time_ptr = param[0] as *mut LARGE_INTEGER;
            let time = *time_ptr;
            println!("time: {:?}", time.QuadPart);
        }
    }

    #[test]
    fn test_get_image() {
        unsafe { println!("{:?}", prepare_stack_data()) }
    }

    #[test]
    fn test_jmp() {
        unsafe {
            let _ = prepare_stack_data();
        }
    }

    #[test]
    fn test_ssn() {
        unsafe {
            get_ssn("ZwUnmapViewOfSection");
            get_ssn("NtReadFile");
            get_ssn("NtAllocateVirtualMemory");
            get_ssn("NtProtectVirtualMemory");
            get_ssn("NtWriteVirtualMemory");
            get_ssn("EtwEventWrite");
        }
    }
}
