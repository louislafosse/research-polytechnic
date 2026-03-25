use std::ptr;

use iced_x86;
use iced_x86::code_asm::{
    CodeAssembler, ah, al, ax, dword_ptr, eax, ecx, rax, rcx, rdx, rsp, word_ptr, xmm0,
};

fn assemble64<F>(build: F) -> Result<Vec<u8>, iced_x86::IcedError>
where
    F: FnOnce(&mut CodeAssembler) -> Result<(), iced_x86::IcedError>,
{
    let mut a = CodeAssembler::new(64)?;
    build(&mut a)?;
    a.assemble(0)
}

/// Generate shellcode that detects FPU stack faults and stores the status word.
pub fn generate_shellcode_fpu_sf(result_ptr: u64) -> Result<Vec<u8>, iced_x86::IcedError> {
    assemble64(|a| {
        a.push(rax)?;
        a.push(rcx)?;
        a.nop()?;
        a.nop()?;
        a.nop()?;
        a.nop()?;
        a.finit()?;
        for _ in 0..9 {
            a.fld1()?;
        }
        a.fstsw(ax)?;
        a.mov(rcx, result_ptr)?;
        a.test(rcx, rcx)?;
        let mut done = a.create_label();
        a.jz(done)?;
        a.mov(word_ptr(rcx), ax)?;
        a.set_label(&mut done)?;
        a.pop(rcx)?;
        a.pop(rax)?;
        a.ret()?;
        Ok(())
    })
}

pub fn shellcode_fpu_overflow_status() -> Result<Vec<u8>, iced_x86::IcedError> {
    assemble64(|a| {
        a.finit()?;
        for _ in 0..9 {
            a.fld1()?;
        }
        a.fstsw(ax)?;
        a.ret()?;
        Ok(())
    })
}

pub fn shellcode_lahf_flags() -> Result<Vec<u8>, iced_x86::IcedError> {
    assemble64(|a| {
        a.xor(eax, eax)?;
        a.add(al, 127)?;
        a.stc()?;
        a.lahf()?;
        a.movzx(eax, ah)?;
        a.ret()?;
        Ok(())
    })
}

pub fn shellcode_rdtscp_aux() -> Result<Vec<u8>, iced_x86::IcedError> {
    assemble64(|a| {
        a.rdtscp()?;
        a.mov(eax, ecx)?;
        a.ret()?;
        Ok(())
    })
}

pub fn shellcode_tsc_monotonic() -> Result<Vec<u8>, iced_x86::IcedError> {
    assemble64(|a| {
        a.rdtsc()?;
        a.shl(rdx, 32)?;
        a.or(rax, rdx)?;
        a.mov(rcx, rax)?;
        a.rdtsc()?;
        a.shl(rdx, 32)?;
        a.or(rax, rdx)?;
        a.cmp(rax, rcx)?;
        a.setg(al)?;
        a.movzx(eax, al)?;
        a.ret()?;
        Ok(())
    })
}

pub fn shellcode_x87_empty_fstp() -> Result<Vec<u8>, iced_x86::IcedError> {
    assemble64(|a| {
        a.sub(rsp, 8)?;
        a.fninit()?;
        a.fstp(dword_ptr(rsp))?;
        a.fstsw(ax)?;
        a.add(rsp, 8)?;
        a.ret()?;
        Ok(())
    })
}

pub fn shellcode_mxcsr_round_down() -> Result<Vec<u8>, iced_x86::IcedError> {
    assemble64(|a| {
        a.sub(rsp, 16)?;
        a.stmxcsr(dword_ptr(rsp))?;
        a.mov(eax, dword_ptr(rsp))?;
        a.and(eax, 0xffff9fffu32)?;
        a.or(eax, 0x2000)?;
        a.mov(dword_ptr(rsp + 4), eax)?;
        a.ldmxcsr(dword_ptr(rsp + 4))?;
        a.mov(dword_ptr(rsp + 8), 0x3ff33333u32)?;
        a.movss(xmm0, dword_ptr(rsp + 8))?;
        a.cvtss2si(eax, xmm0)?;
        a.ldmxcsr(dword_ptr(rsp))?;
        a.add(rsp, 16)?;
        a.ret()?;
        Ok(())
    })
}

pub fn shellcode_sldt() -> Result<Vec<u8>, iced_x86::IcedError> {
    assemble64(|a| {
        a.sldt(ax)?;
        a.ret()?;
        Ok(())
    })
}

pub fn shellcode_str() -> Result<Vec<u8>, iced_x86::IcedError> {
    assemble64(|a| {
        a.str(ax)?;
        a.ret()?;
        Ok(())
    })
}

pub fn shellcode_smsw() -> Result<Vec<u8>, iced_x86::IcedError> {
    assemble64(|a| {
        a.smsw(ax)?;
        a.ret()?;
        Ok(())
    })
}

pub fn run_natively_return_rax(shellcode: &[u8]) -> Result<u64, Box<dyn std::error::Error>> {
    let page_size = 4096usize;
    let len = shellcode.len().max(1).div_ceil(page_size) * page_size;
    let ptr = unsafe {
        libc::mmap(
            ptr::null_mut(),
            len,
            libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        )
    };

    if ptr == libc::MAP_FAILED {
        return Err("native shellcode mmap failed".into());
    }

    let result = unsafe {
        ptr::copy_nonoverlapping(shellcode.as_ptr(), ptr.cast::<u8>(), shellcode.len());
        let func: unsafe extern "C" fn() -> u64 = std::mem::transmute(ptr);
        func()
    };

    let unmap_rc = unsafe { libc::munmap(ptr, len) };
    if unmap_rc != 0 {
        return Err("native shellcode munmap failed".into());
    }

    Ok(result)
}
