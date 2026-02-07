use crate::test_framework::{Test, TestResult};

/// FPU Stack Fault Test
pub struct FpuTest;

impl Test for FpuTest {
    fn name(&self) -> &str {
        "fpu_stack_fault"
    }
    
    fn c_code(&self) -> &str {
        r#"
#include <stdio.h>

int main() {
    unsigned short fpu_status;
    __asm__ __volatile__(
        "finit\n"
        "fld1\n"
        "fld1\n"
        "fld1\n"
        "fld1\n"
        "fld1\n"
        "fld1\n"
        "fld1\n"
        "fld1\n"
        "fld1\n"  // 9th fld1 - overflow!
        "fnstsw %0\n"
        : "=a"(fpu_status)
    );
    printf("%04x\n", fpu_status);
    return 0;
}
"#
    }
    
    fn parse_output(&self, stdout: &str) -> Result<TestResult, Box<dyn std::error::Error>> {
        let status = u16::from_str_radix(stdout.trim(), 16)?;
        let stack_fault = (status & 0x0040) != 0;
        let invalid_op = (status & 0x0001) != 0;
        let c1_bit = (status & 0x0200) != 0;
        
        Ok(TestResult::Fpu { status, invalid_op, stack_fault, c1_bit })
    }
    
    fn format_result(&self, result: &TestResult) -> String {
        match result {
            TestResult::Fpu { status, invalid_op, stack_fault, c1_bit } => {
                crate::c_based::format_fpu_result(*status, *invalid_op, *stack_fault, *c1_bit)
            },
            _ => "Invalid result type".to_string()
        }
    }
}

/// LAHF Flags Test
pub struct LahfTest;

impl Test for LahfTest {
    fn name(&self) -> &str {
        "lahf_flags"
    }
    
    fn c_code(&self) -> &str {
        r#"
#include <stdio.h>
#include <stdint.h>

int main() {
    uint8_t flags_result;
    uint32_t tmp;
    
    __asm__ __volatile__(
        "xor %%eax, %%eax\n"  // Clear all flags (ZF=1, others=0)
        "add $127, %%al\n"    // AL=127, no flags set
        "stc\n"               // Set only CF
        "lahf\n"
        "movzbl %%ah, %0\n"
        : "=r"(tmp)
        :: "eax", "ah"
    );
    
    flags_result = (uint8_t)tmp;
    printf("%02x\n", flags_result);
    return 0;
}
"#
    }
    
    fn parse_output(&self, stdout: &str) -> Result<TestResult, Box<dyn std::error::Error>> {
        let flags = u8::from_str_radix(stdout.trim(), 16)?;
        Ok(TestResult::Lahf { flags })
    }
    
    fn format_result(&self, result: &TestResult) -> String {
        match result {
            TestResult::Lahf { flags } => {
                crate::c_based::format_lahf_result(*flags)
            },
            _ => "Invalid result type".to_string()
        }
    }
}

/// RDTSCP Test
pub struct RdtscpTest;

impl Test for RdtscpTest {
    fn name(&self) -> &str {
        "rdtscp"
    }
    
    fn c_code(&self) -> &str {
        r#"
#include <stdio.h>
#include <stdint.h>

int main() {
    uint32_t aux;
    uint32_t lo, hi;
    
    __asm__ __volatile__(
        "rdtscp"
        : "=a"(lo), "=d"(hi), "=c"(aux)
    );
    
    printf("%08x\n", aux);
    return 0;
}
"#
    }
    
    fn parse_output(&self, stdout: &str) -> Result<TestResult, Box<dyn std::error::Error>> {
        let aux = u32::from_str_radix(stdout.trim(), 16)?;
        Ok(TestResult::Rdtscp { aux })
    }
    
    fn format_result(&self, result: &TestResult) -> String {
        match result {
            TestResult::Rdtscp { aux } => {
                crate::c_based::format_rdtscp_result(*aux)
            },
            _ => "Invalid result type".to_string()
        }
    }
    
    fn requires_dynamic_linking(&self) -> bool {
        true  // RDTSCP requires dynamic linking for TSC_AUX initialization
    }
}
