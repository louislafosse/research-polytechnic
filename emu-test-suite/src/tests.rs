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

        Ok(TestResult::Fpu {
            status,
            invalid_op,
            stack_fault,
            c1_bit,
        })
    }

    fn format_result(&self, result: &TestResult) -> String {
        match result {
            TestResult::Fpu {
                status,
                invalid_op,
                stack_fault,
                c1_bit,
            } => crate::c_based::format_fpu_result(*status, *invalid_op, *stack_fault, *c1_bit),
            _ => "Invalid result type".to_string(),
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
            TestResult::Lahf { flags } => crate::c_based::format_lahf_result(*flags),
            _ => "Invalid result type".to_string(),
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
            TestResult::Rdtscp { aux } => crate::c_based::format_rdtscp_result(*aux),
            _ => "Invalid result type".to_string(),
        }
    }

    fn requires_dynamic_linking(&self) -> bool {
        true // RDTSCP requires dynamic linking for TSC_AUX initialization
    }
}

/// TSC monotonicity test
pub struct TscMonotonicTest;

impl Test for TscMonotonicTest {
    fn name(&self) -> &str {
        "tsc_monotonic"
    }

    fn c_code(&self) -> &str {
        r#"
#include <stdio.h>
#include <stdint.h>

static inline uint64_t rdtsc(void) {
    uint32_t lo, hi;
    __asm__ __volatile__("rdtsc" : "=a"(lo), "=d"(hi));
    return ((uint64_t)hi << 32) | lo;
}

int main() {
    uint64_t t1 = rdtsc();
    uint64_t t2 = rdtsc();
    printf("%s\n", (t2 > t1) ? "ok" : "bad");
    return 0;
}
"#
    }

    fn parse_output(&self, stdout: &str) -> Result<TestResult, Box<dyn std::error::Error>> {
        Ok(TestResult::Custom {
            raw: stdout.trim().to_string(),
        })
    }

    fn format_result(&self, result: &TestResult) -> String {
        match result {
            TestResult::Custom { raw } => raw.clone(),
            _ => "Invalid result type".to_string(),
        }
    }
}

/// IDIV overflow fault test
pub struct IdivOverflowTest;

impl Test for IdivOverflowTest {
    fn name(&self) -> &str {
        "idiv_overflow"
    }

    fn c_code(&self) -> &str {
        r#"
#include <stdio.h>
#include <stdint.h>
#include <signal.h>
#include <setjmp.h>

static sigjmp_buf fault_buf;
static volatile sig_atomic_t fault_signal = 0;

static void signal_handler(int sig) {
    fault_signal = sig;
    siglongjmp(fault_buf, 1);
}

int main() {
    signal(SIGFPE, signal_handler);
    volatile int64_t dividend = (int64_t)0x8000000000000000LL;
    volatile int64_t divisor = -1;
    int64_t quotient = 0;

    if (sigsetjmp(fault_buf, 1) == 0) {
        __asm__ __volatile__(
            "cqo\n"
            "idivq %2\n"
            : "=a"(quotient)
            : "a"(dividend), "r"(divisor)
            : "rdx", "cc"
        );
        printf("ok:%ld\n", quotient);
    } else {
        printf("fault:%d\n", fault_signal);
    }

    return 0;
}
"#
    }

    fn parse_output(&self, stdout: &str) -> Result<TestResult, Box<dyn std::error::Error>> {
        Ok(TestResult::Custom {
            raw: stdout.trim().to_string(),
        })
    }

    fn format_result(&self, result: &TestResult) -> String {
        match result {
            TestResult::Custom { raw } => raw.clone(),
            _ => "Invalid result type".to_string(),
        }
    }
}

/// MOVDQA unaligned fault test
pub struct MovdqaUnalignedTest;

impl Test for MovdqaUnalignedTest {
    fn name(&self) -> &str {
        "movdqa_unaligned"
    }

    fn c_code(&self) -> &str {
        r#"
#include <stdio.h>
#include <stdint.h>
#include <signal.h>
#include <setjmp.h>

static sigjmp_buf fault_buf;
static volatile sig_atomic_t fault_signal = 0;

static void signal_handler(int sig) {
    fault_signal = sig;
    siglongjmp(fault_buf, 1);
}

int main() {
    signal(SIGSEGV, signal_handler);
#ifdef SIGBUS
    signal(SIGBUS, signal_handler);
#endif

    uint8_t buf[32] = {0};
    uint8_t *unaligned = buf + 1;

    if (sigsetjmp(fault_buf, 1) == 0) {
        __asm__ __volatile__("movdqa (%0), %%xmm0" :: "r"(unaligned) : "xmm0");
        printf("ok\n");
    } else {
        printf("fault:%d\n", fault_signal);
    }

    return 0;
}
"#
    }

    fn parse_output(&self, stdout: &str) -> Result<TestResult, Box<dyn std::error::Error>> {
        Ok(TestResult::Custom {
            raw: stdout.trim().to_string(),
        })
    }

    fn format_result(&self, result: &TestResult) -> String {
        match result {
            TestResult::Custom { raw } => raw.clone(),
            _ => "Invalid result type".to_string(),
        }
    }
}

/// x87 empty FSTP status test
pub struct X87EmptyFstpTest;

impl Test for X87EmptyFstpTest {
    fn name(&self) -> &str {
        "x87_empty_fstp"
    }

    fn c_code(&self) -> &str {
        r#"
#include <stdio.h>
#include <stdint.h>

int main() {
    uint16_t status;
    float out = 0.0f;

    __asm__ __volatile__(
        "fninit\n"
        "fstps %0\n"
        "fstsw %1\n"
        : "=m"(out), "=m"(status)
        :
        : "st"
    );

    printf("%04x\n", status);
    return 0;
}
"#
    }

    fn parse_output(&self, stdout: &str) -> Result<TestResult, Box<dyn std::error::Error>> {
        Ok(TestResult::Custom {
            raw: stdout.trim().to_string(),
        })
    }

    fn format_result(&self, result: &TestResult) -> String {
        match result {
            TestResult::Custom { raw } => raw.clone(),
            _ => "Invalid result type".to_string(),
        }
    }
}

/// MXCSR round-down behavior test
pub struct MxcsrRoundingTest;

impl Test for MxcsrRoundingTest {
    fn name(&self) -> &str {
        "mxcsr_rounding"
    }

    fn c_code(&self) -> &str {
        r#"
#include <stdio.h>
#include <stdint.h>

int main() {
    uint32_t mxcsr, modified;
    int result;
    float val = 1.9f;

    __asm__ __volatile__("stmxcsr %0" : "=m"(mxcsr));
    modified = (mxcsr & ~0x6000u) | 0x2000u;
    __asm__ __volatile__("ldmxcsr %0" :: "m"(modified));
    __asm__ __volatile__("cvtss2si %1, %0" : "=r"(result) : "x"(val));
    __asm__ __volatile__("ldmxcsr %0" :: "m"(mxcsr));

    printf("%d\n", result);
    return 0;
}
"#
    }

    fn parse_output(&self, stdout: &str) -> Result<TestResult, Box<dyn std::error::Error>> {
        Ok(TestResult::Custom {
            raw: stdout.trim().to_string(),
        })
    }

    fn format_result(&self, result: &TestResult) -> String {
        match result {
            TestResult::Custom { raw } => raw.clone(),
            _ => "Invalid result type".to_string(),
        }
    }
}

/// System-state instruction snapshot compared to native
pub struct SystemStateTest;

impl Test for SystemStateTest {
    fn name(&self) -> &str {
        "system_state"
    }

    fn c_code(&self) -> &str {
        r#"
#include <stdio.h>
#include <stdint.h>
#include <signal.h>
#include <setjmp.h>

static sigjmp_buf fault_buf;
static volatile sig_atomic_t fault_signal = 0;

struct desc_ptr {
    uint16_t limit;
    uint64_t base;
} __attribute__((packed));

static void signal_handler(int sig) {
    fault_signal = sig;
    siglongjmp(fault_buf, 1);
}

int main() {
    signal(SIGSEGV, signal_handler);
    signal(SIGILL, signal_handler);
#ifdef SIGBUS
    signal(SIGBUS, signal_handler);
#endif

    struct desc_ptr dp;
    uint16_t selector = 0;
    uint16_t msw = 0;

    if (sigsetjmp(fault_buf, 1) == 0) {
        __asm__ __volatile__("sgdt %0" : "=m"(dp));
        printf("sgdt=ok:%04x:%016lx\n", dp.limit, dp.base);
    } else {
        printf("sgdt=fault:%d\n", fault_signal);
    }

    fault_signal = 0;
    if (sigsetjmp(fault_buf, 1) == 0) {
        __asm__ __volatile__("sidt %0" : "=m"(dp));
        printf("sidt=ok:%04x:%016lx\n", dp.limit, dp.base);
    } else {
        printf("sidt=fault:%d\n", fault_signal);
    }

    fault_signal = 0;
    if (sigsetjmp(fault_buf, 1) == 0) {
        __asm__ __volatile__("sldt %0" : "=m"(selector));
        printf("sldt=ok:%04x\n", selector);
    } else {
        printf("sldt=fault:%d\n", fault_signal);
    }

    fault_signal = 0;
    if (sigsetjmp(fault_buf, 1) == 0) {
        __asm__ __volatile__("str %0" : "=m"(selector));
        printf("str=ok:%04x\n", selector);
    } else {
        printf("str=fault:%d\n", fault_signal);
    }

    fault_signal = 0;
    if (sigsetjmp(fault_buf, 1) == 0) {
        __asm__ __volatile__("smsw %0" : "=r"(msw));
        printf("smsw=ok:%04x\n", msw);
    } else {
        printf("smsw=fault:%d\n", fault_signal);
    }

    return 0;
}
"#
    }

    fn parse_output(&self, stdout: &str) -> Result<TestResult, Box<dyn std::error::Error>> {
        Ok(TestResult::Custom {
            raw: stdout.trim().to_string(),
        })
    }

    fn format_result(&self, result: &TestResult) -> String {
        match result {
            TestResult::Custom { raw } => raw.clone(),
            _ => "Invalid result type".to_string(),
        }
    }
}
