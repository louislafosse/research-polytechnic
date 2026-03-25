#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <signal.h>
#include <setjmp.h>

static sigjmp_buf fault_buf;
static volatile sig_atomic_t fault_signal = 0;

static void signal_handler(int sig) {
    fault_signal = sig;
    siglongjmp(fault_buf, 1);
}

static void install_handlers(void) {
    signal(SIGSEGV, signal_handler);
    signal(SIGILL, signal_handler);
    signal(SIGFPE, signal_handler);
    signal(SIGTRAP, signal_handler);
#ifdef SIGBUS
    signal(SIGBUS, signal_handler);
#endif
}

static inline uint64_t rdtsc(void) {
    uint32_t lo, hi;
    __asm__ __volatile__("rdtsc" : "=a"(lo), "=d"(hi));
    return ((uint64_t)hi << 32) | lo;
}

static inline void cpuid(uint32_t leaf, uint32_t subleaf,
                         uint32_t *eax, uint32_t *ebx,
                         uint32_t *ecx, uint32_t *edx) {
    __asm__ __volatile__("cpuid"
        : "=a"(*eax), "=b"(*ebx), "=c"(*ecx), "=d"(*edx)
        : "a"(leaf), "c"(subleaf));
}

static void run_test(int index, const char *name, void (*fn)(void)) {
    printf("\n[%02d] %s\n", index, name);
    fault_signal = 0;
    if (sigsetjmp(fault_buf, 1) == 0) {
        fn();
    } else {
        printf("   FAULT: signal %d\n", fault_signal);
    }
}

static void test_tsc_monotonic(void) {
    uint64_t t1 = rdtsc();
    uint64_t t2 = rdtsc();
    printf("   TSC1: %lu\n", t1);
    printf("   TSC2: %lu\n", t2);
    if (t2 <= t1) {
        printf("   SUSPICIOUS: TSC not monotonic\n");
    }
}

static void test_rflags_reserved(void) {
    uint64_t before, after;
    __asm__ __volatile__("pushfq; popq %0" : "=r"(before));

    uint64_t modified = before & ~(1ULL << 1);
    modified ^= (1ULL << 3);

    __asm__ __volatile__("pushq %0; popfq" :: "r"(modified) : "cc");
    __asm__ __volatile__("pushfq; popq %0" : "=r"(after));
    __asm__ __volatile__("pushq %0; popfq" :: "r"(before) : "cc");

    printf("   RFLAGS before: 0x%016lx\n", before);
    printf("   RFLAGS after : 0x%016lx\n", after);
    if ((after & (1ULL << 1)) == 0) {
        printf("   SUSPICIOUS: RFLAGS bit1 cleared\n");
    }
}

static void test_df_rep_movsb(void) {
    char src[32];
    char dst[32];

    for (int i = 0; i < 32; i++) {
        src[i] = (char)(i + 1);
        dst[i] = 0;
    }

    char *src_ptr = src + 16;
    char *dst_ptr = dst + 16;
    size_t count = 16;

    __asm__ __volatile__(
        "std\n"
        "rep movsb\n"
        "cld\n"
        : "+S"(src_ptr), "+D"(dst_ptr), "+c"(count)
        :
        : "memory"
    );

    int df_ok = (memcmp(dst + 1, src + 1, 16) == 0);
    int df_ignored = (memcmp(dst + 16, src + 16, 16) == 0);

    printf("   DF respected: %s\n", df_ok ? "yes" : "no");
    if (!df_ok && df_ignored) {
        printf("   SUSPICIOUS: DF ignored (copy forward)\n");
    } else if (!df_ok) {
        printf("   SUSPICIOUS: string copy corrupted\n");
    }
}

static void test_rcl_mask(void) {
    uint64_t value = 0;
    uint8_t count = 65; /* effective count should be 1 */
    unsigned char cf;

    __asm__ __volatile__(
        "stc\n"
        "rclq %%cl, %1\n"
        "setc %0\n"
        : "=r"(cf), "+r"(value)
        : "c"(count)
        : "cc"
    );

    printf("   RCL count=65 result=0x%016lx CF=%u\n", value, (unsigned)cf);
    if (value != 1 || cf != 0) {
        printf("   SUSPICIOUS: rotate count masking off\n");
    }
}

static void test_bt_mask(void) {
    uint64_t bits = 1;
    unsigned char cf0, cf64;

    __asm__ __volatile__("bt $0, %1; setc %0" : "=r"(cf0) : "r"(bits) : "cc");
    __asm__ __volatile__("bt $64, %1; setc %0" : "=r"(cf64) : "r"(bits) : "cc");

    printf("   BT bit0 CF=%u, bit64 CF=%u\n", (unsigned)cf0, (unsigned)cf64);
    if (cf0 != 1 || cf64 != 1) {
        printf("   SUSPICIOUS: BT index masking off\n");
    }
}

static void test_flag_chain(void) {
    uint64_t a = 0xffffffffffffffffULL;
    uint64_t b = 0;
    unsigned char cf, zf, of, sf;

    __asm__ __volatile__(
        "stc\n"
        "adcq %5, %4\n"
        "setc %0\n"
        "setz %1\n"
        "seto %2\n"
        "sets %3\n"
        : "=r"(cf), "=r"(zf), "=r"(of), "=r"(sf), "+r"(a)
        : "r"(b)
        : "cc"
    );

    printf("   ADC result=0x%016lx CF=%u ZF=%u OF=%u SF=%u\n",
           a, (unsigned)cf, (unsigned)zf, (unsigned)of, (unsigned)sf);
    if (a != 0 || cf != 1 || zf != 1) {
        printf("   SUSPICIOUS: ADC flag/result mismatch\n");
    }
}

static void test_div_zero(void) {
    printf("   Expecting SIGFPE (divide by zero)\n");
    volatile int64_t dividend = 123;
    volatile int64_t divisor = 0;
    int64_t quotient;

    __asm__ __volatile__(
        "xor %%rdx, %%rdx\n"
        "idivq %2\n"
        : "=a"(quotient)
        : "a"(dividend), "r"(divisor)
        : "rdx", "cc"
    );

    printf("   SUSPICIOUS: no fault, quotient=%ld\n", quotient);
}

static void test_idiv_overflow(void) {
    printf("   Expecting SIGFPE (IDIV overflow)\n");
    volatile int64_t dividend = (int64_t)0x8000000000000000LL;
    volatile int64_t divisor = -1;
    int64_t quotient;

    __asm__ __volatile__(
        "cqo\n"
        "idivq %2\n"
        : "=a"(quotient)
        : "a"(dividend), "r"(divisor)
        : "rdx", "cc"
    );

    printf("   SUSPICIOUS: no fault, quotient=%ld\n", quotient);
}

static void test_ud2(void) {
    printf("   Executing UD2 (should SIGILL)\n");
    __asm__ __volatile__("ud2");
    printf("   SUSPICIOUS: UD2 did not fault\n");
}

static void test_int3(void) {
    printf("   Executing INT3 (should SIGTRAP)\n");
    __asm__ __volatile__("int3");
    printf("   SUSPICIOUS: INT3 did not fault\n");
}

struct desc_ptr {
    uint16_t limit;
    uint64_t base;
} __attribute__((packed));

static void test_sgdt(void) {
    struct desc_ptr gdtr;
    __asm__ __volatile__("sgdt %0" : "=m"(gdtr));
    printf("   GDTR limit=0x%04x base=0x%016lx\n", gdtr.limit, gdtr.base);
}

static void test_sidt(void) {
    struct desc_ptr idtr;
    __asm__ __volatile__("sidt %0" : "=m"(idtr));
    printf("   IDTR limit=0x%04x base=0x%016lx\n", idtr.limit, idtr.base);
}

static void test_sldt(void) {
    uint16_t sel = 0;
    __asm__ __volatile__("sldt %0" : "=m"(sel));
    printf("   LDTR selector=0x%04x\n", sel);
}

static void test_str(void) {
    uint16_t sel = 0;
    __asm__ __volatile__("str %0" : "=m"(sel));
    printf("   TR selector=0x%04x\n", sel);
}

static void test_smsw(void) {
    uint16_t msw = 0;
    __asm__ __volatile__("smsw %0" : "=r"(msw));
    printf("   MSW (CR0[15:0])=0x%04x\n", msw);
}

static void test_movdqa_unaligned(void) {
    uint8_t buf[32];
    uint8_t *unaligned = buf + 1;
    printf("   Expecting fault on MOVDQA unaligned\n");
    __asm__ __volatile__("movdqa (%0), %%xmm0" :: "r"(unaligned) : "xmm0");
    printf("   SUSPICIOUS: MOVDQA unaligned did not fault\n");
}

static void test_movdqu_unaligned(void) {
    uint8_t buf[32];
    uint8_t *unaligned = buf + 1;
    __asm__ __volatile__("movdqu (%0), %%xmm0" :: "r"(unaligned) : "xmm0");
    printf("   MOVDQU unaligned ok\n");
}

static void test_x87_empty_fstp(void) {
    uint16_t status;
    float out = 0.0f;

    __asm__ __volatile__(
        "fninit\n"
        "fstp %0\n"
        "fstsw %1\n"
        : "=m"(out), "=m"(status)
        :
        : "st"
    );

    printf("   FSTP on empty stack status=0x%04x\n", status);
    if ((status & 0x0001) == 0) {
        printf("   SUSPICIOUS: IE bit not set on empty FSTP\n");
    }
}

static void test_mxcsr_round(void) {
    uint32_t mxcsr, modified;
    __asm__ __volatile__("stmxcsr %0" : "=m"(mxcsr));

    modified = (mxcsr & ~0x6000u) | 0x2000u; /* round down */
    __asm__ __volatile__("ldmxcsr %0" :: "m"(modified));

    float val = 1.9f;
    int result;
    __asm__ __volatile__("cvtss2si %1, %0" : "=r"(result) : "x"(val));

    __asm__ __volatile__("ldmxcsr %0" :: "m"(mxcsr));

    printf("   MXCSR=0x%08x round-down 1.9 -> %d\n", mxcsr, result);
    if (result != 1) {
        printf("   SUSPICIOUS: MXCSR rounding ignored\n");
    }
}

static void test_xgetbv(void) {
    uint32_t eax, ebx, ecx, edx;
    cpuid(1, 0, &eax, &ebx, &ecx, &edx);
    if ((ecx & (1u << 27)) == 0) {
        printf("   OSXSAVE not set; skipping XGETBV\n");
        return;
    }

    uint32_t xcr0_lo, xcr0_hi;
    __asm__ __volatile__(".byte 0x0f, 0x01, 0xd0"
                         : "=a"(xcr0_lo), "=d"(xcr0_hi)
                         : "c"(0)
                         : "cc");

    uint64_t xcr0 = ((uint64_t)xcr0_hi << 32) | xcr0_lo;
    printf("   XCR0=0x%016lx\n", xcr0);
}

static int rdrand32_step(uint32_t *out) {
    unsigned char ok;
    __asm__ __volatile__(".byte 0x0f, 0xc7, 0xf0; setc %1"
                         : "=a"(*out), "=qm"(ok)
                         :
                         : "cc");
    return ok;
}

static int rdseed32_step(uint32_t *out) {
    unsigned char ok;
    __asm__ __volatile__(".byte 0x0f, 0xc7, 0xf8; setc %1"
                         : "=a"(*out), "=qm"(ok)
                         :
                         : "cc");
    return ok;
}

static void test_rdrand(void) {
    uint32_t eax, ebx, ecx, edx;
    cpuid(1, 0, &eax, &ebx, &ecx, &edx);
    if ((ecx & (1u << 30)) == 0) {
        printf("   RDRAND not reported by CPUID; skipping\n");
        return;
    }

    uint32_t val = 0;
    int success = 0;
    for (int i = 0; i < 16; i++) {
        if (rdrand32_step(&val)) {
            success = 1;
            break;
        }
    }

    printf("   RDRAND success=%d value=0x%08x\n", success, val);
    if (!success) {
        printf("   SUSPICIOUS: RDRAND never set CF\n");
    }
}

static void test_rdseed(void) {
    uint32_t eax, ebx, ecx, edx;
    cpuid(7, 0, &eax, &ebx, &ecx, &edx);
    if ((ebx & (1u << 18)) == 0) {
        printf("   RDSEED not reported by CPUID; skipping\n");
        return;
    }

    uint32_t val = 0;
    int success = 0;
    for (int i = 0; i < 16; i++) {
        if (rdseed32_step(&val)) {
            success = 1;
            break;
        }
    }

    printf("   RDSEED success=%d value=0x%08x\n", success, val);
    if (!success) {
        printf("   SUSPICIOUS: RDSEED never set CF\n");
    }
}

static void test_bsf_zero(void) {
    uint64_t val = 0;
    uint64_t out = 0xdeadbeefcafebabeULL;
    unsigned char zf;

    __asm__ __volatile__("bsfq %2, %1; setz %0"
                         : "=r"(zf), "+r"(out)
                         : "r"(val)
                         : "cc");

    printf("   BSF(0) ZF=%u dest=0x%016lx (dest undefined)\n",
           (unsigned)zf, out);
    if (zf != 1) {
        printf("   SUSPICIOUS: BSF zero did not set ZF\n");
    }
}

static void test_cmpxchg(void) {
    uint64_t mem = 0x1122334455667788ULL;
    uint64_t expected = 0x1122334455667788ULL;
    uint64_t desired = 0x99aabbccddeeff00ULL;
    unsigned char success;

    __asm__ __volatile__(
        "lock; cmpxchgq %3, %1\n"
        "setz %0\n"
        : "=q"(success), "+m"(mem), "+a"(expected)
        : "r"(desired)
        : "cc", "memory"
    );

    printf("   CMPXCHG success=%u mem=0x%016lx\n",
           (unsigned)success, mem);
    if (!success || mem != desired) {
        printf("   SUSPICIOUS: CMPXCHG failed unexpectedly\n");
    }
}

static void test_lock_xadd(void) {
    volatile uint64_t mem = 5;
    uint64_t add = 7;

    __asm__ __volatile__("lock; xaddq %0, %1"
                         : "+r"(add), "+m"(mem)
                         :
                         : "cc", "memory");

    printf("   XADD old=%lu new=%lu\n", add, mem);
    if (add != 5 || mem != 12) {
        printf("   SUSPICIOUS: XADD result mismatch\n");
    }
}

int main(void) {
    install_handlers();

    printf("=== Extended x86-64 Edge Case Tests ===\n");

    int i = 1;
    run_test(i++, "TSC Monotonic", test_tsc_monotonic);
    run_test(i++, "RFLAGS Reserved Bits", test_rflags_reserved);
    run_test(i++, "DF + REP MOVSB", test_df_rep_movsb);
    run_test(i++, "RCL Count Masking", test_rcl_mask);
    run_test(i++, "BT Index Masking", test_bt_mask);
    run_test(i++, "ADC Flag Chain", test_flag_chain);
    run_test(i++, "DIV By Zero", test_div_zero);
    run_test(i++, "IDIV Overflow", test_idiv_overflow);
    run_test(i++, "UD2 Illegal Instruction", test_ud2);
    run_test(i++, "INT3 Breakpoint", test_int3);
    run_test(i++, "SGDT", test_sgdt);
    run_test(i++, "SIDT", test_sidt);
    run_test(i++, "SLDT", test_sldt);
    run_test(i++, "STR", test_str);
    run_test(i++, "SMSW", test_smsw);
    run_test(i++, "MOVDQA Unaligned", test_movdqa_unaligned);
    run_test(i++, "MOVDQU Unaligned", test_movdqu_unaligned);
    run_test(i++, "x87 Empty FSTP", test_x87_empty_fstp);
    run_test(i++, "MXCSR Rounding", test_mxcsr_round);
    run_test(i++, "XGETBV", test_xgetbv);
    run_test(i++, "RDRAND", test_rdrand);
    run_test(i++, "RDSEED", test_rdseed);
    run_test(i++, "BSF Zero Input", test_bsf_zero);
    run_test(i++, "CMPXCHG", test_cmpxchg);
    run_test(i++, "LOCK XADD", test_lock_xadd);

    return 0;
}
