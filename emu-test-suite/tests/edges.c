#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <signal.h>
#include <setjmp.h>

static jmp_buf fault_buf;
static volatile int fault_caught = 0;

void sigsegv_handler(int sig) {
    fault_caught = 1;
    longjmp(fault_buf, 1);
}

void sigill_handler(int sig) {
    fault_caught = 2;
    longjmp(fault_buf, 1);
}

// RDTSC
static inline uint64_t rdtsc(void) {
    uint32_t lo, hi;
    __asm__ __volatile__ ("rdtsc" : "=a"(lo), "=d"(hi));
    return ((uint64_t)hi << 32) | lo;
}

// RDTSCP (returns TSC + processor ID in ECX)
static inline uint64_t rdtscp(uint32_t *aux) {
    uint32_t lo, hi;
    __asm__ __volatile__ ("rdtscp" : "=a"(lo), "=d"(hi), "=c"(*aux));
    return ((uint64_t)hi << 32) | lo;
}

// CPUID
static inline void cpuid(uint32_t leaf, uint32_t subleaf, uint32_t *eax, uint32_t *ebx, uint32_t *ecx, uint32_t *edx) {
    __asm__ __volatile__("cpuid"
        : "=a"(*eax), "=b"(*ebx), "=c"(*ecx), "=d"(*edx)
        : "a"(leaf), "c"(subleaf));
}

int main() {
    signal(SIGSEGV, sigsegv_handler);
    signal(SIGILL, sigill_handler);
    
    printf("=== Advanced x86-64 Emulator Detection ===\n\n");
    
    // Test 1: RDTSCP (processor ID)
    printf("[1] RDTSCP Test:\n");
    uint32_t aux1, aux2;
    uint64_t tsc1 = rdtscp(&aux1);
    uint64_t tsc2 = rdtscp(&aux2);
    printf("   TSC1: %lu (AUX: 0x%x)\n", tsc1, aux1);
    printf("   TSC2: %lu (AUX: 0x%x)\n", tsc2, aux2);
    if (aux1 == 0 && aux2 == 0) {
        printf("   SUSPICIOUS: TSC_AUX always zero (emulated)\n");
    }
    
    // Test 2: CPUID extended leaves
    printf("\n[2] Extended CPUID:\n");
    uint32_t eax, ebx, ecx, edx;
    cpuid(0x80000000, 0, &eax, &ebx, &ecx, &edx);
    printf("   Max extended leaf: 0x%x\n", eax);
    if (eax >= 0x80000004) {
        char brand[49] = {0};
        cpuid(0x80000002, 0, (uint32_t*)&brand[0], (uint32_t*)&brand[4], 
              (uint32_t*)&brand[8], (uint32_t*)&brand[12]);
        cpuid(0x80000003, 0, (uint32_t*)&brand[16], (uint32_t*)&brand[20],
              (uint32_t*)&brand[24], (uint32_t*)&brand[28]);
        cpuid(0x80000004, 0, (uint32_t*)&brand[32], (uint32_t*)&brand[36],
              (uint32_t*)&brand[40], (uint32_t*)&brand[44]);
        printf("   CPU Brand: %s\n", brand);
    }
    
    // Test 3: x87 FPU status word edge cases
    printf("\n[3] x87 FPU Edge Cases:\n");
    uint16_t fpu_status, fpu_control;
    __asm__ __volatile__(
        "fninit\n"
        "fstcw %0\n"
        "fstsw %1\n"
        : "=m"(fpu_control), "=m"(fpu_status)
    );
    printf("   Initial FPU control: 0x%04x\n", fpu_control);
    printf("   Initial FPU status: 0x%04x\n", fpu_status);
    
    // Test denormal handling
    float denormal = 1.0e-40f;
    float result;
    __asm__ __volatile__(
        "flds %1\n"
        "fmul %%st(0), %%st(0)\n"
        "fstps %0\n"
        : "=m"(result)
        : "m"(denormal)
    );
    printf("   Denormal * Denormal: %e\n", result);
    
    // Test 4: FS/GS segment registers
    printf("\n[4] Segment Registers:\n");
    uint64_t fs_base, gs_base;
    __asm__ __volatile__("mov %%fs, %0" : "=r"(fs_base));
    __asm__ __volatile__("mov %%gs, %0" : "=r"(gs_base));
    printf("   FS: 0x%lx, GS: 0x%lx\n", fs_base, gs_base);
    
    // Test 5: Memory fence instructions
    printf("\n[5] Memory Fence Tests:\n");
    volatile int test_var = 0;
    uint64_t before = rdtsc();
    __asm__ __volatile__("mfence" ::: "memory");
    uint64_t after_mfence = rdtsc();
    __asm__ __volatile__("lfence" ::: "memory");
    uint64_t after_lfence = rdtsc();
    __asm__ __volatile__("sfence" ::: "memory");
    uint64_t after_sfence = rdtsc();
    printf("   MFENCE: %lu cycles\n", after_mfence - before);
    printf("   LFENCE: %lu cycles\n", after_lfence - after_mfence);
    printf("   SFENCE: %lu cycles\n", after_sfence - after_lfence);
    
    // Test 6: PAUSE instruction (for spinlocks)
    printf("\n[6] PAUSE Instruction:\n");
    before = rdtsc();
    for (int i = 0; i < 10; i++) {
        __asm__ __volatile__("pause");
    }
    uint64_t after = rdtsc();
    printf("   10 PAUSE instructions: %lu cycles\n", after - before);
    
    // Test 7: PREFETCH instructions
    printf("\n[7] PREFETCH Tests:\n");
    char buffer[4096];
    before = rdtsc();
    __asm__ __volatile__("prefetchnta (%0)" :: "r"(buffer) : "memory");
    after = rdtsc();
    printf("   PREFETCHNTA: %lu cycles\n", after - before);
    
    // Test 8: CLFLUSH (cache line flush)
    printf("\n[8] CLFLUSH Test:\n");
    fault_caught = 0;
    if (setjmp(fault_buf) == 0) {
        before = rdtsc();
        __asm__ __volatile__("clflush (%0)" :: "r"(buffer) : "memory");
        after = rdtsc();
        printf("   CLFLUSH: %lu cycles\n", after - before);
    } else {
        printf("   CLFLUSH: FAULT (sig=%d)\n", fault_caught);
    }
    
    // Test 9: Atomic operations timing
    printf("\n[9] Atomic Operations:\n");
    volatile long atomic_val = 0;
    before = rdtsc();
    for (int i = 0; i < 1000; i++) {
        __asm__ __volatile__("lock; incq %0" : "+m"(atomic_val));
    }
    after = rdtsc();
    printf("   1000 LOCK INC: %lu cycles (%.2f/op)\n", after - before, 
           (double)(after - before) / 1000);
    
    // Test 10: XCHG (implicit lock)
    printf("\n[10] XCHG Test:\n");
    long val1 = 42, val2 = 99;
    before = rdtsc();
    __asm__ __volatile__("xchg %0, %1" : "+r"(val1), "+m"(val2));
    after = rdtsc();
    printf("   XCHG: %lu cycles\n", after - before);
    
    // Test 11: Self-modifying code
    printf("\n[11] Self-Modifying Code:\n");
    fault_caught = 0;
    if (setjmp(fault_buf) == 0) {
        // Create executable buffer
        unsigned char code[16] = {
            0xb8, 0x2a, 0x00, 0x00, 0x00,  // mov eax, 42
            0xc3                             // ret
        };
        int (*func)(void) = (void*)code;
        int original = func();
        
        // Modify the immediate value
        code[1] = 0x99;  // Change 42 to 153
        
        // Try to execute modified code
        int modified = func();
        printf("   Original: %d, Modified: %d\n", original, modified);
        if (original == modified) {
            printf("   SUSPICIOUS: Self-modification didn't work (emulated)\n");
        }
    } else {
        printf("   Self-modification: FAULT (sig=%d)\n", fault_caught);
    }
    
    // Test 12: BTR/BTS/BTC (bit manipulation)
    printf("\n[12] Bit Test Instructions:\n");
    uint64_t bits = 0;
    before = rdtsc();
    __asm__ __volatile__("bts $5, %0" : "+r"(bits));
    __asm__ __volatile__("bts $10, %0" : "+r"(bits));
    __asm__ __volatile__("btr $5, %0" : "+r"(bits));
    after = rdtsc();
    printf("   BTS/BTR operations: %lu cycles, result: 0x%lx\n", after - before, bits);
    
    // Test 13: CPUID timing variation
    printf("\n[13] CPUID Timing Consistency:\n");
    uint64_t cpuid_times[10];
    for (int i = 0; i < 10; i++) {
        before = rdtsc();
        cpuid(0, 0, &eax, &ebx, &ecx, &edx);
        after = rdtsc();
        cpuid_times[i] = after - before;
    }
    printf("   CPUID timings: ");
    for (int i = 0; i < 10; i++) printf("%lu ", cpuid_times[i]);
    printf("\n");
    
    // Check variance
    uint64_t min = cpuid_times[0], max = cpuid_times[0];
    for (int i = 1; i < 10; i++) {
        if (cpuid_times[i] < min) min = cpuid_times[i];
        if (cpuid_times[i] > max) max = cpuid_times[i];
    }
    printf("   Min: %lu, Max: %lu, Range: %lu\n", min, max, max - min);
    if (max - min < 10) {
        printf("   SUSPICIOUS: Too consistent (emulated)\n");
    }
    
    // Test 14: REP prefix behavior
    printf("\n[14] REP Prefix Test:\n");
    char src[1024], dst[1024];
    memset(src, 0xAA, sizeof(src));
    before = rdtsc();
    char *dst_ptr = dst;
    char *src_ptr = src;
    size_t count = 1024;
    __asm__ __volatile__(
        "rep movsb"
        : "+D"(dst_ptr), "+S"(src_ptr), "+c"(count)
        :: "memory"
    );
    after = rdtsc();
    printf("   REP MOVSB (1024 bytes): %lu cycles\n", after - before);
    
    // Test 15: LAHF/SAHF (legacy flag access)
    printf("\n[15] LAHF/SAHF Test:\n");
    uint8_t flags_uninitialized, flags_controlled;
    uint32_t tmp;
    
    // First test: uninitialized flags (varies by previous operations)
    __asm__ __volatile__(
        "stc\n"           // Set carry
        "lahf\n"
        "movzbl %%ah, %0\n"
        : "=r"(tmp)
        :: "ah"
    );
    flags_uninitialized = (uint8_t)tmp;
    printf("   Flags after STC (uninitialized): 0x%02x\n", flags_uninitialized);
    
    // Second test: controlled flags (cleared then set CF only)
    __asm__ __volatile__(
        "xor %%eax, %%eax\n"  // Clear all flags (ZF=1, others=0)
        "add $127, %%al\n"    // AL=127, no flags set
        "stc\n"               // Set only CF
        "lahf\n"
        "movzbl %%ah, %0\n"
        : "=r"(tmp)
        :: "eax", "ah"
    );
    flags_controlled = (uint8_t)tmp;
    printf("   Flags after STC (controlled): 0x%02x ", flags_controlled);
    printf("(expected: 0x03)\n");
    
    // Check for suspicious deviation
    if (flags_controlled != 0x03) {
        printf("   SUSPICIOUS: Expected 0x03 (CF + bit1), got 0x%02x\n", flags_controlled);
    }
    
    return 0;
}
