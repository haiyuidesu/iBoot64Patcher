#define _GNU_SOURCE

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

int extra = 0;
int version = 0;
int boot_arg = 0;
uint64_t base = 0;
bool paced = false;

#define bswap32(x) __builtin_bswap32(x)
#define hex_set(vers, hex1, hex2) ((vers > version) ? hex1 : hex2)
#define pac_set(vers, hex1, hex2) (((version == vers) && paced) ? hex1 : hex2)

/*************** patchfinder64 ***************/

uint64_t bof64(uint8_t *buf, uint64_t start, uint64_t where)
{
    for (; where >= start; where -= 0x4) {
        uint32_t op = *(uint32_t *)(buf + where);

        if ((op & 0xffc003ff) == 0x910003fd) {
            unsigned delta = (op >> 10) & 0xFFF;
    
            if ((delta & 0xf) == 0) {
                uint64_t prev = where - ((delta >> 0x4) + 1) * 0x4;

                uint32_t au = *(uint32_t *)(buf + prev);

                if ((au & 0xffc003e0) == 0xa98003e0) return prev;

                while (where > start) {
                    where -= 0x4;

                    au = *(uint32_t *)(buf + where);

                    if (((au & 0xffc003ff) == 0xd10003ff) && (((au >> 0xA) & 0xfff) == delta + 0x10)) return where;

                    if ((au & 0xffc003e0) != 0xa90003e0) {
                        where += 0x4;
                        break;
                    }
                }
            }
        }
    }

    return 0;
}

uint64_t xref64(const uint8_t *ibot, uint64_t start, uint64_t end, uint64_t what)
{
    uint64_t i;
    uint64_t value[32];

    memset(value, 0x0, sizeof(value));

    end &= ~0x3;

    for (i = start & ~0x3; i < end; i += 0x4) {
        uint32_t op = *(uint32_t *)(ibot + i);
        unsigned reg = op & 0x1f;

        if ((op & 0x9f000000) == 0x90000000) {
            signed adr = ((op & 0x60000000) >> 0x12) | ((op & 0xffffe0) << 8);

            value[reg] = ((long long)adr << 1) + (i & ~0xfff);
        } else if ((op & 0xff000000) == 0x91000000) {
            unsigned rn = (op >> 0x5) & 0x1f;

            if (rn == 0x1f) {
                value[reg] = 0;
                continue;
            }

            unsigned shift = (op >> 0x16) & 0x3;
            unsigned imm = (op >> 0xA) & 0xfff;

            if (shift == 1) {
                imm <<= 0xC;
            } else {
                if (shift > 1) continue;
            }

            value[reg] = value[rn] + imm;
        } else if ((op & 0xf9C00000) == 0xf9400000) {
            unsigned rn = (op >> 0x5) & 0x1f;
            unsigned imm = ((op >> 0xA) & 0xfff) << 0x3;

            if (!imm) continue;

            value[reg] = value[rn] + imm;
        } else if ((op & 0x9f000000) == 0x10000000) {
            signed adr = ((op & 0x60000000) >> 0x12) | ((op & 0xffffe0) << 8);

            value[reg] = ((long long)adr >> 0xB) + i;
        } else if ((op & 0xff000000) == 0x58000000) {
            unsigned adr = (op & 0xffffe0) >> 3;

            value[reg] = adr + i;
        } else if ((op & 0xfc000000) == 0x94000000) {
            signed imm = (op & 0x3ffffff) << 2;

            if (op & 0x2000000) imm |= 0xf << 0x1c;

            unsigned adr = (unsigned)(i + imm);

            if (adr == what) return i;
        }

        if (value[reg] == what && reg != 0x1f) return i;
    }

    return 0;
}

/*************** eydis ***************/

uint64_t insn_is_bl(void *ibot, uint64_t xref, int bl_to_count, int add)
{
    for (int i = 0; i < bl_to_count; i++) {
        xref += add;

        for (; (*(uint32_t *)(ibot + xref) >> 0x1a) != 0x25; xref += add);
    }

    return xref;
}

uint64_t find_any_insn(void *ibot, uint64_t xref, int x, int add, uint32_t mask, uint32_t value)
{
    for (int i = 0; i < x; i++) {
        xref += add;

        for (; (*(uint32_t *)(ibot + xref) & mask) != value; xref += add);
    }

    return xref;
}

/*************** iBoot64Finder ***************/

#define insn_set(x, v1, v2, v3, v4, v5) \
    if (version == 1940)       x = v1;  \
    else if (version == 2261)  x = v2;  \
    else if (version == 2817)  x = v3;  \
    else if (version == 3406)  x = v4;  \
    else                       x = v5;

void *memdata(void *ibot, uint64_t data, int data_size, void *last_ptr, size_t length)
{
    int loc = length - (ibot - last_ptr);

    void *ptr = (void *)memmem(last_ptr + 0x4, loc - 0x4, (const char *)&data, data_size);

    if (ptr) return ptr;

    return NULL;
}

bool detect_pac(void *ibot, size_t length)
{
    void *pac_search = memdata(ibot, bswap32(0x7f2303d5), 0x4, ibot, length);

    if (pac_search) return (paced = true);

    return (paced = false);
}

/*************** patchs ***************/

uint64_t rmv_signature_check(void *ibot, size_t length)
{
    uint32_t insn = 0;
    void *search = NULL;
    uint32_t opcode = 0;
    uint32_t ret = (paced ? 0xff0f5fd6 : 0xc0035fd6); // RETAB : RET (TODO: build them)

    printf("\n[%s]: removing signatures checks...\n", __func__);

    /*
     * 1. strb w8, [x20, #7] | 2. ldrb w11, [x9, #0x2a]
     * 3. movk w1, #0x4950   | 4. csinv w0, w20, wzr, ne
     * 5. movk w0, #0x4353, lsl #16
     */

    insn_set(insn, 0x881e0039, 0x2ba94039, 0x012a8972, 0x80129f5a, 0x606aa872);

    if ((search = memdata(ibot, bswap32(insn), 0x4, ibot, length)) == NULL) return -1;

    insn = (uint64_t)((uintptr_t)search - (uintptr_t)ibot); // setting up the actual address

    insn = bof64(ibot, 0x0, find_any_insn(ibot, insn, 1, 0x4, 0xfe1f0000, 0xd61f0000));

    printf("[%s]: found '_image4_validate_property_cb_interposer' beginning!\n", __func__);

    opcode = (0x6 << 29) | (0x25 << 23) | 0x0; // movz x0, #0

    *(uint32_t *)(ibot + insn) = bswap32(opcode);

    printf("[%s]: patched to MOVZ x0, #0 insn = 0x%llx\n", __func__, insn + base);

    *(uint32_t *)(ibot + insn + 0x4) = bswap32(ret);

    printf("[%s]: patched to %s insn = 0x%llx\n"
            "[%s]: successfully removed signatures checks!\n",
            __func__, (paced ? "RETAB" : "RET"), (insn + 0x4) + base,
            __func__);

    return 0;
}

uint64_t enable_kernel_debug(void *ibot, size_t length)
{
    void *bl = NULL;
    uint64_t xref = 0;
    uint32_t opcode = 0;

    printf("\n[%s]: enabling kernel debugging...\n", __func__);

    if ((bl = memmem(ibot, length, "debug-enabled", strlen("debug-enabled"))) == NULL) return -1;

    if ((xref = xref64(ibot, 0x0, length, bl - ibot)) == 0) return -1;

    xref = insn_is_bl(ibot, xref, pac_set(6723, 0x5, 0x2), 0x4);

    printf("[%s]: found the BL to '_security_allow_modes' function\n", __func__);

    opcode = (0x6 << 29) | (0x25 << 23) | (0x0 << 0x5) | 0x2; // movz x0, #1

    *(uint32_t *)(ibot + xref) = bswap32(opcode); // movz x0, #1

    printf("[%s]: patched to MOVZ x0, #1 insn = 0x%llx\n", __func__, xref + base);

    printf("[%s]: successfully enabled kernel debugging!\n", __func__);

    return 0;
}

uint64_t allow_any_imagetype(void *ibot, size_t length)
{
    uint64_t xref = 0;
    void *where = NULL;
    uint32_t search = 0, opcode = 0;
    int rd = hex_set(3406, 0x5, 0x4); // rd for the first patch
    char *str = ((version > 3406) ? "cebilefciladrmmhtreptlhptmbr" : "cebilefctmbrtlhptreprmmh");

    printf("\n[%s]: allowing to load any type of images...\n", __func__);

    if ((where = memmem(ibot, length, str, strlen(str))) == NULL) return -1;

    if ((xref = xref64(ibot, 0x0, length, where - ibot)) == 0) return -1;

    opcode = (0x6 << 29) | (0x25 << 23) | rd; // movz x4, #0 | movz x5, #0

    *(uint32_t *)(ibot + xref) = bswap32(opcode); // patch the 'type' variable

    printf("[%s]: patched to MOVZ x%d, #0 insn = 0x%llx\n", __func__, rd, base + xref);

    search = hex_set(5540, hex_set(3406, 0xe5071f32, 0xe60b0032), 0xe6008052);

    where = memdata(ibot, bswap32(search), 0x4, ibot, length);

    rd = hex_set(3406, 0x6, 0x5); // rd for the second patch

    opcode = (0x2 << 29) | (0x25 << 23) | rd; // movz w5, #0 | movz w6, #0

    *(uint32_t *)(where) = bswap32(opcode); // patch the 'count' variable

    printf("[%s]: patched to MOVZ w%d, #0 insn = 0x%llx\n", __func__, rd, base + (uint64_t)((uintptr_t)where - (uintptr_t)ibot));

    printf("[%s]: successfully allowed to load any image types!\n", __func__);

    return 0;
}

// this patch will prevent kaslr to have a random slide.
// (it seems that few devices other than the iPhone5S are supporting it)
uint64_t prevent_kaslr_slide(void *ibot, size_t length)
{
    uint32_t where = 0;
    uint32_t opcode = 0;
    void *current = NULL;
    unsigned _rd = 0, rd = 0;

    if ((version < 3406) || (version > 4513)) return 0;  // only for iOS 10 to iOS 12 for the moment

    printf("\n[%s]: patching the kaslr slide...\n", __func__);

    if ((current = memmem(ibot, length, "__PAGEZERO", sizeof("__PAGEZERO"))) == NULL) return -1;

    where = xref64(ibot, 0x0, length, current - ibot);

    printf("[%s]: found the 'load_kernelcache()' function!\n", __func__);

    if (version == 4513) {
        where = find_any_insn(ibot, where, 2, -0x4, 0x3a000000, 0x28000000) + 0x14; // moving to the 'mov' insn
    } else {
        where = insn_is_bl(ibot, where, 0x3, -0x4);
    }

    for (int i = 0x4; i != (version == 4513 ? 0x40 : 0x24); i += 0x4) {
        if (i == 0x8) {
            _rd = *(uint32_t *)(ibot + where + i) & 0x1f;

            // you can comment out these three lines to get a slide equal to 0x1000000
            opcode = ((0x6 << 29) | (0x25 << 23) | (0x0 << 5) | _rd); // the register for the patched insn should be x21

            *(uint32_t *)(ibot + where + i) = opcode;

            printf("[%s]: patched 'slide_phys' to MOV x%u, #0 = 0x%llx\n", __func__, _rd, base + where + i);
        } else if (i == (version == 4513 ? 0x28 : 0x18)) {
            rd = *(uint32_t *)(ibot + where + i) & 0x1f;

            opcode = ((0x5 << 29) | (0x50 << 21) | ((_rd & 0x1f) << 16) | ((-1 & 0x1f) << 5) | rd); // kaslr_slide = 0x0

            *(uint32_t *)(ibot + where + i) = opcode;

            printf("[%s]: patched 'slide_virt' to MOV x%u, x%u = 0x%llx\n", __func__, rd, _rd, base + where + i);
        } else {
            *(uint32_t *)(ibot + where + i) = bswap32(0x1f2003d5);
        }
    }

    printf("[%s]: NOPed all other instructions.\n"
            "[%s]: successfully patched the kaslr slide!\n"
            , __func__, __func__);

    return 0;
}

/*
 * this one is clearly copied from kairos since i was sick of using it every time i needed to change the boot-args,
 * i am not sure about the bootloaders older than iOS 10 but whatever...
 * this has to be the worst visually written code in this project.
 */
uint64_t set_custom_bootargs(void *ibot, size_t length, char *bootargs)
{
    char *str = NULL;
    unsigned _rd = 0;
    uint64_t what = 0;
    uint64_t where = 0;
    uint32_t opcode = 0;
    void *current = NULL;
    char zeros[270] = {0};

    printf("\n[%s]: setting \"%s\" boot-args...\n", __func__, bootargs);

    if (version == 1940) str = "is-tethered";

    if (version >= 2261) str = "rd=md0 nand-enable-reformat=1 -progress";

    if (version >= 6723) str = "rd=md0";

    if ((current = memmem(ibot, length, str, strlen(str))) == NULL) {
        current = memmem(ibot, length, "rd=md0 -progress -restore", strlen("rd=md0 -progress -restore"));

        if (current == NULL) return -1; // it was the last chance
    }

    where = xref64(ibot, 0x0, length, current - ibot);

    if (version < 2261) {
        where = find_any_insn(ibot, where, 3, -0x4, 0x1f000000, 0x10000000); // find adrp or adr insn
    }

    printf("[%s]: found boot-args string = 0x%llx\n", __func__, base + where);

    void *new_bootarg_addr = memmem(ibot, length, zeros, 270);

    if (new_bootarg_addr == NULL) return -1;

    new_bootarg_addr += 0x10;

    memset(new_bootarg_addr, 0x0, 270);

    unsigned rd = *(uint32_t *)(ibot + where) & 0x1f;

    uint64_t diff = ((uint64_t)new_bootarg_addr - (uint64_t)ibot) - where;

    opcode = (diff % (1 << 2) << 29 | 0x10 << 24 | ((diff >> 2) % (1 << (20 - 2 + 1))) << 5 | rd % (1 << 5));

    *(uint32_t *)(ibot + where) = opcode; // adr <rd>, #imm

    strcpy(new_bootarg_addr, bootargs);

    printf("[%s]: patched the ADR instruction = 0x%llx\n", __func__, base + where);

    if (version < 6723) {
        what = find_any_insn(ibot, where, 1, 0x4, 0x1fe00000, 0x1a800000); // find csel insn

        _rd = *(uint32_t *)(ibot + what) & 0x1f;

        opcode = ((0x5 << 29) | (0x50 << 21) | ((rd & 0x1f) << 16) | ((-1 & 0x1f) << 5) | _rd);

        *(uint32_t *)(ibot + what) = opcode; // mov <rd>, <rd_from_previous_insn>

        printf("[%s]: moved from CSEL instruction (0x%llx) to MOV x%u, x%u\n", __func__, base + what, _rd, rd);
    }

    if (version >= 3406) {
        what = find_any_insn(ibot, where, 1, -0x4, 0x7e000000, 0x34000000); // find cbz insn

        printf("[%s]: found the CBZ instruction = 0x%llx\n", __func__, base + what);

        int64_t offset = ((int64_t)((*(uint32_t *)(ibot + what) >> 5) & 0x7ffff) << 45) >> 43;

        diff = ((uint64_t)new_bootarg_addr - (uint64_t)ibot) - (what + offset); // pointed address

        _rd = *(uint32_t *)(ibot + what + offset) & 0x1f;

        opcode = (((diff >> 2) % (1 << (20 - 2 + 1))) << 5 | ((diff >> 0) % (1 << (1 - 0 + 1))) << 29 | 0x10 << 24 | _rd % (1 << 5));

        *(uint32_t *)(ibot + what + offset) = opcode; // adr <rd>, #imm

        printf("[%s]: replaced the ADR instruction pointing address = 0x%llx\n", __func__, base + what + offset);
    }

    printf("[%s]: successfully set new bootargs!\n", __func__);

    return 0;
}

/* main */

uint64_t apply_generic_patches(void *ibot, size_t length, char *bootargs)
{
    if (rmv_signature_check(ibot, length) != 0) {
        printf("[%s]: unable to enable remove signature check.\n", __func__);
        return -1;
    }

    // Looking if the iBoot has a kernel load routine
    if (memmem(ibot, length, "__PAGEZERO", strlen("__PAGEZERO"))) {
        if (enable_kernel_debug(ibot, length) != 0) {
            printf("[%s]: unable to enable kernel debugging.\n", __func__);
            return -1;
        }

        if (boot_arg) {
            if (set_custom_bootargs(ibot, length, bootargs) != 0) {
                printf("[%s]: unable to patch the boot-args.\n", __func__);
                return -1;
            }
        }

        if (extra) {
            if (allow_any_imagetype(ibot, length) != 0) {
                printf("[%s]: unable to allow to load any image types.\n", __func__);
                return -1;
            }

            if (prevent_kaslr_slide(ibot, length) != 0) {
                printf("[%s]: unable to patch the kaslr slide.\n", __func__);
                return -1;
            }
        }
    }

    return 0;
}

void usage(char *owo[]) {
    char *name = strrchr(owo[0], '/');

    printf("usage: %s <in> <out> [-e] [-b <boot-args>]\n", (name ? name + 1 : owo[0]));
    printf("\tdefault\tapply the generics patches,\n");
    printf("\t-e\tapply the extra patches,\n");
    printf("\t-b\tapply custom boot-args.\n");

    exit(1);
}

int main(int argc, char *argv[])
{
    FILE *fd = NULL;
    void *ibot = NULL;
    char *bootargs = NULL;
    int arg_counter = argc - 1;
    size_t length = 0, read = 0;

    if (argc < 3) usage(argv);

    while (arg_counter) {
        if (*argv[arg_counter] == '-') {
            char arg = *(argv[arg_counter] + 1);

            switch (arg) {
            case 'e':
                extra = 1;
                break;
            case 'b':
                boot_arg = 1;
                bootargs = argv[arg_counter + 1];
                break;
            default:
                printf("warning: unrecognized argument: %s\n", argv[arg_counter]);
                usage(argv);
            }
        }

        arg_counter--;
    }


    printf("[%s]: starting...\n", __func__);

    if (!(fd = fopen(argv[1], "rb"))) {
        printf("[%s]: unable to open %s.\n", __func__, argv[1]);
        return -1;
    }

    fseek(fd, 0x0, SEEK_END);

    length = ftell(fd);

    fseek(fd, 0x0, SEEK_SET);

    ibot = (void *)malloc(sizeof(char) * (length + 1));

    if ((read = fread(ibot, 1, length, fd) != length)) {
        printf("[%s]: can't read %s.\n", __func__, argv[1]);
        free(ibot);
        return -1;
    }

    fclose(fd);

    printf("[%s]: detected iBoot-%s!\n", __func__, (char *)(ibot + 0x286));

    version = atoi(ibot + 0x286);

    base = *(uint64_t *)(ibot + hex_set(6603, 0x318, 0x300));

    printf("[%s]: base_addr = 0x%llx\n", __func__, base);

    printf("[%s]: applying generic iBoot patches...\n", __func__);

    detect_pac(ibot, length); // setting up the 'paced' variable

    if (apply_generic_patches(ibot, length, bootargs) != 0) {
        free(ibot);
        return -1;
    }

    if (!(fd = fopen(argv[2], "wb+"))) {
        printf("\n[%s]: unable to open %s!\n", __func__, argv[2]);
        free(ibot);
        return -1;
    }

    printf("\n[%s]: writing %s...\n", __func__, argv[2]);

    fwrite(ibot, length, 1, fd);

    free(ibot);

    fclose(fd);

    printf("[%s]: done!\n", __func__);

    return 0;
}
