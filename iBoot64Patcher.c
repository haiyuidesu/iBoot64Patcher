#define _GNU_SOURCE

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

int extra = 0, patch_boot_arg = 0;

uint64_t base = 0, version = 0, paced = 0;

#define hex_set(vers, hex1, hex2) ((vers > version) ? hex1 : hex2)

#define pac_set(vers, hex1, hex2) (((version == vers) && paced) ? hex1 : hex2)

#define bswap32(x) __builtin_bswap32(x)

/*************** patchfinder64 ***************/

uint64_t xref64(const uint8_t *ibot, uint64_t start, uint64_t end, uint64_t what) {
  uint64_t i;
  uint64_t value[32];

  memset(value, 0, sizeof(value));

  end &= ~0x3;

  for (i = start & ~0x3; i < end; i += 0x4) {
    uint32_t op = *(uint32_t *)(ibot + i);
    unsigned reg = op & 0x1f;

    if ((op & 0x9f000000) == 0x90000000) {
      signed adr = ((op & 0x60000000) >> 0x12) | ((op & 0xffffe0) << 8);

      value[reg] = ((long long) adr << 1) + (i & ~0xfff);
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

uint64_t insn_is_bl(void *ibot, uint64_t xref, int bl_to_count) {
  for (int i = 0; i < bl_to_count; i++) {
    xref += 0x4;

    while ((*(uint32_t *)(ibot + xref) >> 0x1a) != 0x25) xref += 0x4;
  }

  return xref;
}

uint64_t find_any_insn(void *ibot, uint64_t xref, int x, int add, uint64_t mask, uint64_t value) {
  for (int i = 0; i < x; i++) {
    xref += add;

    while ((*(uint32_t *)(ibot + xref) & mask) != value) xref += add;
  }

  return xref;
}

/*************** iBoot64Finder ***************/

#define insn_set(x, v1, v2, v3, v4, v5) \
if      (version == 1940) x = v1; \
else if (version == 2261) x = v2; \
else if (version == 2817) x = v3; \
else if (version == 3406) x = v4; \
else                      x = v5;

void *find_insn_before_ptr(void *ptr, uint32_t search, int size) {
  int ct = 0;

  while (size) {
    uint32_t insn = *(uint32_t *)(ptr - ct);

    if (insn == search) return (ptr - ct + 0x4);

    size -= 0x4;
    ct += 0x4;
  }

  return NULL;
}

void *memdata(void *ibot, uint64_t data, int data_size, void *last_ptr, unsigned int length) {
  int loc = length - (ibot - last_ptr);
 
  void *ptr = (void *)memmem(last_ptr + 0x4, loc - 0x4, (const char *)&data, data_size);
  
  if (ptr) return ptr;
 
  return NULL;
}

bool detect_pac(void *ibot, unsigned int length) {
  void *pac_search = memdata(ibot, bswap32(0x7f2303d5), 0x4, ibot, length);

  if (pac_search) return (paced = true);
  
  return (paced = false);
}
 
uint64_t locate_func(void *ibot, uint32_t insn, uint32_t _insn, unsigned int length) {
  uint64_t loc = 0;

  void *ibot_loop = ibot;
  
  while (ibot_loop > 0) {
    ibot_loop = memdata(ibot, bswap32(insn), 0x4, ibot_loop, length);
    
    if (ibot_loop && find_insn_before_ptr(ibot_loop, bswap32(_insn), 0x400)) {
      loc = (uint64_t)((uintptr_t)ibot_loop - (uintptr_t)ibot);
 
      return loc;
    }
  }
 
  return 0;
}

/*************** patchs ***************/

uint64_t rmv_signature_check(void *ibot, unsigned int length) {
  printf("\n[%s]: removing signatures checks...\n", __func__);

  uint64_t insn = 0, ret = 0;

  ret = detect_pac(ibot, length) ? 0xff0f5fd6 : 0xc0035fd6; // RETAB | RET

  /*
   * strb w8, [x20, #7]   | ldrb w11, [x9, #0x2a]
   * movk w1, #0x4950     | csinv w0, w20, wzr, ne 
   * movk w0, #0x4353, lsl #16
   */

  insn_set(insn, 0x881e0039, 0x2ba94039, 0x012a8972, 0x80129f5a, 0x606aa872);

  insn = locate_func(ibot, ret, insn, length);

  if (insn == 0) return -1;

  printf("[%s]: found '_image4_validate_property_cb_interposer' RET\n", __func__);

  *(uint32_t *)(ibot + insn) = bswap32(0x000080d2); // mov x0, #0

  printf("[%s]: patched to MOV x0, #0 insn = 0x%llx\n", __func__, insn + base);

  *(uint32_t *)(ibot + insn + 0x4) = bswap32(ret);

  printf("[%s]: patched to RET insn = 0x%llx\n", __func__, (insn + 0x4) + base);

  printf("[%s]: successfully removed signatures checks!\n", __func__);

  return 0;
}

uint64_t enable_kernel_debug(void *ibot, unsigned int length) {
  printf("\n[%s]: enabling kernel debugging...\n", __func__);

  void *bl = memmem(ibot, length, "debug-enabled", strlen("debug-enabled"));

  if (bl == NULL) return -1;

  uint64_t xref = xref64(ibot, 0x0, length, bl - ibot);

  if (xref == 0) return -1;

  uint64_t insn = insn_is_bl(ibot, xref, pac_set(6723, 0x5, 0x2));

  if (!insn) return -1;

  printf("[%s]: found the BL to '_security_allow_modes' function\n", __func__);

  *(uint32_t *)(ibot + insn) = bswap32(0x200080d2); // movz x0, #1

  printf("[%s]: patched to MOVZ x0, #1 insn = 0x%llx\n", __func__, insn + base);

  printf("[%s]: successfully enabled kernel debugging!\n", __func__);

  return 0;
}

// This 'patch' is for the 'go' command that allow to load any image type
uint64_t allow_any_imagetype(void *ibot, unsigned int length) {
  char *str = "cebilefciladrmmhtreptlhptmbr";

  printf("\n[%s]: allowing to load any type of images...\n", __func__);

  if (version < 3406) str = "cebilefctmbrtlhptreprmmh";

  void *where = memmem(ibot, length, str, strlen(str));

  if (where == NULL) return -1;

  uint64_t xref = xref64(ibot, 0x0, length, where - ibot);

  if (xref == 0) return -1;

  uint64_t insn = ((version < 3406) ? 0x040080d2 : 0x050080d2); // mov x4, #0 | mov x5, #0

  *(uint32_t *)(ibot + xref) = bswap32(insn);

  printf("[%s]: patched to MOV %s, #0 insn = 0x%llx\n",
    __func__, ((version < 3406) ? "x4" : "x5"), xref + base);

  // is it okay to patch the count?

  insn = hex_set(5540, hex_set(3406, 0xe5071f32, 0xe60b0032), 0xe6008052);

  where = memdata(ibot, bswap32(insn), 0x4, ibot, length);

  insn = (version < 3406) ? 0x05008052 : 0x06008052; // mov w5, #0 | mov w6, #0

  *(uint32_t *)(where) = bswap32(insn);

  printf("[%s]: patched to MOV %s, #0 insn = 0x%llx\n",
    __func__, ((version < 3406) ? "w5" : "w6"), base + (where - ibot));

  printf("[%s]: successfully allowed to load any image types!\n", __func__);

  return 0;
}

// this patch will prevent kaslr to have a random slide (only for iPhone5S - iOS 12 for the moment though)
// other device support will come later, more iPhone5S version will be quickly added too :')
uint64_t disable_kaslr(void *ibot, unsigned int length) {
  uint32_t opcode = 0;
  unsigned _rd = 0;

  if (version != 4513) return 0;

  printf("\n[%s]: patching the kaslr slide...\n", __func__);

  uint64_t where = locate_func(ibot, 0x08fc3f91, 0xa0008012, length);

  if (where == 0) return -1;

  printf("[%s]: found the 'load_kernelcache()' function!\n", __func__);

  where += 0x8;

  unsigned rd = *(uint32_t *)(ibot + where) & 0x1f;

  opcode |= (0x1 << 31 | 0x294 << 21 | 0x0 << 5 | rd % (1 << 5)); // should be x8

  *(uint32_t *)(ibot + where) = opcode;

  printf("[%s]: patched 'slide_virt' to MOV x%u, #0x0 = 0x%llx\n", __func__, rd, base + where);

  for (int i = 0x4; i != 0x3C; i += 0x4) {
    if (i == 0x8) {
      opcode = 0;

      _rd = *(uint32_t *)(ibot + where + i) & 0x1f;

      opcode |= (0x1 << 31 | 0x294 << 21 | 0x0 << 5 | _rd % (1 << 5)); // should be x21

      *(uint32_t *)(ibot + where + i) = opcode;

      printf("[%s]: patched 'slide_phys' to MOV x%u, #0x0 = 0x%llx\n", __func__, _rd, base + where + i);
    } else if (i == 0x1C) {
      _rd = *(uint32_t *)(ibot + where + i) & 0x1f;
    } else if (i == 0x28) {
      opcode = 0;

      rd = *(uint32_t *)(ibot + where + i) & 0x1f;

      // opcode |= (0x1 << 31 | 0x294 << 21 | 0x0 << 5 | rd % (1 << 5)); // kaslr_slide = 0x0

      opcode |= (0x1 << 31 | 0x150 << 21 | (0 & 0x3f) << 10 | (-1 & 0x1f) << 5 | (_rd & 0x1f) << 16 | rd % (1 << 5)); // kaslr_slide = 0x1000000

      *(uint32_t *)(ibot + where + i) = opcode;

      printf("[%s]: patched to MOV x%u, x%u = 0x%llx\n", __func__, rd, _rd, base + where + i);
    } else {
      *(uint32_t *)(ibot + where + i) = bswap32(0x1f2003d5);
    }
  }

  printf("[%s]: NOPed all other instructions.\n", __func__);

  printf("[%s]: successfully patched kaslr slide!\n", __func__);

  return 0;
}

// This one is clearly copied from kairos since I was sick of using it every time I needed to change the boot-args
// I am not sure about the bootloaders older than iOS 10 but whatever...
uint64_t set_custom_bootargs(void *ibot, unsigned int length, char *bootargs) {
  char *str = NULL;
  unsigned _rd = 0;
  uint64_t what = 0;
  uint32_t opcode = 0;
  char zeros[270] = { 0 };

  printf("\n[%s]: setting \"%s\" boot-args...\n", __func__, bootargs);

  if (version == 1940) str = "is-tethered";

  if (version >= 2261) str = "rd=md0 nand-enable-reformat=1 -progress";

  if (version >= 6723) str = "rd=md0";

  void *current = memmem(ibot, length, str, strlen(str));

  if (current == NULL) {
    current = memmem(ibot, length, "rd=md0 -progress -restore", strlen("rd=md0 -progress -restore"));

    if (current == NULL) return -1; // it was the last chance
  }

  uint64_t where = xref64(ibot, 0x0, length, current - ibot);

  if (version < 2261) where = find_any_insn(ibot, where, 3, -0x4, 0x1f000000, 0x10000000); // find adrp or adr insn

  printf("[%s]: found boot-args string = 0x%llx\n", __func__, base + where);

  void *new_bootarg_addr = memmem(ibot, length, zeros, 270);

  if (new_bootarg_addr == NULL) return -1;

  new_bootarg_addr += 0x10;

  memset(new_bootarg_addr, 0x0, 270);

  unsigned rd = *(uint32_t *)(ibot + where) & 0x1f;

  uint64_t diff = ((uint64_t)new_bootarg_addr - (uint64_t)ibot) - where;

  opcode |= (diff % (1 << 2) << 29 | 0x10 << 24 | ((diff >> 2) % (1 << (20 - 2 + 1))) << 5 | rd % (1 << 5));

  *(uint32_t *)(ibot + where) = opcode; // adr <rd>, #imm

  strcpy(new_bootarg_addr, bootargs);

  printf("[%s]: patched the ADR instruction = 0x%llx\n", __func__, base + where);

  if (version < 6723) {
    what = find_any_insn(ibot, where, 1, 0x4, 0x1fe00000, 0x1a800000); // find csel insn

    _rd = *(uint32_t *)(ibot + what) & 0x1f;

    opcode = 0;

    opcode |= (0x1 << 31 | 0x150 << 21 | (0 & 0x3f) << 10 | (-1 & 0x1f) << 5 | (rd & 0x1f) << 16 | _rd % (1 << 5));

    *(uint32_t *)(ibot + what) = opcode; // mov <rd>, <rd_from_previous_insn>

    printf("[%s]: moved from CSEL instruction (0x%llx) to MOV x%u, x%u\n", __func__, base + what, _rd, rd);
  }

  if (version >= 3406) {
    what = find_any_insn(ibot, where, 1, -0x4, 0x7e000000, 0x34000000); // find cbz insn

    printf("[%s]: found the CBZ instruction = 0x%llx\n", __func__, base + what);

    int64_t offset = ((int64_t)((*(uint32_t *)(ibot + what) >> 5) & 0x7ffff) << 45) >> 43;

    diff = ((uint64_t)new_bootarg_addr - (uint64_t)ibot) - (what + offset); // pointed address

    _rd = *(uint32_t *)(ibot + what + offset) & 0x1f;

    opcode  = 0;

    opcode |= (((diff >> 2) % (1 << (20 - 2 + 1))) << 5 | ((diff >> 0) % (1 << (1 - 0 + 1))) << 29 | 0x10 << 24 | _rd % (1 << 5));

    *(uint32_t *)(ibot + what + offset) = opcode; // adr <rd>, #imm

    printf("[%s]: replaced the ADR instruction pointing address = 0x%llx\n", __func__, base + what + offset);
  }

  printf("[%s]: successfully set new bootargs!\n", __func__);

  return 0;
}

/* main */

uint64_t apply_generic_patches(void *ibot, unsigned int length, char *bootargs) {
  // Looking if the iBoot has a kernel load routine
  if (memmem(ibot, length, "__PAGEZERO", strlen("__PAGEZERO"))) {
    if (rmv_signature_check(ibot, length) != 0) {
      printf("[%s]: unable to enable remove signature check.\n", __func__);
      return -1;
    }

    if (enable_kernel_debug(ibot, length) != 0) {
      printf("[%s]: unable to enable kernel debugging.\n", __func__);
      return -1;
    }

    if (patch_boot_arg) {
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

      if (disable_kaslr(ibot, length) != 0) {
        printf("[%s]: unable to patch kaslr slide.\n", __func__);
        return -1;
      }
    }
  } else {
    printf("[%s]: unable to detect any kernel load routine.\n", __func__);
    return -1;
  }

  return 0;
}

void usage(char *owo[]) {
  char *ibot = NULL;
  ibot = strrchr(owo[0], '/');
  printf("usage: %s [-p] <in> <out> [-e] [-b <boot-args>]\n", (ibot ? ibot + 1 : owo[0]));
  printf("\t-p\tapply the generics patches,\n");
  printf("\t-e\tapply the extra patches,\n");
  printf("\t-b\tapply custom boot-args.\n");
  exit(1);
}

int main(int argc, char *argv[]) {  
  FILE *fd = NULL;
  void *ibot = NULL;
  char *bootargs = NULL;
  unsigned int length = 0, patch = 0;

  if (argc < 4) usage(argv);

  int arg_counter = argc - 1;

  while (arg_counter) {
    if (*argv[arg_counter] == '-') {

      char arg = *(argv[arg_counter] + 1);

      switch (arg) {
        case 'p':
          patch = 1;
          break;

        case 'e':
          extra = 1;
          break;

        case 'b':
          patch_boot_arg = 1;
          bootargs = argv[arg_counter + 1];
          break;

        default:
          printf("warning: unrecognized argument: %s\n", argv[arg_counter]);
          usage(argv);
      }
    }

    arg_counter--;
  }

  if (patch) {
    printf("[%s]: starting...\n", __func__);

    fd = fopen(argv[2], "rb");

    if (!fd) {
      printf("[%s]: can't open %s.\n", __func__, argv[2]);
      return -1;
    }

    fseek(fd, 0x0, SEEK_END);

    length = ftell(fd);

    fseek(fd, 0x0, SEEK_SET);

    ibot = (void *)malloc(length);
    
    fread(ibot, 1, length, fd);

    fclose(fd);

    fflush(stdout);

    printf("[%s]: detected iBoot-%s!\n", __func__, (char *)ibot + 0x286);

    version = atoi(ibot + 0x286);

    base = *(uint64_t *)(ibot + hex_set(6603, 0x318, 0x300));

    printf("[%s]: base_addr = 0x%llx\n", __func__, base);

    printf("[%s]: applying generic iBoot patches...\n", __func__);

    if (apply_generic_patches(ibot, length, bootargs) != 0) return -1;

    fd = fopen(argv[3], "wb+");

    if (!fd) { 
      printf("\n[%s]: unable to open %s!\n", __func__, argv[3]);

      free(ibot);

      return -1;
    }

    printf("\n[%s]: writing %s...\n", __func__, argv[3]);

    fwrite(ibot, length, 1, fd);

    free(ibot);

    fclose(fd);

    printf("[%s]: done!\n", __func__);
  }

  return 0;
}