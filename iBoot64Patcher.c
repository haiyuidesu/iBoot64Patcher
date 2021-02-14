#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

uint64_t base = 0, version = 0, paced = 0, extra = 0;

#define bswap32(x) __builtin_bswap32(x)

#define hex_set(vers, hex1, hex2) ((vers > version) ? hex1 : hex2)
#define pac_set(vers, hex1, hex2) (((version == vers) && paced) ? hex1 : hex2)

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

uint64_t find_bl_insn(void *ibot, uint64_t xref, int bl) {
  for (int i = 0; i < bl; i++) {
    xref += 4;

    while ((*(uint32_t *)(ibot + xref) >> 0x1a) != 0x25) xref += 0x4;
  }

  return xref;
}

/* iBoot64Finder */
#define insn_set(x, v1, v2, v3, v4, v5, v6) \
if      (version == 1940) x = v1; \
else if (version == 2261) x = v2; \
else if (version == 2817) x = v3; \
else if (version == 3406) x = v4; \
else if (version >= 5540) x = v5; \
else                      x = v6;

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
    
    if (ibot_loop && find_insn_before_ptr(ibot_loop, bswap32(_insn), 0x200)) {
      loc = (uint64_t)((uintptr_t)ibot_loop - (uintptr_t)ibot);
 
      return loc;
    }
  }
 
  return 0;
}

uint64_t rmv_signature_check(void *ibot, unsigned int length) {
  printf("\n[%s]: removing signatures checks...\n", __func__);

  uint64_t insn = 0, ret = 0;

  ret = detect_pac(ibot, length) ? 0xff0f5fd6 : 0xc0035fd6; // RETAB | RET

  /*
   * strb w8, [x20, #7]   | ldrb w11, [x9, #0x2a]
   * movk w1, #0x4950     | csinv w0, w20, wzr, ne 
   * csel w0, w9, w10, eq | mov w0, #0x4348
   */

  insn_set(insn, 0x881e0039, 0x2ba94039, 0x012a8972, 0x80129f5a, 0x20018a1a, 0x00698852);

  insn = locate_func(ibot, ret, insn, length);

  if (insn == 0) return -1;

  printf("[%s]: _image4_validate_property_cb_interposer RET = 0x%llx\n", __func__, insn + base);

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

  uint64_t insn = find_bl_insn(ibot, xref, pac_set(6723, 0x5, hex_set(6723, 0x2, 0x1)));

  if (!insn) return -1;

  printf("[%s]: found the BL to '_security_allow_modes' function\n", __func__);

  *(uint32_t *)(ibot + insn) = bswap32(0x200080d2); // movz x0, #1

  printf("[%s]: patched to MOVZ x0, #1 insn = 0x%llx\n", __func__, insn + base);

  printf("[%s]: successfully enabled kernel debugging!\n", __func__);

  return 0;
}

// This 'patch' is for the 'go' command, nothing amazing at all
uint64_t allow_any_imagetype(void *ibot, unsigned int length) {
  printf("\n[%s]: allowing any type of images ('go' command)...\n", __func__);

  uint64_t insn = 0, addr = 0;

  void *bl = memmem(ibot, length, "Memory image not valid", strlen("Memory image not valid"));

  if (bl == NULL) return -1;

  uint64_t xref = xref64(ibot, 0x0, length, bl - ibot);

  if (xref == 0) return -1;

  insn_set(addr, 0x20, 0x2C, 0x2C, 0x30, hex_set(6723, 0x30, 0x34), 0x30);

  insn = ((version < 3406) ? 0x040080d2 : 0x050080d2); // mov x4, #0 | mov x5, #0

  *(uint32_t *)(ibot + xref - addr) = bswap32(insn);

  // iOS 7 use a second time the x4 register so let's clear this !
  if (version == 1940) *(uint32_t *)(ibot + xref - addr + 0x4) = bswap32(insn); 

  printf("[%s]: patched to MOV %s, #0 insn = 0x%llx\n",
    __func__, ((version < 3406) ? "x4" : "x5"), (xref + base) - addr);

  insn_set(addr, 0x14, 0x10, 0x24, 0x28, 0xC, 0x28);

  insn = ((version < 3406) ? 0x05008052 : 0x050080d2); // mov w5, #0 | mov w6, #0

  *(uint32_t *)(ibot + xref - addr) = bswap32(insn);

  printf("[%s]: patched to MOV %s, #0 insn = 0x%llx\n",
    __func__, ((version < 3406) ? "w5" : "w6"), (xref + base) - addr);

  printf("[%s]: successfully allowed any image types ('go' command)!\n", __func__);

  return 0;
}

uint64_t apply_generic_patches(void *ibot, unsigned int length) {
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
  } else {
    printf("[%s]: unable to detect any kernel load routine.\n", __func__);
    return -1;
  }

  if (extra) {
    if (allow_any_imagetype(ibot, length) != 0) {
      printf("[%s]: unable to allow any types of images ('go' command).\n", __func__);
      return -1;
    }
  }

  return 0;
}

void usage(char *owo[]) {
  char *ibot = NULL;
  ibot = strrchr(owo[0], '/');
  printf("usage: %s [-p] <in> <out> [-e]\n", (ibot ? ibot + 1 : owo[0]));
  printf("\t-p, --patch\tapply the generics patches.\n");
  printf("\t-e, --extra\tapply extra patches (test only).\n");
  exit(1);
}

int main(int argc, char *argv[]) {  
  FILE *fd = NULL;
  void *ibot = NULL;
  unsigned int length = 0, patch = 0;

  if (argc < 4) goto usagend;

  for (int i = 1; i < argc; i++) {
    if (!strcmp(argv[i], "-p") || !strcmp(argv[i], "--patch")) {
      patch = 1;

      if (argv[i+3] != NULL) {
        if (!strcmp(argv[i+3], "-e") || !strcmp(argv[i+3], "--extra")) {
          extra = 1;

          break;
        } else {
         printf("warning: unrecognized argument: %s\n", argv[i+3]);
          goto usagend;
        }
      }

      break;
    } else {
      printf("warning: unrecognized argument: %s\n", argv[i]);
      goto usagend;
    }
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

    printf("[%s]: detected iBoot-%s!\n", __func__, ibot + 0x286);

    version = atoi(ibot + 0x286);

    base = *(uint64_t *)(ibot + hex_set(6603, 0x318, 0x300));

    printf("[%s]: base_addr = 0x%llx\n", __func__, base);

    printf("[%s]: applying generic iBoot patches...\n", __func__);

    if (apply_generic_patches(ibot, length) != 0) return -1;

    fd = fopen(argv[3], "wb+");

    if (!fd) { 
      printf("\n[%s]: unable to open %s!\n", __func__, argv[3]);
      goto end; 
    }

    printf("\n[%s]: writing %s...\n", __func__, argv[3]);

    fwrite(ibot, length, 1, fd);

    free(ibot);

    fclose(fd);

    printf("[%s]: done!\n", __func__);
  }

  return 0;

  usagend:
  usage(argv);

  end:
  free(ibot);
  return -1;
}