/* GNU/Linux/RISC-V specific low level interface, for the remote server
   for GDB.
   Copyright (C) 2020 Free Software Foundation, Inc.

   This file is part of GDB.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.  */

#include "server.h"

#include "linux-low.h"
#include "tdesc.h"
#include "elf/common.h"
#include "nat/riscv-linux-tdesc.h"
#include "opcode/riscv.h"

/* Work around glibc header breakage causing ELF_NFPREG not to be usable.  */
#ifndef NFPREG
# define NFPREG 33
#endif

/* Linux target op definitions for the RISC-V architecture.  */

class riscv_target : public linux_process_target
{
public:

  const regs_info *get_regs_info () override;

  int breakpoint_kind_from_pc (CORE_ADDR *pcptr) override;

  const gdb_byte *sw_breakpoint_from_kind (int kind, int *size) override;

protected:

  void low_arch_setup () override;

  bool low_cannot_fetch_register (int regno) override;

  bool low_cannot_store_register (int regno) override;

  bool low_fetch_register (regcache *regcache, int regno) override;

  bool low_supports_breakpoints () override;

  CORE_ADDR low_get_pc (regcache *regcache) override;

  void low_set_pc (regcache *regcache, CORE_ADDR newpc) override;

  bool low_breakpoint_at (CORE_ADDR pc) override;
};

/* The singleton target ops object.  */

static riscv_target the_riscv_target;

bool
riscv_target::low_cannot_fetch_register (int regno)
{
  gdb_assert_not_reached ("linux target op low_cannot_fetch_register "
			  "is not implemented by the target");
}

bool
riscv_target::low_cannot_store_register (int regno)
{
  gdb_assert_not_reached ("linux target op low_cannot_store_register "
			  "is not implemented by the target");
}

/* Implementation of linux target ops method "low_arch_setup".  */

void
riscv_target::low_arch_setup ()
{
  static const char *expedite_regs[] = { "sp", "pc", NULL };

  const riscv_gdbarch_features features
    = riscv_linux_read_features (lwpid_of (current_thread));
  target_desc *tdesc = riscv_create_target_description (features);

  if (!tdesc->expedite_regs)
    init_target_desc (tdesc, expedite_regs);
  current_process ()->tdesc = tdesc;
}

/* Collect GPRs from REGCACHE into BUF.  */

static void
riscv_fill_gregset (struct regcache *regcache, void *buf)
{
  const struct target_desc *tdesc = regcache->tdesc;
  int regno_null, regno_pc;
  int regsize;
  int i;

  if (tdesc_contains_feature (tdesc, "org.gnu.gdb.riscv.cheri"))
    {
      regno_null = find_regno (tdesc, "cnull");
      regno_pc = find_regno (tdesc, "pcc");

      regsize = register_size (tdesc, regno_pc);

      collect_register (regcache, regno_pc, buf);
      collect_register_by_name (regcache, "ddc", (uint8_t *)buf
				+ (regno_pc - regno_null) * regsize);
      for (i = 1; i < (regno_pc - regno_null); i++)
	collect_register (regcache, regno_null + i, (uint8_t *)buf
			  + i * regsize);
    }
  else
    regsize = register_size (tdesc, find_regno (tdesc, "pc"));

  regno_null = find_regno (tdesc, "zero");
  regno_pc = find_regno (tdesc, "pc");

  collect_register (regcache, regno_pc, buf);
  for (i = 1; i < (regno_pc - regno_null); i++)
    collect_register (regcache, regno_null + i, (uint8_t *)buf + i * regsize);
}

/* Supply GPRs from BUF into REGCACHE.  */

static void
riscv_store_gregset (struct regcache *regcache, const void *buf)
{
  const struct target_desc *tdesc = regcache->tdesc;
  int regno_null, regno_pc;
  int regsize;
  int i;

  if (tdesc_contains_feature (tdesc, "org.gnu.gdb.riscv.cheri"))
    {
      regno_null = find_regno (tdesc, "cnull");
      regno_pc = find_regno (tdesc, "pcc");

      regsize = register_size (tdesc, regno_pc);

      supply_register (regcache, regno_pc, buf);
      supply_register_zeroed (regcache, regno_null);
      supply_register_by_name (regcache, "ddc", (uint8_t*)buf
			       + (regno_pc - regno_null) * regsize);
      for (i = 1; i < (regno_pc - regno_null); i++)
	supply_register (regcache, regno_null + i, (uint8_t *)buf
			 + i * regsize);
    }
  else
    regsize = register_size (tdesc, find_regno (tdesc, "pc"));

  regno_null = find_regno (tdesc, "zero");
  regno_pc = find_regno (tdesc, "pc");

  supply_register (regcache, regno_pc, buf);
  supply_register_zeroed (regcache, regno_null);
  for (i = 1; i < (regno_pc - regno_null); i++)
    supply_register (regcache, regno_null + i, (uint8_t *)buf + i * regsize);
}

/* Collect FPRs from REGCACHE into BUF.  */

static void
riscv_fill_fpregset (struct regcache *regcache, void *buf)
{
  const struct target_desc *tdesc = regcache->tdesc;
  int regno = find_regno (tdesc, "ft0");
  int flen = register_size (regcache->tdesc, regno);
  gdb_byte *regbuf = (gdb_byte *) buf;
  int i;

  for (i = 0; i < ELF_NFPREG - 1; i++, regbuf += flen)
    collect_register (regcache, regno + i, regbuf);
  collect_register_by_name (regcache, "fcsr", regbuf);
}

/* Supply FPRs from BUF into REGCACHE.  */

static void
riscv_store_fpregset (struct regcache *regcache, const void *buf)
{
  const struct target_desc *tdesc = regcache->tdesc;
  int regno = find_regno (tdesc, "ft0");
  int flen = register_size (regcache->tdesc, regno);
  const gdb_byte *regbuf = (const gdb_byte *) buf;
  int i;

  for (i = 0; i < ELF_NFPREG - 1; i++, regbuf += flen)
    supply_register (regcache, regno + i, regbuf);
  supply_register_by_name (regcache, "fcsr", regbuf);
}

/* RISC-V/Linux regsets.  FPRs are optional and come in different sizes,
   so define multiple regsets for them marking them all as OPTIONAL_REGS
   rather than FP_REGS, so that "regsets_fetch_inferior_registers" picks
   the right one according to size.  */
/* Note: storing registers is currently not supported with CHERI, because
   the RISC-V kernel ptrace functions and, partially, GDB are not CHERI-aware.
   They would clear the valid tags of the capabilities.  */

/* Maximum regset size is defined by 33 CHERI registers of 16 byte each  */
#define MAX_REGSET_SIZE (33 * 16)

static struct regset_info riscv_regsets[] = {
  { PTRACE_GETREGSET, PTRACE_SETREGSET, NT_PRSTATUS,
    MAX_REGSET_SIZE, GENERAL_REGS,
    NULL, riscv_store_gregset },
  { PTRACE_GETREGSET, PTRACE_SETREGSET, NT_FPREGSET,
    sizeof (struct __riscv_mc_q_ext_state), OPTIONAL_REGS,
    riscv_fill_fpregset, riscv_store_fpregset },
  { PTRACE_GETREGSET, PTRACE_SETREGSET, NT_FPREGSET,
    sizeof (struct __riscv_mc_d_ext_state), OPTIONAL_REGS,
    riscv_fill_fpregset, riscv_store_fpregset },
  { PTRACE_GETREGSET, PTRACE_SETREGSET, NT_FPREGSET,
    sizeof (struct __riscv_mc_f_ext_state), OPTIONAL_REGS,
    riscv_fill_fpregset, riscv_store_fpregset },
  NULL_REGSET
};

/* RISC-V/Linux regset information.  */
static struct regsets_info riscv_regsets_info =
  {
    riscv_regsets, /* regsets */
    0, /* num_regsets */
    NULL, /* disabled_regsets */
  };

/* Definition of linux_target_ops data member "regs_info".  */
static struct regs_info riscv_regs =
  {
    NULL, /* regset_bitmap */
    NULL, /* usrregs */
    &riscv_regsets_info,
  };

/* Implementation of linux target ops method "get_regs_info".  */

const regs_info *
riscv_target::get_regs_info ()
{
  return &riscv_regs;
}

/* Implementation of linux target ops method "low_fetch_register".  */

bool
riscv_target::low_fetch_register (regcache *regcache, int regno)
{
  const struct target_desc *tdesc = regcache->tdesc;

  if (regno != find_regno (tdesc, "zero")
      && regno != find_regno (tdesc, "cnull"))
    return false;
  supply_register_zeroed (regcache, regno);
  return true;
}

bool
riscv_target::low_supports_breakpoints ()
{
  return true;
}

/* Implementation of linux target ops method "low_get_pc".  */

CORE_ADDR
riscv_target::low_get_pc (regcache *regcache)
{
  const struct target_desc *tdesc = regcache->tdesc;
  int regsize;

  /* CHERI: PCC and PC share the same location inside regset, since the
     capability is not used by GDB PC is used.  */
  regsize = register_size (tdesc, find_regno (tdesc, "pc"));

  if (regsize == 8)
    return linux_get_pc_64bit (regcache);
  else
    return linux_get_pc_32bit (regcache);
}

/* Implementation of linux target ops method "low_set_pc".  */

void
riscv_target::low_set_pc (regcache *regcache, CORE_ADDR newpc)
{
  const struct target_desc *tdesc = regcache->tdesc;
  int regsize;

  /* CHERI: PCC and PC share the same location inside regset, since the
     capability is not used by GDB PC is used.  */
  regsize = register_size (tdesc, find_regno (tdesc, "pc"));

  if (regsize == 8)
    linux_set_pc_64bit (regcache, newpc);
  else
    linux_set_pc_32bit (regcache, newpc);
}

/* Correct in either endianness.  */
static const uint16_t riscv_ibreakpoint[] = { 0x0073, 0x0010 };
static const uint16_t riscv_cbreakpoint = 0x9002;

/* Implementation of target ops method "breakpoint_kind_from_pc".  */

int
riscv_target::breakpoint_kind_from_pc (CORE_ADDR *pcptr)
{
  union
    {
      gdb_byte bytes[2];
      uint16_t insn;
    }
  buf;

  if (target_read_memory (*pcptr, buf.bytes, sizeof (buf.insn)) == 0
      && riscv_insn_length (buf.insn == sizeof (riscv_ibreakpoint)))
    return sizeof (riscv_ibreakpoint);
  else
    return sizeof (riscv_cbreakpoint);
}

/* Implementation of target ops method "sw_breakpoint_from_kind".  */

const gdb_byte *
riscv_target::sw_breakpoint_from_kind (int kind, int *size)
{
  *size = kind;
  switch (kind)
    {
      case sizeof (riscv_ibreakpoint):
	return (const gdb_byte *) &riscv_ibreakpoint;
      default:
	return (const gdb_byte *) &riscv_cbreakpoint;
    }
}

/* Implementation of linux target ops method "low_breakpoint_at".  */

bool
riscv_target::low_breakpoint_at (CORE_ADDR pc)
{
  union
    {
      gdb_byte bytes[2];
      uint16_t insn;
    }
  buf;

  if (target_read_memory (pc, buf.bytes, sizeof (buf.insn)) == 0
      && (buf.insn == riscv_cbreakpoint
	  || (buf.insn == riscv_ibreakpoint[0]
	      && target_read_memory (pc + sizeof (buf.insn), buf.bytes,
				     sizeof (buf.insn)) == 0
	      && buf.insn == riscv_ibreakpoint[1])))
    return true;
  else
    return false;
}

/* The linux target ops object.  */

linux_process_target *the_linux_target = &the_riscv_target;

/* Initialize the RISC-V/Linux target.  */

void
initialize_low_arch ()
{
  initialize_regsets_info (&riscv_regsets_info);
}
