import os
import logging
from typing import List

from d810.hexrays_helpers import OPCODES_INFO, MATURITY_TO_STRING_DICT, STRING_TO_MATURITY_DICT, MOP_TYPE_TO_STRING_DICT
from ida_hexrays import minsn_t, mop_t, vd_printer_t, mbl_array_t


logger = logging.getLogger('D810.helper')


def format_minsn_t(ins: minsn_t) -> str:
    if ins is None:
        return "minsn_t is None"

    tmp = ins._print()
    pp_ins = "".join([c if 0x20 <= ord(c) <= 0x7e else "" for c in tmp])
    return pp_ins


def format_mop_t(mop_in: mop_t) -> str:
    if mop_in is None:
        return "mop_t is None"
    if mop_in.t > 15:
        # To avoid error 50581
        return "Unknown mop type {0}".format(mop_in.t)
    return mop_in.dstr()


def format_mop_list(mop_list: List[mop_t]) -> str:
    return ", ".join([format_mop_t(x) for x in mop_list])


def maturity_to_string(maturity_level: int) -> str:
    return MATURITY_TO_STRING_DICT.get(maturity_level, "Unknown maturity: {0}".format(maturity_level))


def string_to_maturity(maturity_string: str) -> int:
    return STRING_TO_MATURITY_DICT.get(maturity_string)


def mop_type_to_string(mop_type: int) -> str:
    return MOP_TYPE_TO_STRING_DICT.get(mop_type, "Unknown mop type: {0}".format(mop_type))


def opcode_to_string(opcode) -> str:
    try:
        return OPCODES_INFO[opcode]["name"]
    except KeyError:
        return "Unknown opcode: {0}".format(opcode)


class mba_printer(vd_printer_t):
    def __init__(self):
        vd_printer_t.__init__(self)
        self.mc = []

    def get_mc(self):
        return self.mc

    def _print(self, indent, line):
        self.mc.append("".join([c if 0x20 <= ord(c) <= 0x7e else "" for c in line])+"\n")
        return 1


class block_printer(vd_printer_t):
    def __init__(self):
        vd_printer_t.__init__(self)
        self.block_ins = []

    def get_block_mc(self):
        return "\n".join(self.block_ins)

    def _print(self, indent, line):
        self.block_ins.append("".join([c if 0x20 <= ord(c) <= 0x7e else "" for c in line]))
        return 1


def write_mc_to_file(mba: mbl_array_t, filename: str, mba_flags: int = 0) -> bool:
    if not mba:
        return False

    vp = mba_printer()
    mba.set_mba_flags(mba_flags)
    mba._print(vp)

    with open(filename, "w") as f:
        f.writelines(vp.get_mc())
    return True


def dump_microcode_for_debug(mba: mbl_array_t, log_dir_path: str, name: str = ""):
    mc_filename = os.path.join(log_dir_path, "{0:x}_maturity_{1}_{2}.log".format(mba.entry_ea, mba.maturity, name))
    logger.info("Dumping microcode in file {0}...".format(mc_filename))
    write_mc_to_file(mba, mc_filename)
