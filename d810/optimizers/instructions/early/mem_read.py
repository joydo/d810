from ida_hexrays import *
from idaapi import SEGPERM_READ, SEGPERM_WRITE, xrefblk_t, getseg, segment_t, XREF_DATA, dr_W, is_loaded

from d810.optimizers.instructions.early.handler import EarlyRule
from d810.ast import AstLeaf, AstConstant, AstNode


class SetGlobalVariablesToZero(EarlyRule):
    DESCRIPTION = "This rule can be used to patch memory read"

    PATTERN = AstNode(m_mov, AstLeaf("ro_dword"))
    REPLACEMENT_PATTERN = AstNode(m_mov, AstConstant("val_res"))

    def __init__(self):
        super().__init__()
        self.ro_dword_min_ea = None
        self.ro_dword_max_ea = None

    def configure(self, kwargs):
        super().configure(kwargs)
        self.ro_dword_min_ea = None
        self.ro_dword_max_ea = None
        if "ro_dword_min_ea" in kwargs.keys():
            self.ro_dword_min_ea = int(kwargs["ro_dword_min_ea"], 16)
        if "ro_dword_max_ea" in kwargs.keys():
            self.ro_dword_max_ea = int(kwargs["ro_dword_max_ea"], 16)

    def check_candidate(self, candidate):
        if (self.ro_dword_min_ea is None) or (self.ro_dword_max_ea is None):
            return False
        if candidate["ro_dword"].mop.t != mop_v:
            return False
        mem_read_address = candidate["ro_dword"].mop.g
        if not(self.ro_dword_min_ea <= mem_read_address <= self.ro_dword_max_ea):
            return False

        candidate.add_constant_leaf("val_res", 0, candidate["ro_dword"].mop.size)
        return True


# This rule is from
# https://www.carbonblack.com/blog/defeating-compiler-level-obfuscations-used-in-apt10-malware/
class SetGlobalVariablesToZeroIfDetectedReadOnly(EarlyRule):
    DESCRIPTION = "WARNING: Use it only if you know what you are doing as it may patch data not related to obfuscation"

    PATTERN = AstNode(m_mov, AstLeaf("ro_dword"))
    REPLACEMENT_PATTERN = AstNode(m_mov, AstConstant("val_res"))

    def is_read_only_inited_var(self, address):
        s: segment_t = getseg(address)
        if s is None:
            return False
        if s.perm != (SEGPERM_READ | SEGPERM_WRITE):
            return False
        if is_loaded(address):
            return False
        ref_finder = xrefblk_t()
        is_ok = ref_finder.first_to(address, XREF_DATA)
        while is_ok:
            if ref_finder.type == dr_W:
                return False
            is_ok = ref_finder.next_to()
        return True

    def check_candidate(self, candidate):
        mem_read_address = None
        if candidate["ro_dword"].mop.t == mop_v:
            mem_read_address = candidate["ro_dword"].mop.g
        elif candidate["ro_dword"].mop.t == mop_a:
            if candidate["ro_dword"].mop.a.t == mop_v:
                mem_read_address = candidate["ro_dword"].mop.a.g

        if mem_read_address is None:
            return False

        if not self.is_read_only_inited_var(mem_read_address):
            return False
        candidate.add_constant_leaf("val_res", 0, candidate["ro_dword"].mop.size)
        return True

