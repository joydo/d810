from ida_hexrays import *

from d810.optimizers.instructions.pattern_matching.handler import PatternMatchingRule
from d810.ast import AstLeaf, AstConstant, AstNode
from d810.hexrays_formatters import  format_mop_t

class ReplaceMovHigh(PatternMatchingRule):
    PATTERN = AstNode(m_mov,
                      AstConstant('c_0'))
    REPLACEMENT_PATTERN = AstNode(m_or, AstConstant("new_c_0"), AstNode(m_and, AstLeaf("new_reg"), AstConstant("mask")))

    def check_candidate(self, candidate):
        # IDA does not do constant propagation for pattern such as:
        # mov     #0x65A4.2, r6.2
        # mov     #0x210F.2, r6^2.2
        # jz      r0.4, r6.4
        # Thus, we try to detect mov to r6^2 and replace by (or #0x210F0000.4, r6.4 & 0x0000ffff.4, r6.4
        # By doing that, IDA constant propagation will work again.

        if candidate.dst_mop.t != mop_r:
            return False
        dst_reg_name = format_mop_t(candidate.dst_mop)
        if dst_reg_name is None:
            return False
        if "^2" in dst_reg_name:
            if candidate["c_0"].mop.size != 2:
                return False
            candidate.add_constant_leaf("new_c_0", candidate["c_0"].value << 16, 4)
            candidate.add_constant_leaf("mask", 0xffff, 4)
            new_dst_reg = mop_t()
            new_dst_reg.make_reg(candidate.dst_mop.r - 2, 4)
            candidate.add_leaf("new_reg", new_dst_reg)
            candidate.dst_mop = new_dst_reg
            return True
        else:
            return False
