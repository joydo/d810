from ida_hexrays import *


from d810.optimizers.instructions.pattern_matching.handler import PatternMatchingRule
from d810.ast import AstLeaf, AstConstant, AstNode
from d810.hexrays_helpers import equal_bnot_mop, AND_TABLE


# GetIdentRule1: ((x_0 & x_1) + (x_0 & ~x_1)) == x_0
class GetIdentRule1(PatternMatchingRule):
    PATTERN = AstNode(m_add,
                      AstNode(m_and,
                              AstLeaf('x_0'),
                              AstLeaf('x_1')),
                      AstNode(m_and,
                              AstLeaf('x_0'),
                              AstLeaf('bnot_x_1')))
    REPLACEMENT_PATTERN = AstNode(m_mov, AstLeaf("x_0"))

    def check_candidate(self, candidate):
        if not equal_bnot_mop(candidate["x_1"].mop, candidate["bnot_x_1"].mop):
            return False
        return True


# GetIdentRule2: ((x_0 & x_1) ^ (x_0 & ~x_1)) == x_0 i
class GetIdentRule2(PatternMatchingRule):
    PATTERN = AstNode(m_xor,
                      AstNode(m_and,
                              AstLeaf('x_0'),
                              AstLeaf('x_1')),
                      AstNode(m_and,
                              AstLeaf('x_0'),
                              AstLeaf('bnot_x_1')))
    REPLACEMENT_PATTERN = AstNode(m_mov, AstLeaf("x_0"))

    def check_candidate(self, candidate):
        if not equal_bnot_mop(candidate["x_1"].mop, candidate["bnot_x_1"].mop):
            return False
        return True


class GetIdentRule3(PatternMatchingRule):
    PATTERN = AstNode(m_and,
                      AstLeaf("x_0"),
                      AstNode(m_or,
                              AstLeaf("x_0"),
                              AstLeaf("x_1")))

    REPLACEMENT_PATTERN = AstNode(m_mov, AstLeaf("x_0"))
