from ida_hexrays import *

from d810.optimizers.instructions.pattern_matching.handler import PatternMatchingRule
from d810.ast import AstLeaf, AstConstant, AstNode
from d810.hexrays_helpers import equal_bnot_mop, is_check_mop, SUB_TABLE


class Mul_MbaRule_1(PatternMatchingRule):
    PATTERN = AstNode(m_add,
                      AstNode(m_mul,
                              AstNode(m_or,
                                      AstLeaf('x_0'),
                                      AstLeaf('x_1')),
                              AstNode(m_and,
                                      AstLeaf('x_0'),
                                      AstLeaf('x_1'))),
                      AstNode(m_mul,
                              AstNode(m_and,
                                      AstLeaf('x_0'),
                                      AstLeaf('bnot_x_1')),
                              AstNode(m_and,
                                      AstLeaf('x_1'),
                                      AstLeaf('bnot_x_0'))))
    REPLACEMENT_PATTERN = AstNode(m_mul, AstLeaf("x_0"), AstLeaf("x_1"))

    def check_candidate(self, candidate):
        if not equal_bnot_mop(candidate["x_0"].mop, candidate["bnot_x_0"].mop):
            return False
        if not equal_bnot_mop(candidate["x_1"].mop, candidate["bnot_x_1"].mop):
            return False
        return True


class Mul_MbaRule_2(PatternMatchingRule):
    PATTERN = AstNode(m_add,
                      AstNode(m_mul,
                              AstNode(m_or,
                                      AstLeaf('x_0'),
                                      AstConstant('c_1')),
                              AstLeaf('x_0')),
                      AstNode(m_mul,
                              AstNode(m_and,
                                      AstLeaf('x_0'),
                                      AstConstant('bnot_c_1')),
                              AstNode(m_and,
                                      AstConstant('c_1'),
                                      AstLeaf('bnot_x_0'))))
    REPLACEMENT_PATTERN = AstNode(m_mul, AstLeaf("x_0"), AstConstant('c_1'))

    def check_candidate(self, candidate):
        if not is_check_mop(candidate["x_0"].mop):
            return False
        if candidate["c_1"].value & 0x1 != 1:
            return False
        if not equal_bnot_mop(candidate["c_1"].mop, candidate["bnot_c_1"].mop):
            return False
        if not equal_bnot_mop(candidate["x_0"].mop, candidate["bnot_x_0"].mop):
            return False
        return True


class Mul_MbaRule_3(PatternMatchingRule):
    PATTERN = AstNode(m_add,
                      AstNode(m_mul,
                              AstNode(m_or,
                                      AstLeaf('x_0'),
                                      AstConstant('c_1')),
                              AstNode(m_and,
                                      AstLeaf('x_0'),
                                      AstConstant('c_1'))),
                      AstNode(m_mul,
                              AstLeaf('x_0'),
                              AstNode(m_and,
                                      AstConstant('c_1'),
                                      AstLeaf('bnot_x_0'))))
    REPLACEMENT_PATTERN = AstNode(m_mul, AstLeaf("x_0"), AstConstant('c_1'))

    def check_candidate(self, candidate):
        if not is_check_mop(candidate["x_0"].mop):
            return False
        if candidate["c_1"].value & 0x1 == 1:
            return False
        if not equal_bnot_mop(candidate["x_0"].mop, candidate["bnot_x_0"].mop):
            return False
        return True


class Mul_MbaRule_4(PatternMatchingRule):
    PATTERN = AstNode(m_add,
                      AstNode(m_mul,
                              AstNode(m_or,
                                      AstLeaf("x_0"),
                                      AstLeaf("x_1")),
                              AstNode(m_and,
                                      AstLeaf("x_0"),
                                      AstLeaf("x_1"))),
                      AstNode(m_mul,
                              AstNode(m_bnot,
                                      AstNode(m_or,
                                              AstLeaf("x_0"),
                                              AstLeaf("bnot_x_1"))),
                              AstNode(m_and,
                                      AstLeaf("x_0"),
                                      AstLeaf("bnot_x_1"))))
    REPLACEMENT_PATTERN = AstNode(m_mul, AstLeaf("x_0"), AstLeaf("x_1"))

    def check_candidate(self, candidate):
        if not equal_bnot_mop(candidate["x_1"].mop, candidate["bnot_x_1"].mop):
            return False
        return True


class Mul_FactorRule_1(PatternMatchingRule):
    PATTERN = AstNode(m_add,
                      AstConstant("2", 2),
                      AstNode(m_mul,
                              AstConstant("2", 2),
                              AstNode(m_add,
                                      AstLeaf("x_1"),
                                      AstNode(m_or,
                                              AstLeaf("x_0"),
                                              AstLeaf("bnot_x_1")))))

    REPLACEMENT_PATTERN = AstNode(m_mul,
                                  AstConstant("2", 2),
                                  AstNode(m_and,
                                          AstLeaf("x_0"),
                                          AstLeaf("x_1")))

    def check_candidate(self, candidate):
        if not equal_bnot_mop(candidate["x_1"].mop, candidate["bnot_x_1"].mop):
            return False
        return True


class Mul_FactorRule_2(PatternMatchingRule):
    PATTERN = AstNode(m_sub,
                      AstNode(m_neg,
                              AstNode(m_and,
                                      AstLeaf("x_0"),
                                      AstLeaf("x_1"))),
                      AstNode(m_and,
                              AstLeaf("x_0"),
                              AstLeaf("x_1")))
    REPLACEMENT_PATTERN = AstNode(m_mul,
                                  AstConstant("val_fe"),
                                  AstNode(m_and,
                                          AstLeaf("x_0"),
                                          AstLeaf("x_1")))

    def check_candidate(self, candidate):
        candidate.add_constant_leaf("val_fe", SUB_TABLE[candidate.size] - 2, candidate.size)
        return True