from ida_hexrays import *

from d810.optimizers.instructions.pattern_matching.handler import PatternMatchingRule
from d810.ast import AstLeaf, AstConstant, AstNode
from d810.hexrays_helpers import equal_ignore_msb_cst, equal_bnot_mop, AND_TABLE


class Add_HackersDelightRule_1(PatternMatchingRule):
    PATTERN = AstNode(m_sub,
                      AstLeaf("x_0"),
                      AstNode(m_sub,
                              AstNode(m_bnot,
                                      AstLeaf("x_1")),
                              AstConstant("1", 1)))
    REPLACEMENT_PATTERN = AstNode(m_add, AstLeaf("x_0"), AstLeaf("x_1"))


class Add_HackersDelightRule_2(PatternMatchingRule):
    PATTERN = AstNode(m_add,
                      AstNode(m_xor,
                              AstLeaf("x_0"),
                              AstLeaf("x_1")),
                      AstNode(m_mul,
                              AstConstant("2", 2),
                              AstNode(m_and,
                                      AstLeaf("x_0"),
                                      AstLeaf("x_1"))))
    REPLACEMENT_PATTERN = AstNode(m_add, AstLeaf("x_0"), AstLeaf("x_1"))


class Add_HackersDelightRule_3(PatternMatchingRule):
    PATTERN = AstNode(m_add,
                      AstNode(m_or,
                              AstLeaf("x_0"),
                              AstLeaf("x_1")),
                      AstNode(m_and,
                              AstLeaf("x_0"),
                              AstLeaf("x_1")))
    REPLACEMENT_PATTERN = AstNode(m_add, AstLeaf("x_0"), AstLeaf("x_1"))


class Add_HackersDelightRule_4(PatternMatchingRule):
    PATTERN = AstNode(m_sub,
                      AstNode(m_mul,
                              AstConstant("2", 2),
                              AstNode(m_or,
                                      AstLeaf("x_0"),
                                      AstLeaf("x_1"))),
                      AstNode(m_xor,
                              AstLeaf("x_0"),
                              AstLeaf("x_1")))
    REPLACEMENT_PATTERN = AstNode(m_add, AstLeaf("x_0"), AstLeaf("x_1"))


class Add_HackersDelightRule_5(PatternMatchingRule):
    PATTERN = AstNode(m_sub,
                      AstNode(m_mul,
                              AstConstant("2", 2),
                              AstNode(m_or,
                                      AstNode(m_or,
                                              AstLeaf("x_0"),
                                              AstLeaf("x_1")),
                                      AstLeaf("x_2"))),
                      AstNode(m_xor,
                              AstLeaf("x_0"),
                              AstNode(m_or,
                                      AstLeaf("x_1"),
                                      AstLeaf("x_2"))))
    REPLACEMENT_PATTERN = AstNode(m_add, AstLeaf("x_0"), AstNode(m_or, AstLeaf("x_1"), AstLeaf("x_2")))


class Add_SpecialConstantRule_1(PatternMatchingRule):
    PATTERN = AstNode(m_add,
                      AstNode(m_xor,
                              AstLeaf("x_0"),
                              AstConstant("c_1")),
                      AstNode(m_mul,
                              AstConstant("2", 2),
                              AstNode(m_and,
                                      AstLeaf("x_0"),
                                      AstConstant("c_2"))))
    REPLACEMENT_PATTERN = AstNode(m_add, AstLeaf("x_0"), AstConstant("c_1"))

    def check_candidate(self, candidate):
        return equal_ignore_msb_cst(candidate["c_1"].mop, candidate["c_2"].mop)


class Add_SpecialConstantRule_2(PatternMatchingRule):
    PATTERN = AstNode(m_add,
                      AstNode(m_xor,
                              AstNode(m_and,
                                      AstLeaf("x_0"),
                                      AstConstant("val_ff", 0xff)),
                              AstConstant("c_1")),
                      AstNode(m_mul,
                              AstConstant("2", 2),
                              AstNode(m_and,
                                      AstLeaf("x_0"),
                                      AstConstant("c_2"))))
    REPLACEMENT_PATTERN = AstNode(m_add, AstLeaf("x_0"), AstConstant("c_1"))

    def check_candidate(self, candidate):
        return (candidate["c_1"].value & 0xff) == candidate["c_2"].value


class Add_SpecialConstantRule_3(PatternMatchingRule):
    PATTERN = AstNode(m_add,
                      AstNode(m_xor,
                              AstLeaf("x_0"),
                              AstConstant("c_1")),
                      AstNode(m_mul,
                              AstConstant("2", 2),
                              AstNode(m_or,
                                      AstLeaf("x_0"),
                                      AstConstant("c_2"))))
    REPLACEMENT_PATTERN = AstNode(m_add, AstLeaf("x_0"), AstConstant("val_res"))

    def check_candidate(self, candidate):
        if not equal_bnot_mop(candidate["c_1"].mop, candidate["c_2"].mop):
            return False
        candidate.add_constant_leaf("val_res", candidate["c_2"].value - 1, candidate["x_0"].size)
        return True


class Add_OllvmRule_1(PatternMatchingRule):
    PATTERN = AstNode(m_add,
                      AstNode(m_bnot,
                              AstNode(m_xor,
                                      AstLeaf('x_0'),
                                      AstLeaf('x_1'))),
                      AstNode(m_mul,
                              AstConstant("2", 2),
                              AstNode(m_or,
                                      AstLeaf('x_1'),
                                      AstLeaf('x_0'))))
    REPLACEMENT_PATTERN = AstNode(m_sub,
                                  AstNode(m_add,
                                          AstLeaf('x_0'),
                                          AstLeaf('x_1')),
                                  AstConstant("val_1"))

    def check_candidate(self, candidate):
        candidate.add_constant_leaf("val_1", 1, candidate.size)
        return True


class Add_OllvmRule_2(PatternMatchingRule):
    PATTERN = AstNode(m_sub,
                      AstNode(m_bnot,
                              AstNode(m_xor,
                                      AstLeaf('x_0'),
                                      AstLeaf('x_1'))),
                      AstNode(m_mul,
                              AstConstant("val_fe"),
                              AstNode(m_or,
                                      AstLeaf('x_0'),
                                      AstLeaf('x_1'))))
    REPLACEMENT_PATTERN = AstNode(m_sub,
                                  AstNode(m_add,
                                          AstLeaf('x_0'),
                                          AstLeaf('x_1')),
                                  AstConstant("val_1"))

    def check_candidate(self, candidate):
        if (candidate["val_fe"].value + 2) & AND_TABLE[candidate["val_fe"].size] != 0:
            return False
        candidate.add_constant_leaf("val_1", 1, candidate.size)
        return True


class Add_OllvmRule_3(PatternMatchingRule):
    PATTERN = AstNode(m_add,
                      AstNode(m_xor,
                              AstLeaf('x_0'),
                              AstLeaf('x_1')),
                      AstNode(m_mul,
                              AstConstant("2", 2),
                              AstNode(m_and,
                                      AstLeaf('x_0'),
                                      AstLeaf('x_1'))))
    REPLACEMENT_PATTERN = AstNode(m_add, AstLeaf('x_0'), AstLeaf('x_1'))


class Add_OllvmRule_4(PatternMatchingRule):
    PATTERN = AstNode(m_sub,
                      AstNode(m_xor,
                              AstLeaf('x_0'),
                              AstLeaf('x_1')),
                      AstNode(m_mul,
                              AstConstant("val_fe"),
                              AstNode(m_and,
                                      AstLeaf('x_0'),
                                      AstLeaf('x_1'))))
    REPLACEMENT_PATTERN = AstNode(m_add, AstLeaf('x_0'), AstLeaf('x_1'))


class AddXor_Rule_1(PatternMatchingRule):
    PATTERN = AstNode(m_sub,
                      AstNode(m_sub,
                              AstLeaf("x_0"),
                              AstLeaf("x_1")),
                      AstNode(m_mul,
                              AstConstant("2", 2),
                              AstNode(m_or,
                                      AstLeaf("x_0"),
                                      AstLeaf("bnot_x_1"))))
    REPLACEMENT_PATTERN = AstNode(m_add,
                                  AstNode(m_xor,
                                          AstLeaf("x_0"),
                                          AstLeaf("x_1")),
                                  AstConstant("val_2"))

    def check_candidate(self, candidate):
        if not equal_bnot_mop(candidate["x_1"].mop, candidate["bnot_x_1"].mop):
            return False
        candidate.add_constant_leaf("val_2", 2, candidate["x_0"].size)
        return True


class AddXor_Rule_2(PatternMatchingRule):
    PATTERN = AstNode(m_sub,
                      AstNode(m_sub,
                              AstLeaf("x_0"),
                              AstLeaf("x_1")),
                      AstNode(m_mul,
                              AstConstant("2", 2),
                              AstNode(m_bnot,
                                      AstNode(m_and,
                                              AstLeaf("bnot_x_0"),
                                              AstLeaf("x_1")))))

    REPLACEMENT_PATTERN = AstNode(m_add,
                                  AstNode(m_xor,
                                          AstLeaf("x_0"),
                                          AstLeaf("x_1")),
                                  AstLeaf("val_2"))

    def check_candidate(self, candidate):
        if not equal_bnot_mop(candidate["x_0"].mop, candidate["bnot_x_0"].mop):
            return False
        candidate.add_constant_leaf("val_2", 2, candidate["x_0"].size)
        return True

