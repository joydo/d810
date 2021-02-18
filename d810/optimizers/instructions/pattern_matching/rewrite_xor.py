from ida_hexrays import *

from d810.optimizers.instructions.pattern_matching.handler import PatternMatchingRule
from d810.ast import AstLeaf, AstConstant, AstNode
from d810.hexrays_helpers import equal_bnot_mop, equal_bnot_cst, SUB_TABLE


class Xor_HackersDelightRule_1(PatternMatchingRule):
    PATTERN = AstNode(m_sub,
                      AstNode(m_or,
                              AstLeaf("x_0"),
                              AstLeaf("x_1")),
                      AstNode(m_and,
                              AstLeaf("x_0"),
                              AstLeaf("x_1")))
    REPLACEMENT_PATTERN = AstNode(m_xor, AstLeaf("x_0"), AstLeaf("x_1"))


class Xor_HackersDelightRule_2(PatternMatchingRule):
    PATTERN = AstNode(m_sub,
                      AstNode(m_mul,
                              AstConstant("2", 2),
                              AstNode(m_or,
                                      AstLeaf("x_0"),
                                      AstLeaf("x_1"))),
                      AstNode(m_add,
                              AstLeaf("x_0"),
                              AstLeaf("x_1")))

    REPLACEMENT_PATTERN = AstNode(m_xor, AstLeaf("x_0"), AstLeaf("x_1"))


class Xor_HackersDelightRule_3(PatternMatchingRule):
    PATTERN = AstNode(m_sub,
                      AstNode(m_add,
                              AstLeaf("x_0"),
                              AstLeaf("x_1")),
                      AstNode(m_mul,
                              AstConstant("2", 2),
                              AstNode(m_and,
                                      AstLeaf("x_0"),
                                      AstLeaf("x_1"))))

    REPLACEMENT_PATTERN = AstNode(m_xor, AstLeaf("x_0"), AstLeaf("x_1"))


class Xor_HackersDelightRule_4(PatternMatchingRule):
    PATTERN = AstNode(m_sub,
                      AstNode(m_sub,
                              AstNode(m_sub,
                                      AstLeaf('x_0'),
                                      AstLeaf('x_1')),
                              AstNode(m_mul,
                                      AstConstant('2', 2),
                                      AstNode(m_or,
                                              AstLeaf('x_0'),
                                              AstNode(m_bnot, AstLeaf('x_1'))))),
                      AstConstant('2', 2))

    REPLACEMENT_PATTERN = AstNode(m_xor, AstLeaf("x_0"), AstLeaf("x_1"))


class Xor_HackersDelightRule_5(PatternMatchingRule):
    FUZZ_PATTERN = False
    PATTERN = AstNode(m_sub,
                      AstLeaf("x_0"),
                      AstNode(m_sub,
                              AstNode(m_mul,
                                      AstConstant('2', 2),
                                      AstNode(m_and,
                                              AstLeaf("x_0"),
                                              AstLeaf("x_1"))),
                              AstLeaf("x_1")))
    PATTERNS = [
        AstNode(m_sub, AstLeaf("x_0"), AstNode(m_sub, AstNode(m_mul, AstConstant('2', 2), AstNode(m_and, AstLeaf("x_1"), AstLeaf("x_0"))), AstLeaf("x_1")))
    ]

    REPLACEMENT_PATTERN = AstNode(m_xor, AstLeaf("x_0"), AstLeaf("x_1"))


class Xor_MbaRule_1(PatternMatchingRule):
    PATTERN = AstNode(m_sub,
                      AstLeaf('x_0'),
                      AstNode(m_sub,
                              AstNode(m_mul,
                                      AstConstant('2', 2),
                                      AstNode(m_and,
                                              AstLeaf('x_1'),
                                              AstNode(m_bnot,
                                                      AstNode(m_xor,
                                                              AstLeaf('x_0'),
                                                              AstLeaf('x_1'))))),
                              AstLeaf('x_1')))
    REPLACEMENT_PATTERN = AstNode(m_xor, AstLeaf("x_0"), AstLeaf("x_1"))


class Xor_MbaRule_2(PatternMatchingRule):
    PATTERN = AstNode(m_sub,
                      AstLeaf('x_0'),
                      AstNode(m_sub,
                              AstNode(m_mul,
                                      AstConstant('2', 2),
                                      AstNode(m_and,
                                              AstLeaf('x_0'),
                                              AstLeaf('x_1'))),
                              AstLeaf('x_1')))
    REPLACEMENT_PATTERN = AstNode(m_xor, AstLeaf("x_0"), AstLeaf("x_1"))


class Xor_MbaRule_3(PatternMatchingRule):
    PATTERN = AstNode(m_sub,
                      AstLeaf('x_0'),
                      AstNode(m_mul,
                              AstConstant('2', 2),
                              AstNode(m_and,
                                      AstLeaf('x_0'),
                                      AstLeaf('x_1'))))
    REPLACEMENT_PATTERN = AstNode(m_sub,
                                  AstNode(m_xor,
                                          AstLeaf("x_0"),
                                          AstLeaf("x_1")),
                                  AstLeaf("x_1"))


class Xor_FactorRule_1(PatternMatchingRule):
    PATTERN = AstNode(m_or,
                      AstNode(m_and,
                              AstLeaf("x_0"),
                              AstLeaf("bnot_x_1")),
                      AstNode(m_and,
                              AstLeaf("bnot_x_0"),
                              AstLeaf("x_1")))
    REPLACEMENT_PATTERN = AstNode(m_xor, AstLeaf("x_0"), AstLeaf("x_1"))

    def check_candidate(self, candidate):
        if not equal_bnot_mop(candidate["x_0"].mop, candidate["bnot_x_0"].mop):
            return False
        if not equal_bnot_mop(candidate["x_1"].mop, candidate["bnot_x_1"].mop):
            return False
        return True


class Xor_FactorRule_2(PatternMatchingRule):
    PATTERN = AstNode(m_xor,
                      AstNode(m_and,
                              AstLeaf('bnot_x_0'),
                              AstLeaf('x_1')),
                      AstNode(m_and,
                              AstLeaf('x_0'),
                              AstLeaf('bnot_x_1')))
    REPLACEMENT_PATTERN = AstNode(m_xor, AstLeaf("x_0"), AstLeaf("x_1"))

    def check_candidate(self, candidate):
        if not equal_bnot_mop(candidate["x_0"].mop, candidate["bnot_x_0"].mop):
            return False
        if not equal_bnot_mop(candidate["x_1"].mop, candidate["bnot_x_1"].mop):
            return False
        return True


class Xor_FactorRule_3(PatternMatchingRule):
    PATTERN = AstNode(m_xor,
                      AstNode(m_and,
                              AstLeaf('x_0'),
                              AstLeaf('x_1')),
                      AstNode(m_or,
                              AstLeaf('x_0'),
                              AstLeaf('x_1')))
    REPLACEMENT_PATTERN = AstNode(m_xor, AstLeaf("x_0"), AstLeaf("x_1"))


class Xor_SpecialConstantRule_1(PatternMatchingRule):
    PATTERN = AstNode(m_add,
                      AstNode(m_sub,
                              AstLeaf("x_0"),
                              AstLeaf("x_1")),
                      AstNode(m_mul,
                              AstConstant("2", 2),
                              AstNode(m_and,
                                      AstNode(m_bnot,
                                              AstLeaf("x_0")),
                                      AstLeaf("x_1"))))
    REPLACEMENT_PATTERN = AstNode(m_xor, AstLeaf("x_0"), AstLeaf("x_1"))


class Xor_SpecialConstantRule_2(PatternMatchingRule):
    PATTERN = AstNode(m_add,
                      AstLeaf('x_0'),
                      AstNode(m_add,
                              AstNode(m_mul,
                                      AstConstant('0xfe'),
                                      AstNode(m_and,
                                              AstLeaf('x_0'),
                                              AstLeaf('x_1'))),
                              AstLeaf('x_1')))
    REPLACEMENT_PATTERN = AstNode(m_xor, AstLeaf("x_0"), AstLeaf("x_1"))

    def check_candidate(self, candidate):
        return candidate["0xfe"].value == SUB_TABLE[candidate["0xfe"].size] - 2


class Xor1_MbaRule_1(PatternMatchingRule):
    PATTERN = AstNode(m_add,
                      AstNode(m_bnot,
                              AstLeaf('x_0')),
                      AstNode(m_or,
                              AstNode(m_mul,
                                      AstConstant('2', 2),
                                      AstLeaf('x_0')),
                              AstConstant('2', 2)))
    REPLACEMENT_PATTERN = AstNode(m_xor, AstLeaf('x_0'), AstConstant("val_1"))

    def check_candidate(self, candidate):
        candidate.add_constant_leaf("val_1", 1, candidate.size)
        return True


class Xor_Rule_1(PatternMatchingRule):
    PATTERN = AstNode(m_or,
                      AstNode(m_and,
                              AstLeaf("x_0"),
                              AstLeaf("x_1")),
                      AstNode(m_bnot,
                              AstNode(m_or,
                                      AstLeaf("x_0"),
                                      AstLeaf("x_1"))))

    REPLACEMENT_PATTERN = AstNode(m_xor,
                                  AstLeaf('x_0'),
                                  AstNode(m_bnot, AstLeaf("x_1")))


# Found sometimes with OLLVM
class Xor_Rule_2(PatternMatchingRule):
    PATTERN = AstNode(m_or,
                      AstNode(m_and,
                              AstNode(m_xor,
                                      AstLeaf('x_0'),
                                      AstLeaf('x_2')),
                              AstNode(m_xor,
                                      AstLeaf('x_1'),
                                      AstLeaf('bnot_x2'))),
                      AstNode(m_and,
                              AstNode(m_xor,
                                      AstLeaf('x_0'),
                                      AstLeaf('bnot_x2')),
                              AstNode(m_xor,
                                      AstLeaf('x_1'),
                                      AstLeaf('x_2'))))
    REPLACEMENT_PATTERN = AstNode(m_xor, AstLeaf('x_0'), AstLeaf('x_1'))


# Found sometimes with OLLVM
class Xor_Rule_3(PatternMatchingRule):
    PATTERN = AstNode(m_or,
                      AstNode(m_and,
                              AstNode(m_xor,
                                      AstLeaf('x_0'),
                                      AstLeaf('x_2')),
                              AstNode(m_xor,
                                      AstLeaf('x_1'),
                                      AstLeaf('x_2'))),
                      AstNode(m_and,
                              AstNode(m_xor,
                                      AstLeaf('x_0'),
                                      AstLeaf('bnot_x2')),
                              AstNode(m_xor,
                                      AstLeaf('x_1'),
                                      AstLeaf('bnot_x2'))))
    REPLACEMENT_PATTERN = AstNode(m_xor, AstNode(m_bnot, AstLeaf('x_0')), AstLeaf('x_1'))


class Xor_Rule_4(PatternMatchingRule):
    PATTERN = AstNode(m_or,
                      AstNode(m_and,
                              AstLeaf("x_0"),
                              AstLeaf("bnot_x_1")),
                      AstNode(m_and,
                              AstLeaf("bnot_x_0"),
                              AstLeaf("x_1")))

    REPLACEMENT_PATTERN = AstNode(m_xor,
                                  AstLeaf('x_0'),
                                  AstLeaf("x_1"))

    def check_candidate(self, candidate):
        if not equal_bnot_mop(candidate["x_0"].mop, candidate["bnot_x_0"].mop):
            return False
        if not equal_bnot_mop(candidate["x_1"].mop, candidate["bnot_x_1"].mop):
            return False
        return True


class Xor_Rule_4_WithXdu(PatternMatchingRule):
    PATTERN = AstNode(m_or,
                      AstNode(m_and,
                              AstLeaf("x_0"),
                              AstConstant("bnot_c_1")),
                      AstNode(m_and,
                              AstNode(m_bnot, AstLeaf("x_0")),
                              AstConstant("c_1")))

    REPLACEMENT_PATTERN = AstNode(m_xor,
                                  AstLeaf("x_0"),
                                  AstLeaf("c_1"))

    def check_candidate(self, candidate):
        if candidate["x_0"].mop.t != mop_d:
            return False
        if candidate["x_0"].mop.d.opcode != m_xdu:
            return False
        return equal_bnot_cst(candidate["c_1"].mop, candidate["bnot_c_1"].mop, mop_size=candidate["x_0"].mop.d.l.size)


class XorAlmost_Rule_1(PatternMatchingRule):
    PATTERN = AstNode(m_sub,
                      AstNode(m_add,
                              AstLeaf("x_0"),
                              AstLeaf("x_1")),
                      AstNode(m_mul,
                              AstConstant("2", 2),
                              AstNode(m_or,
                                      AstLeaf("x_0"),
                                      AstNode(m_sub,
                                              AstLeaf("x_1"),
                                              AstConstant("1", 1)))))

    REPLACEMENT_PATTERN = AstNode(m_add,
                                  AstNode(m_xor,
                                          AstLeaf("x_0"),
                                          AstNode(m_neg, AstLeaf("x_1"))),
                                  AstLeaf("val_2"))

    def check_candidate(self, candidate):
        candidate.add_constant_leaf("val_2", 2, candidate.size)
        return True


class Xor_NestedStuff(PatternMatchingRule):
    PATTERN = AstNode(m_sub,
                      AstNode(m_add,
                              AstNode(m_add,
                                      AstLeaf('x_9'),
                                      AstLeaf('x_10')),
                              AstLeaf("x_11")),
                      AstNode(m_add,
                              AstLeaf("x_14"),
                              AstNode(m_mul,
                                      AstConstant('2', 2),
                                      AstNode(m_and,
                                              AstLeaf('x_10'),
                                              AstNode(m_sub,
                                                      AstNode(m_add,
                                                              AstLeaf('x_9'),
                                                              AstLeaf("x_11")),
                                                      AstLeaf("x_14"))))))


    REPLACEMENT_PATTERN = AstNode(m_xor,
                                  AstLeaf("x_10"),
                                  AstNode(m_sub,
                                          AstNode(m_add,
                                                  AstLeaf('x_9'),
                                                  AstLeaf("x_11")),
                                          AstLeaf("x_14")))
    FUZZ_PATTERN = False

