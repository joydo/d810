from ida_hexrays import *

from d810.optimizers.instructions.pattern_matching.handler import PatternMatchingRule
from d810.ast import AstLeaf, AstConstant, AstNode
from d810.hexrays_helpers import equal_bnot_mop, SUB_TABLE, AND_TABLE


# PredSetnzRule1: (x_0 | c_1) != c_2 ==> 1 if c_1 | c_2 != c_2
class PredSetnzRule1(PatternMatchingRule):
    PATTERN = AstNode(m_setnz,
                      AstNode(m_or,
                              AstLeaf("x_0"),
                              AstConstant("c_1")),
                      AstConstant("c_2"))
    REPLACEMENT_PATTERN = AstNode(m_mov, AstConstant("val_1"))

    def check_candidate(self, candidate):
        if (candidate["c_1"].value | candidate["c_2"].value) == candidate["c_2"].value:
            return False
        candidate.add_constant_leaf("val_1", 1, candidate.size)
        return True


# PredSetnzRule2: (x_0 & c_1) != c_2 ==> 1 if c_1 & c_2 != c_2
class PredSetnzRule2(PatternMatchingRule):
    PATTERN = AstNode(m_setnz,
                      AstNode(m_and,
                              AstLeaf("x_0"),
                              AstConstant("c_1")),
                      AstConstant("c_2"))
    REPLACEMENT_PATTERN = AstNode(m_mov, AstConstant("val_1"))

    def check_candidate(self, candidate):
        if (candidate["c_1"].value & candidate["c_2"].value) == candidate["c_2"].value:
            return False
        candidate.add_constant_leaf("val_1", 1, candidate.size)
        return True


# PredSetnzRule3: (x_0 | 2) + (x_0 ^ 2) != 0 ==> 1 (because math)
class PredSetnzRule3(PatternMatchingRule):
    PATTERN = AstNode(m_setnz,
                      AstNode(m_add,
                              AstNode(m_or,
                                      AstLeaf("x_0"),
                                      AstConstant("2", 2)),
                              AstNode(m_xor,
                                      AstLeaf("x_0"),
                                      AstConstant("2", 2))),
                      AstConstant("0", 0))
    REPLACEMENT_PATTERN = AstNode(m_mov, AstConstant("val_1"))

    def check_candidate(self, candidate):
        candidate.add_constant_leaf("val_1", 1, candidate.size)
        return True


# PredSetnzRule4: (cst_1 - x_0) ^ x_0 != 0 ==> 1 if cst_1 % 2 == 1 (because math)
class PredSetnzRule4(PatternMatchingRule):
    PATTERN = AstNode(m_setnz,
                      AstNode(m_xor,
                              AstNode(m_sub,
                                      AstConstant("cst_1"),
                                      AstLeaf("x_0")),
                              AstLeaf("x_0")),
                      AstConstant("0", 0))
    REPLACEMENT_PATTERN = AstNode(m_mov, AstConstant("val_1"))

    def check_candidate(self, candidate):
        if (candidate["cst_1"].value % 2) == 0:
            return False
        candidate.add_constant_leaf("val_1", 1, candidate.size)
        return True


# PredSetnzRule5: (-(~x_0 & 1)) != x_0 ==> 1 (because math)
class PredSetnzRule5(PatternMatchingRule):
    PATTERN = AstNode(m_setnz,
                      AstNode(m_neg,
                              AstNode(m_and,
                                      AstNode(m_bnot,
                                              AstLeaf("x_0")),
                                      AstConstant("1", 1))),
                      AstLeaf("x_0"))
    REPLACEMENT_PATTERN = AstNode(m_mov, AstConstant("val_1"))

    def check_candidate(self, candidate):
        candidate.add_constant_leaf("val_1", 1, candidate.size)
        return True


# PredSetnzRule6: ((x_0 + c_1) + ((x_0 + c_2) & 1)) != 0 ==> 1 (if (c_2 - c_1) & 1 == 1)
class PredSetnzRule6(PatternMatchingRule):
    PATTERN = AstNode(m_setnz,
                      AstNode(m_add,
                              AstNode(m_add,
                                      AstLeaf("x_0"),
                                      AstConstant("c_1")),
                              AstNode(m_and,
                                      AstNode(m_add,
                                              AstLeaf("x_0"),
                                              AstConstant("c_2")),
                                      AstConstant("1", 1))),
                      AstConstant("0", 0))
    REPLACEMENT_PATTERN = AstNode(m_mov, AstConstant("val_1"))

    def check_candidate(self, candidate):
        if (candidate["c_2"].value - candidate["c_1"].value) & 0x1 != 1:
            return False
        candidate.add_constant_leaf("val_1", 1, candidate.size)
        return True


# PredSetnzRule8: bnot((3 - x_0)) ^ bnot(x_0) != 0 ==> 1
class PredSetnzRule8(PatternMatchingRule):
    PATTERN = AstNode(m_setnz,
                      AstNode(m_xor,
                              AstNode(m_bnot,
                                      AstNode(m_sub,
                                              AstConstant("3", 3),
                                              AstLeaf("x_0"))),
                              AstNode(m_bnot,
                                      AstLeaf("x_0"))),
                      AstConstant("0", 0))
    REPLACEMENT_PATTERN = AstNode(m_mov, AstConstant("val_1"))

    def check_candidate(self, candidate):
        candidate.add_constant_leaf("val_1", 1, candidate.size)
        return True


# PredSetzRule1: (x_0 | c_1) == c_2 ==> 0 if c_1 | c_2 != c_2
class PredSetzRule1(PatternMatchingRule):
    PATTERN = AstNode(m_setz,
                      AstNode(m_or,
                              AstLeaf("x_0"),
                              AstConstant("c_1")),
                      AstConstant("c_2"))
    REPLACEMENT_PATTERN = AstNode(m_mov, AstConstant("val_0"))

    def check_candidate(self, candidate):
        if (candidate["c_1"].value | candidate["c_2"].value) == candidate["c_2"].value:
            return False
        candidate.add_constant_leaf("val_0", 0, candidate.size)
        return True


# PredSetzRule2: (x_0 & c_1) == c_2 ==> 0 if c_1 & c_2 != c_2
class PredSetzRule2(PatternMatchingRule):
    PATTERN = AstNode(m_setz,
                      AstNode(m_and,
                              AstLeaf("x_0"),
                              AstConstant("c_1")),
                      AstConstant("c_2"))
    REPLACEMENT_PATTERN = AstNode(m_mov, AstConstant("val_0"))

    def check_candidate(self, candidate):
        if (candidate["c_1"].value & candidate["c_2"].value) == candidate["c_2"].value:
            return False
        candidate.add_constant_leaf("val_0", 0, candidate.size)
        return True


# PredSetzRule3: (x_0 | 2) + (x_0 ^ 2) == 0 ==> 0 (because math)
class PredSetzRule3(PatternMatchingRule):
    PATTERN = AstNode(m_setz,
                      AstNode(m_add,
                              AstNode(m_or,
                                      AstLeaf("x_0"),
                                      AstConstant("2", 2)),
                              AstNode(m_xor,
                                      AstLeaf("x_0"),
                                      AstConstant("2", 2))),
                      AstConstant("0", 0))
    REPLACEMENT_PATTERN = AstNode(m_mov, AstConstant("val_0"))

    def check_candidate(self, candidate):
        candidate.add_constant_leaf("val_0", 0, candidate.size)
        return True


# PredSetbRule1: (x_0 & c_1) <u c_2 ==> 0 if c_1 <u c_2
class PredSetbRule1(PatternMatchingRule):
    PATTERN = AstNode(m_setb,
                      AstNode(m_and,
                              AstLeaf("x_0"),
                              AstConstant("c_1")),
                      AstConstant("c_2"))
    REPLACEMENT_PATTERN = AstNode(m_mov, AstConstant("val_0"))

    def check_candidate(self, candidate):
        if candidate["c_1"].value >= candidate["c_2"].value:
            return False
        candidate.add_constant_leaf("val_0", 0, candidate.size)
        return True


class PredOdd1(PatternMatchingRule):
    PATTERN = AstNode(m_and,
                      AstNode(m_mul,
                              AstLeaf('x_0'),
                              AstNode(m_sub,
                                      AstLeaf('x_0'),
                                      AstConstant('1', 1))),
                      AstConstant('1', 1))
    REPLACEMENT_PATTERN = AstNode(m_mov, AstConstant('val_0'))

    def check_candidate(self, candidate):
        candidate.add_constant_leaf("val_0", 0, candidate.size)
        return True


class PredOdd2(PatternMatchingRule):
    PATTERN = AstNode(m_and,
                      AstNode(m_mul,
                              AstLeaf('x_0'),
                              AstNode(m_add,
                                      AstLeaf('x_0'),
                                      AstConstant('1', 1))),
                      AstConstant('1', 1))
    REPLACEMENT_PATTERN = AstNode(m_mov, AstConstant('val_0'))

    def check_candidate(self, candidate):
        candidate.add_constant_leaf("val_0", 0, candidate.size)
        return True


# Pred0Rule1: (x_0 & ~x_0) ==> 0
class Pred0Rule1(PatternMatchingRule):
    PATTERN = AstNode(m_and,
                      AstLeaf("x_0"),
                      AstNode(m_bnot,
                              AstLeaf("x_0")))
    REPLACEMENT_PATTERN = AstNode(m_mov, AstConstant("val_0"))

    def check_candidate(self, candidate):
        candidate.add_constant_leaf("val_0", 0, candidate.size)
        return True


# Pred0Rule2: (xdu(x_0 & 1) == 2) ==> 0
class Pred0Rule2(PatternMatchingRule):
    PATTERN = AstNode(m_setz,
                      AstNode(m_xdu,
                              AstNode(m_and,
                                      AstLeaf("x_0"),
                                      AstConstant("c_1", 1))),
                      AstConstant("c_2", 2))
    REPLACEMENT_PATTERN = AstNode(m_mov, AstConstant("val_0"))

    def check_candidate(self, candidate):
        candidate.add_constant_leaf("val_0", 0, candidate.size)
        return True


class Pred0Rule3(PatternMatchingRule):
    PATTERN = AstNode(m_and,
                      AstLeaf("x_0"),
                      AstNode(m_bnot,
                              AstNode(m_or,
                                      AstLeaf("x_0"),
                                      AstLeaf("x_1"))))
    REPLACEMENT_PATTERN = AstNode(m_mov, AstLeaf("val_0"))

    def check_candidate(self, candidate):
        candidate.add_constant_leaf("val_0", 0, candidate.size)
        return True


class Pred0Rule4(PatternMatchingRule):
    PATTERN = AstNode(m_and,
                      AstNode(m_and,
                              AstLeaf('x_0'),
                              AstLeaf('x_1')),
                      AstNode(m_bnot,
                              AstNode(m_or,
                                      AstLeaf('x_0'),
                                      AstLeaf('x_1'))))
    REPLACEMENT_PATTERN = AstNode(m_mov, AstLeaf("val_0"))

    def check_candidate(self, candidate):
        candidate.add_constant_leaf("val_0", 0, candidate.size)
        return True


class Pred0Rule5(PatternMatchingRule):
    PATTERN = AstNode(m_and,
                      AstNode(m_and,
                              AstLeaf('x_0'),
                              AstLeaf('x_1')),
                      AstNode(m_xor,
                              AstLeaf('x_0'),
                              AstLeaf('x_1')))
    REPLACEMENT_PATTERN = AstNode(m_mov, AstLeaf("val_0"))

    def check_candidate(self, candidate):
        candidate.add_constant_leaf("val_0", 0, candidate.size)
        return True


class PredFFRule1(PatternMatchingRule):
    PATTERN = AstNode(m_or,
                      AstLeaf("x_0"),
                      AstNode(m_bnot,
                              AstLeaf("x_0")))
    REPLACEMENT_PATTERN = AstNode(m_mov, AstConstant("val_ff"))

    def check_candidate(self, candidate):
        candidate.add_constant_leaf("val_ff", AND_TABLE[candidate.size], candidate.size)
        return True


# Pred1Rule2: (x_0 ^ x_1) | (~x_0 | x_1) ==> 0xff
class PredFFRule2(PatternMatchingRule):
    PATTERN = AstNode(m_or,
                      AstNode(m_xor,
                              AstLeaf("x_0"),
                              AstLeaf("x_1")),
                      AstNode(m_or,
                              AstLeaf("bnot_x_0"),
                              AstLeaf("x_1")))
    REPLACEMENT_PATTERN = AstNode(m_mov, AstConstant("val_ff"))

    def check_candidate(self, candidate):
        if not equal_bnot_mop(candidate["x_0"].mop, candidate["bnot_x_0"].mop):
            return False
        candidate.add_constant_leaf("val_ff", AND_TABLE[candidate.size], candidate.size)
        return True


class PredFFRule3(PatternMatchingRule):
    PATTERN = AstNode(m_or,
                      AstLeaf("x_0"),
                      AstNode(m_bnot,
                              AstNode(m_and,
                                      AstLeaf("x_0"),
                                      AstLeaf("x_1"))))

    REPLACEMENT_PATTERN = AstNode(m_mov, AstLeaf("val_ff"))

    def check_candidate(self, candidate):
        candidate.add_constant_leaf("val_ff", AND_TABLE[candidate.size], candidate.size)
        return True


class PredFFRule4(PatternMatchingRule):
    DESCRIPTION = "(x_0 | x_1) | (~(x_0 & x_1))  ==>  0xff"
    PATTERN = AstNode(m_or,
                      AstNode(m_or,
                              AstLeaf('x_0'),
                              AstLeaf('x_1')),
                      AstNode(m_bnot,
                              AstNode(m_and,
                                      AstLeaf('x_0'),
                                      AstLeaf('x_1'))))
    REPLACEMENT_PATTERN = AstNode(m_mov, AstConstant("val_ff"))

    def check_candidate(self, candidate):
        candidate.add_constant_leaf("val_ff", AND_TABLE[candidate.size], candidate.size)
        return True


class PredOr2_Rule_1(PatternMatchingRule):
    PATTERN = AstNode(m_and,
                      AstNode(m_bnot,
                              AstNode(m_mul,
                                      AstLeaf('x_0'),
                                      AstLeaf('x_0'))),
                      AstConstant('3', 3))
    REPLACEMENT_PATTERN = AstNode(m_or,
                                  AstNode(m_and,
                                          AstNode(m_bnot, AstLeaf('x_0')),
                                          AstConstant('val_1')),
                                  AstConstant('val_2'))

    def check_candidate(self, candidate):
        candidate.add_constant_leaf("val_1", 1, candidate["x_0"].mop.size)
        candidate.add_constant_leaf("val_2", 2, candidate["x_0"].mop.size)
        return True


class PredOr1_Rule_1(PatternMatchingRule):
    PATTERN = AstNode(m_xor,
                      AstLeaf('x_0'),
                      AstNode(m_add,
                              AstNode(m_and,
                                      AstLeaf('x_0'),
                                      AstConstant('1', 1)),
                              AstConstant('1', 1)))
    REPLACEMENT_PATTERN = AstNode(m_or,
                                  AstNode(m_xor,
                                          AstLeaf('x_0'),
                                          AstNode(m_mul,
                                                  AstConstant('val_2'),
                                                  AstNode(m_and,
                                                          AstLeaf('x_0'),
                                                          AstConstant('val_1')))),
                                  AstConstant('val_1'))

    def check_candidate(self, candidate):
        candidate.add_constant_leaf("val_1", 1, candidate["x_0"].mop.size)
        candidate.add_constant_leaf("val_2", 2, candidate["x_0"].mop.size)
        return True
