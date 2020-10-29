from ida_hexrays import *

from d810.ast import AstLeaf, AstConstant, AstNode
from d810.hexrays_helpers import equal_mops_bypass_xdu, equal_bnot_mop
from d810.optimizers.flow.jumps.handler import JumpOptimizationRule


class CompareConstantRule1(JumpOptimizationRule):
    ORIGINAL_JUMP_OPCODES = [m_jge]
    LEFT_PATTERN = AstNode(m_and,
                           AstNode(m_or, AstLeaf("xdu_x_0"), AstConstant("c_2")),
                           AstNode(m_or,
                                   AstNode(m_xor, AstLeaf("x_0"), AstConstant("c_1")),
                                   AstNode(m_bnot, AstNode(m_sub, AstLeaf("x_0"), AstConstant("c_1")))))
    RIGHT_PATTERN = AstConstant("0", 0)

    REPLACEMENT_OPCODE = m_jl
    REPLACEMENT_LEFT_PATTERN = AstLeaf("x_0")
    REPLACEMENT_RIGHT_PATTERN = AstLeaf("c_1")

    def check_candidate(self, opcode, left_candidate, right_candidate):
        if not equal_mops_bypass_xdu(left_candidate["xdu_x_0"].mop, left_candidate["x_0"].mop):
            return False
        if not equal_bnot_mop(left_candidate["c_2"].mop, left_candidate["c_1"].mop):
            return False
        self.jump_replacement_block_serial = self.jump_original_block_serial
        return True


class CompareConstantRule2(JumpOptimizationRule):
    ORIGINAL_JUMP_OPCODES = [m_jge]
    LEFT_PATTERN = AstNode(m_or,
                           AstNode(m_xdu,
                                   AstNode(m_and,
                                           AstNode(m_bnot, AstLeaf("x_0")), AstConstant("c_1"))),
                           AstNode(m_and,
                                   AstNode(m_sub, AstLeaf('xdu_x_0'), AstConstant('xdu_c_1')),
                                   AstNode(m_bnot, AstNode(m_xdu, AstNode(m_xor, AstLeaf('xdu1_x_0'), AstConstant('xdu_c_1'))))))
    RIGHT_PATTERN = AstConstant("0", 0)

    REPLACEMENT_OPCODE = m_jge
    REPLACEMENT_LEFT_PATTERN = AstLeaf("x_0")
    REPLACEMENT_RIGHT_PATTERN = AstLeaf("c_1")

    def check_candidate(self, opcode, left_candidate, right_candidate):
        if not equal_mops_bypass_xdu(left_candidate["xdu_x_0"].mop, left_candidate["x_0"].mop):
            return False
        if not equal_mops_bypass_xdu(left_candidate["xdu1_x_0"].mop, left_candidate["x_0"].mop):
            return False
        self.jump_replacement_block_serial = self.jump_original_block_serial
        return True


class CompareConstantRule3(JumpOptimizationRule):
    ORIGINAL_JUMP_OPCODES = [m_jge]
    LEFT_PATTERN = AstNode(m_and,
                           AstNode(m_sub, AstLeaf('x_0'), AstConstant('c_1')),
                           AstNode(m_bnot, AstLeaf("x_0")))
    RIGHT_PATTERN = AstConstant("0", 0)

    REPLACEMENT_OPCODE = m_jg
    REPLACEMENT_LEFT_PATTERN = AstLeaf("x_0")
    REPLACEMENT_RIGHT_PATTERN = AstLeaf("c_1")

    def check_candidate(self, opcode, left_candidate, right_candidate):
        self.jump_replacement_block_serial = self.jump_original_block_serial
        return True


class CompareConstantRule4(JumpOptimizationRule):
    ORIGINAL_JUMP_OPCODES = [m_jl, m_jge]
    LEFT_PATTERN = AstNode(m_and,
                           AstNode(m_or,
                                   AstNode(m_bnot,
                                           AstNode(m_sub,
                                                   AstLeaf('x_0'),
                                                   AstConstant('c_1'))),
                                   AstNode(m_xor,
                                           AstLeaf('x_0'),
                                           AstConstant('c_1'))),
                           AstNode(m_or,
                                   AstLeaf("xdu_x_0"),
                                   AstConstant('bnot_c_1')))

    RIGHT_PATTERN = AstConstant("0", 0)

    REPLACEMENT_OPCODE = m_jge
    REPLACEMENT_LEFT_PATTERN = AstLeaf("x_0")
    REPLACEMENT_RIGHT_PATTERN = AstLeaf("c_1")

    def check_candidate(self, opcode, left_candidate, right_candidate):
        print("dflighdrth")
        if not equal_mops_bypass_xdu(left_candidate["xdu_x_0"].mop, left_candidate["x_0"].mop):
            return False
        if not equal_bnot_mop(left_candidate["c_1"].mop, left_candidate["bnot_c_1"].mop):
            return False
        self.jump_replacement_block_serial = self.jump_original_block_serial
        return True
