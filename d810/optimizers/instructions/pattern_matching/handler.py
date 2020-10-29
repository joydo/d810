import logging
import itertools
from ida_hexrays import *
from typing import List, Union
from d810.optimizers.instructions.handler import GenericPatternRule, InstructionOptimizer, InstructionOptimizationRule
from d810.ast import minsn_to_ast, AstNode, AstLeaf
from d810.hexrays_formatters import format_minsn_t, format_mop_t

optimizer_logger = logging.getLogger('D810.optimizer')
pattern_search_logger = logging.getLogger('D810.pattern_search')


class PatternMatchingRule(GenericPatternRule):
    PATTERN = None
    PATTERNS = None
    FUZZ_PATTERN = True
    REPLACEMENT_PATTERN = None

    def __init__(self):
        super().__init__()
        self.fuzz_pattern = self.FUZZ_PATTERN

    def configure(self, fuzz_pattern=None, **kwargs):
        super().configure(kwargs)
        if fuzz_pattern is not None:
            self.fuzz_pattern = fuzz_pattern
        self._generate_pattern_candidates()
        pattern_search_logger.debug("Rule {0} configured with {1} patterns"
                                    .format(self.__class__.__name__, len(self.pattern_candidates)))

    def _generate_pattern_candidates(self):
        self.fuzz_pattern = self.FUZZ_PATTERN
        if self.PATTERN is not None:
            self.PATTERN.reset_mops()
        if not self.fuzz_pattern:
            if self.PATTERN is not None:
                self.pattern_candidates = [self.PATTERN]
                if self.PATTERNS is not None:
                    self.pattern_candidates += [x for x in self.PATTERNS]
            else:
                self.pattern_candidates = [x for x in self.PATTERNS]
        else:
            self.pattern_candidates = ast_generator(self.PATTERN)

    def check_candidate(self, candidate: AstNode):
        return True

    def check_pattern_and_replace(self, candidate_pattern: AstNode, test_ast: AstNode):
        if not candidate_pattern.check_pattern_and_copy_mops(test_ast):
            return None
        if not self.check_candidate(candidate_pattern):
            return None
        new_instruction = self.get_replacement(candidate_pattern)
        return new_instruction


class RulePatternInfo(object):
    def __init__(self, rule, pattern):
        self.rule = rule
        self.pattern = pattern


def signature_generator(ref_sig):
    for i, x in enumerate(ref_sig):
        if x not in ["N", "L"]:
            for sig_suffix in signature_generator(ref_sig[i + 1:]):
                yield ref_sig[:i] + ["L"] + sig_suffix
    yield ref_sig


class PatternStorage(object):
    # The PatternStorage object is used to store patterns associated to rules
    # A PatternStorage contains a dictionary (next_layer_patterns) where:
    #  - keys are the signature of a pattern at a specific depth (i.e. the opcodes, the variable and constant)
    #  - values are PatternStorage object for the next depth
    # Additionally, it stores the rule objects which are resolved for the PatternStorage depth
    def __init__(self, depth=1):
        self.depth = depth
        self.next_layer_patterns = {}
        self.rule_resolved = []

    def add_pattern_for_rule(self, pattern: AstNode, rule: InstructionOptimizationRule):
        layer_signature = self.layer_signature_to_key(pattern.get_depth_signature(self.depth))
        if len(layer_signature.replace(",", "")) == (layer_signature.count("N")):
            self.rule_resolved.append(RulePatternInfo(rule, pattern))
        else:
            if layer_signature not in self.next_layer_patterns.keys():
                self.next_layer_patterns[layer_signature] = PatternStorage(self.depth + 1)
            self.next_layer_patterns[layer_signature].add_pattern_for_rule(pattern, rule)

    @staticmethod
    def layer_signature_to_key(sig: List[str]) -> str:
        return ",".join(sig)

    @staticmethod
    def is_layer_signature_compatible(instruction_signature: str, pattern_signature: str) -> bool:
        if instruction_signature == pattern_signature:
            return True
        instruction_node_list = instruction_signature.split(",")
        pattern_node_list = pattern_signature.split(",")
        for ins_node_sig, pattern_node_sig in zip(instruction_node_list, pattern_node_list):
            if pattern_node_sig not in ["L", "C", "N"] and ins_node_sig != pattern_node_sig:
                return False
        return True

    def get_matching_rule_pattern_info(self, pattern: AstNode):
        pattern_search_logger.info("Searching : {0}".format(pattern))
        return self.explore_one_level(pattern, 1)

    def explore_one_level(self, searched_pattern: AstNode, cur_level: int):
        # We need to check if searched_pattern is in self.next_layer_patterns
        # Easy solution: try/except self.next_layer_patterns[searched_pattern]
        # Problem is that known patterns may not exactly match the microcode instruction, e.g.
        #   -> Pattern layer 3 signature is ["L", "N", "15", "L"]
        #   -> Multiple instruction can match that: ["L", "N", "15", "L"], ["C", "N", "15", "L"], ["C", "N", "15", "13"]
        # This piece of code tries to handles that in a (semi) efficient way
        if len(self.next_layer_patterns) == 0:
            return []
        searched_layer_signature = searched_pattern.get_depth_signature(cur_level)
        nb_possible_signature = 2 ** (len(searched_layer_signature) - searched_layer_signature.count("N") - \
                                searched_layer_signature.count("L"))
        pattern_search_logger.debug("  Layer {0}: {1} -> {2} variations (storage has {3} signature)"
                                    .format(cur_level, searched_layer_signature, nb_possible_signature,
                                            len(self.next_layer_patterns)))
        matched_rule_pattern_info = []
        if nb_possible_signature < len(self.next_layer_patterns):
            pattern_search_logger.debug("  => Using method 1")
            for possible_sig in signature_generator(searched_layer_signature):
                try:
                    test_sig = self.layer_signature_to_key(possible_sig)
                    pattern_storage = self.next_layer_patterns[test_sig]
                    pattern_search_logger.info("    Compatible signature: {0} -> resolved: {1}"
                                               .format(test_sig, pattern_storage.rule_resolved))
                    matched_rule_pattern_info += pattern_storage.rule_resolved
                    matched_rule_pattern_info += pattern_storage.explore_one_level(searched_pattern, cur_level + 1)
                except KeyError:
                    pass
        else:
            pattern_search_logger.debug("  => Using method 2")
            searched_layer_signature_key = self.layer_signature_to_key(searched_layer_signature)
            for test_sig, pattern_storage in self.next_layer_patterns.items():
                if self.is_layer_signature_compatible(searched_layer_signature_key, test_sig):
                    pattern_search_logger.info("    Compatible signature: {0} -> resolved: {1}"
                                               .format(test_sig, pattern_storage.rule_resolved))
                    matched_rule_pattern_info += pattern_storage.rule_resolved
                    matched_rule_pattern_info += pattern_storage.explore_one_level(searched_pattern, cur_level + 1)
        return matched_rule_pattern_info


class PatternOptimizer(InstructionOptimizer):
    # The main idea of PatternOptimizer is to generate/store all possible patterns associated to all known rules in a $
    # dictionary-like object (PatternStorage) when the plugin is loaded.
    # => it means that we generate a very large number of patterns
    #
    # At runtime, we transform the microcode instruction in a list of keys that we search in the PatternStorage object
    # to speed up the checks
    # => we don't want to test all patterns, so we use the PatternStorage object to (quickly) get the patterns
    # which have the same shape as the microcode instruction

    RULE_CLASSES = [PatternMatchingRule]

    def __init__(self, maturities, log_dir=None):
        super().__init__(maturities, log_dir=log_dir)
        self.pattern_storage = PatternStorage(depth=1)

    def add_rule(self, rule: InstructionOptimizationRule):
        is_ok = super().add_rule(rule)
        if not is_ok:
            return False
        for pattern in rule.pattern_candidates:
            self.pattern_storage.add_pattern_for_rule(pattern, rule)
        return True

    def get_optimized_instruction(self, blk: mblock_t, ins: minsn_t) -> Union[None, minsn_t]:
        if blk is not None:
            self.cur_maturity = blk.mba.maturity
        if self.cur_maturity not in self.maturities:
            return None
        tmp = minsn_to_ast(ins)
        if tmp is None:
            return None

        all_matchs = self.pattern_storage.get_matching_rule_pattern_info(tmp)
        for rule_pattern_info in all_matchs:
            try:
                new_ins = rule_pattern_info.rule.check_pattern_and_replace(rule_pattern_info.pattern, tmp)
                if new_ins is not None:
                    self.rules_usage_info[rule_pattern_info.rule.name] += 1
                    optimizer_logger.info("Rule {0} matched:".format(rule_pattern_info.rule.name))
                    optimizer_logger.info("  orig: {0}".format(format_minsn_t(ins)))
                    optimizer_logger.info("  new : {0}".format(format_minsn_t(new_ins)))
                    return new_ins
            except RuntimeError as e:
                optimizer_logger.error("Error during rule {0} for instruction {1}: {2}"
                                       .format(rule_pattern_info.rule, format_minsn_t(ins), e))
        return None

# AST equivalent pattern generation stuff
# TODO: refactor/clean this


def rec_get_all_binary_subtree_representation(elt_list):
    if len(elt_list) == 1:
        return elt_list
    if len(elt_list) == 2:
        return [elt_list]
    tmp_res = []
    for i in range(1, len(elt_list)):
        left_list = rec_get_all_binary_subtree_representation(elt_list[:i])
        right_list = rec_get_all_binary_subtree_representation(elt_list[i:])
        for l in left_list:
            for r in right_list:
                tmp_res.append([l, r])
    return tmp_res


def rec_get_all_binary_tree_representation(elt_list):
    if len(elt_list) <= 1:
        return elt_list
    tmp = list(itertools.permutations(elt_list))
    tmp2 = []
    for perm_tmp in tmp:
        tmp2 += rec_get_all_binary_subtree_representation(perm_tmp)
    return tmp2


def get_all_binary_tree_representation(all_elt):
    tmp = rec_get_all_binary_tree_representation(all_elt)
    return tmp


def generate_ast(opcode, leafs):
    if isinstance(leafs, AstLeaf):
        return leafs
    if isinstance(leafs, AstNode):
        return leafs
    if len(leafs) == 1:
        return leafs[0]
    if len(leafs) == 2:
        return AstNode(opcode, generate_ast(opcode, leafs[0]), generate_ast(opcode, leafs[1]))


def get_addition_operands(ast_node):
    if not isinstance(ast_node, AstNode):
        return [ast_node]
    if ast_node.opcode == m_add:
        return get_addition_operands(ast_node.left) + get_addition_operands(ast_node.right)
    elif ast_node.opcode == m_sub:
        tmp = get_addition_operands(ast_node.left)
        for aaa in get_addition_operands(ast_node.right):
            tmp.append(AstNode(m_neg, aaa))
        return tmp
    else:
        return [ast_node]


def get_opcode_operands(ref_opcode, ast_node):
    if not isinstance(ast_node, AstNode):
        return [ast_node]
    if ast_node.opcode == ref_opcode:
        return get_opcode_operands(ref_opcode, ast_node.left) + get_opcode_operands(ref_opcode, ast_node.right)
    else:
        return [ast_node]


def get_similar_opcode_operands(ast_node):
    if ast_node.opcode in [m_add, m_sub]:
        add_elts = get_addition_operands(ast_node)
        all_add_ordering = get_all_binary_tree_representation(add_elts)
        ast_res = []
        for leaf_ordering in all_add_ordering:
            ast_res.append(generate_ast(m_add, leaf_ordering))
        return ast_res
    elif ast_node.opcode in [m_xor, m_or, m_and, m_mul]:
        same_elts = get_opcode_operands(ast_node.opcode, ast_node)
        all_same_ordering = get_all_binary_tree_representation(same_elts)
        ast_res = []
        for leaf_ordering in all_same_ordering:
            ast_res.append(generate_ast(ast_node.opcode, leaf_ordering))
        return ast_res

    else:
        return [ast_node]


def get_ast_variations_with_add_sub(opcode, left, right):
    possible_ast = [AstNode(opcode, left, right)]
    if opcode == m_add:
        if isinstance(left, AstNode) and isinstance(right, AstNode):
            if (left.opcode == m_neg) and (right.opcode == m_neg):
                possible_ast.append(AstNode(m_neg, AstNode(m_add, left.left, right.left)))
        if isinstance(right, AstNode) and (right.opcode == m_neg):
            possible_ast.append(AstNode(m_sub, left, right.left))
    return possible_ast


def ast_generator(ast_node, excluded_opcodes=None):
    if not isinstance(ast_node, AstNode):
        return [ast_node]
    res_ast = []
    excluded_opcodes = excluded_opcodes if excluded_opcodes is not None else []
    if ast_node.opcode not in excluded_opcodes:
        if ast_node.opcode in [m_add, m_sub]:
            similar_ast_list = get_similar_opcode_operands(ast_node)
            for similar_ast in similar_ast_list:
                sub_ast_left_list = ast_generator(similar_ast.left, excluded_opcodes=[m_add, m_sub])
                sub_ast_right_list = ast_generator(similar_ast.right, excluded_opcodes=[m_add, m_sub])
                for sub_ast_left in sub_ast_left_list:
                    for sub_ast_right in sub_ast_right_list:
                        res_ast += get_ast_variations_with_add_sub(m_add, sub_ast_left, sub_ast_right)
            return res_ast
        if ast_node.opcode in [m_xor, m_or, m_and, m_mul]:
            similar_ast_list = get_similar_opcode_operands(ast_node)
            for similar_ast in similar_ast_list:
                sub_ast_left_list = ast_generator(similar_ast.left, excluded_opcodes=[ast_node.opcode])
                sub_ast_right_list = ast_generator(similar_ast.right, excluded_opcodes=[ast_node.opcode])
                for sub_ast_left in sub_ast_left_list:
                    for sub_ast_right in sub_ast_right_list:
                        res_ast += get_ast_variations_with_add_sub(ast_node.opcode, sub_ast_left, sub_ast_right)
            return res_ast
    if ast_node.opcode not in [m_add, m_sub, m_or, m_and, m_mul]:
        excluded_opcodes = []
    nb_operands = 0
    if ast_node.left is not None:
        nb_operands += 1
    if ast_node.right is not None:
        nb_operands += 1
    if nb_operands == 1:
        sub_ast_list = ast_generator(ast_node.left, excluded_opcodes=excluded_opcodes)
        for sub_ast in sub_ast_list:
            res_ast.append(AstNode(ast_node.opcode, sub_ast))
        return res_ast
    if nb_operands == 2:
        sub_ast_left_list = ast_generator(ast_node.left, excluded_opcodes=excluded_opcodes)
        sub_ast_right_list = ast_generator(ast_node.right, excluded_opcodes=excluded_opcodes)
        for sub_ast_left in sub_ast_left_list:
            for sub_ast_right in sub_ast_right_list:
                res_ast += get_ast_variations_with_add_sub(ast_node.opcode, sub_ast_left, sub_ast_right)
        return res_ast
    return []
