/*
 * shecc - Self-Hosting and Educational C Compiler.
 *
 * shecc is freely redistributable under the BSD 2 clause license. See the
 * file "LICENSE" for information on usage and redistribution of this file.
 */

#include <stdbool.h>

#include "defs.h"
#include "globals.c"

bool is_fusible_insn(ph2_ir_t *ph2_ir)
{
    switch (ph2_ir->op) {
    case OP_add:
    case OP_sub:
    case OP_mul:
    case OP_div:
    case OP_mod:
    case OP_lshift:
    case OP_rshift:
    case OP_bit_and:
    case OP_bit_or:
    case OP_bit_xor:
    case OP_log_and:
    case OP_log_or:
    case OP_log_not:
    case OP_negate:
    case OP_load:
    case OP_global_load:
    case OP_load_data_address:
        return true;
    default:
        return false;
    }
}

bool insn_fusion(ph2_ir_t *ph2_ir)
{
    ph2_ir_t *next = ph2_ir->next;
    if (!next)
        return false;

    if (next->op == OP_assign) {
        if (is_fusible_insn(ph2_ir) && ph2_ir->dest == next->src0) {
            /* eliminates:
             * {ALU rn, rs1, rs2; mv rd, rn;}
             * reduces to:
             * {ALU rd, rs1, rs2;}
             */
            ph2_ir->dest = next->dest;
            ph2_ir->next = next->next;
            return true;
        }
    }

    if (ph2_ir->op == OP_load_constant && ph2_ir->src0 == 0) {
        if (next->op == OP_add &&
            (ph2_ir->dest == next->src0 || ph2_ir->dest == next->src1)) {
            /* eliminates:
             * {li rn, 0; add rd, rs1, rn;} or
             * {li rn, 0; add rd, rn, rs1;}
             * reduces to:
             * {mv rd, rs1;}, based on identity property of addition
             */
            /* Determine the non-zero source operand */
            int non_zero_src =
                (ph2_ir->dest == next->src0) ? next->src1 : next->src0;

            /* Transform instruction sequence from addition with zero to move */
            ph2_ir->op = OP_assign;
            ph2_ir->src0 = non_zero_src;
            ph2_ir->dest = next->dest;
            ph2_ir->next = next->next;
            return true;
        }

        if (next->op == OP_sub) {
            if (ph2_ir->dest == next->src1) {
                /* eliminates:
                 * {li rn, 0; sub rd, rs1, rn;}
                 * reduces to:
                 * {mv rd, rs1;}
                 */
                ph2_ir->op = OP_assign;
                ph2_ir->src0 = next->src0;
                ph2_ir->dest = next->dest;
                ph2_ir->next = next->next;
                return true;
            }

            if (ph2_ir->dest == next->src0) {
                /* eliminates:
                 * {li rn, 0; sub rd, rn, rs1;}
                 * reduces to:
                 * {negate rd, rs1;}
                 */
                ph2_ir->op = OP_negate;
                ph2_ir->src0 = next->src1;
                ph2_ir->dest = next->dest;
                ph2_ir->next = next->next;
                return true;
            }
        }

        if (next->op == OP_mul &&
            (ph2_ir->dest == next->src0 || ph2_ir->dest == next->src1)) {
            /* eliminates:
             * {li rn, 0; mul rd, rs1, rn;} or
             * {li rn, 0; mul rd, rn, rs1;}
             * reduces to:
             * {li rd, 0}, based on zero property of multiplication
             */
            ph2_ir->op = OP_load_constant;
            ph2_ir->src0 = 0;
            ph2_ir->dest = next->dest;
            ph2_ir->next = next->next;
            return true;
        }
    }

    if (ph2_ir->op == OP_load_constant && ph2_ir->src0 == 1) {
        if (next->op == OP_mul &&
            (ph2_ir->dest == next->src0 || ph2_ir->dest == next->src1)) {
            /* eliminates:
             * {li rn, 1; mul rd, rs1, rn;} or
             * {li rn, 1; mul rd, rn, rs1;}
             * reduces to:
             * {li rd, rs1}, based on identity property of multiplication
             */
            ph2_ir->op = OP_assign;
            ph2_ir->src0 = ph2_ir->dest == next->src0 ? next->src1 : next->src0;
            ph2_ir->dest = next->dest;
            ph2_ir->next = next->next;
            return true;
        }
    }

    /* Other instruction fusion should be done here, and for any success fusion,
     * it should return true. This meant to allow peephole optimization to do
     * multiple passes over the IR list to maximize optimization as much as
     * possbile.
     */

    return false;
}



/**
 * @brief Peephole optimization pass 窥孔优化
 * 一种局部代码优化技术，通过滑动一个"小窗口"（peephole）检查相邻指令的模式并进行优化
 * This function performs peephole optimization on the intermediate
 * representation (IR) of the compiler.
 * It iterates through the functions and their basic blocks,
 * looking for opportunities to optimize sequences of instructions.
 * It specifically looks for patterns that can be simplified,
 * such as redundant loads or unnecessary moves.
 * The optimization is done in place, modifying the IR directly.
 * 
 */
void peephole(void)
{
    ///< 遍历所有函数
    for (func_t *func = FUNC_LIST.head; func; func = func->next) {
        ///< 遍历函数的基本块 按逆后序访问
        for (basic_block_t *bb = func->bbs; bb; bb = bb->rpo_next) {
            ///< 遍历基本块中的 IR 指令
            for (ph2_ir_t *ir = bb->ph2_ir_list.head; ir; ir = ir->next) {
                ph2_ir_t *next = ir->next;
                if (!next)
                    continue;
                ///< 检测 OP_assign（赋值指令）且目标操作数（dest）与源操作数（src0）相同，则跳过（删除）如x = x
                if (next->op == OP_assign && next->dest == next->src0) {
                    ir->next = next->next;
                    continue;
                }
                ///< 合并可优化的指令对
                insn_fusion(ir);
            }
        }
    }
}
