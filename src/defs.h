/*
 * shecc - Self-Hosting and Educational C Compiler.
 *
 * shecc is freely redistributable under the BSD 2 clause license. See the
 * file "LICENSE" for information on usage and redistribution of this file.
 */

#pragma once
#include <stdbool.h>

/* definitions */

/* Limitations */
#define MAX_TOKEN_LEN 256
#define MAX_ID_LEN 64
#define MAX_LINE_LEN 256
#define MAX_VAR_LEN 32
#define MAX_TYPE_LEN 32
#define MAX_PARAMS 8
#define MAX_LOCALS 1600
#define MAX_FIELDS 64
#define MAX_TYPES 64
#define MAX_IR_INSTR 60000
#define MAX_BB_PRED 128
#define MAX_BB_DOM_SUCC 64
#define MAX_BB_RDOM_SUCC 256
#define MAX_GLOBAL_IR 256
#define MAX_SOURCE 524288
#define MAX_CODE 262144
#define MAX_DATA 262144
#define MAX_SYMTAB 65536
#define MAX_STRTAB 65536
#define MAX_HEADER 1024
#define MAX_SECTION 1024
#define MAX_ALIASES 128
#define MAX_CONSTANTS 1024
#define MAX_CASES 128
#define MAX_NESTING 128
#define MAX_OPERAND_STACK_SIZE 32
#define MAX_ANALYSIS_STACK_SIZE 800

/* Default capacities for common data structures */
/* Default arena size is initialized with 256 KiB */
#define DEFAULT_ARENA_SIZE 262144
#define DEFAULT_FUNCS_SIZE 64
#define DEFAULT_INCLUSIONS_SIZE 16

#define ELF_START 0x10000
#define PTR_SIZE 4

/* Number of the available registers. Either 7 or 8 is accepted now. */
#define REG_CNT 8

/* This macro will be automatically defined at shecc run-time. */
#ifdef __SHECC__
/* use do-while as a substitution for nop */
#define UNUSED(x) \
    do {          \
        ;         \
    } while (0)
#define HOST_PTR_SIZE 4
#else
/* suppress GCC/Clang warnings */
#define UNUSED(x) (void) (x)
/* configure host data model when using 'memcpy'. */
#define HOST_PTR_SIZE __SIZEOF_POINTER__
#endif

/* Common data structures */
typedef struct arena_block {
    char *memory;
    int capacity;
    int offset;
    struct arena_block *next;
} arena_block_t;

typedef struct {
    arena_block_t *head;
} arena_t;

/* string-based hash map definitions */

typedef struct hashmap_node {
    char *key;
    void *val;
    struct hashmap_node *next;
} hashmap_node_t;

typedef struct {
    int size;
    int cap;
    hashmap_node_t **buckets;
} hashmap_t;

/* lexer tokens */
typedef enum {
    T_start, /* FIXME: it was intended to start the state machine. */
    T_numeric,
    T_identifier,
    T_comma,  /* , */
    T_string, /* null-terminated string */
    T_char,
    T_open_bracket,  /* ( */
    T_close_bracket, /* ) */
    T_open_curly,    /* { */
    T_close_curly,   /* } */
    T_open_square,   /* [ */
    T_close_square,  /* ] */
    T_asterisk,      /* '*' */
    T_divide,        /* / */
    T_mod,           /* % */
    T_bit_or,        /* | */
    T_bit_xor,       /* ^ */
    T_bit_not,       /* ~ */
    T_log_and,       /* && */
    T_log_or,        /* || */
    T_log_not,       /* ! */
    T_lt,            /* < */
    T_gt,            /* > */
    T_le,            /* <= */
    T_ge,            /* >= */
    T_lshift,        /* << */
    T_rshift,        /* >> */
    T_dot,           /* . */
    T_arrow,         /* -> */
    T_plus,          /* + */
    T_minus,         /* - */
    T_minuseq,       /* -= */
    T_pluseq,        /* += */
    T_asteriskeq,    /* *= */
    T_divideeq,      /* /= */
    T_modeq,         /* %= */
    T_lshifteq,      /* <<= */
    T_rshifteq,      /* >>= */
    T_xoreq,         /* ^= */
    T_oreq,          /* |= */
    T_andeq,         /* &= */
    T_eq,            /* == */
    T_noteq,         /* != */
    T_assign,        /* = */
    T_increment,     /* ++ */
    T_decrement,     /* -- */
    T_question,      /* ? */
    T_colon,         /* : */
    T_semicolon,     /* ; */
    T_eof,           /* end-of-file (EOF) */
    T_ampersand,     /* & */
    T_return,
    T_if,
    T_else,
    T_while,
    T_for,
    T_do,
    T_typedef,
    T_enum,
    T_struct,
    T_sizeof,
    T_elipsis, /* ... */
    T_switch,
    T_case,
    T_break,
    T_default,
    T_continue,
    /* C pre-processor directives */
    T_cppd_include,
    T_cppd_define,
    T_cppd_undef,
    T_cppd_error,
    T_cppd_if,
    T_cppd_elif,
    T_cppd_else,
    T_cppd_endif,
    T_cppd_ifdef,
    T_cppd_ifndef,
    T_cppd_pragma
} token_t;

/* builtin types */
typedef enum {
    TYPE_void = 0,
    TYPE_int,
    TYPE_char,
    TYPE_struct,
    TYPE_typedef
} base_type_t;

/* IR opcode */
typedef enum {
    /* intermediate use in front-end. No code generation */
    OP_generic,

    OP_phi,
    OP_unwound_phi, /* work like address_of + store */

    /* calling convention */
    OP_define,   /* function entry point */
    OP_push,     /* prepare arguments */
    OP_call,     /* function call */
    OP_indirect, /* indirect call with function pointer */
    OP_return,   /* explicit return */

    OP_allocat, /* allocate space on stack */
    OP_assign,
    OP_load_constant,     /* load constant */
    OP_load_data_address, /* lookup address of a constant in data section */

    /* control flow */
    OP_branch,   /* conditional jump */
    OP_jump,     /* unconditional jump */
    OP_func_ret, /* returned value */

    /* function pointer */
    OP_address_of_func, /* resolve function entry */
    OP_load_func,       /* prepare indirective call */
    OP_global_load_func,

    /* memory address operations */
    OP_address_of, /* lookup variable's address */
    OP_global_address_of,
    OP_load, /* load a word from stack */
    OP_global_load,
    OP_store, /* store a word to stack */
    OP_global_store,
    OP_read,  /* read from memory address */
    OP_write, /* write to memory address */

    /* arithmetic operators */
    OP_add,
    OP_sub,
    OP_mul,
    OP_div,     /* signed division */
    OP_mod,     /* modulo */
    OP_ternary, /* ? : */
    OP_lshift,
    OP_rshift,
    OP_log_and,
    OP_log_or,
    OP_log_not,
    OP_eq,  /* equal */
    OP_neq, /* not equal */
    OP_lt,  /* less than */
    OP_leq, /* less than or equal */
    OP_gt,  /* greater than */
    OP_geq, /* greater than or equal */
    OP_bit_or,
    OP_bit_and,
    OP_bit_xor,
    OP_bit_not,
    OP_negate,

    /* data type conversion */
    OP_trunc,
    OP_sign_ext,

    /* entry point of the state machine */
    OP_start
} opcode_t;

/* variable definition */
typedef struct {
    int counter;
    int stack[64];
    int stack_idx;
} rename_t;

typedef struct ref_block ref_block_t;

struct ref_block_list {
    ref_block_t *head;
    ref_block_t *tail;
};

typedef struct ref_block_list ref_block_list_t;

typedef struct insn insn_t;

typedef struct use_chain_node {
    insn_t *insn;
    struct use_chain_node *next;
    struct use_chain_node *prev;
} use_chain_t;

typedef struct var var_t;
typedef struct type type_t;

typedef struct var_list {
    int capacity;
    int size;
    var_t **elements;
} var_list_t;

struct var {
    type_t *type;
    char var_name[MAX_VAR_LEN];
    int is_ptr;
    bool is_func;
    bool is_global;
    int array_size;
    int offset;   /* offset from stack or frame, index 0 is reserved */
    int init_val; /* for global initialization */
    int liveness; /* live range */
    int in_loop;
    struct var *base;
    int subscript;
    struct var *subscripts[64];
    int subscripts_idx;
    rename_t rename;
    ref_block_list_t ref_block_list; /* blocks which kill variable */
    use_chain_t *users_head;
    use_chain_t *users_tail;
    struct insn *last_assign;
    int consumed;
    bool is_ternary_ret;
    bool is_logical_ret;
    bool is_const; /* whether a constant representaion or not */
};

typedef struct {
    char name[MAX_VAR_LEN];
    bool is_variadic;
    int start_source_idx;
    var_t param_defs[MAX_PARAMS];
    int num_param_defs;
    int params[MAX_PARAMS];
    int num_params;
    bool disabled;
} macro_t;

typedef struct func func_t;

/* block definition */
struct block {
    var_list_t locals;
    struct block *parent;
    func_t *func;
    macro_t *macro;
    struct block *next;
};

typedef struct block block_t;
typedef struct basic_block basic_block_t;

/* Definition of a growable buffer for a mutable null-terminated string
 * @size:     Current number of elements in the array
 * @capacity: Number of elements that can be stored without resizing
 * @elements: Pointer to the array of characters
 */
typedef struct {
    int size;
    int capacity;
    char *elements;
} strbuf_t;

/**
 * @brief Phase-2 IR definition
 * Phase-2 IR 是编译器优化阶段使用的一种中级中间表示（Intermediate Representation），
 * 介于前端生成的初始 IR（如抽象语法树 AST）和低级 IR（如 LLVM IR 或机器相关的 RTL）之间
 */
/* phase-2 IR definition */
struct ph2_ir {
    opcode_t op;     ///< 三地址操作码 操作符
    int src0;       ///< 第一个源操作数
    int src1;       ///< 第二个源操作数
    int dest;       ///< 目标操作数
    char func_name[MAX_VAR_LEN];
    basic_block_t *next_bb;
    basic_block_t *then_bb;
    basic_block_t *else_bb;
    struct ph2_ir *next;
    bool is_branch_detached;
};

typedef struct ph2_ir ph2_ir_t;

/* type definition */
struct type {
    char type_name[MAX_TYPE_LEN];
    base_type_t base_type;
    struct type *base_struct;
    int size;
    var_t fields[MAX_FIELDS];
    int num_fields;
};

/* lvalue details */
typedef struct {
    int size;
    int is_ptr;
    bool is_func;
    bool is_reference;
    type_t *type;
} lvalue_t;

/* alias for #defines */
typedef struct {
    char alias[MAX_VAR_LEN];
    char value[MAX_VAR_LEN];
    bool disabled;
} alias_t;

/* constants for enums */
typedef struct {
    char alias[MAX_VAR_LEN];
    int value;
} constant_t;

struct phi_operand {
    var_t *var;
    basic_block_t *from;
    struct phi_operand *next;
};

typedef struct phi_operand phi_operand_t;

/**
 * @brief Instruction definition 第一遍原始指令 IR指令链表
 * This structure represents a single instruction in the
 * intermediate representation (IR) of the compiler.
 * It contains fields for the operation code (opcode),
 * the destination register (rd),
 * the source registers (rs1, rs2),
 * the size of the operation (sz),
 * and a flag indicating whether the instruction is useful 用于死代码消除
 * (used in dead code elimination).
 * It also includes a pointer to the basic block   belong_to
 * to which the instruction belongs,
 * a string representation of the instruction,
 * and a linked list of phi operands
 * for phi nodes in the control flow graph.  存储 Phi 指令的操作数（用于 SSA 形式的静态单赋值优化） ssa 静态单赋值
 * next prev 链表
 * 
*/
struct insn {
    struct insn *next;
    struct insn *prev;
    int idx;
    opcode_t opcode;
    var_t *rd;        ///< 操作数：目标寄存器（rd）和源寄存器（rs1, rs2），支持三地址码形式
    var_t *rs1;
    var_t *rs2;
    int sz;
    bool useful; /* Used in DCE process. Set true if instruction is useful. */
    basic_block_t *belong_to;   ///< 指向所属的基本块（控制流图节点）
    phi_operand_t *phi_ops;     ///< 存储 Phi 指令的操作数（用于 SSA 形式的静态单赋值优化）
    char str[64];               ///< 命令的字符串表示形式，用于调试和输出
};

typedef struct {
    insn_t *head;
    insn_t *tail;
} insn_list_t;

typedef struct {
    ph2_ir_t *head;
    ph2_ir_t *tail;
} ph2_ir_list_t;

typedef enum { NEXT, ELSE, THEN } bb_connection_type_t;

typedef struct {
    basic_block_t *bb;
    bb_connection_type_t type;
} bb_connection_t;

struct symbol {
    var_t *var;
    int index;
    struct symbol *next;
};

typedef struct symbol symbol_t;

typedef struct {
    symbol_t *head;
    symbol_t *tail;
} symbol_list_t;

/**
 * 结构体定义了编译器控制流分析中的核心数据结构——基本块（Basic Block），
 * 它是控制流图（CFG）的核心节点
 * 支配（Dominate）：在控制流图（CFG）中，节点 d 支配节点 n，当且仅当从入口到 n 的所有路径都必须经过 d。
 * 支配边界 DF(d)：所有满足以下条件的节点 b 的集合：
 * 存在一个从 d 到 b 的前驱 a，使得 d 支配 a 但不支配 b。
 * 直观地说：b 是“第一个”不被 d 支配的节点，因此 b 是 d 的支配边界。
 * 
 * 基本块（Basic Block）
 * Basic Block（基本块）是编译器控制流分析和优化的核心概念，表示程序中的一个线性指令序列，具有以下关键特性：
 * 1. 核心定义
 * 单入口：除块的第一条指令外，没有其他指令是跳转目标。
 * 单出口：除块的最后一条指令外，其他指令不会导致控制流转移。
 * 无分支：块内无跳转、循环或条件语句（仅最后一条指令可以是分支指令）。
 * 
 * Basic Block 是编译器优化的原子单位，通过简化控制流复杂性，为数据流分析、指令调度和代码生成提供高效的基础结构。
 */
struct basic_block {
    insn_list_t insn_list;       ///< 原始指令链表 中间表示
    ph2_ir_list_t ph2_ir_list;   ///< Phase-2 IR 指令链表 优化后指令
    bb_connection_t prev[MAX_BB_PRED];   ///< 前驱基本块列表，最多支持 128 个前驱
    /* Used in instruction dumping when ir_dump is enabled. */
    char bb_label_name[MAX_VAR_LEN];     ///< 基本块标签名称 （用于调试输出）
    struct basic_block *next;  /* normal BB */       ///< 下一个基本块（正常顺序执行） 顺序后继
    struct basic_block *then_; /* conditional BB */  ///< 条件分支 真then/假else分支  条件后继
    struct basic_block *else_;                       ///< 条件分支 真then/假else分支  条件后继
    struct basic_block *idom;           ///< 立即支配的基本块（IDOM）直接支配者（Immediate Dominator）父节点
    struct basic_block *r_idom;         ///< 逆后序遍历的立即支配者（R_IDOM）
    struct basic_block *rpo_next;       ///< 逆后序遍历的下一个基本块
    struct basic_block *rpo_r_next;     ///< 逆后序遍历的下一个基本块（反向）
    var_t *live_gen[MAX_ANALYSIS_STACK_SIZE];   ///< 活跃变量生成列表  
    int live_gen_idx;                           ///< 活跃变量生成索引
    var_t *live_kill[MAX_ANALYSIS_STACK_SIZE];  ///< 活跃变量消除列表
    int live_kill_idx;                          ///< 活跃变量消除索引
    var_t *live_in[MAX_ANALYSIS_STACK_SIZE];    ///< 入口活跃变量：进入块时活跃的变量
    int live_in_idx;                            ///< 入口活跃变量索引    
    var_t *live_out[MAX_ANALYSIS_STACK_SIZE];   ///< 出口活跃变量：离开块时活跃的变量
    int live_out_idx;                           ///< 出口活跃变量索引
    int rpo;                                    ///< 逆后序遍历索引
    int rpo_r;                              ///< 逆后序遍历反向索引
    struct basic_block *DF[64];             ///< 支配边界（Dominance Frontier）：用于构建 SSA 形式 支配前驱（DF）列表，最多支持 64 个支配前驱
    struct basic_block *RDF[64];            ///< 逆支配边界（Reverse Dominance Frontier）
    int df_idx;                  ///< 支配边界索引  
    int rdf_idx;            ///< 逆支配边界索引
    int visited;            ///< 是否访问过（用于遍历和分析）
    bool useful; /* indicate whether this BB contains useful instructions */  ///< 是否包含有用的指令
    struct basic_block *dom_next[64];       ///< 支配子节点列表（最多支持 64 个支配子节点） 支配树结构
    struct basic_block *dom_prev;           ///< 支配前驱节点（支配树中的父节点）
    struct basic_block *rdom_next[256];     ///< 逆支配子节点列表（最多支持 256 个逆支配子节点） 逆支配树结构
    struct basic_block *rdom_prev;      ///< 逆支配前驱节点（逆支配树中的父节点）
    func_t *belong_to;                  ///< 所属函数（Function）指针
    block_t *scope;                     ///< 所属作用域（Block）指针 （如循环或条件块）
    symbol_list_t symbol_list; /* variable declaration */ ///< 符号列表（变量声明）符号表 块内局部变量声明
    int elf_offset;         ///< ELF 偏移量（用于代码生成时的符号定位）
};

struct ref_block {
    basic_block_t *bb;
    struct ref_block *next;
};


/* Syntactic representation of func, combines syntactic details (e.g., return
 * type, parameters) with SSA-related information (e.g., basic blocks, control
 * flow) to support parsing, analysis, optimization, and code generation.
 */
struct func {
    /* Syntatic info */
    var_t return_def;                ///< 返回值定义
    var_t param_defs[MAX_PARAMS];    ///< 参数定义列表
    int num_params;                  ///< 参数数量
    int va_args;                     ///< 可变参数标记：非零表示函数接受可变参数（如 printf）
    int stack_size; /* stack always starts at offset 4 for convenience */   ///< 栈空间大小：函数局部变量和临时值的总栈偏移(从 4 开始对齐)

    /* SSA info */
    basic_block_t *bbs;             ///< 基本块列表（控制流图）指向函数的入口基本块
    basic_block_t *exit;            ///< 函数退出基本块（通常是 return 语句所在的块） 出口块
    symbol_list_t global_sym_list;  ///< 全局符号列表（全局变量和函数）符号表 全局变量声明
    int bb_cnt;                     ///< 基本块计数：函数中基本块的数量
    int visited;                    ///< 是否访问过（用于遍历和分析）

    struct func *next;              ///< 下一个函数指针（用于函数链表）链表
};

typedef struct {
    func_t *head;
    func_t *tail;
} func_list_t;

typedef struct {
    func_t *func;
    basic_block_t *bb;
    void (*preorder_cb)(func_t *, basic_block_t *);
    void (*postorder_cb)(func_t *, basic_block_t *);
} bb_traversal_args_t;

typedef struct {
    var_t *var;
    int polluted;
} regfile_t;

/* FIXME: replace char[2] with a short data type in ELF header structures */
/* ELF header */
typedef struct {
    char e_ident[16];
    char e_type[2];
    char e_machine[2];
    int e_version;
    int e_entry;
    int e_phoff;
    int e_shoff;
    int e_flags;
    char e_ehsize[2];
    char e_phentsize[2];
    char e_phnum[2];
    char e_shentsize[2];
    char e_shnum[2];
    char e_shstrndx[2];
} elf32_hdr_t;

/* ELF program header */
typedef struct {
    int p_type;
    int p_offset;
    int p_vaddr;
    int p_paddr;
    int p_filesz;
    int p_memsz;
    int p_flags;
    int p_align;
} elf32_phdr_t;

/* ELF section header */
typedef struct {
    int sh_name;
    int sh_type;
    int sh_flags;
    int sh_addr;
    int sh_offset;
    int sh_size;
    int sh_link;
    int sh_info;
    int sh_addralign;
    int sh_entsize;
} elf32_shdr_t;
