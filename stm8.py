
import sys
import struct
from types import MethodType

from ida_bytes import *
from ida_ua import *
from ida_idp import *
from ida_auto import *
from ida_nalt import *
from ida_funcs import *
from ida_lines import *
from ida_problems import *
from ida_segment import *
from ida_name import *
from ida_netnode import *
from ida_xref import *
from ida_idaapi import *
import ida_frame
import ida_offset
import ida_pro
import idc
import struct
import idaapi
from ida_ida import *
from ida_segregs import *
from ida_struct import *
from ida_diskio import *
import ida_netnode
import ida_xref

itype_map={}

# extract bitfield occupying bits high..low from val (inclusive, start from 0)
def BITS(val, high, low):
  return (val>>low)&((1<<(high-low+1))-1)

# extract one bit
def BIT(val, bit):
  return (val>>bit) & 1

# sign extend b low bits in x
# from "Bit Twiddling Hacks"
def SIGNEXT(x, b):
  m = 1 << (b - 1)
  x = x & ((1 << b) - 1)
  return (x ^ m) - m

def get_signed(value, mask):
    if mask == 0:
        return 0  
    highest_bit = mask.bit_length() - 1
    masked_value = value & mask
    if (masked_value >> highest_bit) & 1:
        return masked_value - (1 << (highest_bit + 1))
    else:
        return masked_value
    

class STM8Processor(processor_t):

    # 处理器基本信息
    id = 0x8002  # 自定义处理器唯一 ID
    flag = idaapi.PR_SEGS | idaapi.PRN_HEX | idaapi.PR_RNAMESOK | idaapi.PR_WORD_INS \
         | idaapi.PR_USE32 | idaapi.PR_DEFSEG32  # 支持 32 位程序
    cnbits = 8  # 指令宽度（命令字宽度）
    dnbits = 8  # 数据宽度
    #psnames = ["TMS320F2837xD"]  # 短名称
    #plnames = ["Texas Instruments TMS320F2837xD DSP"]  # 全称
    psnames = ['stm8']

    # long processor names
    # No restriction on name lengthes.
    plnames = ['STM8']

    reg_first_sreg = 20
    reg_last_sreg  = 21
    segreg_size = 0

        # number of CS register
    reg_code_sreg = 20

        # number of DS register
    reg_data_sreg = 21

    real_width = (0, 7, 15, 0)
    icode_return=0x81
    assembler = {
        # flag
        'flag' : ASH_HEXF0 | ASD_DECF0 | ASO_OCTF5 | ASB_BINF0 | AS_N2CHR,

        # user defined flags (local only for IDP) (optional)
        'uflag' : 0,

        # Assembler name (displayed in menus)
        'name': "Generic stm8 assembler",

        # array of automatically generated header lines they appear at the start of disassembled text (optional)
        'header': [".stm8"],

        # org directive
        'origin': ".org",

        # end directive
        'end': ".end",

        # comment string (see also cmnt2)
        'cmnt': ";",

        # ASCII string delimiter
        'ascsep': '"',

        # ASCII char constant delimiter
        'accsep': '\'',

        # ASCII special chars (they can't appear in character and ascii constants)
        'esccodes': "\"'",

        #
        #      Data representation (db,dw,...):
        #
        # ASCII string directive
        'a_ascii': ".char",

        # byte directive
        'a_byte': ".byte",

        # word directive
        'a_word': ".short",

        # dword (32 bits)
        'a_dword': ".long",

        # qword (64 bits)
        'a_qword': ".quad",
        
        # float;  4bytes; remove if not allowed
        'a_float': ".float",

        # double ; 8bytes; remove if not allowed
        'a_double': ".double",
        'a_tbyte': "",
        'a_packreal':"",
        'a_dups': "",

        # uninitialized data directive (should include '%s' for the size of data)
        'a_bss': ".space %s",

        # 'equ' Used if AS_UNEQU is set (optional)
        'a_equ': ".set",

        # 'seg ' prefix (example: push seg seg001)
        'a_seg': "seg",

        # current IP (instruction pointer) symbol in assembler
        'a_curip': "$",
        'out_func_header': "",
        'out_func_footer': "",

        # "public" name keyword. NULL-gen default, ""-do not generate
        'a_public': ".global",

        # "weak"   name keyword. NULL-gen default, ""-do not generate
        'a_weak': "",

        # "extrn"  name keyword
        'a_extrn': ".ref",

        # "comm" (communal variable)
        'a_comdef': "",

        # "align" keyword
        'a_align': ".align",

        # Left and right braces used in complex expressions
        'lbrace': "(",
        'rbrace': ")",

        # %  mod     assembler time operation
        'a_mod': "%",

        # &  bit and assembler time operation
        'a_band': "&",

        # |  bit or  assembler time operation
        'a_bor': "|",

        # ^  bit xor assembler time operation
        'a_xor': "^",

        # ~  bit not assembler time operation
        'a_bnot': "~",

        # << shift left assembler time operation
        'a_shl': "<<",

        # >> shift right assembler time operation
        'a_shr': ">>",

        # size of type (format string) (optional)
        'a_sizeof_fmt': "size %s",

        'flag2': 0,

        # the include directive (format string) (optional)
        'a_include_fmt': '.include "%s"',
    } # Assembler

    
    Instructions = ['','ADD']
    #instruction map multi instruction list
    instruc=[{'name':"",'feature':0x0},
            {'name': 'adc', 'feature': 0x304},
            {'name': 'add', 'feature': 0x304},
            {'name': 'addw', 'feature': 0x304},
            {'name': 'and', 'feature': 0x304},
            {'name': 'bccm', 'feature': 0x304},
            {'name': 'bcpl', 'feature': 0x304},
            {'name': 'bcp', 'feature': 0x304},
            {'name': 'bres', 'feature': 0x304},
            {'name': 'bset', 'feature': 0x304},
            {'name': 'btjf', 'feature': 0x304|CF_JUMP},
            {'name': 'btjt', 'feature': 0x304|CF_JUMP},
            {'name': 'call', 'feature': CF_CALL},
            {'name': 'callf', 'feature': CF_CALL},
            {'name': 'callr', 'feature': CF_CALL},
            {'name': 'ccf', 'feature': 0x304},
            {'name': 'clr', 'feature': 0x304},
            {'name': 'clrw', 'feature': 0x304},
            {'name': 'cp', 'feature': 0x304},
            {'name': 'cpw', 'feature': 0x304},
            {'name': 'cpl', 'feature': 0x304},
            {'name': 'cplw', 'feature': 0x304},
            {'name': 'dec', 'feature': 0x304},
            {'name': 'decw', 'feature': 0x304},
            {'name': 'div', 'feature': 0x304},
            {'name': 'exg', 'feature': 0x304},
            {'name': 'exgw', 'feature': 0x304},
            {'name': 'halt', 'feature': 0x304},
            {'name': 'inc', 'feature': 0x304},
            {'name': 'incw', 'feature': 0x304},
            {'name': 'int', 'feature': 0x304},
            {'name': 'iret', 'feature': 0x304},
            {'name': 'jp', 'feature': 0x304|CF_JUMP},
            {'name': 'jpf', 'feature': 0x304|CF_JUMP},
            {'name': 'jra', 'feature': 0x304|CF_JUMP},
            {'name': 'ld', 'feature': 0x304},
            {'name': 'ldf', 'feature': 0x304},
            {'name': 'ldw', 'feature': 0x304},
            {'name': 'mov', 'feature': 0x304},
            {'name': 'mul', 'feature': 0x304},
            {'name': 'neg', 'feature': 0x304},
            {'name': 'negw', 'feature': 0x304},
            {'name': 'nop', 'feature': 0x304},
            {'name': 'or', 'feature': 0x304},
            {'name': 'pop', 'feature': 0x304},
            {'name': 'popw', 'feature': 0x304},
            {'name': 'push', 'feature': 0x304},
            {'name': 'pushw', 'feature': 0x304},
            {'name': 'rcf', 'feature': 0x304},
            {'name': 'ret', 'feature': 0x304},
            {'name': 'retf', 'feature': 0x304},
            {'name': 'rim', 'feature': 0x304},
            {'name': 'rlc', 'feature': 0x304},
            {'name': 'rlcw', 'feature': 0x304},
            {'name': 'rlwa', 'feature': 0x304},
            {'name': 'rrc', 'feature': 0x304},
            {'name': 'rrcw', 'feature': 0x304},
            {'name': 'rrwa', 'feature': 0x304},
            {'name': 'rvf', 'feature': 0x304},
            {'name': 'sbc', 'feature': 0x304},
            {'name': 'scf', 'feature': 0x304},
            {'name': 'sim', 'feature': 0x304},
            {'name': 'sll', 'feature': 0x304},
            {'name': 'sllw', 'feature': 0x304},
            {'name': 'sra', 'feature': 0x304},
            {'name': 'sraw', 'feature': 0x304},
            {'name': 'srl', 'feature': 0x304},
            {'name': 'srlw', 'feature': 0x304},
            {'name': 'sub', 'feature': 0x304},
            {'name': 'subw', 'feature': 0x304},
            {'name': 'swap', 'feature': 0x304},
            {'name': 'swapw', 'feature': 0x304},
            {'name': 'tnz', 'feature': 0x304},
            {'name': 'tnzw', 'feature': 0x304},
            {'name': 'trap', 'feature': 0x304},
            {'name': 'wfe', 'feature': 0x304},
            {'name': 'wfi', 'feature': 0x304},
            {'name': 'xor', 'feature': 0x304},
            {"name": "jrc","feature":CF_USE1|CF_JUMP},
            {"name": "jreq","feature":CF_USE1|CF_JUMP},
            {"name": "jrf","feature":CF_USE1|CF_JUMP},
            {"name": "jrh","feature":CF_USE1|CF_JUMP},
            {"name": "jrih","feature":CF_USE1|CF_JUMP},
            {"name": "jril","feature":CF_USE1|CF_JUMP},
            {"name": "jrm","feature":CF_USE1|CF_JUMP},
            {"name": "jrmi","feature":CF_USE1|CF_JUMP},
            {"name": "jrnc","feature":CF_USE1|CF_JUMP},
            {"name": "jrne","feature":CF_USE1|CF_JUMP},
            {"name": "jrnh","feature":CF_USE1|CF_JUMP},
            {"name": "jrnm","feature":CF_USE1|CF_JUMP},
            {"name": "jrnv","feature":CF_USE1|CF_JUMP},
            {"name": "jrpl","feature":CF_USE1|CF_JUMP},
            {"name": "jrsge","feature":CF_USE1|CF_JUMP},
            {"name": "jrsgt","feature":CF_USE1|CF_JUMP},
            {"name": "jrsle","feature":CF_USE1|CF_JUMP},
            {"name": "jrslt","feature":CF_USE1|CF_JUMP},
            {"name": "jrt","feature":CF_USE1|CF_JUMP},
            {"name": "jruge","feature":CF_USE1|CF_JUMP},
            {"name": "jrugt","feature":CF_USE1|CF_JUMP},
            {"name": "jrule","feature":CF_USE1|CF_JUMP},
            {"name": "jrc","feature":CF_USE1|CF_JUMP},
            {"name": "jrult","feature":CF_USE1|CF_JUMP},
            {"name": "jrv","feature":CF_USE1|CF_JUMP}
           ]
    instruc_start = 0

    # icode of the last instruction + 1
    
    instruc_end = len(instruc) + 1
    
    
    ins_map={0x00a9 : {"name" : "adc", "ins_type" :"single", "insn_size": 2, "opcode_mask": 0xff},
                    0x00b9 : {"name" : "adc", "ins_type" :"single", "insn_size": 2, "opcode_mask": 0xff},
                    0x00c9 : {"name" : "adc", "ins_type" :"single", "insn_size": 3, "opcode_mask": 0xff},
                    0x00f9 : {"name" : "adc", "ins_type" :"single", "insn_size": 1, "opcode_mask": 0xff},
                    0x00e9 : {"name" : "adc", "ins_type" :"single", "insn_size": 2, "opcode_mask": 0xff},
                    0x00d9 : {"name" : "adc", "ins_type" :"single", "insn_size": 3, "opcode_mask": 0xff},
                    0x90f9 : {"name" : "adc", "ins_type" :"single", "insn_size": 2, "opcode_mask": 0xffff},
                    0x90e9 : {"name" : "adc", "ins_type" :"single", "insn_size": 3, "opcode_mask": 0xffff},
                    0x90d9 : {"name" : "adc", "ins_type" :"single", "insn_size": 4, "opcode_mask": 0xffff},
                    0x0019 : {"name" : "adc", "ins_type" :"single", "insn_size": 2, "opcode_mask": 0xff},
                    0x92c9 : {"name" : "adc", "ins_type" :"single", "insn_size": 3, "opcode_mask": 0xffff},
                    0x72c9 : {"name" : "adc", "ins_type" :"single", "insn_size": 4, "opcode_mask": 0xffff},
                    0x92d9 : {"name" : "adc", "ins_type" :"single", "insn_size": 3, "opcode_mask": 0xffff},
                    0x72d9 : {"name" : "adc", "ins_type" :"single", "insn_size": 4, "opcode_mask": 0xffff},
                    0x91d9 : {"name" : "adc", "ins_type" :"single", "insn_size": 3, "opcode_mask": 0xffff},
                    0x00ab : {"name" : "add", "ins_type" :"single", "insn_size": 2, "opcode_mask": 0xff},
                    0x00bb : {"name" : "add", "ins_type" :"single", "insn_size": 2, "opcode_mask": 0xff},
                    0x00cb : {"name" : "add", "ins_type" :"single", "insn_size": 3, "opcode_mask": 0xff},
                    0x00fb : {"name" : "add", "ins_type" :"single", "insn_size": 1, "opcode_mask": 0xff},
                    0x00eb : {"name" : "add", "ins_type" :"single", "insn_size": 2, "opcode_mask": 0xff},
                    0x00db : {"name" : "add", "ins_type" :"single", "insn_size": 3, "opcode_mask": 0xff},
                    0x90fb : {"name" : "add", "ins_type" :"single", "insn_size": 2, "opcode_mask": 0xffff},
                    0x90eb : {"name" : "add", "ins_type" :"single", "insn_size": 3, "opcode_mask": 0xffff},
                    0x90db : {"name" : "add", "ins_type" :"single", "insn_size": 4, "opcode_mask": 0xffff},
                    0x001b : {"name" : "add", "ins_type" :"single", "insn_size": 2, "opcode_mask": 0xff},
                    0x92cb : {"name" : "add", "ins_type" :"single", "insn_size": 3, "opcode_mask": 0xffff},
                    0x72cb : {"name" : "add", "ins_type" :"single", "insn_size": 4, "opcode_mask": 0xffff},
                    0x92db : {"name" : "add", "ins_type" :"single", "insn_size": 3, "opcode_mask": 0xffff},
                    0x72db : {"name" : "add", "ins_type" :"single", "insn_size": 4, "opcode_mask": 0xffff},
                    0x91db : {"name" : "add", "ins_type" :"single", "insn_size": 3, "opcode_mask": 0xffff},
                    0x001c : {"name" : "addw", "ins_type" :"single", "insn_size": 3, "opcode_mask": 0xff},
                    0x72bb : {"name" : "addw", "ins_type" :"single", "insn_size": 4, "opcode_mask": 0xffff},
                    0x72fb : {"name" : "addw", "ins_type" :"single", "insn_size": 3, "opcode_mask": 0xffff},
                    0x72a9 : {"name" : "addw", "ins_type" :"single", "insn_size": 4, "opcode_mask": 0xffff},
                    0x72b9 : {"name" : "addw", "ins_type" :"single", "insn_size": 4, "opcode_mask": 0xffff},
                    0x72f9 : {"name" : "addw", "ins_type" :"single", "insn_size": 3, "opcode_mask": 0xffff},
                    0x005b : {"name" : "addw", "ins_type" :"single", "insn_size": 2, "opcode_mask": 0xff},
                    0x00a4 : {"name" : "and", "ins_type" :"single", "insn_size": 2, "opcode_mask": 0xff},
                    0x00b4 : {"name" : "and", "ins_type" :"single", "insn_size": 2, "opcode_mask": 0xff},
                    0x00c4 : {"name" : "and", "ins_type" :"single", "insn_size": 3, "opcode_mask": 0xff},
                    0x00f4 : {"name" : "and", "ins_type" :"single", "insn_size": 1, "opcode_mask": 0xff},
                    0x00e4 : {"name" : "and", "ins_type" :"single", "insn_size": 2, "opcode_mask": 0xff},
                    0x00d4 : {"name" : "and", "ins_type" :"single", "insn_size": 3, "opcode_mask": 0xff},
                    0x90f4 : {"name" : "and", "ins_type" :"single", "insn_size": 2, "opcode_mask": 0xffff},
                    0x90e4 : {"name" : "and", "ins_type" :"single", "insn_size": 3, "opcode_mask": 0xffff},
                    0x90d4 : {"name" : "and", "ins_type" :"single", "insn_size": 4, "opcode_mask": 0xffff},
                    0x0014 : {"name" : "and", "ins_type" :"single", "insn_size": 2, "opcode_mask": 0xff},
                    0x92c4 : {"name" : "and", "ins_type" :"single", "insn_size": 3, "opcode_mask": 0xffff},
                    0x72c4 : {"name" : "and", "ins_type" :"single", "insn_size": 4, "opcode_mask": 0xffff},
                    0x92d4 : {"name" : "and", "ins_type" :"single", "insn_size": 3, "opcode_mask": 0xffff},
                    0x72d4 : {"name" : "and", "ins_type" :"single", "insn_size": 4, "opcode_mask": 0xffff},
                    0x91d4 : {"name" : "and", "ins_type" :"single", "insn_size": 3, "opcode_mask": 0xffff},
                    0x901 : {"name" : "bccm_dup", "ins_type" :"dup", "insn_size": 4, "cmt":"bccm bcpl", "opcode_mask": 0xfff},
                    0x00a5 : {"name" : "bcp", "ins_type" :"single", "insn_size": 2, "opcode_mask": 0xff},
                    0x00b5 : {"name" : "bcp", "ins_type" :"single", "insn_size": 2, "opcode_mask": 0xff},
                    0x00c5 : {"name" : "bcp", "ins_type" :"single", "insn_size": 3, "opcode_mask": 0xff},
                    0x00f5 : {"name" : "bcp", "ins_type" :"single", "insn_size": 1, "opcode_mask": 0xff},
                    0x00e5 : {"name" : "bcp", "ins_type" :"single", "insn_size": 2, "opcode_mask": 0xff},
                    0x00d5 : {"name" : "bcp", "ins_type" :"single", "insn_size": 3, "opcode_mask": 0xff},
                    0x90f5 : {"name" : "bcp", "ins_type" :"single", "insn_size": 2, "opcode_mask": 0xffff},
                    0x90e5 : {"name" : "bcp", "ins_type" :"single", "insn_size": 3, "opcode_mask": 0xffff},
                    0x90d5 : {"name" : "bcp", "ins_type" :"single", "insn_size": 4, "opcode_mask": 0xffff},
                    0x0015 : {"name" : "bcp", "ins_type" :"single", "insn_size": 2, "opcode_mask": 0xff},
                    0x92c5 : {"name" : "bcp", "ins_type" :"single", "insn_size": 3, "opcode_mask": 0xffff},
                    0x72c5 : {"name" : "bcp", "ins_type" :"single", "insn_size": 4, "opcode_mask": 0xffff},
                    0x92d5 : {"name" : "bcp", "ins_type" :"single", "insn_size": 3, "opcode_mask": 0xffff},
                    0x72d5 : {"name" : "bcp", "ins_type" :"single", "insn_size": 4, "opcode_mask": 0xffff},
                    0x91d5 : {"name" : "bcp", "ins_type" :"single", "insn_size": 3, "opcode_mask": 0xffff},
                    0x008b : {"name" : "bcpl", "ins_type" :"single", "insn_size": 1, "opcode_mask": 0xff},
                    0x721 : {"name" : "bres_dup", "ins_type" :"dup", "insn_size": 4, "cmt":"bres bset", "opcode_mask": 0xfff},
                    0x720 : {"name" : "btjf_dup", "ins_type" :"dup", "insn_size": 5, "cmt":"btjf btjt", "opcode_mask": 0xfff},
                    0x00cd : {"name" : "call", "ins_type" :"single", "insn_size": 3, "opcode_mask": 0xff},
                    0x00fd : {"name" : "call", "ins_type" :"single", "insn_size": 1, "opcode_mask": 0xff},
                    0x00ed : {"name" : "call", "ins_type" :"single", "insn_size": 2, "opcode_mask": 0xff},
                    0x00dd : {"name" : "call", "ins_type" :"single", "insn_size": 3, "opcode_mask": 0xff},
                    0x90fd : {"name" : "call", "ins_type" :"single", "insn_size": 2, "opcode_mask": 0xffff},
                    0x90ed : {"name" : "call", "ins_type" :"single", "insn_size": 3, "opcode_mask": 0xffff},
                    0x90dd : {"name" : "call", "ins_type" :"single", "insn_size": 4, "opcode_mask": 0xffff},
                    0x92cd : {"name" : "call", "ins_type" :"single", "insn_size": 3, "opcode_mask": 0xffff},
                    0x72cd : {"name" : "call", "ins_type" :"single", "insn_size": 4, "opcode_mask": 0xffff},
                    0x92dd : {"name" : "call", "ins_type" :"single", "insn_size": 3, "opcode_mask": 0xffff},
                    0x72dd : {"name" : "call", "ins_type" :"single", "insn_size": 4, "opcode_mask": 0xffff},
                    0x91dd : {"name" : "call", "ins_type" :"single", "insn_size": 3, "opcode_mask": 0xffff},
                    0x008d : {"name" : "callf", "ins_type" :"single", "insn_size": 4, "opcode_mask": 0xff},
                    0x928d : {"name" : "callf", "ins_type" :"single", "insn_size": 4, "opcode_mask": 0xffff},
                    0x00ad : {"name" : "callr", "ins_type" :"single", "insn_size": 2, "opcode_mask": 0xff},
                    0x008c : {"name" : "ccf", "ins_type" :"single", "insn_size": 1, "opcode_mask": 0xff},
                    0x004f : {"name" : "clr", "ins_type" :"single", "insn_size": 1, "opcode_mask": 0xff},
                    0x003f : {"name" : "clr", "ins_type" :"single", "insn_size": 2, "opcode_mask": 0xff},
                    0x725f : {"name" : "clr", "ins_type" :"single", "insn_size": 4, "opcode_mask": 0xffff},
                    0x007f : {"name" : "clr", "ins_type" :"single", "insn_size": 1, "opcode_mask": 0xff},
                    0x006f : {"name" : "clr", "ins_type" :"single", "insn_size": 2, "opcode_mask": 0xff},
                    0x724f : {"name" : "clr", "ins_type" :"single", "insn_size": 4, "opcode_mask": 0xffff},
                    0x907f : {"name" : "clr", "ins_type" :"single", "insn_size": 2, "opcode_mask": 0xffff},
                    0x906f : {"name" : "clr", "ins_type" :"single", "insn_size": 3, "opcode_mask": 0xffff},
                    0x904f : {"name" : "clr", "ins_type" :"single", "insn_size": 4, "opcode_mask": 0xffff},
                    0x000f : {"name" : "clr", "ins_type" :"single", "insn_size": 2, "opcode_mask": 0xff},
                    0x923f : {"name" : "clr", "ins_type" :"single", "insn_size": 3, "opcode_mask": 0xffff},
                    0x723f : {"name" : "clr", "ins_type" :"single", "insn_size": 4, "opcode_mask": 0xffff},
                    0x926f : {"name" : "clr", "ins_type" :"single", "insn_size": 3, "opcode_mask": 0xffff},
                    0x726f : {"name" : "clr", "ins_type" :"single", "insn_size": 4, "opcode_mask": 0xffff},
                    0x916f : {"name" : "clr", "ins_type" :"single", "insn_size": 3, "opcode_mask": 0xffff},
                    0x005f : {"name" : "clrw", "ins_type" :"single", "insn_size": 1, "opcode_mask": 0xff},
                    0x905f : {"name" : "clrw", "ins_type" :"single", "insn_size": 2, "opcode_mask": 0xffff},
                    0x00a1 : {"name" : "cp", "ins_type" :"single", "insn_size": 2, "opcode_mask": 0xff},
                    0x00b1 : {"name" : "cp", "ins_type" :"single", "insn_size": 2, "opcode_mask": 0xff},
                    0x00c1 : {"name" : "cp", "ins_type" :"single", "insn_size": 3, "opcode_mask": 0xff},
                    0x00f1 : {"name" : "cp", "ins_type" :"single", "insn_size": 1, "opcode_mask": 0xff},
                    0x00e1 : {"name" : "cp", "ins_type" :"single", "insn_size": 2, "opcode_mask": 0xff},
                    0x00d1 : {"name" : "cp", "ins_type" :"single", "insn_size": 3, "opcode_mask": 0xff},
                    0x90f1 : {"name" : "cp", "ins_type" :"single", "insn_size": 2, "opcode_mask": 0xffff},
                    0x90e1 : {"name" : "cp", "ins_type" :"single", "insn_size": 3, "opcode_mask": 0xffff},
                    0x90d1 : {"name" : "cp", "ins_type" :"single", "insn_size": 4, "opcode_mask": 0xffff},
                    0x0011 : {"name" : "cp", "ins_type" :"single", "insn_size": 2, "opcode_mask": 0xff},
                    0x92c1 : {"name" : "cp", "ins_type" :"single", "insn_size": 3, "opcode_mask": 0xffff},
                    0x72c1 : {"name" : "cp", "ins_type" :"single", "insn_size": 4, "opcode_mask": 0xffff},
                    0x92d1 : {"name" : "cp", "ins_type" :"single", "insn_size": 3, "opcode_mask": 0xffff},
                    0x72d1 : {"name" : "cp", "ins_type" :"single", "insn_size": 4, "opcode_mask": 0xffff},
                    0x91d1 : {"name" : "cp", "ins_type" :"single", "insn_size": 3, "opcode_mask": 0xffff},
                    0x00a3 : {"name" : "cpw", "ins_type" :"single", "insn_size": 3, "opcode_mask": 0xff},
                    0x00b3 : {"name" : "cpw", "ins_type" :"single", "insn_size": 2, "opcode_mask": 0xff},
                    0x00c3 : {"name" : "cpw", "ins_type" :"single", "insn_size": 3, "opcode_mask": 0xff},
                    0x90f3 : {"name" : "cpw", "ins_type" :"single", "insn_size": 2, "opcode_mask": 0xffff},
                    0x90e3 : {"name" : "cpw", "ins_type" :"single", "insn_size": 3, "opcode_mask": 0xffff},
                    0x90d3 : {"name" : "cpw", "ins_type" :"single", "insn_size": 4, "opcode_mask": 0xffff},
                    0x0013 : {"name" : "cpw", "ins_type" :"single", "insn_size": 2, "opcode_mask": 0xff},
                    0x92c3 : {"name" : "cpw", "ins_type" :"single", "insn_size": 3, "opcode_mask": 0xffff},
                    0x72c3 : {"name" : "cpw", "ins_type" :"single", "insn_size": 4, "opcode_mask": 0xffff},
                    0x91d3 : {"name" : "cpw", "ins_type" :"single", "insn_size": 3, "opcode_mask": 0xffff},
                    0x90a3 : {"name" : "cpw", "ins_type" :"single", "insn_size": 4, "opcode_mask": 0xffff},
                    0x90b3 : {"name" : "cpw", "ins_type" :"single", "insn_size": 3, "opcode_mask": 0xffff},
                    0x90c3 : {"name" : "cpw", "ins_type" :"single", "insn_size": 4, "opcode_mask": 0xffff},
                    0x00f3 : {"name" : "cpw", "ins_type" :"single", "insn_size": 1, "opcode_mask": 0xff},
                    0x00e3 : {"name" : "cpw", "ins_type" :"single", "insn_size": 2, "opcode_mask": 0xff},
                    0x00d3 : {"name" : "cpw", "ins_type" :"single", "insn_size": 3, "opcode_mask": 0xff},
                    0x91c3 : {"name" : "cpw", "ins_type" :"single", "insn_size": 3, "opcode_mask": 0xffff},
                    0x92d3 : {"name" : "cpw", "ins_type" :"single", "insn_size": 3, "opcode_mask": 0xffff},
                    0x72d3 : {"name" : "cpw", "ins_type" :"single", "insn_size": 4, "opcode_mask": 0xffff},
                    0x0043 : {"name" : "cpl", "ins_type" :"single", "insn_size": 1, "opcode_mask": 0xff},
                    0x0033 : {"name" : "cpl", "ins_type" :"single", "insn_size": 2, "opcode_mask": 0xff},
                    0x7253 : {"name" : "cpl", "ins_type" :"single", "insn_size": 4, "opcode_mask": 0xffff},
                    0x0073 : {"name" : "cpl", "ins_type" :"single", "insn_size": 1, "opcode_mask": 0xff},
                    0x0063 : {"name" : "cpl", "ins_type" :"single", "insn_size": 2, "opcode_mask": 0xff},
                    0x7243 : {"name" : "cpl", "ins_type" :"single", "insn_size": 4, "opcode_mask": 0xffff},
                    0x9073 : {"name" : "cpl", "ins_type" :"single", "insn_size": 2, "opcode_mask": 0xffff},
                    0x9063 : {"name" : "cpl", "ins_type" :"single", "insn_size": 3, "opcode_mask": 0xffff},
                    0x9043 : {"name" : "cpl", "ins_type" :"single", "insn_size": 4, "opcode_mask": 0xffff},
                    0x0003 : {"name" : "cpl", "ins_type" :"single", "insn_size": 2, "opcode_mask": 0xff},
                    0x9233 : {"name" : "cpl", "ins_type" :"single", "insn_size": 3, "opcode_mask": 0xffff},
                    0x7233 : {"name" : "cpl", "ins_type" :"single", "insn_size": 4, "opcode_mask": 0xffff},
                    0x9263 : {"name" : "cpl", "ins_type" :"single", "insn_size": 3, "opcode_mask": 0xffff},
                    0x7263 : {"name" : "cpl", "ins_type" :"single", "insn_size": 4, "opcode_mask": 0xffff},
                    0x9163 : {"name" : "cpl", "ins_type" :"single", "insn_size": 3, "opcode_mask": 0xffff},
                    0x0053 : {"name" : "cplw", "ins_type" :"single", "insn_size": 1, "opcode_mask": 0xff},
                    0x9053 : {"name" : "cplw", "ins_type" :"single", "insn_size": 2, "opcode_mask": 0xffff},
                    0x004a : {"name" : "dec", "ins_type" :"single", "insn_size": 1, "opcode_mask": 0xff},
                    0x003a : {"name" : "dec", "ins_type" :"single", "insn_size": 2, "opcode_mask": 0xff},
                    0x725a : {"name" : "dec", "ins_type" :"single", "insn_size": 4, "opcode_mask": 0xffff},
                    0x007a : {"name" : "dec", "ins_type" :"single", "insn_size": 1, "opcode_mask": 0xff},
                    0x006a : {"name" : "dec", "ins_type" :"single", "insn_size": 2, "opcode_mask": 0xff},
                    0x724a : {"name" : "dec", "ins_type" :"single", "insn_size": 4, "opcode_mask": 0xffff},
                    0x907a : {"name" : "dec", "ins_type" :"single", "insn_size": 2, "opcode_mask": 0xffff},
                    0x906a : {"name" : "dec", "ins_type" :"single", "insn_size": 3, "opcode_mask": 0xffff},
                    0x904a : {"name" : "dec", "ins_type" :"single", "insn_size": 4, "opcode_mask": 0xffff},
                    0x000a : {"name" : "dec", "ins_type" :"single", "insn_size": 2, "opcode_mask": 0xff},
                    0x923a : {"name" : "dec", "ins_type" :"single", "insn_size": 3, "opcode_mask": 0xffff},
                    0x723a : {"name" : "dec", "ins_type" :"single", "insn_size": 4, "opcode_mask": 0xffff},
                    0x926a : {"name" : "dec", "ins_type" :"single", "insn_size": 3, "opcode_mask": 0xffff},
                    0x726a : {"name" : "dec", "ins_type" :"single", "insn_size": 4, "opcode_mask": 0xffff},
                    0x916a : {"name" : "dec", "ins_type" :"single", "insn_size": 3, "opcode_mask": 0xffff},
                    0x005a : {"name" : "decw", "ins_type" :"single", "insn_size": 1, "opcode_mask": 0xff},
                    0x905a : {"name" : "decw", "ins_type" :"single", "insn_size": 2, "opcode_mask": 0xffff},
                    0x0062 : {"name" : "div", "ins_type" :"single", "insn_size": 1, "opcode_mask": 0xff},
                    0x9062 : {"name" : "div", "ins_type" :"single", "insn_size": 2, "opcode_mask": 0xffff},
                    0x0065 : {"name" : "div", "ins_type" :"single", "insn_size": 1, "opcode_mask": 0xff},
                    0x0041 : {"name" : "exg", "ins_type" :"single", "insn_size": 1, "opcode_mask": 0xff},
                    0x0051 : {"name" : "exgw", "ins_type" :"single", "insn_size": 1, "opcode_mask": 0xff},
                    0x0061 : {"name" : "exg", "ins_type" :"single", "insn_size": 1, "opcode_mask": 0xff},
                    0x0031 : {"name" : "exg", "ins_type" :"single", "insn_size": 3, "opcode_mask": 0xff},
                    0x008e : {"name" : "halt", "ins_type" :"single", "insn_size": 1, "opcode_mask": 0xff},
                    0x004c : {"name" : "inc", "ins_type" :"single", "insn_size": 1, "opcode_mask": 0xff},
                    0x003c : {"name" : "inc", "ins_type" :"single", "insn_size": 2, "opcode_mask": 0xff},
                    0x725c : {"name" : "inc", "ins_type" :"single", "insn_size": 4, "opcode_mask": 0xffff},
                    0x007c : {"name" : "inc", "ins_type" :"single", "insn_size": 1, "opcode_mask": 0xff},
                    0x006c : {"name" : "inc", "ins_type" :"single", "insn_size": 2, "opcode_mask": 0xff},
                    0x724c : {"name" : "inc", "ins_type" :"single", "insn_size": 4, "opcode_mask": 0xffff},
                    0x907c : {"name" : "inc", "ins_type" :"single", "insn_size": 2, "opcode_mask": 0xffff},
                    0x906c : {"name" : "inc", "ins_type" :"single", "insn_size": 3, "opcode_mask": 0xffff},
                    0x904c : {"name" : "inc", "ins_type" :"single", "insn_size": 4, "opcode_mask": 0xffff},
                    0x000c : {"name" : "inc", "ins_type" :"single", "insn_size": 2, "opcode_mask": 0xff},
                    0x923c : {"name" : "inc", "ins_type" :"single", "insn_size": 3, "opcode_mask": 0xffff},
                    0x723c : {"name" : "inc", "ins_type" :"single", "insn_size": 4, "opcode_mask": 0xffff},
                    0x926c : {"name" : "inc", "ins_type" :"single", "insn_size": 3, "opcode_mask": 0xffff},
                    0x726c : {"name" : "inc", "ins_type" :"single", "insn_size": 4, "opcode_mask": 0xffff},
                    0x916c : {"name" : "inc", "ins_type" :"single", "insn_size": 3, "opcode_mask": 0xffff},
                    0x005c : {"name" : "incw", "ins_type" :"single", "insn_size": 1, "opcode_mask": 0xff},
                    0x905c : {"name" : "incw", "ins_type" :"single", "insn_size": 2, "opcode_mask": 0xffff},
                    0x0082 : {"name" : "int", "ins_type" :"single", "insn_size": 4, "opcode_mask": 0xff},
                    0x0080 : {"name" : "iret", "ins_type" :"single", "insn_size": 1, "opcode_mask": 0xff},
                    0x00cc : {"name" : "jp", "ins_type" :"single", "insn_size": 3, "opcode_mask": 0xff},
                    0x00fc : {"name" : "jp", "ins_type" :"single", "insn_size": 1, "opcode_mask": 0xff},
                    0x00ec : {"name" : "jp", "ins_type" :"single", "insn_size": 2, "opcode_mask": 0xff},
                    0x00dc : {"name" : "jp", "ins_type" :"single", "insn_size": 3, "opcode_mask": 0xff},
                    0x90fc : {"name" : "jp", "ins_type" :"single", "insn_size": 2, "opcode_mask": 0xffff},
                    0x90ec : {"name" : "jp", "ins_type" :"single", "insn_size": 3, "opcode_mask": 0xffff},
                    0x90dc : {"name" : "jp", "ins_type" :"single", "insn_size": 4, "opcode_mask": 0xffff},
                    0x92cc : {"name" : "jp", "ins_type" :"single", "insn_size": 3, "opcode_mask": 0xffff},
                    0x72cc : {"name" : "jp", "ins_type" :"single", "insn_size": 4, "opcode_mask": 0xffff},
                    0x92dc : {"name" : "jp", "ins_type" :"single", "insn_size": 3, "opcode_mask": 0xffff},
                    0x72dc : {"name" : "jp", "ins_type" :"single", "insn_size": 4, "opcode_mask": 0xffff},
                    0x91dc : {"name" : "jp", "ins_type" :"single", "insn_size": 3, "opcode_mask": 0xffff},
                    0x00ac : {"name" : "jpf", "ins_type" :"single", "insn_size": 4, "opcode_mask": 0xff},
                    0x92ac : {"name" : "jpf", "ins_type" :"single", "insn_size": 4, "opcode_mask": 0xffff},
                    0x0020 : {"name" : "jra", "ins_type" :"single", "insn_size": 2, "opcode_mask": 0xff},
                    0x00a6 : {"name" : "ld", "ins_type" :"single", "insn_size": 2, "opcode_mask": 0xff},
                    0x00b6 : {"name" : "ld", "ins_type" :"single", "insn_size": 2, "opcode_mask": 0xff},
                    0x00c6 : {"name" : "ld", "ins_type" :"single", "insn_size": 3, "opcode_mask": 0xff},
                    0x00f6 : {"name" : "ld", "ins_type" :"single", "insn_size": 1, "opcode_mask": 0xff},
                    0x00e6 : {"name" : "ld", "ins_type" :"single", "insn_size": 2, "opcode_mask": 0xff},
                    0x00d6 : {"name" : "ld", "ins_type" :"single", "insn_size": 3, "opcode_mask": 0xff},
                    0x90f6 : {"name" : "ld", "ins_type" :"single", "insn_size": 2, "opcode_mask": 0xffff},
                    0x90e6 : {"name" : "ld", "ins_type" :"single", "insn_size": 3, "opcode_mask": 0xffff},
                    0x90d6 : {"name" : "ld", "ins_type" :"single", "insn_size": 4, "opcode_mask": 0xffff},
                    0x007b : {"name" : "ld", "ins_type" :"single", "insn_size": 2, "opcode_mask": 0xff},
                    0x92c6 : {"name" : "ld", "ins_type" :"single", "insn_size": 3, "opcode_mask": 0xffff},
                    0x72c6 : {"name" : "ld", "ins_type" :"single", "insn_size": 4, "opcode_mask": 0xffff},
                    0x92d6 : {"name" : "ld", "ins_type" :"single", "insn_size": 3, "opcode_mask": 0xffff},
                    0x72d6 : {"name" : "ld", "ins_type" :"single", "insn_size": 4, "opcode_mask": 0xffff},
                    0x91d6 : {"name" : "ld", "ins_type" :"single", "insn_size": 3, "opcode_mask": 0xffff},
                    0x00b7 : {"name" : "ld", "ins_type" :"single", "insn_size": 2, "opcode_mask": 0xff},
                    0x00c7 : {"name" : "ld", "ins_type" :"single", "insn_size": 3, "opcode_mask": 0xff},
                    0x00f7 : {"name" : "ld", "ins_type" :"single", "insn_size": 1, "opcode_mask": 0xff},
                    0x00e7 : {"name" : "ld", "ins_type" :"single", "insn_size": 2, "opcode_mask": 0xff},
                    0x00d7 : {"name" : "ld", "ins_type" :"single", "insn_size": 3, "opcode_mask": 0xff},
                    0x90f7 : {"name" : "ld", "ins_type" :"single", "insn_size": 2, "opcode_mask": 0xffff},
                    0x90e7 : {"name" : "ld", "ins_type" :"single", "insn_size": 3, "opcode_mask": 0xffff},
                    0x90d7 : {"name" : "ld", "ins_type" :"single", "insn_size": 4, "opcode_mask": 0xffff},
                    0x006b : {"name" : "ld", "ins_type" :"single", "insn_size": 2, "opcode_mask": 0xff},
                    0x92c7 : {"name" : "ld", "ins_type" :"single", "insn_size": 3, "opcode_mask": 0xffff},
                    0x72c7 : {"name" : "ld", "ins_type" :"single", "insn_size": 4, "opcode_mask": 0xffff},
                    0x92d7 : {"name" : "ld", "ins_type" :"single", "insn_size": 3, "opcode_mask": 0xffff},
                    0x72d7 : {"name" : "ld", "ins_type" :"single", "insn_size": 4, "opcode_mask": 0xffff},
                    0x91d7 : {"name" : "ld", "ins_type" :"single", "insn_size": 3, "opcode_mask": 0xffff},
                    0x0097 : {"name" : "ld", "ins_type" :"single", "insn_size": 1, "opcode_mask": 0xff},
                    0x009f : {"name" : "ld", "ins_type" :"single", "insn_size": 1, "opcode_mask": 0xff},
                    0x9097 : {"name" : "ld", "ins_type" :"single", "insn_size": 2, "opcode_mask": 0xffff},
                    0x909f : {"name" : "ld", "ins_type" :"single", "insn_size": 2, "opcode_mask": 0xffff},
                    0x0095 : {"name" : "ld", "ins_type" :"single", "insn_size": 1, "opcode_mask": 0xff},
                    0x009e : {"name" : "ld", "ins_type" :"single", "insn_size": 1, "opcode_mask": 0xff},
                    0x9095 : {"name" : "ld", "ins_type" :"single", "insn_size": 2, "opcode_mask": 0xffff},
                    0x909e : {"name" : "ld", "ins_type" :"single", "insn_size": 2, "opcode_mask": 0xffff},
                    0x00bc : {"name" : "ldf", "ins_type" :"single", "insn_size": 4, "opcode_mask": 0xff},
                    0x00af : {"name" : "ldf", "ins_type" :"single", "insn_size": 4, "opcode_mask": 0xff},
                    0x90af : {"name" : "ldf", "ins_type" :"single", "insn_size": 5, "opcode_mask": 0xffff},
                    0x92af : {"name" : "ldf", "ins_type" :"single", "insn_size": 4, "opcode_mask": 0xffff},
                    0x91af : {"name" : "ldf", "ins_type" :"single", "insn_size": 4, "opcode_mask": 0xffff},
                    0x92bc : {"name" : "ldf", "ins_type" :"single", "insn_size": 4, "opcode_mask": 0xffff},
                    0x00bd : {"name" : "ldf", "ins_type" :"single", "insn_size": 4, "opcode_mask": 0xff},
                    0x00a7 : {"name" : "ldf", "ins_type" :"single", "insn_size": 4, "opcode_mask": 0xff},
                    0x90a7 : {"name" : "ldf", "ins_type" :"single", "insn_size": 5, "opcode_mask": 0xffff},
                    0x92a7 : {"name" : "ldf", "ins_type" :"single", "insn_size": 4, "opcode_mask": 0xffff},
                    0x91a7 : {"name" : "ldf", "ins_type" :"single", "insn_size": 4, "opcode_mask": 0xffff},
                    0x92bd : {"name" : "ldf", "ins_type" :"single", "insn_size": 4, "opcode_mask": 0xffff},
                    0x00ae : {"name" : "ldw", "ins_type" :"single", "insn_size": 3, "opcode_mask": 0xff},
                    0x00be : {"name" : "ldw", "ins_type" :"single", "insn_size": 2, "opcode_mask": 0xff},
                    0x00ce : {"name" : "ldw", "ins_type" :"single", "insn_size": 3, "opcode_mask": 0xff},
                    0x00fe : {"name" : "ldw", "ins_type" :"single", "insn_size": 1, "opcode_mask": 0xff},
                    0x00ee : {"name" : "ldw", "ins_type" :"single", "insn_size": 2, "opcode_mask": 0xff},
                    0x00de : {"name" : "ldw", "ins_type" :"single", "insn_size": 3, "opcode_mask": 0xff},
                    0x001e : {"name" : "ldw", "ins_type" :"single", "insn_size": 2, "opcode_mask": 0xff},
                    0x92ce : {"name" : "ldw", "ins_type" :"single", "insn_size": 3, "opcode_mask": 0xffff},
                    0x72ce : {"name" : "ldw", "ins_type" :"single", "insn_size": 4, "opcode_mask": 0xffff},
                    0x92de : {"name" : "ldw", "ins_type" :"single", "insn_size": 3, "opcode_mask": 0xffff},
                    0x72de : {"name" : "ldw", "ins_type" :"single", "insn_size": 4, "opcode_mask": 0xffff},
                    0x00bf : {"name" : "ldw", "ins_type" :"single", "insn_size": 2, "opcode_mask": 0xff},
                    0x00cf : {"name" : "ldw", "ins_type" :"single", "insn_size": 3, "opcode_mask": 0xff},
                    0x00ff : {"name" : "ldw", "ins_type" :"single", "insn_size": 1, "opcode_mask": 0xff},
                    0x00ef : {"name" : "ldw", "ins_type" :"single", "insn_size": 2, "opcode_mask": 0xff},
                    0x00df : {"name" : "ldw", "ins_type" :"single", "insn_size": 3, "opcode_mask": 0xff},
                    0x001f : {"name" : "ldw", "ins_type" :"single", "insn_size": 2, "opcode_mask": 0xff},
                    0x92cf : {"name" : "ldw", "ins_type" :"single", "insn_size": 3, "opcode_mask": 0xffff},
                    0x72cf : {"name" : "ldw", "ins_type" :"single", "insn_size": 4, "opcode_mask": 0xffff},
                    0x92df : {"name" : "ldw", "ins_type" :"single", "insn_size": 3, "opcode_mask": 0xffff},
                    0x72df : {"name" : "ldw", "ins_type" :"single", "insn_size": 4, "opcode_mask": 0xffff},
                    0x90ae : {"name" : "ldw", "ins_type" :"single", "insn_size": 4, "opcode_mask": 0xffff},
                    0x90be : {"name" : "ldw", "ins_type" :"single", "insn_size": 3, "opcode_mask": 0xffff},
                    0x90ce : {"name" : "ldw", "ins_type" :"single", "insn_size": 4, "opcode_mask": 0xffff},
                    0x90fe : {"name" : "ldw", "ins_type" :"single", "insn_size": 2, "opcode_mask": 0xffff},
                    0x90ee : {"name" : "ldw", "ins_type" :"single", "insn_size": 3, "opcode_mask": 0xffff},
                    0x90de : {"name" : "ldw", "ins_type" :"single", "insn_size": 4, "opcode_mask": 0xffff},
                    0x0016 : {"name" : "ldw", "ins_type" :"single", "insn_size": 2, "opcode_mask": 0xff},
                    0x91ce : {"name" : "ldw", "ins_type" :"single", "insn_size": 3, "opcode_mask": 0xffff},
                    0x91de : {"name" : "ldw", "ins_type" :"single", "insn_size": 3, "opcode_mask": 0xffff},
                    0x90bf : {"name" : "ldw", "ins_type" :"single", "insn_size": 3, "opcode_mask": 0xffff},
                    0x90cf : {"name" : "ldw", "ins_type" :"single", "insn_size": 4, "opcode_mask": 0xffff},
                    0x90ff : {"name" : "ldw", "ins_type" :"single", "insn_size": 2, "opcode_mask": 0xffff},
                    0x90ef : {"name" : "ldw", "ins_type" :"single", "insn_size": 3, "opcode_mask": 0xffff},
                    0x90df : {"name" : "ldw", "ins_type" :"single", "insn_size": 4, "opcode_mask": 0xffff},
                    0x0017 : {"name" : "ldw", "ins_type" :"single", "insn_size": 2, "opcode_mask": 0xff},
                    0x91cf : {"name" : "ldw", "ins_type" :"single", "insn_size": 3, "opcode_mask": 0xffff},
                    0x91df : {"name" : "ldw", "ins_type" :"single", "insn_size": 3, "opcode_mask": 0xffff},
                    0x9093 : {"name" : "ldw", "ins_type" :"single", "insn_size": 2, "opcode_mask": 0xffff},
                    0x0093 : {"name" : "ldw", "ins_type" :"single", "insn_size": 1, "opcode_mask": 0xff},
                    0x0096 : {"name" : "ldw", "ins_type" :"single", "insn_size": 1, "opcode_mask": 0xff},
                    0x0094 : {"name" : "ldw", "ins_type" :"single", "insn_size": 1, "opcode_mask": 0xff},
                    0x9096 : {"name" : "ldw", "ins_type" :"single", "insn_size": 2, "opcode_mask": 0xffff},
                    0x9094 : {"name" : "ldw", "ins_type" :"single", "insn_size": 2, "opcode_mask": 0xffff},
                    0x0035 : {"name" : "mov", "ins_type" :"single", "insn_size": 4, "opcode_mask": 0xff},
                    0x0045 : {"name" : "mov", "ins_type" :"single", "insn_size": 3, "opcode_mask": 0xff},
                    0x0055 : {"name" : "mov", "ins_type" :"single", "insn_size": 5, "opcode_mask": 0xff},
                    0x0042 : {"name" : "mul", "ins_type" :"single", "insn_size": 1, "opcode_mask": 0xff},
                    0x9042 : {"name" : "mul", "ins_type" :"single", "insn_size": 2, "opcode_mask": 0xffff},
                    0x0040 : {"name" : "neg", "ins_type" :"single", "insn_size": 1, "opcode_mask": 0xff},
                    0x0030 : {"name" : "neg", "ins_type" :"single", "insn_size": 2, "opcode_mask": 0xff},
                    0x7250 : {"name" : "neg", "ins_type" :"single", "insn_size": 4, "opcode_mask": 0xffff},
                    0x0070 : {"name" : "neg", "ins_type" :"single", "insn_size": 1, "opcode_mask": 0xff},
                    0x0060 : {"name" : "neg", "ins_type" :"single", "insn_size": 2, "opcode_mask": 0xff},
                    0x7240 : {"name" : "neg", "ins_type" :"single", "insn_size": 4, "opcode_mask": 0xffff},
                    0x9070 : {"name" : "neg", "ins_type" :"single", "insn_size": 2, "opcode_mask": 0xffff},
                    0x9060 : {"name" : "neg", "ins_type" :"single", "insn_size": 3, "opcode_mask": 0xffff},
                    0x9040 : {"name" : "neg", "ins_type" :"single", "insn_size": 4, "opcode_mask": 0xffff},
                    0x0000 : {"name" : "neg", "ins_type" :"single", "insn_size": 2, "opcode_mask": 0xff},
                    0x9230 : {"name" : "neg", "ins_type" :"single", "insn_size": 3, "opcode_mask": 0xffff},
                    0x7230 : {"name" : "neg", "ins_type" :"single", "insn_size": 4, "opcode_mask": 0xffff},
                    0x9260 : {"name" : "neg", "ins_type" :"single", "insn_size": 3, "opcode_mask": 0xffff},
                    0x7260 : {"name" : "neg", "ins_type" :"single", "insn_size": 4, "opcode_mask": 0xffff},
                    0x9160 : {"name" : "neg", "ins_type" :"single", "insn_size": 3, "opcode_mask": 0xffff},
                    0x0050 : {"name" : "negw", "ins_type" :"single", "insn_size": 1, "opcode_mask": 0xff},
                    0x9050 : {"name" : "negw", "ins_type" :"single", "insn_size": 2, "opcode_mask": 0xffff},
                    0x009d : {"name" : "nop", "ins_type" :"single", "insn_size": 1, "opcode_mask": 0xff},
                    0x00aa : {"name" : "or", "ins_type" :"single", "insn_size": 2, "opcode_mask": 0xff},
                    0x00ba : {"name" : "or", "ins_type" :"single", "insn_size": 2, "opcode_mask": 0xff},
                    0x00ca : {"name" : "or", "ins_type" :"single", "insn_size": 3, "opcode_mask": 0xff},
                    0x00fa : {"name" : "or", "ins_type" :"single", "insn_size": 1, "opcode_mask": 0xff},
                    0x00ea : {"name" : "or", "ins_type" :"single", "insn_size": 2, "opcode_mask": 0xff},
                    0x00da : {"name" : "or", "ins_type" :"single", "insn_size": 3, "opcode_mask": 0xff},
                    0x90fa : {"name" : "or", "ins_type" :"single", "insn_size": 2, "opcode_mask": 0xffff},
                    0x90ea : {"name" : "or", "ins_type" :"single", "insn_size": 3, "opcode_mask": 0xffff},
                    0x90da : {"name" : "or", "ins_type" :"single", "insn_size": 4, "opcode_mask": 0xffff},
                    0x001a : {"name" : "or", "ins_type" :"single", "insn_size": 2, "opcode_mask": 0xff},
                    0x92ca : {"name" : "or", "ins_type" :"single", "insn_size": 3, "opcode_mask": 0xffff},
                    0x72ca : {"name" : "or", "ins_type" :"single", "insn_size": 4, "opcode_mask": 0xffff},
                    0x92da : {"name" : "or", "ins_type" :"single", "insn_size": 3, "opcode_mask": 0xffff},
                    0x72da : {"name" : "or", "ins_type" :"single", "insn_size": 4, "opcode_mask": 0xffff},
                    0x91da : {"name" : "or", "ins_type" :"single", "insn_size": 3, "opcode_mask": 0xffff},
                    0x0084 : {"name" : "pop", "ins_type" :"single", "insn_size": 1, "opcode_mask": 0xff},
                    0x0086 : {"name" : "pop", "ins_type" :"single", "insn_size": 1, "opcode_mask": 0xff},
                    0x0032 : {"name" : "pop", "ins_type" :"single", "insn_size": 3, "opcode_mask": 0xff},
                    0x0085 : {"name" : "popw", "ins_type" :"single", "insn_size": 1, "opcode_mask": 0xff},
                    0x9085 : {"name" : "popw", "ins_type" :"single", "insn_size": 2, "opcode_mask": 0xffff},
                    0x0088 : {"name" : "push", "ins_type" :"single", "insn_size": 1, "opcode_mask": 0xff},
                    0x008a : {"name" : "push", "ins_type" :"single", "insn_size": 1, "opcode_mask": 0xff},
                    0x004b : {"name" : "push", "ins_type" :"single", "insn_size": 2, "opcode_mask": 0xff},
                    0x003b : {"name" : "push", "ins_type" :"single", "insn_size": 3, "opcode_mask": 0xff},
                    0x0089 : {"name" : "pushw", "ins_type" :"single", "insn_size": 1, "opcode_mask": 0xff},
                    0x9089 : {"name" : "pushw", "ins_type" :"single", "insn_size": 2, "opcode_mask": 0xffff},
                    0x0098 : {"name" : "rcf", "ins_type" :"single", "insn_size": 1, "opcode_mask": 0xff},
                    0x0081 : {"name" : "ret", "ins_type" :"single", "insn_size": 1, "opcode_mask": 0xff},
                    0x0087 : {"name" : "retf", "ins_type" :"single", "insn_size": 1, "opcode_mask": 0xff},
                    0x009a : {"name" : "rim", "ins_type" :"single", "insn_size": 1, "opcode_mask": 0xff},
                    0x0049 : {"name" : "rlc", "ins_type" :"single", "insn_size": 1, "opcode_mask": 0xff},
                    0x0039 : {"name" : "rlc", "ins_type" :"single", "insn_size": 2, "opcode_mask": 0xff},
                    0x7259 : {"name" : "rlc", "ins_type" :"single", "insn_size": 4, "opcode_mask": 0xffff},
                    0x0079 : {"name" : "rlc", "ins_type" :"single", "insn_size": 1, "opcode_mask": 0xff},
                    0x0069 : {"name" : "rlc", "ins_type" :"single", "insn_size": 2, "opcode_mask": 0xff},
                    0x7249 : {"name" : "rlc", "ins_type" :"single", "insn_size": 4, "opcode_mask": 0xffff},
                    0x9079 : {"name" : "rlc", "ins_type" :"single", "insn_size": 2, "opcode_mask": 0xffff},
                    0x9069 : {"name" : "rlc", "ins_type" :"single", "insn_size": 3, "opcode_mask": 0xffff},
                    0x9049 : {"name" : "rlc", "ins_type" :"single", "insn_size": 4, "opcode_mask": 0xffff},
                    0x0009 : {"name" : "rlc", "ins_type" :"single", "insn_size": 2, "opcode_mask": 0xff},
                    0x9239 : {"name" : "rlc", "ins_type" :"single", "insn_size": 3, "opcode_mask": 0xffff},
                    0x7239 : {"name" : "rlc", "ins_type" :"single", "insn_size": 4, "opcode_mask": 0xffff},
                    0x9269 : {"name" : "rlc", "ins_type" :"single", "insn_size": 3, "opcode_mask": 0xffff},
                    0x7269 : {"name" : "rlc", "ins_type" :"single", "insn_size": 4, "opcode_mask": 0xffff},
                    0x9169 : {"name" : "rlc", "ins_type" :"single", "insn_size": 3, "opcode_mask": 0xffff},
                    0x0059 : {"name" : "rlcw", "ins_type" :"single", "insn_size": 1, "opcode_mask": 0xff},
                    0x9059 : {"name" : "rlcw", "ins_type" :"single", "insn_size": 2, "opcode_mask": 0xffff},
                    0x0002 : {"name" : "rlwa", "ins_type" :"single", "insn_size": 1, "opcode_mask": 0xff},
                    0x9002 : {"name" : "rlwa", "ins_type" :"single", "insn_size": 2, "opcode_mask": 0xffff},
                    0x0046 : {"name" : "rrc", "ins_type" :"single", "insn_size": 1, "opcode_mask": 0xff},
                    0x0036 : {"name" : "rrc", "ins_type" :"single", "insn_size": 2, "opcode_mask": 0xff},
                    0x7256 : {"name" : "rrc", "ins_type" :"single", "insn_size": 4, "opcode_mask": 0xffff},
                    0x0076 : {"name" : "rrc", "ins_type" :"single", "insn_size": 1, "opcode_mask": 0xff},
                    0x0066 : {"name" : "rrc", "ins_type" :"single", "insn_size": 2, "opcode_mask": 0xff},
                    0x7246 : {"name" : "rrc", "ins_type" :"single", "insn_size": 4, "opcode_mask": 0xffff},
                    0x9076 : {"name" : "rrc", "ins_type" :"single", "insn_size": 2, "opcode_mask": 0xffff},
                    0x9066 : {"name" : "rrc", "ins_type" :"single", "insn_size": 3, "opcode_mask": 0xffff},
                    0x9046 : {"name" : "rrc", "ins_type" :"single", "insn_size": 4, "opcode_mask": 0xffff},
                    0x0006 : {"name" : "rrc", "ins_type" :"single", "insn_size": 2, "opcode_mask": 0xff},
                    0x9236 : {"name" : "rrc", "ins_type" :"single", "insn_size": 3, "opcode_mask": 0xffff},
                    0x7236 : {"name" : "rrc", "ins_type" :"single", "insn_size": 4, "opcode_mask": 0xffff},
                    0x9266 : {"name" : "rrc", "ins_type" :"single", "insn_size": 3, "opcode_mask": 0xffff},
                    0x7266 : {"name" : "rrc", "ins_type" :"single", "insn_size": 4, "opcode_mask": 0xffff},
                    0x9166 : {"name" : "rrc", "ins_type" :"single", "insn_size": 3, "opcode_mask": 0xffff},
                    0x0056 : {"name" : "rrcw", "ins_type" :"single", "insn_size": 1, "opcode_mask": 0xff},
                    0x9056 : {"name" : "rrcw", "ins_type" :"single", "insn_size": 2, "opcode_mask": 0xffff},
                    0x0001 : {"name" : "rrwa", "ins_type" :"single", "insn_size": 1, "opcode_mask": 0xff},
                    0x9001 : {"name" : "rrwa", "ins_type" :"single", "insn_size": 2, "opcode_mask": 0xffff},
                    0x009c : {"name" : "rvf", "ins_type" :"single", "insn_size": 1, "opcode_mask": 0xff},
                    0x00a2 : {"name" : "sbc", "ins_type" :"single", "insn_size": 2, "opcode_mask": 0xff},
                    0x00b2 : {"name" : "sbc", "ins_type" :"single", "insn_size": 2, "opcode_mask": 0xff},
                    0x00c2 : {"name" : "sbc", "ins_type" :"single", "insn_size": 3, "opcode_mask": 0xff},
                    0x00f2 : {"name" : "sbc", "ins_type" :"single", "insn_size": 1, "opcode_mask": 0xff},
                    0x00e2 : {"name" : "sbc", "ins_type" :"single", "insn_size": 2, "opcode_mask": 0xff},
                    0x00d2 : {"name" : "sbc", "ins_type" :"single", "insn_size": 3, "opcode_mask": 0xff},
                    0x90f2 : {"name" : "sbc", "ins_type" :"single", "insn_size": 2, "opcode_mask": 0xffff},
                    0x90e2 : {"name" : "sbc", "ins_type" :"single", "insn_size": 3, "opcode_mask": 0xffff},
                    0x90d2 : {"name" : "sbc", "ins_type" :"single", "insn_size": 4, "opcode_mask": 0xffff},
                    0x0012 : {"name" : "sbc", "ins_type" :"single", "insn_size": 2, "opcode_mask": 0xff},
                    0x92c2 : {"name" : "sbc", "ins_type" :"single", "insn_size": 3, "opcode_mask": 0xffff},
                    0x72c2 : {"name" : "sbc", "ins_type" :"single", "insn_size": 4, "opcode_mask": 0xffff},
                    0x92d2 : {"name" : "sbc", "ins_type" :"single", "insn_size": 3, "opcode_mask": 0xffff},
                    0x72d2 : {"name" : "sbc", "ins_type" :"single", "insn_size": 4, "opcode_mask": 0xffff},
                    0x91d2 : {"name" : "sbc", "ins_type" :"single", "insn_size": 3, "opcode_mask": 0xffff},
                    0x0099 : {"name" : "scf", "ins_type" :"single", "insn_size": 1, "opcode_mask": 0xff},
                    0x009b : {"name" : "sim", "ins_type" :"single", "insn_size": 1, "opcode_mask": 0xff},
                    0x0048 : {"name" : "sll", "ins_type" :"single", "insn_size": 1, "opcode_mask": 0xff},
                    0x0038 : {"name" : "sll", "ins_type" :"single", "insn_size": 2, "opcode_mask": 0xff},
                    0x7258 : {"name" : "sll", "ins_type" :"single", "insn_size": 4, "opcode_mask": 0xffff},
                    0x0078 : {"name" : "sll", "ins_type" :"single", "insn_size": 1, "opcode_mask": 0xff},
                    0x0068 : {"name" : "sll", "ins_type" :"single", "insn_size": 2, "opcode_mask": 0xff},
                    0x7248 : {"name" : "sll", "ins_type" :"single", "insn_size": 4, "opcode_mask": 0xffff},
                    0x9078 : {"name" : "sll", "ins_type" :"single", "insn_size": 2, "opcode_mask": 0xffff},
                    0x9068 : {"name" : "sll", "ins_type" :"single", "insn_size": 3, "opcode_mask": 0xffff},
                    0x9048 : {"name" : "sll", "ins_type" :"single", "insn_size": 4, "opcode_mask": 0xffff},
                    0x0008 : {"name" : "sll", "ins_type" :"single", "insn_size": 2, "opcode_mask": 0xff},
                    0x9238 : {"name" : "sll", "ins_type" :"single", "insn_size": 3, "opcode_mask": 0xffff},
                    0x7238 : {"name" : "sll", "ins_type" :"single", "insn_size": 4, "opcode_mask": 0xffff},
                    0x9268 : {"name" : "sll", "ins_type" :"single", "insn_size": 3, "opcode_mask": 0xffff},
                    0x0058 : {"name" : "sllw", "ins_type" :"single", "insn_size": 1, "opcode_mask": 0xff},
                    0x9058 : {"name" : "sllw", "ins_type" :"single", "insn_size": 2, "opcode_mask": 0xffff},
                    0x0047 : {"name" : "sra", "ins_type" :"single", "insn_size": 1, "opcode_mask": 0xff},
                    0x0037 : {"name" : "sra", "ins_type" :"single", "insn_size": 2, "opcode_mask": 0xff},
                    0x7257 : {"name" : "sra", "ins_type" :"single", "insn_size": 4, "opcode_mask": 0xffff},
                    0x0077 : {"name" : "sra", "ins_type" :"single", "insn_size": 1, "opcode_mask": 0xff},
                    0x0067 : {"name" : "sra", "ins_type" :"single", "insn_size": 2, "opcode_mask": 0xff},
                    0x7247 : {"name" : "sra", "ins_type" :"single", "insn_size": 4, "opcode_mask": 0xffff},
                    0x9077 : {"name" : "sra", "ins_type" :"single", "insn_size": 2, "opcode_mask": 0xffff},
                    0x9067 : {"name" : "sra", "ins_type" :"single", "insn_size": 3, "opcode_mask": 0xffff},
                    0x9047 : {"name" : "sra", "ins_type" :"single", "insn_size": 4, "opcode_mask": 0xffff},
                    0x0007 : {"name" : "sra", "ins_type" :"single", "insn_size": 2, "opcode_mask": 0xff},
                    0x9237 : {"name" : "sra", "ins_type" :"single", "insn_size": 3, "opcode_mask": 0xffff},
                    0x7237 : {"name" : "sra", "ins_type" :"single", "insn_size": 4, "opcode_mask": 0xffff},
                    0x9267 : {"name" : "sra", "ins_type" :"single", "insn_size": 3, "opcode_mask": 0xffff},
                    0x7267 : {"name" : "sra", "ins_type" :"single", "insn_size": 4, "opcode_mask": 0xffff},
                    0x9167 : {"name" : "sra", "ins_type" :"single", "insn_size": 3, "opcode_mask": 0xffff},
                    0x0057 : {"name" : "sraw", "ins_type" :"single", "insn_size": 1, "opcode_mask": 0xff},
                    0x9057 : {"name" : "sraw", "ins_type" :"single", "insn_size": 2, "opcode_mask": 0xffff},
                    0x0044 : {"name" : "srl", "ins_type" :"single", "insn_size": 1, "opcode_mask": 0xff},
                    0x0034 : {"name" : "srl", "ins_type" :"single", "insn_size": 2, "opcode_mask": 0xff},
                    0x7254 : {"name" : "srl", "ins_type" :"single", "insn_size": 4, "opcode_mask": 0xffff},
                    0x0074 : {"name" : "srl", "ins_type" :"single", "insn_size": 1, "opcode_mask": 0xff},
                    0x0064 : {"name" : "srl", "ins_type" :"single", "insn_size": 2, "opcode_mask": 0xff},
                    0x7244 : {"name" : "srl", "ins_type" :"single", "insn_size": 4, "opcode_mask": 0xffff},
                    0x9074 : {"name" : "srl", "ins_type" :"single", "insn_size": 2, "opcode_mask": 0xffff},
                    0x9064 : {"name" : "srl", "ins_type" :"single", "insn_size": 3, "opcode_mask": 0xffff},
                    0x9044 : {"name" : "srl", "ins_type" :"single", "insn_size": 4, "opcode_mask": 0xffff},
                    0x0004 : {"name" : "srl", "ins_type" :"single", "insn_size": 2, "opcode_mask": 0xff},
                    0x9234 : {"name" : "srl", "ins_type" :"single", "insn_size": 3, "opcode_mask": 0xffff},
                    0x7234 : {"name" : "srl", "ins_type" :"single", "insn_size": 4, "opcode_mask": 0xffff},
                    0x9264 : {"name" : "srl", "ins_type" :"single", "insn_size": 3, "opcode_mask": 0xffff},
                    0x7264 : {"name" : "srl", "ins_type" :"single", "insn_size": 4, "opcode_mask": 0xffff},
                    0x9164 : {"name" : "srl", "ins_type" :"single", "insn_size": 3, "opcode_mask": 0xffff},
                    0x0054 : {"name" : "srlw", "ins_type" :"single", "insn_size": 1, "opcode_mask": 0xff},
                    0x9054 : {"name" : "srlw", "ins_type" :"single", "insn_size": 2, "opcode_mask": 0xffff},
                    0x00a0 : {"name" : "sub", "ins_type" :"single", "insn_size": 2, "opcode_mask": 0xff},
                    0x00b0 : {"name" : "sub", "ins_type" :"single", "insn_size": 2, "opcode_mask": 0xff},
                    0x00c0 : {"name" : "sub", "ins_type" :"single", "insn_size": 3, "opcode_mask": 0xff},
                    0x00f0 : {"name" : "sub", "ins_type" :"single", "insn_size": 1, "opcode_mask": 0xff},
                    0x00e0 : {"name" : "sub", "ins_type" :"single", "insn_size": 2, "opcode_mask": 0xff},
                    0x00d0 : {"name" : "sub", "ins_type" :"single", "insn_size": 3, "opcode_mask": 0xff},
                    0x90f0 : {"name" : "sub", "ins_type" :"single", "insn_size": 2, "opcode_mask": 0xffff},
                    0x90e0 : {"name" : "sub", "ins_type" :"single", "insn_size": 3, "opcode_mask": 0xffff},
                    0x90d0 : {"name" : "sub", "ins_type" :"single", "insn_size": 4, "opcode_mask": 0xffff},
                    0x0010 : {"name" : "sub", "ins_type" :"single", "insn_size": 2, "opcode_mask": 0xff},
                    0x92c0 : {"name" : "sub", "ins_type" :"single", "insn_size": 3, "opcode_mask": 0xffff},
                    0x72c0 : {"name" : "sub", "ins_type" :"single", "insn_size": 4, "opcode_mask": 0xffff},
                    0x92d0 : {"name" : "sub", "ins_type" :"single", "insn_size": 3, "opcode_mask": 0xffff},
                    0x72d0 : {"name" : "sub", "ins_type" :"single", "insn_size": 4, "opcode_mask": 0xffff},
                    0x91d0 : {"name" : "sub", "ins_type" :"single", "insn_size": 3, "opcode_mask": 0xffff},
                    0x0052 : {"name" : "sub", "ins_type" :"single", "insn_size": 2, "opcode_mask": 0xff},
                    0x001d : {"name" : "subw", "ins_type" :"single", "insn_size": 3, "opcode_mask": 0xff},
                    0x72b0 : {"name" : "subw", "ins_type" :"single", "insn_size": 4, "opcode_mask": 0xffff},
                    0x72f0 : {"name" : "subw", "ins_type" :"single", "insn_size": 3, "opcode_mask": 0xffff},
                    0x72a2 : {"name" : "subw", "ins_type" :"single", "insn_size": 4, "opcode_mask": 0xffff},
                    0x72b2 : {"name" : "subw", "ins_type" :"single", "insn_size": 4, "opcode_mask": 0xffff},
                    0x72f2 : {"name" : "subw", "ins_type" :"single", "insn_size": 3, "opcode_mask": 0xffff},
                    0x004e : {"name" : "swap", "ins_type" :"single", "insn_size": 1, "opcode_mask": 0xff},
                    0x003e : {"name" : "swap", "ins_type" :"single", "insn_size": 2, "opcode_mask": 0xff},
                    0x725e : {"name" : "swap", "ins_type" :"single", "insn_size": 4, "opcode_mask": 0xffff},
                    0x007e : {"name" : "swap", "ins_type" :"single", "insn_size": 1, "opcode_mask": 0xff},
                    0x006e : {"name" : "swap", "ins_type" :"single", "insn_size": 2, "opcode_mask": 0xff},
                    0x724e : {"name" : "swap", "ins_type" :"single", "insn_size": 4, "opcode_mask": 0xffff},
                    0x907e : {"name" : "swap", "ins_type" :"single", "insn_size": 2, "opcode_mask": 0xffff},
                    0x906e : {"name" : "swap", "ins_type" :"single", "insn_size": 3, "opcode_mask": 0xffff},
                    0x904e : {"name" : "swap", "ins_type" :"single", "insn_size": 4, "opcode_mask": 0xffff},
                    0x000e : {"name" : "swap", "ins_type" :"single", "insn_size": 2, "opcode_mask": 0xff},
                    0x923e : {"name" : "swap", "ins_type" :"single", "insn_size": 3, "opcode_mask": 0xffff},
                    0x723e : {"name" : "swap", "ins_type" :"single", "insn_size": 4, "opcode_mask": 0xffff},
                    0x926e : {"name" : "swap", "ins_type" :"single", "insn_size": 3, "opcode_mask": 0xffff},
                    0x726e : {"name" : "swap", "ins_type" :"single", "insn_size": 4, "opcode_mask": 0xffff},
                    0x916e : {"name" : "swap", "ins_type" :"single", "insn_size": 3, "opcode_mask": 0xffff},
                    0x005e : {"name" : "swapw", "ins_type" :"single", "insn_size": 1, "opcode_mask": 0xff},
                    0x905e : {"name" : "swapw", "ins_type" :"single", "insn_size": 2, "opcode_mask": 0xffff},
                    0x004d : {"name" : "tnz", "ins_type" :"single", "insn_size": 1, "opcode_mask": 0xff},
                    0x003d : {"name" : "tnz", "ins_type" :"single", "insn_size": 2, "opcode_mask": 0xff},
                    0x725d : {"name" : "tnz", "ins_type" :"single", "insn_size": 4, "opcode_mask": 0xffff},
                    0x007d : {"name" : "tnz", "ins_type" :"single", "insn_size": 1, "opcode_mask": 0xff},
                    0x006d : {"name" : "tnz", "ins_type" :"single", "insn_size": 2, "opcode_mask": 0xff},
                    0x724d : {"name" : "tnz", "ins_type" :"single", "insn_size": 4, "opcode_mask": 0xffff},
                    0x907d : {"name" : "tnz", "ins_type" :"single", "insn_size": 2, "opcode_mask": 0xffff},
                    0x906d : {"name" : "tnz", "ins_type" :"single", "insn_size": 3, "opcode_mask": 0xffff},
                    0x904d : {"name" : "tnz", "ins_type" :"single", "insn_size": 4, "opcode_mask": 0xffff},
                    0x000d : {"name" : "tnz", "ins_type" :"single", "insn_size": 2, "opcode_mask": 0xff},
                    0x923d : {"name" : "tnz", "ins_type" :"single", "insn_size": 3, "opcode_mask": 0xffff},
                    0x723d : {"name" : "tnz", "ins_type" :"single", "insn_size": 4, "opcode_mask": 0xffff},
                    0x926d : {"name" : "tnz", "ins_type" :"single", "insn_size": 3, "opcode_mask": 0xffff},
                    0x726d : {"name" : "tnz", "ins_type" :"single", "insn_size": 4, "opcode_mask": 0xffff},
                    0x916d : {"name" : "tnz", "ins_type" :"single", "insn_size": 3, "opcode_mask": 0xffff},
                    0x005d : {"name" : "tnzw", "ins_type" :"single", "insn_size": 1, "opcode_mask": 0xff},
                    0x905d : {"name" : "tnzw", "ins_type" :"single", "insn_size": 2, "opcode_mask": 0xffff},
                    0x0083 : {"name" : "trap", "ins_type" :"single", "insn_size": 1, "opcode_mask": 0xff},
                    0x728f : {"name" : "wfe", "ins_type" :"single", "insn_size": 2, "opcode_mask": 0xffff},
                    0x008f : {"name" : "wfi", "ins_type" :"single", "insn_size": 1, "opcode_mask": 0xff},
                    0x00a8 : {"name" : "xor", "ins_type" :"single", "insn_size": 2, "opcode_mask": 0xff},
                    0x00b8 : {"name" : "xor", "ins_type" :"single", "insn_size": 2, "opcode_mask": 0xff},
                    0x00c8 : {"name" : "xor", "ins_type" :"single", "insn_size": 3, "opcode_mask": 0xff},
                    0x00f8 : {"name" : "xor", "ins_type" :"single", "insn_size": 1, "opcode_mask": 0xff},
                    0x00e8 : {"name" : "xor", "ins_type" :"single", "insn_size": 2, "opcode_mask": 0xff},
                    0x00d8 : {"name" : "xor", "ins_type" :"single", "insn_size": 3, "opcode_mask": 0xff},
                    0x90f8 : {"name" : "xor", "ins_type" :"single", "insn_size": 2, "opcode_mask": 0xffff},
                    0x90e8 : {"name" : "xor", "ins_type" :"single", "insn_size": 3, "opcode_mask": 0xffff},
                    0x90d8 : {"name" : "xor", "ins_type" :"single", "insn_size": 4, "opcode_mask": 0xffff},
                    0x0018 : {"name" : "xor", "ins_type" :"single", "insn_size": 2, "opcode_mask": 0xff},
                    0x92c8 : {"name" : "xor", "ins_type" :"single", "insn_size": 3, "opcode_mask": 0xffff},
                    0x72c8 : {"name" : "xor", "ins_type" :"single", "insn_size": 4, "opcode_mask": 0xffff},
                    0x92d8 : {"name" : "xor", "ins_type" :"single", "insn_size": 3, "opcode_mask": 0xffff},
                    0x72d8 : {"name" : "xor", "ins_type" :"single", "insn_size": 4, "opcode_mask": 0xffff},
                    0x91d8 : {"name" : "xor", "ins_type" :"single", "insn_size": 3, "opcode_mask": 0xffff},
                    0x0025 : {"name": "jrc", "ins_type":"single","insn_size":2, "opcode_mask": 0xff},
                    0x0027 : {"name": "jreq", "ins_type":"single","insn_size":2, "opcode_mask": 0xff},
                    0x0021 : {"name": "jrf", "ins_type":"single","insn_size":2, "opcode_mask": 0xff},
                    0x9029 : {"name": "jrh", "ins_type":"single","insn_size":3, "opcode_mask": 0xffff},
                    0x902f : {"name": "jrih", "ins_type":"single","insn_size":3, "opcode_mask": 0xffff},
                    0x902e : {"name": "jril", "ins_type":"single","insn_size":3, "opcode_mask": 0xffff},
                    0x902d : {"name": "jrm", "ins_type":"single","insn_size":3, "opcode_mask": 0xffff},
                    0x002b : {"name": "jrmi", "ins_type":"single","insn_size":2, "opcode_mask": 0xff},
                    0x0024 : {"name": "jrnc", "ins_type":"single","insn_size":2, "opcode_mask": 0xff},
                    0x0026 : {"name": "jrne", "ins_type":"single","insn_size":2, "opcode_mask": 0xff},
                    0x9028 : {"name": "jrnh", "ins_type":"single","insn_size":3, "opcode_mask": 0xffff},
                    0x902c : {"name": "jrnm", "ins_type":"single","insn_size":3, "opcode_mask": 0xffff},
                    0x0028 : {"name": "jrnv", "ins_type":"single","insn_size":2, "opcode_mask": 0xff},
                    0x002a : {"name": "jrpl", "ins_type":"single","insn_size":2, "opcode_mask": 0xff},
                    0x002e : {"name": "jrsge", "ins_type":"single","insn_size":2, "opcode_mask": 0xff},
                    0x002c : {"name": "jrsgt", "ins_type":"single","insn_size":2, "opcode_mask": 0xff},
                    0x002d : {"name": "jrsle", "ins_type":"single","insn_size":2, "opcode_mask": 0xff},
                    0x002f : {"name": "jrslt", "ins_type":"single","insn_size":2, "opcode_mask": 0xff},
                    0x0020 : {"name": "jrt", "ins_type":"single","insn_size":2, "opcode_mask": 0xff},
                    0x0024 : {"name": "jruge", "ins_type":"single","insn_size":2, "opcode_mask": 0xff},
                    0x0022 : {"name": "jrugt", "ins_type":"single","insn_size":2, "opcode_mask": 0xff},
                    0x0023 : {"name": "jrule", "ins_type":"single","insn_size":2, "opcode_mask": 0xff},
                    0x0025 : {"name": "jrc", "ins_type":"single","insn_size":2, "opcode_mask": 0xff},
                    0x0025 : {"name": "jrult", "ins_type":"single","insn_size":2, "opcode_mask": 0xff},
                    0x0029 : {"name": "jrv", "ins_type":"single","insn_size":2, "opcode_mask": 0xff}
}
    # 指令集配置
    

    def ev_out_segstart(self,ctx, seg):
     
        return True
            
    def ev_ana_insn(self,insn):
        
        hb = get_byte(insn.ea)
        lb = get_byte(insn.ea+1)
        lo = (hb<<8)|lb
        print("lo 0x%x"%lo)
        op8bits = lo  >> 8 
        op16bits = lo
        op12bits = lo >> 4

        
        if op8bits in self.itable.keys():
            ins = self.itable[op8bits]
        elif op16bits in self.itable.keys():
            ins = self.itable[op16bits]
        elif op12bits in self.itable.keys():
            ins = self.itable[op12bits]
        else:
            print("cant find opcode")
            return False

        print('addr 0x%x opmask 0x%x insn_size 0x%x ins_name %s itype 0x%x'%(insn.ea,ins.opcode_mask,ins.insn_size,ins.name,ins.itype))
        if ins.dup == False:
            insn.itype = getattr(self, 'itype_' + ins.name)
        insn.size = ins.insn_size

        ins.d(insn,lo)
        
        
        #insn.size+=1
        #hi= get_wide_byte(insn.ea+1)
        
        return True
               
               
                    
        

    def ev_set_idp_options(self, keyword, value_type, value, idb_loaded):
        return 0


    def ev_newfile(self, fname):
       
       
        return 0

    def ev_oldfile(self, fname):
        return 0
     
    def ev_gen_stkvar_def(self, ctx, mptr, v):
        #print("gen stk var 0x%x"%v)
        
        

        return True

    def ev_is_ret_insn(self, insn, strict):
        return True

    def ev_create_func_frame(self, pfn):
        print("create func start 0x%x end 0x%x"%(pfn.start_ea,pfn.end_ea))
        
        
        return True

    def ev_may_be_func(self, insn, state):
        print("mybe")
        return True

    def handle_operand(self, insn, op, flags, bool_data):
        op.offb = insn.size

        if op.type == o_mem:
            if op.specflag2 != 3:
                addr = op.addr + insn.cs * 16
                if addr != -1:
                    insn.create_op_data(addr, op.offb, op.dtype)
                    if bool_data == True:
                        insn.add_dref(addr, op.offb, 2)
                    else:
                        insn.add_dref(addr, op.offb, 3)

        elif op.type == o_displ:
            set_immd(insn.ea)
            if op.reg == str2reg("DP"):
                addr = op.addr
                insn.create_op_data(addr, op.offb, op.dtype)
                if bool_data == True:
                    insn.add_dref(addr, op.offb,2)
                else:
                    insn.add_dref(addr, op.offb,3)
            r = is_defarg(flags ,op.n)
            if r & 1 ==0:
                r = get_func(insn.ea)
                if op.reg == str2reg("SP"):
                    r = ida_ua.insn_create_stkvar(insn, op, op.addr, 1)
                    print("create stk in emu itype ea 0x%x %s op.addr 0x%x"%(insn.ea,maptable[insn.itype],op.addr))
                    #print(r)
                    if r:
                        r = op_stkvar(insn.ea, op.n)
                        #print("op stkvar")
        elif op.type == o_near:
            addr = op.addr
            if has_insn_feature(insn.itype, CF_CALL):
                if func_does_return(addr) & 1 ==0:
                    crf = fl_CN
                else:
                    crf = fl_JN
                insn.add_cref(addr, op.offb , crf)
                #ida_xref.add_cref(insn.ea, addr, fl_JN)

        elif op.type == o_imm:
            if bool_data & 1 != 0:
                set_immd(insn.ea)
                if is_defarg(flags, op.n) & 1 ==0:
                    if op.specflag2 - 1 >= 2:
                        t = 0x2200000
                    else:
                        t = 0x1100000
                    set_op_type(insn.ea, t, op.n)
                r = op_adds_xrefs(flags, op.n)
                if r:
                    r = insn.add_off_drefs(op, 1, 0)
                if op.specflag2 == 2:
                    v = op.value #& 0xfffe
                    if insn.itype == self.itype_mov:
                        #v &= 0x3ff
                        print("emu mov o_imm")
                        pass
           

        return True

    def ev_emu_insn(self,insn):
        """
        指令模拟函数：模拟指令执行
        """
        #idaapi.ua_add_cref(0, idaapi.cmd.ea + 2, idaapi.fl_F)
        print("emu")
        
        Feature = insn.get_canon_feature()
        flow = (Feature & CF_STOP) == 0
        itype = insn.itype
        
        
        flags = get_flags_ex(insn.ea, 0)
        if Feature & CF_JUMP != 0:
            print("insn.itype 0x%x"%insn.itype)
            if insn.itype != itype_map["itype_btjf"] and insn.itype != itype_map["itype_btjt"]:
                print("normal add cref")
                ida_xref.add_cref(insn.ea, insn.Op1.addr, fl_JN)
            else:
                print("btjf/btjt add cref")
                ida_xref.add_cref(insn.ea, insn.Op3.addr, fl_JN)
        elif Feature & CF_CALL != 0:
            if insn.Op1.type == o_mem:
                ida_xref.add_cref(insn.ea, insn.Op1.addr, fl_JN)

        
        ida_xref.add_cref(insn.ea,insn.ea + insn.size, fl_F )

        """
        if Feature & 0x100 != 0:
            self.handle_operand(insn, insn.Op1, flags, True)
        elif Feature & 0x200 != 0:
            self.handle_operand(insn, insn.Op2, flags, True)
        elif Feature & 0x400 != 0:
            self.handle_operand(insn, insn.Op3, flags, True)
        elif Feature & 4 != 0:
            self.handle_operand(insn, insn.Op1, flags, False)
        elif Feature & 8 != 0:
            self.handle_operand(insn, insn.Op2, flags, False)
        elif Feature & 0x10 != 0:
            self.handle_operand(insn, insn.Op3, flags, False)
        
        if itype == self.itype_rpt:
            ea = insn.ea + 1
            v = 1

            #netnode.supset(ea, v ,1)
        """
        return True

    def ev_out_insn(self,ctx):
        """
        输出指令的反汇编文本
        """
        print("ev_out_insn called")
        ctx.out_mnemonic()

        print("op1.type %d op2.type %d"%(ctx.insn.Op1.type,ctx.insn.Op2.type))
        
        if ctx.insn.Op1.type != idaapi.o_void:
            op_result = ctx.out_one_operand(0)
              
        # 输出其余操作数，用逗号分隔
        for i in range(1, 3):
            if ctx.insn[i].type == idaapi.o_void:
                break
            ctx.out_symbol(',')
            ctx.out_char(' ')
            op_result = ctx.out_one_operand(i)

        ctx.set_gen_cmt()  # 生成注释
        ctx.flush_outbuf()  # 刷新输出缓冲
       
        return True
    
    def handle_o_phrase(self, ctx, op):
       

        return True
    
 

    def ev_out_operand(self, ctx, op):
        optype = op.type
        flag1 = op.specflag1
        flag2 = op.specflag2
        
        if optype == o_reg:
            ctx.out_register(self.reg_names[op.reg])
        elif optype == o_imm:
            ctx.out_symbol("#")
            ctx.out_symbol("$")
            ctx.out_value(op, OOFW_IMM | OOFW_16 | OOFW_8 | OOFW_24)
            
        elif optype == o_mem:
            if flag1 == 0:
                print("o_mem addr 0x%x"%op.addr)
                ctx.out_symbol("$")
                r = ctx.out_name_expr(op, op.addr, BADADDR)
                if not r:
                    ctx.out_tagon(COLOR_ERROR)
                    ctx.out_btoa(op.addr, 16)
                    ctx.out_tagoff(COLOR_ERROR)
                    remember_problem(PR_NONAME, ctx.insn.ea)
            elif flag1 > 0:
                ctx.out_symbol("[")
                ctx.out_symbol("$")
                r = ctx.out_name_expr(op, op.addr, BADADDR)
                if not r:
                    ctx.out_tagon(COLOR_ERROR)
                    ctx.out_btoa(op.addr, 16)
                    ctx.out_tagoff(COLOR_ERROR)
                    remember_problem(PR_NONAME, ctx.insn.ea)
                if flag1 == 2:
                    ctx.out_symbol(".")
                    ctx.out_symbol("w")
                ctx.out_symbol("]")
            

            
        elif optype == o_phrase:
            ctx.out_symbol("(")
            if flag1 == 1:
                if flag2 == 0:
                    ctx.out_symbol("$")
                    ctx.out_value(op, OOFW_IMM | OOFW_16 | OOFW_8 | OOFW_24)
                elif flag2 == 1:
                    ctx.out_symbol("[")
                    ctx.out_symbol("$")
                    ctx.out_value(op, OOFW_IMM | OOFW_8 |OOFW_16|OOFW_24)
                    ctx.out_symbol("]")
                elif flag2 == 2:
                    ctx.out_symbol("[")
                    ctx.out_symbol("$")
                    ctx.out_value(op, OOFW_IMM | OOFW_8 |OOFW_16|OOFW_24 )
                    ctx.out_symbol(".")
                    ctx.out_symbol("w")
                    ctx.out_symbol("]")
                ctx.out_symbol(",")
            ctx.out_register(self.reg_names[op.reg])
            ctx.out_symbol(")")
        elif optype == o_displ:
            pass
        elif optype == o_near:
            pass
        elif optype == o_far:
            pass

        return True #lesson learned here, must return True
        
    
    def ev_init(self):
        print("ev_Init")
        return True


    
    def init_registers(self):
        """This function parses the register table and creates corresponding ireg_XXX constants"""

        # Registers definition

        # Create the ireg_XXXX constants
        self.reg_names=[
                "A", #8 bits
                "X", #16 bits
                "XL",#8 bits
                "XH",
                "Y",
                "YL",
                "YH",
                "SP",
                "PC", #24 bits
                "PCL", #8bits low
                "PCH", #8bits hi
                "PCE", #8bits extend
                "CC", #8 bits bit7 V, bit5 l1, H,l0, N, Z ,C
                "CC.V",
                "CC.l0",
                "CC.H",
                "CC.l1",
                "CC.N",
                "CC.Z",
                "CC.C",
                "CS",
                "DS"
                ]
        regs_num = len(self.reg_names)
        for i in range(len(self.reg_names)):
            setattr(self, 'ireg_' + self.reg_names[i], i)

        self.reg_first_sreg = self.ireg_CS
        self.reg_last_sreg  = self.ireg_DS

        # number of CS register
        self.reg_code_sreg = self.ireg_CS

        # number of DS register
        self.reg_data_sreg = self.ireg_DS

    def init_instructions(self):
        class idef:
            """
            Internal class that describes an instruction by:
            - instruction name
            - instruction decoding routine
            - canonical flags used by IDA
            """
            def __init__(self, name , insn_size, opcode_mask,cmt = None,dup_ins = False,itype = 0):
                #setattr(self, 'handle_'+name, 'handle_'+name)
                func = getattr(self, 'handle_'+name)
                self.name = name
                self.cf  = CF_USE1 | CF_CHG1 | CF_USE2
                self.d   = func
                self.cmt = cmt
                self.insn_size = insn_size
                self.opcode_mask = opcode_mask
                self.dup = dup_ins
                self.itype = itype

            def handle_adc(self, insn, w):
                return True

            def handle_add(self, insn, w):
                ba = get_bytes(insn.ea, insn.size)
                insn.Op1.type = o_reg
                if insn.size == 2:
                    if ba[0] == 0xab:
                        insn.Op1.reg = str2reg("A")
                        insn.Op2.type = o_imm
                        insn.Op2.value = ba[1]


                return True

            def handle_addw(self, insn, w):
                ba = get_bytes(insn.ea, insn.size)
                insn.Op1.type = o_reg
                if insn.size == 2 and ba[0] == 0x5b:
                    xx = ba[1]
                    insn.Op1.reg = str2reg("SP")
                    insn.Op2.type = o_imm
                    insn.Op2.value = xx
                elif insn.size == 3:
                    v=(ba[0]<<8)|ba[1]
                    if ba[0] == 0x1c:
                        insn.Op1.reg = str2reg("X")
                        ms = ba[1]
                        ls = ba[2]
                        imm = (ms<<8)|ls
                        insn.Op2.type = o_imm
                        insn.Op2.value = imm
                    elif v == 0x72fb:
                        insn.Op1.reg = str2reg("X")
                        insn.Op2.type = o_phrase
                        insn.Op2.reg = str2reg("SP")
                        insn.Op2.value = ba[2]
                        insn.Op2.specflag1 = 1
                    elif v == 0x72f9:
                        insn.Op1.reg = str2reg("Y")
                        insn.Op2.type = o_phrase
                        insn.Op2.reg = str2reg("SP")
                        insn.Op2.value = ba[2]
                        insn.Op2.specflag1 = 1


                elif insn.size == 4:
                    v=(ba[0]<<8)|ba[1]
                    mem = (ba[2]<<8)|ba[3]
                    
                    if v == 0x72bb:
                        insn.Op1.reg = str2reg("X")
                        insn.Op2.type = o_imm
                        insn.Op2.value = mem
                    elif v == 0x72a9:
                        insn.Op1.reg = str2reg("Y")
                        insn.Op2.type = o_mem
                        insn.Op2.addr = mem
                    elif v == 0x72b9:
                        insn.Op1.reg = str2reg("Y")
                        insn.Op2.type = o_imm
                        insn.Op2.value = mem
                    
                return True

            def handle_and(self, insn, w):
                ba = get_bytes(insn.ea,insn.size)
                if insn.size == 2:
                    if ba[0] == 0xa4:
                        insn.Op1.type = o_reg
                        insn.Op1.reg = str2reg("A")
                        insn.Op2.type = o_imm
                        insn.Op2.value = ba[1]
                    
                    
                elif insn.size == 3:
                    if ba[0] == 0xc4:
                        insn.Op1.type = o_reg
                        insn.Op1.reg = str2reg("A")
                        insn.Op2.type = o_mem
                        insn.Op2.addr = (ba[1]<<8)|ba[2]
                    elif ba[0] == 0xd4:
                        insn.Op1.type = o_reg
                        insn.Op1.reg = str2reg("A")
                        insn.Op2.type = o_phrase
                        insn.Op2.reg = str2reg("X")
                        insn.Op2.value = (ba[1]<<8)|ba[2]
                        insn.Op2.specflag1 = 1
                return True

            def handle_bccm(self, insn, w):
                return True

            def handle_bcp(self, insn, w):
                ba = get_bytes(insn.ea, insn.size)
                if insn.size == 2:
                    if ba[0] == 0xb5:
                        insn.Op1.type = o_reg
                        insn.Op1.reg = str2reg("A")
                        insn.Op2.type = o_mem
                        insn.Op2.addr = ba[1]
                    elif ba[0] == 0xa5:
                        insn.Op1.type = o_reg
                        insn.Op1.reg = str2reg("A")
                        insn.Op2.type = o_imm
                        insn.Op2.value = ba[1]
                return True

            def handle_bcpl(self, insn, w):
                return True

            def handle_bres(self, insn, w):
                ba = get_bytes(insn.ea, 4)
                n = ba[1] & 0xf
                ms= ba[2]
                ls= ba[3]
                if n%2 == 0:
                    insn.itype = itype_map['itype_bset']
                else:
                    insn.itype = itype_map['itype_bres']
                n = int(n/2)
                insn.Op1.type = o_mem
                insn.Op1.addr = (ba[2]<<8)|ba[3]
                insn.Op2.type = o_imm
                insn.Op2.value = n


                return True

            def handle_btjf(self, insn, w):
                self.handle_btjt(insn,w)
                return True

            def handle_btjt(self, insn, w):
                print("handle btjt")
                ba = get_bytes(insn.ea, 5)
                n = ba[1] & 0xf
                ms = ba[2]
                ls = ba[3]
                xx = ba[4]
                if n%2 == 0:
                    insn.itype = itype_map["itype_btjt"]
                else:
                    insn.itype = itype_map["itype_btjf"]
                insn.Op1.type = o_mem
                insn.Op1.addr = (ba[2]<<8)|ba[3]
                pos = int(n/2)
                insn.Op2.type = o_imm
                insn.Op2.value = pos
                insn.Op3.type = o_mem
                insn.Op3.addr = insn.ea + 5 + get_signed(ba[4],0xff)

                return True
            def handle_call(self, insn, w):
                ba = get_bytes(insn.ea,insn.size)
                if insn.size == 1:
                    if ba[0] == 0xfd:
                        insn.Op1.type = o_phrase
                        insn.Op1.reg = str2reg("X")
                elif insn.size == 2:
                    if ba[0] == 0xed:
                        insn.Op1.type = o_phrase
                        insn.Op1.reg = str2reg("X")
                        insn.Op1.value = ba[1]
                    elif ba[0] == 0x90 and ba[1] == 0xfd:
                        insn.Op1.type = o_phrase
                        insn.Op1.reg = str2reg("Y")
                elif insn.size == 3:
                    if ba[0] == 0xcd:
                        insn.Op1.type = o_mem
                        insn.Op1.addr = (ba[1]<<8)|ba[2]
                    elif ba[0] == 0xdd:
                        insn.Op1.type = o_phrase
                        insn.Op1.reg = str2reg("X")
                        insn.Op1.value = (ba[1]<<8)|ba[2]
                    elif ba[0] == 0x90 and ba[1] == 0xed:
                        insn.Op1.type = o_phrase
                        insn.Op1.reg = str2reg("Y")
                        insn.Op1.value = ba[2]
                    elif ba[0] == 0x92 and ba[1] == 0xcd:
                        insn.Op1.type = o_mem
                        insn.Op1.addr = ba[2]
                        insn.Op1.specflag1 = 2
                    elif ba[0] == 0x92 and ba[1] == 0xdd:
                        insn.Op1.type = o_phrase
                        insn.Op1.reg = str2reg("X")
                        insn.Op1.value = ba[2]
                        insn.Op1.specflag1 = 1
                        insn.Op1.specflag2 = 2
                    elif ba[0] == 0x91 and ba[1] == 0xdd:
                        insn.Op1.type = o_phrase
                        insn.Op1.reg = str2reg("Y")
                        insn.Op1.value = ba[2]
                        insn.Op1.specflag1 = 1
                        insn.Op1.specflag2 = 2
                elif insn.size == 4:
                    if ba[0] == 0x90 and ba[1] == 0xdd:
                        insn.Op1.type = o_phrase
                        insn.Op1.reg = str2reg("Y")
                        insn.Op1.value = (ba[2]<<8)|ba[3]
                    elif ba[0] == 0x72 and ba[1] == 0xcd:
                        insn.Op1.type = o_mem
                        insn.Op1.addr = (ba[2]<<8)|ba[3]
                        insn.Op1.specflag1 = 2
                    elif ba[0] == 0x72 and ba[1] == 0xdd:
                        insn.Op1.type = o_phrase
                        insn.Op1.reg = str2reg("X")
                        insn.Op1.value = (ba[2]<<8)|ba[3]
                        insn.Op1.specflag1 = 1
                        insn.Op1.specflag2 = 2
                return True

            def handle_callf(self, insn, w):
                ba = get_bytes(insn.ea,insn.size)
                if insn.size == 4:
                    if ba[0] == 0x8d:
                        insn.Op1.type = o_mem
                        insn.Op1.addr = (ba[1]<<16)|(ba[2]<<8)|ba[3]
                return True

            def handle_callr(self, insn, w):
                return True

            def handle_ccf(self, insn, w):
                return True

            def handle_clr(self, insn, w):
                ba = get_bytes(insn.ea,insn.size)
                if insn.size == 1:
                    if ba[0] == 0x4f:
                        insn.Op1.type = o_reg
                        insn.Op1.reg = str2reg("A")
                    elif ba[0] == 0x7f:
                        insn.Op1.type = o_phrase
                        insn.Op1.reg = str2reg("X")
                        insn.Op1.specflag1 = 1

                elif insn.size == 2:
                    mem = ba[1]
                    if ba[0] == 0x3f:
                        insn.Op1.type = o_mem
                        insn.Op1.addr = mem
                    elif ba[0] == 0x6f:
                        insn.Op1.type = o_phrase
                        insn.Op1.reg = str2reg("X")
                        insn.Op1.value = mem
                    elif ba[0] == 0x0f:
                        insn.Op1.type = o_phrase
                        insn.Op1.reg = str2reg("SP")
                        insn.Op1.value = mem
                        insn.Op1.specflag1 = 1

                elif insn.size == 3:
                    if ba[0] == 0x90 and ba[1] == 0x6f:
                        insn.Op1.type = o_phrase
                        insn.Op1.reg = str2reg("Y")
                        insn.Op1.value = ba[2]

                    elif ba[0] == 0x92 and ba[1] == 0x3f:
                        insn.Op1.type = o_mem
                        insn.Op1.addr = ba[2]
                        insn.Op1.specflag1 = 1 #[shortptr.w]
                    elif ba[0] == 0x92 and ba[1] == 0x6f:
                        insn.Op1.type = o_phrase
                        insn.Op1.reg = str2reg("X")
                        insn.Op1.addr = ba[2]
                        insn.Op1.specflag1 = 1 #[shortptr.w]
                        insn.Op1.specflag2 = 1
                    elif ba[0] == 0x91 and ba[1] == 0x6f:
                        insn.Op1.type = o_phrase
                        insn.Op1.reg = str2reg("Y")
                        insn.Op1.addr = ba[2]
                        insn.Op1.specflag1 = 1 #[shortptr.w]
                        insn.Op1.specflag2 = 1

                elif insn.size == 4:
                    if ba[0] == 0x72 and ba[1] == 0x5f:
                        insn.Op1.type = o_mem
                        insn.Op1.addr = (ba[2])<<8|ba[3]
                    elif ba[0] == 0x72 and ba[1] == 0x4f:
                        insn.Op1.type = o_phrase
                        insn.Op1.reg = str2reg("X")
                        insn.Op1.addr = (ba[2])<<8|ba[3]
                    elif ba[0] == 0x90 and ba[1] == 0x4f:
                        insn.Op1.type = o_phrase
                        insn.Op1.reg = str2reg("Y")
                        insn.Op1.addr = (ba[2])<<8|ba[3]
                    elif ba[0] == 0x72 and ba[1] == 0x3f:
                        insn.Op1.type = o_mem
                        insn.Op1.addr = (ba[2])<<8|ba[3]
                        insn.Op1.specflag1 = 1 #[longptr.w]
                        insn.Op1.specflag2 = 2
                    elif ba[0] == 0x72 and ba[1] == 0x6f:
                        insn.Op1.type = o_phrase
                        insn.Op1.reg = str2reg("X")
                        insn.Op1.addr = (ba[2])<<8|ba[3]
                        insn.Op1.specflag1 = 1 #([longptr.w].X]
                        insn.Op1.specflag2 = 2

                    

                return True

            def handle_clrw(self, insn, w):
                ba = get_bytes(insn.ea,insn.size)
                if insn.size == 1:
                    insn.Op1.type = o_reg
                    insn.Op1.reg = str2reg("X")
                else:
                    insn.Op1.type = o_reg
                    insn.Op1.reg = str2reg("Y")
                return True

            def handle_cp(self, insn, w):
                ba = get_bytes(insn.ea,insn.size)
                if insn.size == 2:
                    if ba[0] == 0xa1:
                        insn.Op1.type = o_reg
                        insn.Op1.reg = str2reg("A")
                        insn.Op2.type = o_imm
                        insn.Op2.value = ba[1]
                    elif ba[0] == 0xb1:
                        insn.Op1.type = o_reg
                        insn.Op1.reg = str2reg("A")
                        insn.Op2.type = o_mem
                        insn.Op2.addr = ba[1]
                    elif ba[0] == 0xe1:
                        insn.Op1.type = o_reg
                        insn.Op1.reg = str2reg("A")
                        insn.Op2.type = o_phrase
                        insn.Op2.reg = str2reg("X")
                        insn.Op2.value = ba[1]
                        insn.Op2.specflag1 = 1
                elif insn.size == 3:
                    if ba[0] == 0x92 and ba[1] == 0xc1:
                        insn.Op1.type = o_reg
                        insn.Op1.reg = str2reg("A")
                        insn.Op2.type = o_mem
                        insn.Op2.addr = ba[2]
                        insn.Op2.specflag1 = 2
                return True

            def handle_cpw(self, insn, w):
                ba = get_bytes(insn.ea,insn.size)
                if insn.size == 2:
                    if ba[0] == 0xb3:
                        insn.Op1.type = o_reg
                        insn.Op1.reg = str2reg("X")
                        insn.Op2.type = o_imm
                        insn.Op2.value = ba[1]
                elif insn.size == 3:
                    if ba[0] == 0xc3:
                        insn.Op1.type = o_reg
                        insn.Op1.reg = str2reg("X")
                        insn.Op2.type = o_mem
                        insn.Op2.addr = (ba[1]<<8)|ba[2]
                    elif ba[0] == 0xa3:
                        insn.Op1.type = o_reg
                        insn.Op1.reg = str2reg("X")
                        insn.Op2.type = o_imm
                        insn.Op2.value = (ba[1]<<8)|ba[2]

                elif insn.size == 4:
                    if ba[0] == 0x90 and ba[1] == 0xa3:
                        insn.Op1.type = o_reg
                        insn.Op1.reg = str2reg("Y")
                        insn.Op2.type = o_imm
                        insn.Op2.value = (ba[2]<<8)|ba[3]
                    elif ba[0] == 0x90 and ba[1] == 0xc3:
                        insn.Op1.type = o_reg
                        insn.Op1.reg = str2reg("Y")
                        insn.Op2.type = o_mem
                        insn.Op2.addr = (ba[2]<<8)|ba[3]
                return True

            def handle_cpl(self, insn, w):
                ba = get_bytes(insn.ea,insn.size)
                if insn.size == 1:
                    insn.Op1.type = o_reg
                    insn.Op1.reg = str2reg("A")
                elif insn.size == 2:
                    if ba[0] == 3:
                        insn.Op1.type = o_phrase
                        insn.Op1.reg = str2reg("SP")
                        insn.Op1.value = ba[1]
                        insn.Op1.specflag1 = 1

                return True

            def handle_cplw(self, insn, w):
                if insn.size == 1:
                    insn.Op1.type = o_reg
                    insn.Op1.reg = str2reg("X")
                else:
                    insn.Op1.type = o_reg
                    insn.Op1.reg = str2reg("Y")
                return True

            def handle_dec(self, insn, w):
                ba = get_bytes(insn.ea,insn.size)
                if insn.size == 1:
                    if ba[0] == 0x4a:
                        insn.Op1.type = o_reg
                        insn.Op1.reg = str2reg("A")
                elif insn.size == 2:
                    if ba[0] == 0x0a:
                        insn.Op1.type = o_phrase
                        insn.Op1.reg = str2reg("SP")
                        insn.Op1.value = ba[1]
                        insn.Op1.specflag1 = 1
                    elif ba[0] == 0x3a:
                        insn.Op1.type = o_mem
                        insn.Op1.addr = ba[1]
                return True

            def handle_decw(self, insn, w):
                insn.Op1.type = o_reg
                if insn.size == 1:
                    insn.Op1.reg = str2reg("X")
                else:
                    insn.Op1.reg = str2reg("Y")
                return True

            def handle_div(self, insn, w):
                insn.Op1.type = o_reg
                insn.Op2.type = o_reg
                insn.Op1.reg = str2reg("X")
                insn.Op2.reg = str2reg("Y")
                return True

            def handle_exg(self, insn, w):
                ba = get_bytes(insn.ea,insn.size)
                if insn.size == 1:
                    insn.Op1.type = o_reg
                    insn.Op2.type = o_reg
                    if ba[0] == 0x41:
                        insn.Op1.reg = str2reg("A")
                        insn.Op2.reg = str2reg("XL")
                    elif ba[0] == 0x61:
                        insn.Op1.reg = str2reg("A")
                        insn.Op2.reg = str2reg("YL")

                elif insn.size == 3 and ba[0] == 0x31:
                    mem = (ba[1]<<8)|ba[2]
                    insn.Op1.type = o_reg
                    insn.Op1.reg = str2reg("A")
                    insn.Op2.type = o_mem
                    insn.Op2.addr = mem


                return True
            
            def handle_exgw(self, insn, w):
                insn.Op1.type = o_reg
                insn.Op2.type = o_reg
                insn.Op1.reg = str2reg("X")
                insn.Op2.reg = str2reg("Y")
                return True

            def handle_halt(self, insn, w):
                return True

            def handle_inc(self, insn, w):
                ba = get_bytes(insn.ea,insn.size)
                if insn.size == 1:
                    if ba[0] == 0x4c:
                        insn.Op1.type = o_reg
                        insn.Op1.reg = str2reg("A")
                elif insn.size == 2:
                    if ba[0] == 0x3c:
                        insn.Op1.type = o_mem
                        insn.Op1.addr = ba[1]
                return True

            def handle_incw(self, insn, w):
                insn.Op1.type = o_reg
                if insn.size == 1:
                    insn.Op1.reg = str2reg("X")
                else:
                    insn.Op1.reg = str2reg("Y")
                return True

            def handle_int(self, insn, w):
                return True

            def handle_iret(self, insn, w):
                return True

            def handle_jp(self, insn, w):
                ba = get_bytes(insn.ea, insn.size)
                if insn.size == 3:
                    if ba[0] == 0xcc:
                        insn.Op1.type = o_mem
                        insn.Op1.addr = (ba[1]<<8)|ba[2]
                return True

            def handle_jpf(self, insn, w):
                return True

            def handle_jra(self, insn, w):
                return True

            def handle_ld(self, insn, w):
                ba= get_bytes(insn.ea, insn.size)
                

                if insn.size == 1:
                    if ba[0] == 0xf6:
                        insn.Op1.type = o_reg
                        insn.Op1.reg = str2reg("A")
                        insn.Op2.type = o_phrase
                        insn.Op2.reg = str2reg("X")
                    elif ba[0] == 0xf7:
                        insn.Op1.type = o_phrase
                        insn.Op1.reg = str2reg("X")
                        insn.Op2.type = o_reg
                        insn.Op2.reg = str2reg("A")
                    elif ba[0] == 0x97:
                        insn.Op1.type = o_reg
                        insn.Op1.reg = str2reg("XL")
                        insn.Op2.type = o_reg
                        insn.Op2.reg = str2reg("A")
                    elif ba[0] == 0x9f:
                        insn.Op1.type = o_reg
                        insn.Op1.reg = str2reg("A")
                        insn.Op2.type = o_reg
                        insn.Op2.reg = str2reg("XL")
                    elif ba[0] == 0x95:
                        insn.Op1.type = o_reg
                        insn.Op2.type = o_reg
                        insn.Op1.reg = str2reg("XH")
                        insn.Op2.reg = str2reg("A")
                    elif ba[0] == 0x9e:
                        insn.Op1.type = o_reg
                        insn.Op2.type = o_reg
                        insn.Op1.reg = str2reg("A")
                        insn.Op2.reg = str2reg("XH")
                elif insn.size == 2:
                    if ba[0] == 0xa6:
                        insn.Op1.type = o_reg
                        insn.Op1.reg = str2reg("A")
                        insn.Op2.type = o_imm
                        insn.Op2.value = ba[1]
                    elif ba[0] == 0xb6:
                        insn.Op1.type = o_reg
                        insn.Op1.reg = str2reg("A")
                        insn.Op2.type = o_mem
                        insn.Op2.addr = ba[1]
                    elif ba[0] == 0xb7:
                        insn.Op1.type = o_mem
                        insn.Op1.addr = ba[1]
                        insn.Op2.type = o_reg
                        insn.Op2.reg = str2reg("A")
                    elif ba[0] == 0xe6:
                        insn.Op1.type = o_reg
                        insn.Op1.reg = str2reg("A")
                        insn.Op2.type = o_phrase
                        insn.Op2.reg = str2reg("X")
                        insn.Op2.value = ba[1]
                        insn.Op2.specflag1 = 1
                    elif ba[0] == 0xe7:
                        insn.Op1.type = o_phrase
                        insn.Op1.reg = str2reg("X")
                        insn.Op1.value = ba[1]
                        insn.Op1.specflag1 = 1
                        insn.Op2.type = o_reg
                        insn.Op2.reg = str2reg("A")
                    elif ba[0] == 0x90 and ba[1] == 0xf6:
                        insn.Op1.type = o_reg
                        insn.Op1.reg = str2reg("A")
                        insn.Op2.type = o_phrase
                        insn.Op2.reg = str2reg("Y")
                    elif ba[0] == 0x7b:
                        insn.Op1.type = o_reg
                        insn.Op1.reg = str2reg("A")
                        insn.Op2.type = o_phrase
                        insn.Op2.reg = str2reg("SP")
                        insn.Op2.value = ba[1]
                        insn.Op2.specflag1 = 1
                    elif ba[0] == 0x90 and ba[1] == 0xf7:
                        insn.Op1.type = o_phrase
                        insn.Op1.reg = str2reg("Y")
                        insn.Op2.type = o_reg
                        insn.Op2.reg = str2reg("A")
                    elif ba[0] == 0x6b:
                        insn.Op1.type = o_phrase
                        insn.Op1.reg = str2reg("SP")
                        insn.Op1.value = ba[1]
                        insn.Op1.specflag1 = 1
                        insn.Op2.type = o_reg
                        insn.Op2.reg = str2reg("A")
                    elif ba[0] == 0x90 and ba[1] == 0x97:
                        insn.Op1.type = o_reg
                        insn.Op2.type = o_reg
                        insn.Op1.reg = str2reg("YL")
                        insn.Op2.reg = str2reg("A")
                    elif ba[0] == 0x90 and ba[1] == 0x9f:
                        insn.Op1.type = o_reg
                        insn.Op2.type = o_reg
                        insn.Op1.reg = str2reg("A")
                        insn.Op2.reg = str2reg("YL")
                    elif ba[0] == 0x90 and ba[1] == 0x95:
                        insn.Op1.type = o_reg
                        insn.Op2.type = o_reg
                        insn.Op1.reg = str2reg("YH")
                        insn.Op2.reg = str2reg("A")
                    elif ba[0] == 0x90 and ba[1] == 0x9e:
                        insn.Op1.type = o_reg
                        insn.Op2.type = o_reg
                        insn.Op1.reg = str2reg("A")
                        insn.Op2.reg = str2reg("YH")


                elif insn.size == 3:
                    if ba[0] == 0xc6:
                        insn.Op1.type = o_reg
                        insn.Op1.reg = str2reg("A")
                        insn.Op2.type = o_mem
                        insn.Op2.addr = (ba[1]<<8)|ba[2]
                    elif ba[0] == 0xc7:
                        insn.Op1.type = o_mem
                        insn.Op1.addr = (ba[1]<<8)|ba[2]
                        insn.Op2.type = o_reg
                        insn.Op2.reg = str2reg("A")
                    elif ba[0] == 0xd7:
                        insn.Op1.type = o_phrase
                        insn.Op1.reg = str2reg("X")
                        insn.Op1.value = (ba[1]<<8)|ba[2]
                        insn.Op1.specflag1 = 1
                        insn.Op2.type = o_reg
                        insn.Op2.reg =  str2reg("A")
                    elif ba[0] == 0xd6:
                        insn.Op1.type = o_reg
                        insn.Op1.reg = str2reg("A")
                        insn.Op2.type = o_phrase
                        insn.Op2.reg = str2reg("X")
                        insn.Op2.value = (ba[1]<<8)|ba[2]
                        insn.Op2.specflag1 = 1
                    elif ba[0] == 0x90 and ba[1] == 0xe6:
                        insn.Op1.type = o_reg
                        insn.Op1.reg = str2reg("A")
                        insn.Op2.type = o_phrase
                        insn.Op2.reg = str2reg("Y")
                        insn.Op2.value = ba[2]
                        insn.Op2.specflag1 = 1
                    elif ba[0] == 0x92 and ba[1] == 0xc6:
                        insn.Op1.type = o_reg
                        insn.Op1.reg = str2reg("A")
                        insn.Op2.type = o_mem
                        insn.Op2.addr = ba[2]
                        insn.Op2.specflag1 = 2
                    elif ba[0] == 0x92 and ba[1] == 0xc7:
                        insn.Op1.type = o_mem
                        insn.Op2.reg = str2reg("A")
                        insn.Op2.type = o_reg
                        insn.Op1.addr = ba[2]
                        insn.Op1.specflag1 = 2
                    elif ba[0] == 0x92 and ba[1] == 0xd6:
                        insn.Op1.type = o_reg
                        insn.Op1.reg = str2reg("A")
                        insn.Op2.type = o_phrase
                        insn.Op2.reg = str2reg("X")
                        insn.Op2.value = ba[2]
                        insn.Op2.specflag1 = 1
                        insn.Op2.specflag2 = 2
                    elif ba[0] == 0x92 and ba[1] == 0xd7:
                        insn.Op2.type = o_reg
                        insn.Op2.reg = str2reg("A")
                        insn.Op1.type = o_phrase
                        insn.Op1.reg = str2reg("X")
                        insn.Op1.value = ba[2]
                        insn.Op1.specflag1 = 1
                        insn.Op1.specflag2 = 2
                    elif ba[0] == 0x91 and ba[1] == 0xd7:
                        insn.Op2.type = o_reg
                        insn.Op2.reg = str2reg("A")
                        insn.Op1.type = o_phrase
                        insn.Op1.reg = str2reg("Y")
                        insn.Op1.value = ba[2]
                        insn.Op1.specflag1 = 1
                        insn.Op1.specflag2 = 2
                    elif ba[0] == 0x91 and ba[1] == 0xd6:
                        insn.Op1.type = o_reg
                        insn.Op1.reg = str2reg("A")
                        insn.Op2.type = o_phrase
                        insn.Op2.reg = str2reg("Y")
                        insn.Op2.value = ba[2]
                        insn.Op2.specflag1 = 1
                        insn.Op2.specflag2 = 2
                    elif ba[0] == 0x90 and ba[1] == 0xe7:
                        insn.Op1.type = o_phrase
                        insn.Op1.reg = str2reg("Y")
                        insn.Op1.value = ba[2]
                        insn.Op1.specflag1 = 1
                        insn.Op2.type = o_reg
                        insn.Op2.reg = str2reg("A")


                elif insn.size == 4:
                    if ba[0] == 0x72 and ba[1] == 0xc6:
                        insn.Op1.type = o_reg
                        insn.Op1.reg = str2reg("A")
                        insn.Op2.type = o_mem
                        insn.Op2.addr = (ba[2]<<8)|ba[3]
                        insn.Op2.specflag1 = 2
                    elif ba[0] == 0x72 and ba[1] == 0xc7:
                        insn.Op1.type = o_mem
                        insn.Op2.reg = str2reg("A")
                        insn.Op2.type = o_reg
                        insn.Op1.addr = (ba[2]<<8)|ba[3]
                        insn.Op1.specflag1 = 2
                    elif ba[0] == 0x90 and ba[1] == 0xd6:
                        insn.Op1.type = o_reg
                        insn.Op1.reg = str2reg("A")
                        insn.Op2.type = o_phrase
                        insn.Op2.reg = str2reg("Y")
                        insn.Op2.value = (ba[2]<<8)|ba[3]
                        insn.Op2.specflag1 = 1
                    elif ba[0] == 0x72 and ba[1] == 0xd6:
                        insn.Op1.type = o_reg
                        insn.Op1.reg = str2reg("A")
                        insn.Op2.type = o_phrase
                        insn.Op2.reg = str2reg("X")
                        insn.Op2.value = (ba[2]<<8)|ba[3]
                        insn.Op2.specflag1 = 1
                        insn.Op2.specflag2 = 2
                    elif ba[0] == 0x90 and ba[1] == 0xd7:
                        insn.Op1.type = o_phrase
                        insn.Op1.reg = str2reg("Y")
                        insn.Op1.value = (ba[2]<<8)|ba[3]
                        insn.Op1.specflag1 = 1
                        insn.Op2.type = o_reg
                        insn.Op2.reg = str2reg("A")
                    elif ba[0] == 0x72 and ba[1] == 0xd7:
                        insn.Op2.type = o_reg
                        insn.Op2.reg = str2reg("A")
                        insn.Op1.type = o_phrase
                        insn.Op1.reg = str2reg("X")
                        insn.Op1.value = (ba[2]<<8)|ba[3]
                        insn.Op1.specflag1 = 1
                        insn.Op1.specflag2 = 2


                return True

            def handle_ldf(self, insn, w):
                return True

            def handle_ldw(self, insn, w):
                ba = get_bytes(insn.ea,insn.size)
                if insn.size == 1:
                    if ba[0] == 0xfe:
                        insn.Op1.type = o_reg
                        insn.Op1.reg = str2reg("X")
                        insn.Op2.type = o_phrase
                        insn.Op2.reg = str2reg("X")
                    elif ba[0] == 0xff:
                        insn.Op1.type = o_phrase
                        insn.Op1.reg = str2reg("X")
                        insn.Op2.type = o_reg
                        insn.Op2.reg = str2reg("Y")
                    elif ba[0] == 0x93:
                        insn.Op1.type = o_reg
                        insn.Op2.type = o_reg
                        insn.Op1.reg = str2reg("X")
                        insn.Op2.reg = str2reg("Y")
                    elif ba[0] == 0x96:
                        insn.Op1.type = o_reg
                        insn.Op2.type = o_reg
                        insn.Op1.reg = str2reg("X")
                        insn.Op2.reg = str2reg("SP")
                    elif ba[0] == 0x94:
                        insn.Op1.type = o_reg
                        insn.Op2.type = o_reg
                        insn.Op1.reg = str2reg("SP")
                        insn.Op2.reg = str2reg("X")

                elif insn.size == 2:
                    if ba[0] == 0xbe:
                        insn.Op1.type = o_reg
                        insn.Op1.reg = str2reg("X")
                        insn.Op2.type = o_mem
                        insn.Op2.addr = ba[1]
                    elif ba[0] == 0xee:
                        insn.Op1.type = o_reg
                        insn.Op1.reg = str2reg("X")
                        insn.Op2.type = o_phrase
                        insn.Op2.reg = str2reg("X")
                        insn.Op2.value = ba[1]
                        insn.Op2.specflag1 = 1
                    elif ba[0] == 0x1e:
                        insn.Op1.type = o_reg
                        insn.Op1.reg = str2reg("X")
                        insn.Op2.type = o_phrase
                        insn.Op2.reg = str2reg("SP")
                        insn.Op2.value = ba[1]
                        insn.Op2.specflag1 = 1
                    elif ba[0] == 0xbf:
                        insn.Op1.type = o_mem
                        insn.Op1.addr = ba[1]
                        insn.Op2.type = o_reg
                        insn.Op2.reg = str2reg("X")
                    elif ba[0] == 0xef:
                        insn.Op1.type = o_phrase
                        insn.Op1.reg = str2reg("X")
                        insn.Op1.value = ba[1]
                        insn.Op1.specflag1 = 1
                        insn.Op2.type = o_reg
                        insn.Op2.reg = str2reg("Y")
                    elif ba[0] == 0x1f:
                        insn.Op1.type = o_phrase
                        insn.Op1.reg = str2reg("SP")
                        insn.Op1.value = ba[1]
                        insn.Op1.specflag1 = 1
                        insn.Op2.type = o_reg
                        insn.Op2.reg = str2reg("X")
                    elif ba[0] == 0x90 and ba[1] == 0x93:
                        insn.Op1.type = o_reg
                        insn.Op2.type = o_reg
                        insn.Op1.reg = str2reg("Y")
                        insn.Op2.reg = str2reg("X")
                    elif ba[0] == 0x90 and ba[1] == 0xfe:
                        insn.Op1.type = o_reg
                        insn.Op1.reg = str2reg("Y")
                        insn.Op2.type = o_phrase
                        insn.Op2.reg = str2reg("Y")

                elif insn.size == 3:
                    if ba[0] == 0xae:
                        insn.Op1.type = o_reg
                        insn.Op1.reg = str2reg("X")
                        insn.Op2.type = o_imm
                        insn.Op2.value = (ba[1]<<8)|ba[2]
                    elif ba[0] == 0xce:
                        insn.Op1.type = o_reg
                        insn.Op1.reg = str2reg("X")
                        insn.Op2.type = o_mem
                        insn.Op2.addr = (ba[1]<<8)|ba[2]
                    elif ba[0] == 0xde:
                        insn.Op1.type = o_reg
                        insn.Op1.reg = str2reg("X")
                        insn.Op2.type = o_phrase
                        insn.Op2.reg = str2reg("X")
                        insn.Op2.value = (ba[1]<<8)|ba[2]
                        insn.Op2.specflag1 = 1
                    elif ba[0] == 0x92 and ba[1] == 0xce:
                        insn.Op1.type = o_reg
                        insn.Op1.reg = str2reg("X")
                        insn.Op2.type = o_mem
                        insn.Op2.addr = ba[2]
                        insn.Op2.specflag1 = 2
                    elif ba[0] == 0x92 and ba[1] == 0xde:
                        insn.Op1.type = o_reg
                        insn.Op1.reg = str2reg("X")
                        insn.Op2.type = o_phrase
                        insn.Op2.reg = str2reg("X")
                        insn.Op2.value = ba[2]
                        insn.Op2.specflag1 = 1
                        insn.Op2.specflag2 = 2
                    elif ba[0] == 0xcf:
                        insn.Op1.type = o_mem
                        insn.Op1.addr = (ba[1]<<8)|ba[2]
                        insn.Op2.type = o_reg
                        insn.Op2.reg = str2reg("X")
                    elif ba[0] == 0xdf:
                        insn.Op1.type = o_phrase
                        insn.Op1.reg = str2reg("X")
                        insn.Op1.value = (ba[1]<<8)|ba[2]
                        insn.Op1.specflag1 = 1
                        insn.Op2.type = o_reg
                        insn.Op2.reg = str2reg("Y")
                    elif ba[0] == 0x92 and ba[1] == 0xcf:
                        insn.Op1.type = o_mem
                        insn.Op1.addr = ba[2]
                        insn.Op1.specflag1 = 2
                        insn.Op2.type = o_reg
                        insn.Op2.reg = str2reg("X")
                    elif ba[0] == 0x92 and ba[1] == 0xdf:
                        insn.Op1.type = o_phrase
                        insn.Op1.reg = str2reg("X")
                        insn.Op1.addr = ba[2]
                        insn.Op1.specflag1 = 1
                        insn.Op2.specflag2 = 2
                        insn.Op2.type = o_reg
                        insn.Op2.reg = str2reg("Y")
                    elif ba[0] == 0x90 and ba[1] == 0xbe:
                        insn.Op1.type = o_reg
                        insn.Op1.reg = str2reg("Y")
                        insn.Op2.type = o_mem
                        insn.Op2.addr = ba[2]
                    elif ba[0] == 0x90 and ba[1] == 0xbf:
                        insn.Op2.type = o_reg
                        insn.Op2.reg = str2reg("Y")
                        insn.Op1.type = o_mem
                        insn.Op1.addr = ba[2]

                elif insn.size == 4:
                    if ba[0] == 0x72 and ba[1] == 0xce:
                        insn.Op1.type = o_reg
                        insn.Op1.reg = str2reg("X")
                        insn.Op2.type = o_mem
                        insn.Op2.addr = (ba[2]<<8)|ba[3]
                        insn.Op2.specflag1 = 2
                    if ba[0] == 0x72 and ba[1] == 0xcf:
                        insn.Op2.type = o_reg
                        insn.Op2.reg = str2reg("X")
                        insn.Op1.type = o_mem
                        insn.Op1.addr = (ba[2]<<8)|ba[3]
                        insn.Op1.specflag1 = 2
                    elif ba[0] == 0x22 and ba[1] == 0xde:
                        insn.Op1.type = o_reg
                        insn.Op1.reg = str2reg("X")
                        insn.Op2.type = o_phrase
                        insn.Op2.reg = str2reg("X")
                        insn.Op2.value = (ba[2]<<8)|ba[3]
                        insn.Op2.specflag1 = 1
                        insn.Op2.specflag2 = 2
                    elif ba[0] == 0x72 and ba[1] == 0xdf:
                        insn.Op1.type = o_phrase
                        insn.Op1.reg = str2reg("X")
                        insn.Op1.addr = (ba[2]<<8)|ba[3]
                        insn.Op1.specflag1 = 1
                        insn.Op2.specflag2 = 2
                        insn.Op2.type = o_reg
                        insn.Op2.reg = str2reg("Y")
                    elif ba[0] == 0x90 and ba[1] == 0xae:
                        insn.Op1.type = o_reg
                        insn.Op1.reg = str2reg("Y")
                        insn.Op2.type = o_imm
                        insn.Op2.value = (ba[2]<<8)|ba[3]
                        
                return True

            def handle_mov(self, insn, w):
                ba = get_bytes(insn.ea,insn.size)
                if insn.size == 3:
                    if ba[0] == 0x45:
                        insn.Op1.type = o_mem
                        insn.Op1.addr = ba[2]
                        insn.Op2.type = o_mem
                        insn.Op2.addr = ba[1]
                elif insn.size == 4:
                    if ba[0] == 0x35:
                        insn.Op1.type = o_mem
                        insn.Op1.addr = (ba[2]<<8)|ba[3]
                        insn.Op2.type = o_imm
                        insn.Op2.value = ba[1]
                    elif ba[0] == 0x55:
                        insn.Op1.type = o_mem
                        insn.Op1.addr = (ba[3]<<8)|ba[4]
                        insn.Op2.type = o_mem
                        insn.Op2.addr = (ba[1]<<8)|ba[2]
                return True

            def handle_mul(self, insn, w):
                return True

            def handle_neg(self, insn, w):
                ba = get_bytes(insn.ea,insn.size)
                if insn.size == 2:
                    if ba[0] == 0x00:
                        insn.Op1.type = o_phrase
                        insn.Op1.value = ba[1]
                        insn.Op1.reg = str2reg("SP")
                        insn.Op1.specflag1 = 1

                return True

            def handle_negw(self, insn, w):
                return True

            def handle_nop(self, insn, w):
                return True

            def handle_or(self, insn, w):
                ba = get_bytes(insn.ea,insn.size)
                if insn.size == 2:
                    if ba[0] == 0xba:
                        insn.Op1.type = o_reg
                        insn.Op1.reg = str2reg("A")
                        insn.Op2.type = o_mem
                        insn.Op2.addr = ba[1]
                elif insn.size == 3:
                    if ba[0] == 0xca:
                        insn.Op1.type = o_reg
                        insn.Op1.reg = str2reg("A")
                        insn.Op2.type = o_mem
                        insn.Op2.addr = (ba[1]<<8)|ba[2]
                return True

            def handle_pop(self, insn, w):
                ba = get_bytes(insn.ea,insn.size)
                if insn.size == 1:
                    insn.Op1.type = o_reg
                    if ba[0] == 0x84:
                        insn.Op1.reg = str2reg("A")
                    elif ba[0] == 0x86:
                        insn.Op1.reg = str2reg("CC")
                elif insn.size == 3:
                    if ba[0] == 0x32:
                        insn.Op1.type = o_mem
                        insn.Op1.addr = (ba[1]<<8)|ba[2]

                return True

            def handle_popw(self, insn, w):
                ba = get_bytes(insn.ea,insn.size)
                insn.Op1.type = o_reg
                if insn.size == 1:
                    insn.Op1.reg = str2reg("X")
                else:
                    insn.Op1.reg = str2reg("Y")
                return True

            def handle_push(self, insn, w):
                ba = get_bytes(insn.ea,insn.size)
                if insn.size == 1:
                    insn.Op1.type = o_reg
                    if ba[0] == 0x88:
                        insn.Op1.reg = str2reg("A")
                    elif ba[0] == 0x8a:
                        insn.Op1.reg = str2reg("CC")
                elif insn.size == 2:
                    if ba[0] == 0x4b:
                        insn.Op1.type = o_imm
                        insn.Op1.value = ba[1]
                elif insn.size == 3:
                    if ba[0] == 0x3b:
                        insn.Op1.type = o_mem
                        insn.Op1.addr = (ba[1]<<8)|ba[2]
                return True

            def handle_pushw(self, insn, w):
                ba = get_bytes(insn.ea,insn.size)
                if insn.size == 1:
                    if ba[0] == 0x89:
                        insn.Op1.type = o_reg
                        insn.Op1.reg = str2reg("X")
                elif insn.size == 2:    
                    if ba[0] == 0x90 and ba[1] == 0x89:
                        insn.Op1.type = o_reg
                        insn.Op1.reg = str2reg("Y")
                return True

            def handle_rcf(self, insn, w):
                return True

            def handle_ret(self, insn, w):
                return True

            def handle_retf(self, insn, w):
                return True

            def handle_rim(self, insn, w):
                return True

            def handle_rlc(self, insn, w):
                ba = get_bytes(insn.ea,insn.size)
                if insn.size == 2:
                    if ba[0] == 9:
                        insn.Op1.type = o_phrase
                        insn.Op1.reg = str2reg("SP")
                        insn.Op1.value = ba[1]
                        insn.Op1.specflag1 = 1
                return True

            def handle_rlcw(self, insn, w):
                return True

            def handle_rlwa(self, insn, w):
                insn.Op1.type = o_reg
                if insn.size == 1:
                    insn.Op1.reg = str2reg("X")
                else:
                    insn.Op1.reg = str2reg("Y")

                return True

            def handle_rrc(self, insn, w):
                return True

            def handle_rrcw(self, insn, w):
                return True

            def handle_rrwa(self, insn, w):
                ba = get_bytes(insn.ea,insn.size)
                if insn.size == 1 and ba[0] == 1:
                    insn.Op1.type = o_reg
                    insn.Op1.reg = str2reg("X")
                elif insn.size == 2 and ba[0] == 0x90 and ba[1] == 1:
                    insn.Op1.type = o_reg
                    insn.Op1.reg = str2reg("Y")

                return True

            def handle_rvf(self, insn, w):
                return True

            def handle_sbc(self, insn, w):
                return True

            def handle_scf(self, insn, w):
                return True

            def handle_sim(self, insn, w):
                return True

            def handle_sll(self, insn, w):
                ba = get_bytes(insn.ea,insn.size)
                if insn.size == 1:
                    if ba[0] == 0x48:
                        insn.Op1.type = o_reg
                        insn.Op1.reg = str2reg("A")
                elif insn.size == 2:
                    if ba[0] == 0x08:
                        insn.Op1.type = o_phrase
                        insn.Op1.reg = str2reg("SP")
                        insn.Op1.value = ba[1]
                        insn.Op1.specflag1 = 1
                return True

            def handle_sllw(self, insn, w):
                if insn.size == 1:
                    insn.Op1.type = o_reg
                    insn.Op1.reg = str2reg("X")
                elif insn.size == 2:
                    insn.Op1.type = o_reg
                    insn.Op1.reg = str2reg("Y")
                return True

            def handle_sra(self, insn, w):
                return True

            def handle_sraw(self, insn, w):
                return True

            def handle_srl(self, insn, w):
                ba = get_bytes(insn.ea,insn.size)
                if insn.size == 1:
                    if ba[0] == 0x44:
                        insn.Op1.type = o_reg
                        insn.Op1.reg = str2reg("A")
                elif insn.size == 2:
                    if ba[0] == 4:
                        insn.Op1.type = o_phrase
                        insn.Op1.reg = str2reg("SP")
                        insn.Op1.value = ba[1]
                        insn.Op1.specflag1 = 1
                    
                return True

            def handle_srlw(self, insn, w):
                insn.Op1.type = o_reg
                insn.Op1.reg = str2reg("X")
                return True

            def handle_sub(self, insn, w):
                ba = get_bytes(insn.ea,insn.size)
                if insn.size == 2:
                    if ba[0] == 0x52:
                        insn.Op1.type = o_reg
                        insn.Op1.reg = str2reg("SP")
                        insn.Op2.type = o_imm
                        insn.Op2.value = ba[1]
                    elif ba[0] == 0x10:
                        insn.Op1.type = o_reg
                        insn.Op1.reg = str2reg("A")
                        insn.Op2.type = o_phrase
                        insn.Op2.reg = str2reg("SP")
                        insn.Op2.value = ba[1]
                        insn.Op2.specflag1 = 1

                return True

            def handle_subw(self, insn, w):
                ba = get_bytes(insn.ea,insn.size)
                if insn.size == 3:
                    insn.Op1.type = o_reg
                    insn.Op1.reg = str2reg("X")
                    insn.Op2.type = o_imm
                    insn.Op2.value = (ba[1]<<8)|ba[2]
                elif insn.size == 4:
                    insn.Op1.type = o_reg
                    insn.Op1.reg = str2reg("Y")
                    insn.Op2.type = o_mem
                    insn.Op2.addr = (ba[2]<<8)|ba[3]
                return True

            def handle_swap(self, insn, w):
                ba = get_bytes(insn.ea,insn.size)
                if insn.size  == 1:
                    if ba[0] == 0x4e:
                        insn.Op1.type = o_reg
                        insn.Op1.reg = str2reg("A")
                elif insn.size == 2:
                    if ba[0] == 0x0e:
                        insn.Op1.type = o_phrase
                        insn.Op1.reg = str2reg("SP")
                        insn.Op1.value = ba[1]
                        insn.Op1.specflag1 = 1
                return True

            def handle_swapw(self, insn, w):
                return True

            def handle_tnz(self, insn, w):
                ba = get_bytes(insn.ea,insn.size)
                if insn.size == 2:
                    if ba[0] == 0x3d:
                        insn.Op1.type = o_mem
                        insn.Op1.addr = ba[1]
                return True

            def handle_tnzw(self, insn, w):
                insn.Op1.type = o_reg
                if insn.size == 1:
                    insn.Op1.reg = str2reg("X")
                else:
                    insn.Op1.reg = str2reg("Y")
                return True

            def handle_trap(self, insn, w):
                return True

            def handle_wfe(self, insn, w):
                return True

            def handle_wfi(self, insn, w):
                return True

            def handle_xor(self, insn, w):
                ba = get_bytes(insn.ea,insn.size)
                if insn.size == 1:
                    if ba[0] == 0xf8:
                        insn.Op1.type = o_reg
                        insn.Op1.reg = str2reg("A")
                        insn.Op2.type = o_phrase
                        insn.Op2.reg = str2reg("X")
                elif insn.size == 2:
                    if ba[0] == 0xb8:
                        insn.Op1.type = o_reg
                        insn.Op1.reg = str2reg("A")
                        insn.Op2.type = o_imm
                        insn.Op2.value = ba[1]
                    elif ba[0] == 0xa8:
                        insn.Op1.type = o_reg
                        insn.Op1.reg = str2reg("A")
                        insn.Op2.type = o_imm
                        insn.Op2.value = ba[1]
                    elif ba[0] == 0x90 and ba[1] == 0xf8:
                        insn.Op1.type = o_reg
                        insn.Op1.reg = str2reg("A")
                        insn.Op2.type = o_phrase
                        insn.Op2.reg = str2reg("Y")
                elif insn.size == 3:
                    if ba[0] == 0x92 and ba[1] == 0xc8:
                        insn.Op1.type = o_reg
                        insn.Op1.reg = str2reg("A")
                        insn.Op2.type = o_mem
                        insn.Op2.addr = ba[2]
                        insn.Op2.specflag1 = 2
                return True
            
            def handle_jrc(self, insn, w):
                ba = get_bytes(insn.ea,insn.size)
                insn.Op1.type = o_mem
                insn.Op1.addr = insn.ea + 2 + get_signed(ba[1],0xff)
                return True

            def handle_jreq(self, insn, w):
                ba = get_bytes(insn.ea,insn.size)
                insn.Op1.type = o_mem
                insn.Op1.addr = get_signed(ba[1],0xff) + insn.ea + 2
                return True

            def handle_jrf(self, insn, w):
                ba = get_bytes(insn.ea,insn.size)
                insn.Op1.type = o_mem
                insn.Op1.addr = insn.ea + 2 + get_signed(ba[1],0xff)
                return True

            def handle_jrh(self, insn, w):
                ba = get_bytes(insn.ea,insn.size)
                insn.Op1.type = o_mem
                insn.Op1.addr = insn.ea + 2 + get_signed(ba[1],0xff)
                return True

            def handle_jrih(self, insn, w):
                ba = get_bytes(insn.ea,insn.size)
                insn.Op1.type = o_mem
                insn.Op1.addr = insn.ea + 2 + get_signed(ba[1],0xff)
                return True

            def handle_jril(self, insn, w):
                ba = get_bytes(insn.ea,insn.size)
                insn.Op1.type = o_mem
                insn.Op1.addr = insn.ea + 2 + get_signed(ba[1],0xff)
                return True

            def handle_jrm(self, insn, w):
                ba = get_bytes(insn.ea,insn.size)
                insn.Op1.type = o_mem
                insn.Op1.addr = insn.ea + 2 + get_signed(ba[1],0xff)
                return True

            def handle_jrmi(self, insn, w):
                ba = get_bytes(insn.ea,insn.size)
                insn.Op1.type = o_mem
                insn.Op1.addr = insn.ea + 2 + get_signed(ba[1],0xff)
                return True

            def handle_jrnc(self, insn, w):
                ba = get_bytes(insn.ea,insn.size)
                insn.Op1.type = o_mem
                insn.Op1.addr = insn.ea + 2 + get_signed(ba[1],0xff)
                return True

            def handle_jrne(self, insn, w):
                ba = get_bytes(insn.ea,insn.size)
                if insn.size == 2:
                    insn.Op1.type = o_mem
                    insn.Op1.addr = insn.ea + 2 + get_signed(ba[1],0xff)
                return True

            def handle_jrnh(self, insn, w):
                ba = get_bytes(insn.ea,insn.size)
                insn.Op1.type = o_mem
                insn.Op1.addr = insn.ea + 2 + get_signed(ba[1],0xff)
                return True

            def handle_jrnm(self, insn, w):
                ba = get_bytes(insn.ea,insn.size)
                insn.Op1.type = o_mem
                insn.Op1.addr = insn.ea + 2 + get_signed(ba[1],0xff)
                return True

            def handle_jrnv(self, insn, w):
                ba = get_bytes(insn.ea,insn.size)
                insn.Op1.type = o_mem
                insn.Op1.addr = insn.ea + 2 + get_signed(ba[1],0xff)
                return True

            def handle_jrpl(self, insn, w):
                ba = get_bytes(insn.ea,insn.size)
                insn.Op1.type = o_mem
                insn.Op1.addr = insn.ea + 2 + get_signed(ba[1],0xff)
                return True

            def handle_jrsge(self, insn, w):
                ba = get_bytes(insn.ea,insn.size)
                insn.Op1.type = o_mem
                insn.Op1.addr = insn.ea + 2 + get_signed(ba[1],0xff)
                return True

            def handle_jrsgt(self, insn, w):
                ba = get_bytes(insn.ea,insn.size)
                insn.Op1.type = o_mem
                insn.Op1.addr = insn.ea + 2 + get_signed(ba[1],0xff)
                return True

            def handle_jrsle(self, insn, w):
                ba = get_bytes(insn.ea,insn.size)
                insn.Op1.type = o_mem
                insn.Op1.addr = insn.ea + 2 + get_signed(ba[1],0xff)
                return True

            def handle_jrslt(self, insn, w):
                ba = get_bytes(insn.ea,insn.size)
                insn.Op1.type = o_mem
                insn.Op1.addr = insn.ea + 2 + get_signed(ba[1],0xff)
                return True

            def handle_jrt(self, insn, w):
                ba = get_bytes(insn.ea,insn.size)
                insn.Op1.type = o_mem
                insn.Op1.addr = insn.ea + get_signed(ba[1],0xff) + 2
                return True

            def handle_jruge(self, insn, w):
                ba = get_bytes(insn.ea,insn.size)
                insn.Op1.type = o_mem
                insn.Op1.addr = insn.ea + 2 + get_signed(ba[1],0xff)
                return True
            
            def handle_jrugt(self, insn, w):
                ba = get_bytes(insn.ea,insn.size)
                insn.Op1.type = o_mem
                insn.Op1.addr = insn.ea + 2 + get_signed(ba[1],0xff)
                return True

            def handle_jrule(self, insn, w):
                ba = get_bytes(insn.ea,insn.size)
                insn.Op1.type = o_mem
                insn.Op1.addr = insn.ea + 2 + get_signed(ba[1],0xff)
                return True

            def handle_jrc(self, insn, w):
                ba = get_bytes(insn.ea,insn.size)
                insn.Op1.type = o_mem
                insn.Op1.addr = insn.ea + 2 + get_signed(ba[1],0xff)
                return True

            def handle_jrult(self, insn, w):
                ba = get_bytes(insn.ea,insn.size)
                insn.Op1.type = o_mem
                insn.Op1.addr = insn.ea + 2 + get_signed(ba[1],0xff)
                return True

            def handle_jrv(self, insn, w):
                ba = get_bytes(insn.ea,insn.size)
                insn.Op1.type = o_mem
                insn.Op1.addr = insn.ea + 2 + get_signed(ba[1],0xff)
                return True
        
        i = 0
        for x in self.instruc:
            if x['name']!= "":
                setattr(self, 'itype_' + x['name'], i)
                itype_map['itype_' + x['name']]=i
            else:
                setattr(self, 'itype_null', i)
            i += 1
    
        # icode of the last instruction + 1
        self.instruc_end = i

        self.itable={}
        
        i=0
        for opcode in self.ins_map.keys():
            ins = self.ins_map[opcode]
            name=ins['name']
            insn_size=ins['insn_size']
            opcode_mask=ins['opcode_mask']
            ins_type = ins['ins_type']
            if ins_type != 'dup':
                
                v = getattr(self, 'itype_' + name)
                ins_def = idef(name,insn_size,opcode_mask,itype = v)
                
                
                
            else:
                ins_list=ins['cmt'].split(' ')
                ins_def = idef(ins_list[0],insn_size,opcode_mask, dup_ins = True)
            
                i+=len(ins_list)
                
            
            self.itable[opcode]=ins_def
        
        #instruction to map id
        

    def __init__(self):
        processor_t.__init__(self)
        self.init_instructions()
        self.init_registers()

# 注册处理器模块
def PROCESSOR_ENTRY():
    return STM8Processor()
