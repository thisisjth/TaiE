# -*- encoding: utf-8

from queue import Queue
import re, math
from re import Pattern
from angr import SimState
from capstone import CsInsn
from config.constant import RT_NO_RET, STACK_UNSATISFIED
from lib.executor import Executor
from lib.stack.arml import ArmLStack
from typing import Callable, Dict, List, Tuple
from lib import Binary, Cache, ExePath, Func, InsnMgr, InsnNotFound, InvalidAddress, Helper, Logger


# 指令执行条件
conds:List[str] = ['eq', 'ne', 'cs', 'hs', 'cc' ,'lo', 'mi', 'pl', 'vs', 'vc', 'hi', 'ls', 'ge', 'lt', 'gt', 'le', 'nv', 'al', '']

class ArmLExecutor(Executor):
    '''
    ARM小端指令集执行器基类
    '''

    # 架构名称：用于angr加载二进制，需要与angr中的对应
    arch_name:str = 'armel'

    # 条件跳转指令
    cjmps:List[str] = Helper.merge(*map(lambda b: list(map(lambda c:b+c, conds[:-3])), ['b']))
    # 非条件跳转指令
    ucjmps:List[str] = Helper.merge(*map(lambda b: list(map(lambda c:b+c, conds[-2:])), ['b']))
    # 跳转指令
    jmps:List[str] = cjmps + ucjmps
    # 函数返回指令
    rets:List[str] = []
    # 函数调用指令
    calls:List[str] = Helper.merge(*map(lambda b: list(map(lambda c:b+c, conds)), ['bl', 'blx', 'bx']))
    # nop指令 
    nops:List[str] = []
    # 函数间填充字节
    paddings:List[int] = []
    # 无意义指令的规则列表
    null_insn_regs:List[Pattern] = [
        re.compile('nop'),
        re.compile('svclo'),
        re.compile('andeq (?P<reg>\w+), (?P=reg), (?P=reg)'),
        re.compile('mov (?P<reg>\S+), (?P=reg)')
    ]
    # 寄存器们
    registers:List[str] = list(map(lambda i:f'r{i}', range(16))) + ['pc', 'lr', 'sp', 'fp', 'cpsr']
    # 用于提取间接跳转表达式中下标指示变量的正则
    idx_reg:Pattern = re.compile(r'\[(?:[a-z\d]+\s*\+\s*)?(\[?[a-z]{2,6}\s*(?:[\+\-](?:0x)?[\da-f]+)?\]?)\s*\*\s*\d+(?:\s*[\+\-]\s*(?:0x)?[\da-f]+)?\]')
    # 寄存器的正则
    reg_reg:Pattern = re.compile(r'(?:r\d)|(?:lr|fp|sp|pc|cpsr)')
    # 根据条件跳转的类型 决定生成的下标范围
    op_to_ranges:Dict[str, Callable[[int], List[int]]] = {
        'eq': lambda b: [b],
        'cs': lambda b: list(range(b, 256)),
        'hs': lambda b: list(range(b, 256)),
        'cc': lambda b: list(range(b)),
        'lo': lambda b: list(range(b)),
        'hi': lambda b: list(range(b+1, 256)),
        'ls': lambda b: list(range(b+1)),
        'ge': lambda b: list(range(b, 256)),
        'lt': lambda b: list(range(b)),
        'gt': lambda b: list(range(b+1, 256)),
        'le': lambda b: list(range(b+1))
    }
    # 栈操作指令字节序列的识别规则
    stack_op_regs:Dict[str, Dict[str, Tuple[Pattern, int]]] = {
        # 开栈正则
        'O': {
            # push {rrr, lr}
            'push_rrr_lr': (re.compile(rb'.{1}[\x40\x41\x42\x44\x45\x48\x4F\x50][\xAD\x2D]\xE9'), 2),
            # push {lr}
            'push_lr': (re.compile(rb'\x04\xE0\x2D\xE5'), 2),
            # push reg 
            'push': (re.compile(rb'.{2}[\xAD\x2D][\x05\x15\x25\x35\x45\x55\x65\x75\x85\x95\xA5\xB5\xC5\xD5\xE5]'), 1),
            # stmia sp! E8AD000F   stmda sp! E82D000F
            'stmxa': (re.compile(rb'.{2}[\xAD\x2D][\x08\x18\x28\x38\x48\x58\x68\x78\x88\x98\xA8\xB8\xC8\xD8\xE8]'), 1),
            # stmib sp! E9AD000F   stmdb sp! E92D000F   
            'stmxb': (re.compile(rb'.{1}[^\x40\x41\x42\x44\x48\x4F\x50][\xAD\x2D][\x09\x19\x29\x39\x49\x59\x69\x79\x89\x99\xA9\xB9\xC9\xD9\xE9]'), 1),
            # sub sp reg
            'sub_sp_reg': (re.compile(rb'.{1}[\xD0-\xDF][\x40-\x4F][\x00\x10\x20\x30\x40\x50\x60\x70\x80\x90\xA0\xB0\xC0\xD0\xE0]'), 1),
            # sub sp #2
            'sub_sp': (re.compile(rb'.{1}[\xD0-\xDF][\x40-\x4F][\x02\x12\x22\x32\x42\x52\x62\x72\x82\x92\xA2\xB2\xC2\xD2\xE2]'), 1),
            # add fp, sp, #0
            'add_fp_sp_0': (re.compile(rb'.{1}\xB0\x8D\xE2'), 1),
            # mov fp, #0
            'mov_fp_0': (re.compile(rb'\x00\xB0\xA0\xE3'), 1),
            # mov lr, #0
            'mov_lr_0': (re.compile(rb'\x00\xE0\xA0\xE3'), 1)
        },
        # 退栈正则
        'R': {
            # pop reg 
            'pop': (re.compile(rb'.{2}[\x9D\x1D][\x04\x14\x24\x34\x44\x54\x64\x74\x84\x94\xA4\xB4\xC4\xD4\xE4]'), 1),
            # ldmia sp! E8BD0001   ldmda sp! E83D0001
            'ldmxa': (re.compile(rb'.{2}[\xBD\x3D][\x08\x18\x28\x38\x48\x58\x68\x78\x88\x98\xA8\xB8\xC8\xD8\xE8]'), 1),
            # ldmib sp! E9BD0001   ldmdb sp! E93D0001
            'ldmxb': (re.compile(rb'.{2}[\xBD\x3D][\x09\x19\x29\x39\x49\x59\x69\x79\x89\x99\xA9\xB9\xC9\xD9\xE9]'), 1),
            # add sp reg
            'add_sp_reg': (re.compile(rb'.{1}[\xD0-\xDF][\x80-\x8F][\x00\x10\x20\x30\x40\x50\x60\x70\x80\x90\xA0\xB0\xC0\xD0\xE0]'), 1),
            # add sp #2
            'add_sp': (re.compile(rb'.{1}[\xD0-\xDF][\x80-\x8F][\x02\x12\x22\x32\x42\x52\x62\x72\x82\x92\xA2\xB2\xC2\xD2\xE2]'), 1),
        }
    }

    logger:Logger = Logger('Executor.ArmL')

    @classmethod
    def search_stack_ops(cls, bin:Binary) -> List[Tuple[int, bytes, int, str, str]]:
        '''
        根据规则从二进制中寻找相关的开/退栈操作，并返回操作指令所在位置、指令字节、规则权重、规则名称与栈操作类型
        '''
        # 结果 先按照正则获取到指令集合
        results:List[Tuple[int, bytes, int, str, str]] = super().search_stack_ops(bin)
        # 由于ARM指令都是定长的 可以剔除地址不对的指令
        return list(filter(lambda r:(bin.text_base+r[0]) % 4 == 0, results))

    @classmethod
    def callsites_of(cls, addr:int, bin:Binary) -> List[CsInsn]:
        '''
        寻找所有以addr为目标的函数调用行为所在的位置
        '''
        # 如果没有缓存下来的函数调用指令进行分析先
        if Cache.CALL_INSNS is None:
            Cache.CALL_INSNS = []
            # 先找所有的函数调用指令
            for m in re.finditer(rb'.{3}[\x0B\x1B\x2B\x3B\x4B\x5B\x6B\x7B\x8B\x9B\xAB\xBB\xCB\xDB\xEB]', bin.bytes):
                # 文件偏移也得是4字节对齐的吧？
                if m.start() % 4 != 0: continue
                # 尝试反汇编 检查是否符合对目标地址的调用
                try:
                    insn:CsInsn = list(bin.disasm.disasm(m.group(0), bin.text_base+m.start()))[0]
                    if Helper.is_int(insn.op_str) and insn.address % 4 == 0 and Helper.to_int(insn.op_str) % 4 == 0: Cache.CALL_INSNS.append(insn)
                except Exception: continue
        # 使用函数调用指令进行分析
        return list(filter(lambda insn: Helper.to_int(insn.op_str) == addr, Cache.CALL_INSNS))

    @classmethod
    def reliable_stack_op_groups(cls, stack_ops:List[Tuple[int, bytes, int, str, str]], bin:Binary, l:int=2) -> List[Tuple[int, int]]:
        # 获取初步分组结果
        op_groups:List[Tuple[int, int]] = super().reliable_stack_op_groups(stack_ops, bin, l=l)
        i:int = 0
        while i < len(op_groups):
            grp:Tuple[int, int] = op_groups[i]
            the_addr:int = Helper.align(bin.text_base+stack_ops[grp[0]][0])
            try:
                the_insn:CsInsn = InsnMgr.insn_at(the_addr, bin, cls)
                if the_addr == bin.text_base+stack_ops[grp[0]][0] and not Helper.any(lambda k1: Helper.any(lambda v2:v2[0].match(the_insn.bytes), cls.stack_op_regs[k1].values()), cls.stack_op_regs.keys()):
                    op_groups.pop(i)
                    continue
                if the_insn.address != bin.text_base+stack_ops[grp[0]][0] and the_insn.address+the_insn.size != bin.text_base+stack_ops[grp[0]][0]:
                    op_groups.pop(i)
                    continue
            except Exception:
                op_groups.pop(i)
                continue
            i += 1
        return op_groups

    @classmethod
    def get_idx_in_expression(cls, exp:str) -> str:
        '''
        从间接跳转的目标地址值中提取下标变量
        '''
        ms:List[str] = cls.idx_reg.findall(exp)
        if len(ms) > 0: return ms[0]
        return None

    @classmethod
    def targets_for_indirect_jmp(cls, insn:CsInsn, bin:Binary, history:List[CsInsn]) -> List[int]:
        '''
        为间接跳转寻找目标
        '''
        # 如果有缓存
        if insn.address in Cache.INDIRECT_JUMP: return Cache.INDIRECT_JUMP[insn.address]
        # 如果是 LDRxx PC, [PC, xx, LSL#xx]  以及  r2, [pc, #0xbf4];  cmp     r3, r2; ldrls   pc, [pc, r3, lsl #2] 的情况
        if insn.mnemonic.startswith('ldr'): return cls.targets_for_indirect_jmp_ldr(insn, bin, history)
        # 如果是 TBB.w [PC, Rm] 的情况
        if insn.mnemonic.startswith('tbb'): return cls.targets_for_indirect_jmp_tbb(insn, bin, history)
        # 如果是 TBH.w [PC, Rm] 的情况
        if insn.mnemonic.startswith('tbh'): return cls.targets_for_indirect_jmp_tbh(insn, bin, history)
    
    @classmethod
    def targets_for_indirect_jmp_ldr(cls, insn:CsInsn, bin:Binary, history:List[CsInsn]) -> List[int]:
        targets:List[int] = []
        # 目前能处理 LDRxx PC, [PC, xx, LSL#xx]  以及  r2, [pc, #0xbf4];  cmp     r3, r2; ldrls   pc, [pc, r3, lsl #2] 的情况
        # 从尾巴开始寻找一个ldr指令
        ldr_index:int = Helper.last_index(lambda i:i.mnemonic.startswith('ldr') and not Helper.is_int(i.op_str) and i.op_str.split(',')[0] in ['pc'] and len(i.op_str.split(',')) >= 4, history)
        # 如果找不到 那就出问题了
        if ldr_index < 0: 
            cls.logger.error('Cannot find a valid LDR instruction')
            return targets
        insn = history[ldr_index]

        # 确定用作索引的寄存器
        index_reg:str = insn.op_str.split(',')[2].strip()
        # 单个地址长度 （偷懒不计算了，直接定死4字节）
        addr_size:int = 4
        # 基址寄存器
        base_reg:str = insn.op_str.split(',')[1].replace('[', '').strip()
        # 如果不是以pc作为基址寄存器 那也不知道咋处理了
        if base_reg not in ['pc']:
            cls.logger.error(f'Cannot deal with "{insn.mnemonic}\t{insn.op_str}"', highlight=True)
            return targets
        # 看看边界值是多少
        boundary_value:int = cls.__idx_reg_boundary(index_reg, bin, history)
        if boundary_value < 0: return targets
        # 计算索引下标可能值
        index_values:List[int] = []
        if cls.has_cond(insn):
            index_values = cls.op_to_ranges[insn.mnemonic.replace('.w', '').replace('ldr', '')](boundary_value)
        else:
            # 寻找最近的一个条件跳转
            cjmp:CsInsn = Helper.last(lambda i:cls.is_cjmp(i), history)
            index_values = list(set(range(256)) - set(cls.op_to_ranges[cjmp.mnemonic.replace('.w', '')[-2:]](boundary_value)))
        # 在ARM中 相对寻址时候 使用的是PC+8作为基址
        targets = list(map(lambda iv: cls.compute(f'[{insn.address+8}+{addr_size}*{iv}]', bin, 'little'), index_values))
        Cache.INDIRECT_JUMP[insn.address] = list(set(targets))
        return Cache.INDIRECT_JUMP[insn.address]
    
    @classmethod
    def targets_for_indirect_jmp_tbb(cls, insn:CsInsn, bin:Binary, history:List[CsInsn]) -> List[int]:
        # 目前能处理 tbb.w [PC, Rm] 的情况
        targets:List[int] = []
        m:re.Match = re.match(r'^\[(?P<base>(?:r\d+|sp|fp|pc|lr|ip)), (?P<idx>(?:r\d+|sp|fp|pc|lr|ip))\]$', insn.op_str)
        if not m: 
            cls.logger.error(f'OP_STR "{insn.op_str}" not satisfied with predefined pattern')
            return targets
        base_reg:str = m.group('base')
        idx_reg:str = m.group('idx')
        # 暂时只处理以PC为基址的情况
        if base_reg != 'pc':
            cls.logger.error(f'Can not proceed when base_reg={base_reg}')
            return targets
        boundary:int = cls.__idx_reg_boundary(idx_reg, bin, history)
        values:List[int] = []
        if cls.has_cond(insn):
            values = cls.op_to_ranges[insn.mnemonic.replace('.w', '').replace('tbb', '')](boundary)
        else:
            # 寻找最近的一个条件跳转
            cjmp:CsInsn = Helper.last(lambda i:cls.is_cjmp(i), history)
            values = list(set(range(256)) - set(cls.op_to_ranges[cjmp.mnemonic.replace('.w', '')[-2:]](boundary)))
        # 在ARM中 相对寻址时候 使用的是PC+4作为基址
        addr_size:int = 1
        targets = list(map(lambda v: insn.address + 4 + 2 * cls.compute(f'[{insn.address+4}+{v}*{addr_size}]', bin, 'little', size=addr_size, signed=False), values))
        Cache.INDIRECT_JUMP[insn.address] = list(set(targets))
        return Cache.INDIRECT_JUMP[insn.address]
    
    @classmethod
    def targets_for_indirect_jmp_tbh(cls, insn:CsInsn, bin:Binary, history:List[CsInsn]) -> List[int]:
        # 目前能处理 tbh.w [PC, Rm, LSL #1] 的情况
        targets:List[int] = []
        m:re.Match = re.match(r'^\[(?P<base>(?:r\d+|sp|fp|pc|lr|ip)), (?P<idx>(?:r\d+|sp|fp|pc|lr|ip|sb)), lsl (?P<num>#?-?(?:0x)?[\da-f]+)\]$', insn.op_str)
        if not m: 
            cls.logger.error(f'OP_STR "{insn.op_str}" not satisfied with predefined pattern')
            return targets 
        base_reg:str = m.group('base')
        idx_reg:str = m.group('idx')
        # 暂时只处理以PC为基址的情况
        if base_reg != 'pc':
            cls.logger.error(f'Can not proceed when base_reg={base_reg}')
            return targets
        boundary:int = cls.__idx_reg_boundary(idx_reg, bin, history)
        values:List[int] = []
        if cls.has_cond(insn):
            values = cls.op_to_ranges[insn.mnemonic.replace('.w', '').replace('tbh', '')](boundary)
        else:
            # 寻找最近的一个条件跳转
            cjmp:CsInsn = Helper.last(lambda i:cls.is_cjmp(i), history)
            values = list(set(range(256)) - set(cls.op_to_ranges[cjmp.mnemonic.replace('.w', '')[-2:]](boundary)))
        # 在ARM中 相对寻址时候 使用的是PC+4作为基址
        addr_size:int = 2
        targets = list(map(lambda v: insn.address + 4 + pow(2, Helper.to_int(m.group('num'))) * cls.compute(f'[{insn.address+4}+{v}*{addr_size}]', bin, 'little', size=addr_size, signed=False), values))
        Cache.INDIRECT_JUMP[insn.address] = list(set(targets))
        return Cache.INDIRECT_JUMP[insn.address]

    @classmethod
    def __idx_reg_boundary(cls, idx_reg:str, bin:Binary, history:List[CsInsn]) -> int:
        '''
        构造用于求解间接跳转目标的表达式
        '''
        # 寻找对索引寄存器进行比较的指令
        the_cmp_insn_idx:int = Helper.last_index(lambda i:i.mnemonic in ['cmp'] and i.op_str.split(',')[0] == idx_reg, history)
        # 如果找不到cmp指令 那就没法分析了
        if the_cmp_insn_idx < 0: raise InsnNotFound('Cannot find a valid cmp instruction')
        # 分析比较的对象是谁
        value_source:str = history[the_cmp_insn_idx].op_str.split(',')[1]
        # 如果是常量 直接返回
        if Helper.is_int(value_source): return Helper.to_int(value_source)
        related_regs:List[str] = list(set(cls.reg_reg.findall(value_source)))
        for insn in history[:the_cmp_insn_idx][::-1]:
            try:
                boundary:int = cls.compute(value_source, bin, 'little')
                return boundary
            except Exception: pass
            # 如果不是相关指令 那就不分析了
            if insn.op_str.split(',')[0] not in related_regs: continue
            # 值进行替换
            if insn.mnemonic.startswith('ldr') or insn.mnemonic.startswith('mov'):
                opstr_parts:List[str] = insn.op_str.split(',')
                # ldr rr, [pc, rr]
                if len(opstr_parts) == 3 and opstr_parts[1].startswith(' [pc') and not opstr_parts[2].startswith(' #'): value_source = value_source.replace(opstr_parts[0], f'[{insn.address+8}+{opstr_parts[2].strip("]")}]')
                # ldr rr, [pc, #nn]
                elif len(opstr_parts) == 3 and opstr_parts[1].startswith(' [pc') and opstr_parts[2].startswith(' #'): value_source = value_source.replace(opstr_parts[0], f'[{insn.address+8}+{Helper.to_int(opstr_parts[2].strip("]").strip())}]')
                # ldr rr [rr, rr, #nn]
                elif len(opstr_parts) == 4 and opstr_parts[1].starswith(' [pc') and  opstr_parts[3].startswith(' lsl'): value_source = value_source.replace(opstr_parts[0], f'[{insn.address+8}+{opstr_parts[1].strip()}*{pow(2, opstr_parts[2].strip("]").replace("lsl", ""))}]')
            elif insn.mnemonic.startswith('add'): value_source = value_source.replace(insn.op_str.split(',')[0], '(' + '+'.join(insn.op_str.split(',')[-2:]) + ')') 
            elif insn.mnemonic.startswith('sub'): value_source = value_source.replace(insn.op_str.split(',')[0], '(' + '-'.join(insn.op_str.split(',')[-2:]) + ')')  
            # 更新相关寄存器
            related_regs:List[str] = list(set(cls.reg_reg.findall(value_source)))
        return -1

    @classmethod
    def resolve_indirect_call(cls, insn:CsInsn, bin:Binary, history:List[CsInsn]) -> List[int]:
        '''
        解决间接调用问题

        \param  history             历史执行路径
        \param  inst                间接调用指令本身
        \param  binary              相关二进制
        '''
        # 如果有缓存
        if insn.address in Cache.INDIRECT_CALL: return Cache.INDIRECT_CALL[insn.address]
        targets:List[int] = []
        # 等遇到了再看情况编写代码
        if len(targets) <= 0: raise NotImplementedError()
        Cache.INDIRECT_CALL[insn.address] = list(set(targets))
        return Cache.INDIRECT_CALL[insn.address]

    @classmethod
    def is_stack_satisfied(cls, insns:List[CsInsn]) -> int:
        '''
        判断输入的指令序列是否满足栈平衡
        '''
        s:ArmLStack = ArmLStack()
        try:
            for i in range(len(insns)):
                insn:CsInsn = insns[i]
                parts:List[str] = insn.op_str.split(', ')
                ops:List[str] = parts[:1] + [', '.join(parts[1:])]
                if insn.mnemonic.startswith('stm'):
                    values:List[str] = ops[1].strip('{').strip('}').strip().split(', ')
                    mnemonic:str = insn.mnemonic if not cls.has_cond(insn) else insn.mnemonic[:-2]
                    full_or_empty:str = ['e', 'e', 'e', 'e', 'f', 'f', 'f', 'f', 'f'][['ea', 'ia', 'ed', 'da', 'fa', 'ib', 'fd', 'db', 'tm'].index(mnemonic[-2:])]
                    ace_or_desc:str = ['a', 'a', 'd', 'd', 'a', 'a', 'd', 'd', 'd'][['ea', 'ia', 'ed', 'da', 'fa', 'ib', 'fd', 'db', 'tm'].index(mnemonic[-2:])]
                    s.stm(values, ops[0].strip('!').strip(), full_or_empty=full_or_empty, ace_or_desc=ace_or_desc, write_back=ops[0].endswith('!'))
                elif insn.mnemonic.startswith('ldm'):
                    # 如果是作为返回指令 但是又不是最后一条的话 那就放弃
                    if cls.is_ret(insn) and cls.has_cond(insn) and i < len(insns) - 1: continue
                    values:List[str] = ops[1].strip('{').strip('}').strip().split(', ')
                    mnemonic:str = insn.mnemonic if not cls.has_cond(insn) else insn.mnemonic[:-2]
                    full_or_empty:str = ['e', 'f', 'e', 'f', 'f', 'e', 'f', 'e', 'f'][['ea', 'ia', 'ed', 'da', 'fa', 'ib', 'fd', 'db', 'dm'].index(mnemonic[-2:])]
                    ace_or_desc:str = ['a', 'd', 'd', 'a', 'a', 'd', 'd', 'a', 'd'][['ea', 'ia', 'ed', 'da', 'fa', 'ib', 'fd', 'db', 'dm'].index(mnemonic[-2:])]
                    s.ldm(values, ops[0].strip('!').strip(), full_or_empty=full_or_empty, ace_or_desc=ace_or_desc, write_back=ops[0].endswith('!'))
                elif insn.mnemonic.startswith('push'):
                    values:List[str] = insn.op_str.strip('{').strip('}').strip().split(', ')
                    s.stm(values, 'sp', write_back=True)
                elif insn.mnemonic.startswith('pop'):
                    # 如果是作为返回指令 但是又不是最后一条的话 那就放弃
                    if cls.is_ret(insn) and cls.has_cond(insn) and i < len(insns) - 1: continue
                    values:List[str] = insn.op_str.strip('{').strip('}').strip().split(', ')
                    s.ldm(values, 'sp', write_back=True)
                if 'sp' not in insn.op_str and 'fp' not in insn.op_str and not (insn.mnemonic.startswith('mov') and ops[0] == 'pc' and ops[1] == 'lr'): continue
                if insn.mnemonic.startswith('mov'): 
                    # 如果是作为返回指令 但是又不是最后一条的话 那就放弃
                    if cls.is_ret(insn) and cls.has_cond(insn) and i < len(insns) - 1: continue
                    s.mov(ops[1].strip(), ops[0].strip())
                elif insn.mnemonic.startswith('str'): 
                    # str r0, [r1, #8]
                    m:re.Match = re.match(r'^(?P<frm>(?:r\d+|sp|fp|pc|lr|ip)), \[(?P<to>(?:r\d+|sp|fp|pc|lr|ip)), (?P<num>#?-?(?:0x)?[\da-f]+)\]$', insn.op_str)
                    if m: s.str(m.group('frm'), m.group('to'), offset=m.group('num'))
                    # str r0, [r1]
                    m:re.Match = re.match(r'^(?P<frm>(?:r\d+|sp|fp|pc|lr|ip)), \[(?P<to>(?:r\d+|sp|fp|pc|lr|ip))\]$', insn.op_str)
                    if m: s.str(m.group('frm'), m.group('to'))
                    # str r0, [r1], #8
                    m:re.Match = re.match(r'^(?P<frm>(?:r\d+|sp|fp|pc|lr|ip)), \[(?P<to>(?:r\d+|sp|fp|pc|lr|ip))\], (?P<num>#?-?(?:0x)?[\da-f]+)$', insn.op_str)
                    if m: s.str(m.group('frm'), m.group('to'), step=m.group('num'), write_back=True)
                    # str r0, [r1, #8]!
                    m:re.Match = re.match(r'^(?P<frm>(?:r\d+|sp|fp|pc|lr|ip)), \[(?P<to>(?:r\d+|sp|fp|pc|lr|ip)), (?P<num>#?-?(?:0x)?[\da-f]+)\]!$', insn.op_str)
                    if m: s.str(m.group('frm'), m.group('to'), offset=m.group('num'), step=m.group('num'), write_back=True)
                elif insn.mnemonic.startswith('ldr'):
                    # ldr r0, [r1]
                    m:re.Match = re.match(r'^(?P<to>(?:r\d+|sp|fp|pc|lr|ip)), \[(?P<frm>(?:r\d+|sp|fp|pc|lr|ip))\]$', insn.op_str)
                    if m: s.ldr(m.group('frm'), m.group('to'))
                    # ldr r0, [r1], #8
                    m:re.Match = re.match(r'^(?P<to>(?:r\d+|sp|fp|pc|lr|ip)), \[(?P<frm>(?:r\d+|sp|fp|pc|lr|ip))\], (?P<num>#?-?(?:0x)?[\da-f]+)$', insn.op_str)
                    if m: s.ldr(m.group('frm'), m.group('to'), step=m.group('num'), write_back=True)
                    # ldr r0, [r1, r2]
                    m:re.Match = re.match(r'^(?P<to>(?:r\d+|sp|fp|pc|lr|ip)), \[(?P<frm>(?:r\d+|sp|fp|pc|lr|ip)), (?P<num>(?:r\d+|sp|fp|pc|lr|ip))\]$', insn.op_str)
                    if m: s.ldr(m.group('frm'), m.group('to'), offset=m.group('num'))
                    # ldr r0, [r1, #8]
                    m:re.Match = re.match(r'^(?P<to>(?:r\d+|sp|fp|pc|lr|ip)), \[(?P<frm>(?:r\d+|sp|fp|pc|lr|ip)), (?P<num>#?-?(?:0x)?[\da-f]+)\]$', insn.op_str)
                    if m: s.ldr(m.group('frm'), m.group('to'), offset=m.group('num'))
                    # ldr r0, [r1, r2, LSL#8]
                    m:re.Match = re.match(r'^(?P<to>(?:r\d+|sp|fp|pc|lr|ip)), \[(?P<frm>(?:r\d+|sp|fp|pc|lr|ip)), (?P<tmp>(?:r\d+|sp|fp|pc|lr|ip)), LSL(?P<num>#?-?(?:0x)?[\da-f]+)\]$', insn.op_str)
                    if m: s.ldr(m.group('frm'), m.group('to'), offset=s.regs[m.group('tmp')]*pow(2, Helper.to_int(m.group('num'))))
                    # ldr r0, [r1, r2]
                    m:re.Match = re.match(r'^(?P<to>(?:r\d+|sp|fp|pc|lr|ip)), \[(?P<frm>(?:r\d+|sp|fp|pc|lr|ip)), (?P<num>(?:r\d+|sp|fp|pc|lr|ip))\]!$', insn.op_str)
                    if m: s.ldr(m.group('frm'), m.group('to'), offset=m.group('num'), step=m.group('num'), write_back=True)
                    # ldr r0, [r1, #8]
                    m:re.Match = re.match(r'^(?P<to>(?:r\d+|sp|fp|pc|lr|ip)), \[(?P<frm>(?:r\d+|sp|fp|pc|lr|ip)), (?P<num>#?-?(?:0x)?[\da-f]+)\]!$', insn.op_str)
                    if m: s.ldr(m.group('frm'), m.group('to'), offset=m.group('num'), step=m.group('num'), write_back=True)
                    # ldr r0, [r1, r2, LSL#8]!
                    m:re.Match = re.match(r'^(?P<to>(?:r\d+|sp|fp|pc|lr|ip)), \[(?P<frm>(?:r\d+|sp|fp|pc|lr|ip)), (?P<tmp>(?:r\d+|sp|fp|pc|lr|ip)), LSL(?P<num>#?-?(?:0x)?[\da-f]+)\]!$', insn.op_str)
                    if m: s.ldr(m.group('frm'), m.group('to'), offset=s.regs[m.group('tmp')]*pow(2, Helper.to_int(m.group('num'))), step=s.regs[m.group('tmp')]*pow(2, Helper.to_int(m.group('num'))),write_back=True)
                    # ldr r0, [r1], r2
                    m:re.Match = re.match(r'^(?P<to>(?:r\d+|sp|fp|pc|lr|ip)), \[(?P<frm>(?:r\d+|sp|fp|pc|lr|ip))\], (?P<num>(?:r\d+|sp|fp|pc|lr|ip))$', insn.op_str)
                    if m: s.ldr(m.group('frm'), m.group('to'), step=m.group('num'), write_back=True)
                    # ldr r0, [r1], r2, #8
                    m:re.Match = re.match(r'^(?P<to>(?:r\d+|sp|fp|pc|lr|ip)), \[(?P<frm>(?:r\d+|sp|fp|pc|lr|ip))\], (?P<tmp>(?:r\d+|sp|fp|pc|lr|ip)), LSL(?P<num>#?-?(?:0x)?[\da-f]+)\]$', insn.op_str)
                    if m: s.ldr(m.group('frm'), m.group('to'), step=s.regs[m.group('tmp')]*pow(2, Helper.to_int(m.group('num'))), write_back=True)
                elif insn.mnemonic.startswith('add'): s.add(ops[1].split(', ')[0].strip(), ops[0].strip(), ops[1].split(', ')[1].strip())
                elif insn.mnemonic.startswith('sub'): s.sub(ops[1].split(', ')[0].strip(), ops[0].strip(), ops[1].split(', ')[1].strip())
            return s.is_satisfied()
        except Exception as e:
            cls.logger.error(e)
            return STACK_UNSATISFIED

    @classmethod
    def neighborred_duplicated_insns(cls, insns:List[CsInsn]) -> bool:
        '''
        指令序列是否存在连续且重复的指令
        '''
        # 判断的标准主要是指令的连续重复情况
        for i in range(len(insns)-1):
            # 连续的push操作可以看做是将同一个数据作为函数调用时的不同参数
            if insns[i].mnemonic == insns[i+1].mnemonic and insns[i].op_str == insns[i+1].op_str and insns[i].mnemonic not in ['push']: return True
        return False

    @classmethod
    def gen_exe_paths_from_addr(cls, head:int, bin:Binary, min_addr:int=-1, max_addr:int=math.inf, funcs_map:Dict[int, Func]={}, ignore_indirect_call:bool=True, extend_on_demand:bool=True, use_cache:bool=True, from_func_head:bool=False) -> List[ExePath]:
        '''
        从指定地址开始构造控制流图
        '''
        # 结果
        exe_paths:List[ExePath] = []
        # 如果反汇编起始地址不是对齐 则没法搞了
        if head % 4 != 0: 
            # raise InvalidAddress(f'Instructions should be aligned with 4 bytes: {hex(head)}')
            cls.logger.error(f'Instructions should be aligned with 4 bytes: {hex(head)}')
            return exe_paths
        try:
            insns:List[CsInsn] = InsnMgr.insns_from(head, bin, cls)
        except Exception as e: 
            cls.logger.error(e)
            return exe_paths
        # 待分析队列
        states:Queue[Tuple[List[CsInsn], int, List[int], List[int], List[int], List[CsInsn]]] = Queue()
        # 已加入队列的情况
        done_states:List[int] = [head]
        states.put_nowait(([], head, [], [], [], insns))
        while not states.empty():
            history, addr, ucjmps, callees, constants, insns = states.get_nowait()
            states.task_done()
            # 是否是为了避免循环而结束的分析
            end_due_to_loop:bool = False
            # 是否由于路径合并得以提前结束分析
            end_due_to_merging:bool = False
            # 是否由于指令不够
            end_due_to_insufficient_insns:bool = False
            # 是否由于识别到了tail call而中断
            end_due_to_tail_call:bool = False
            # 是否由于出现了不可能的跳转目标
            end_due_to_impossible_callee:bool = False
            # 是否由于跳转到一个已知的无返回函数
            end_due_to_calling_noreturn:bool = False
            # 是否因为指令超过地址范围而中断
            end_due_to_out_of_range:bool = False
            # 是否加入当前执行路径
            append_current_exepath:bool = True
            index:int = 0
            while True:
                # 如果超过了现有的指令 就需要拓展
                if index >= len(insns): 
                    try:
                        insns.extend(InsnMgr.insns_from(insns[-1].address+insns[-1].size, bin, cls))
                    except Exception as e:
                        cls.logger.error(e)
                        end_due_to_insufficient_insns = True
                        break
                insn:CsInsn = insns[index]
                # 如果已经分析过这条指令 则不再分析
                if Helper.first_index(lambda h:h.address == insn.address, history) >= 0:
                    end_due_to_loop = True
                    break
                # 如果指令超过了最大/最小的地址 也跳过
                if insn.address >= max_addr or insn.address < min_addr: 
                    end_due_to_out_of_range = True
                    break
                # 如果压到了所涉及的各个常量地址 那也不行
                if insn.address in constants:
                    end_due_to_out_of_range = True
                    # 自行保存路径
                    append_current_exepath = False
                    # 构造路径 用以裁切
                    new_exepath:ExePath = ExePath(history, ucjmps, callees, 
                        terminate_due_to_loop=end_due_to_loop, 
                        terminate_due_to_insufficient_insns=end_due_to_insufficient_insns,
                        terminate_due_to_tail_call=end_due_to_tail_call,
                        terminate_due_to_impossible_callee=end_due_to_impossible_callee,
                        terminate_due_to_calling_noreturn=end_due_to_calling_noreturn,
                        terminate_due_to_out_of_range=end_due_to_out_of_range,
                        from_func_head=from_func_head)
                    # 裁切路径
                    the_idx:int = cls.corp_exepath(new_exepath, direct_only=False)
                    # if the_idx >= 0: exe_paths.append(new_exepath)
                    # 为啥只有切了才保存？
                    exe_paths.append(new_exepath)
                    break
                # 检查缓存
                # 康康有没有缓存过的分析结果
                if use_cache and insn.address in Cache.EXEPATH and len(Cache.EXEPATH[insn.address]) > 0:
                    # 好家伙 找到了 那就合并
                    merged_exe_paths:List[ExePath] = cls.merge_exe_paths(insn.address, history, ucjmps, callees, Cache.EXEPATH[insn.address], bin, from_func_head, funcs_map=funcs_map, min_addr=min_addr, max_addr=max_addr)
                    end_due_to_merging = True
                    # 将合并后的路径直接添加到结果中
                    exe_paths.extend(merged_exe_paths)
                    break
                history.append(insn)
                # 条件跳转
                if cls.is_cjmp(insn):
                    # 如果是直接跳转
                    if Helper.is_int(insn.op_str) or (insn.mnemonic in ['cbz', 'cbnz'] and Helper.is_int(insn.op_str.split(',')[1])):
                        jmp_target:int = Helper.to_int(insn.op_str) if insn.mnemonic not in ['cbz', 'cbnz'] else Helper.to_int(insn.op_str.split(',')[1])
                        if jmp_target < bin.text_base or jmp_target >= bin.text_base + bin.size:
                            cls.logger.warn(f'Target Address {hex(jmp_target)} Is Impossible')
                            index += 1
                            continue
                        # 如果是跳转到一个已确定的无返回函数 则直接分析下一条指令了
                        if jmp_target in funcs_map and funcs_map[jmp_target].return_type == RT_NO_RET:
                            cls.logger.dbg(f'Target Address {hex(jmp_target)} Is A Non-return Function')
                            index += 1
                            continue
                        # 看看能不能获取到目标地址的指令
                        try:
                            # 如果能够成功找到指令 就可以跳过去分析
                            tgt_insns:CsInsn = InsnMgr.insns_from(jmp_target, bin, cls)
                            if jmp_target not in done_states:
                                # 那就加入待分析队列吧
                                states.put_nowait((history.copy(), jmp_target, ucjmps.copy(), callees.copy(), constants.copy(), tgt_insns,))
                                done_states.append(jmp_target)
                        except Exception as e: cls.logger.error(e) 
                    # 间接跳转需要考虑分析跳转目标
                    else: 
                        # 寻找间接跳转的目标
                        indirect_targets:List[int] = cls.targets_for_indirect_jmp(insn, bin, history)
                        for jmp_target in indirect_targets:
                            # 如果是跳转到一个已确定的无返回函数 则直接分析下一条指令了
                            if jmp_target in funcs_map and funcs_map[jmp_target].return_type == RT_NO_RET:
                                cls.logger.info(f'Indirect Jump To A Non-Return Function')
                                continue
                            # 看看能不能获取到目标地址的指令
                            try:
                                # 如果能够成功找到指令 就可以跳过去分析
                                tgt_insns:CsInsn = InsnMgr.insns_from(jmp_target, bin, cls)
                                if jmp_target not in done_states:
                                    # 那就加入待分析队列吧
                                    states.put_nowait((history.copy(), jmp_target, ucjmps.copy(), callees.copy(), constants.copy(), tgt_insns))
                                    done_states.append(jmp_target)
                            except Exception as e: cls.logger.error(e)
                # 无条件跳转
                elif cls.is_ucjmp(insn, insns[index-1] if index > 0 else None):
                    # 如果是直接跳转
                    if Helper.is_int(insn.op_str):
                        jmp_target:int = Helper.to_int(insn.op_str)
                        # 如果比最小地址还小 那就认为是一个函数
                        if jmp_target < min_addr:
                            callees.append(jmp_target)
                            end_due_to_tail_call = True
                            break
                        if jmp_target >= bin.text_base + len(bin.bytes):
                            cls.logger.warn(f'Target Address {hex(jmp_target)} Is Impossible')
                            end_due_to_impossible_callee = True
                            break
                        # 如果是跳转到一个已确定的函数 则直接分析下一条指令了
                        if jmp_target in funcs_map:
                            cls.logger.info(f'Jump To A Known Function')
                            end_due_to_tail_call = True
                            break
                        # 看看能不能获取到目标地址的指令
                        try:
                            # 如果能够成功找到指令 就可以跳过去分析
                            tgt_insns:CsInsn = InsnMgr.insns_from(jmp_target, bin, cls)
                            ucjmps.append(jmp_target)
                            if jmp_target not in done_states:
                                # 那就加入待分析队列吧
                                states.put_nowait((history.copy(), jmp_target, ucjmps.copy(), callees.copy(), constants.copy(), tgt_insns))
                                done_states.append(jmp_target)
                                append_current_exepath = False
                        except Exception as e: cls.logger.error(e)
                        break
                    # 如果是间接跳转
                    else:
                        # 寻找间接跳转的目标
                        indirect_targets:List[int] = cls.targets_for_indirect_jmp(insn, bin, history)
                        for jmp_target in indirect_targets:
                            # 如果是跳转到一个已确定的无返回函数 则直接分析下一条指令了
                            if jmp_target in funcs_map and funcs_map[jmp_target].return_type == RT_NO_RET:
                                cls.logger.info(f'Indirect Jump To A Non-Return Function')
                                end_due_to_calling_noreturn = True
                                continue
                            # 看看能不能获取到目标地址的指令
                            try:
                                # 如果能够成功找到指令 就可以跳过去分析
                                tgt_insns:CsInsn = InsnMgr.insns_from(jmp_target, bin, cls)
                                ucjmps.append(jmp_target)
                                if jmp_target not in done_states:
                                    # 那就加入待分析队列吧
                                    states.put_nowait((history.copy(), jmp_target, ucjmps.copy(), callees.copy(), constants.copy(), tgt_insns))
                                    done_states.append(jmp_target)
                                    append_current_exepath = False
                            except Exception as e: cls.logger.error(e)
                        break
                # 函数返回指令
                elif cls.is_ret(insn): 
                    # 如果是有条件返回 就需要分叉执行路径了
                    if cls.has_cond(insn):
                        tgt_addr:int = insn.address + insn.size
                        try:
                            tgt_insns:List[CsInsn] = InsnMgr.insns_from(tgt_addr, bin, cls)
                            if tgt_addr not in done_states: 
                                states.put_nowait((history.copy(), tgt_addr, ucjmps.copy(), callees.copy(), constants.copy(), tgt_insns))
                                done_states.append(tgt_addr)
                        except Exception as e: cls.logger.error(e)
                    break
                # 函数调用指令
                elif cls.is_call(insn):
                    # 如果是有条件调用 就需要分叉执行路径了
                    if cls.has_cond(insn):
                        tgt_addr:int = insn.address + insn.size
                        try:
                            tgt_insns:List[CsInsn] = InsnMgr.insns_from(tgt_addr, bin, cls)
                            if tgt_addr not in done_states: 
                                states.put_nowait((history.copy(), tgt_addr, ucjmps.copy(), callees.copy(), constants.copy(), tgt_insns,))
                                done_states.append(tgt_addr)
                        except Exception as e: cls.logger.error(e)
                    # 直接调用
                    if Helper.is_int(insn.op_str):
                        tgt_addr:int = Helper.to_int(insn.op_str)
                        # 屏蔽 call $+5这种
                        if tgt_addr >= 0 and tgt_addr != insn.address + insn.size: callees.append(tgt_addr)
                        # 如果调用的目标确定是一个无返回函数 则结束当前路径
                        if tgt_addr in funcs_map and funcs_map[tgt_addr].return_type == RT_NO_RET: break
                        try:
                            # 如果其后跟着两个填充指令 就认为是tail call 
                            tmp_insns:List[CsInsn] = InsnMgr.insns_from(insn.address, bin, cls)
                            if len(tmp_insns) >= 3 and cls.null_insn(tmp_insns[1], bin) and cls.null_insn(tmp_insns[2], bin): 
                                end_due_to_calling_noreturn = True
                                break
                        except Exception as e:
                            cls.logger.error(e)
                    # 间接调用 如果忽略间接调用 否则就需要处理
                    elif not ignore_indirect_call: callees.extend(cls.resolve_indirect_call(insn, bin, history))
                # arm特有 ldr指令处理
                elif len(insn.op_str.split(','))==3 and (insn.mnemonic[:3] in ['ldr'] or insn.mnemonic[:4] in ['vldr']) and '#' in insn.op_str.split(',')[2] and '#-' not in insn.op_str.split(',')[2] and insn.op_str.endswith(']') and insn.op_str.split(',')[0] not in ['pc'] and 'pc' in insn.op_str.split(',')[1]:
                    constant:int = Helper.align(Helper.align(insn.address)+8)+Helper.to_int(insn.op_str.split(',')[2].replace(']', ''))
                    constants.append(constant)
                index += 1
            # 如果是合并了缓存 则不需要再次向结果中加入执行路径
            if end_due_to_merging: continue
            # 如果历史长度不够 就不考虑纳入了吧
            if len(history) <= 0: continue
            # 如果因为一些特殊原因明确记录这条路径 那就算了
            if not append_current_exepath: continue
            exe_paths.append(ExePath(history, ucjmps, callees, 
                                    terminate_due_to_loop=end_due_to_loop, 
                                    terminate_due_to_insufficient_insns=end_due_to_insufficient_insns,
                                    terminate_due_to_tail_call=end_due_to_tail_call,
                                    terminate_due_to_impossible_callee=end_due_to_impossible_callee,
                                    terminate_due_to_calling_noreturn=end_due_to_calling_noreturn,
                                    terminate_due_to_out_of_range=end_due_to_out_of_range,
                                    from_func_head=from_func_head))
        # 如果使用缓存的话
        if use_cache:
            addrs:List[int] = list(set(Helper.merge(*list(map(lambda exe_path: list(map(lambda insn: insn.address, exe_path.insns)), exe_paths)))))
            for addr in addrs: Cache.EXEPATH[addr] = []
            for exe_path in exe_paths:
                # 将新的分析结果进行缓存
                addrs:List[int] = list(map(lambda insn: insn.address, exe_path.insns))
                for addr in addrs: Cache.EXEPATH[addr].append(exe_path)
        return exe_paths

    @classmethod
    def is_ret(cls, insn:CsInsn) -> bool:
        '''
        判断指令是否用于返回执行流
        '''
        return (
            (insn.mnemonic.startswith('bx') and insn.op_str in ['lr'])
            or (insn.mnemonic.startswith('pop') and 'pc' in insn.op_str)
            # or (insn.mnemonic.startswith('ldr') and 'pc' in insn.op_str.split(',')[0] and len(insn.op_str.split(',')) <= 3)
            or (insn.mnemonic.startswith('mov') and insn.op_str.split(',')[0].strip() in ['pc'] and insn.op_str.split(',')[1].strip() in ['lr'])
            or (insn.mnemonic in ['ret'])
            or (insn.mnemonic.startswith('ldm') and 'pc' in insn.op_str)
            or (insn.mnemonic.startswith('ldm') and 'fp' in insn.op_str.split(',')[0] and 'sp' in insn.op_str and 'fp' in ','.join(insn.op_str.split(',')[1:]))
        )
    
    @classmethod
    def is_call(cls, insn:CsInsn) -> bool:
        '''
        是否为函数调用指令
        '''
        return insn.mnemonic in cls.calls

    @classmethod
    def is_ucjmp(cls, insn:CsInsn, last_insn:CsInsn=None) -> bool:
        '''
        是否为无条件跳转指令
        '''
        return (
            (insn.mnemonic in cls.ucjmps) 
            or ((last_insn is None or not (last_insn.mnemonic[:3] in ['mov'] and last_insn.op_str == 'lr, pc')) and (insn.mnemonic in ['ldr'] and 'pc' in insn.op_str.split(',')[0]))
            or (insn.mnemonic in ['b.w', 'tbb', 'tbh'])
        )

    @classmethod
    def is_cjmp(cls, insn:CsInsn) -> bool:
        '''
        是否为条件跳转指令
        '''
        return (
            (insn.mnemonic in cls.cjmps) 
            or (len(insn.mnemonic) == 5 and insn.mnemonic.startswith('ldr') and cls.has_cond(insn) and 'pc' in insn.op_str.split(',')[0])
            or (insn.mnemonic in ['cbz', 'cbnz'])
        ) 
    
    @classmethod
    def is_it(cls, insn:CsInsn) -> bool:
        '''
        是否为it指令
        '''
        return insn.mnemonic.startswith('it')

    @classmethod
    def has_cond(cls, insn:CsInsn) -> bool:
        '''
        指令执行是否有条件
        '''
        return insn.mnemonic.replace('.w','')[-2:] in conds[:-3]






