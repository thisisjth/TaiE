# -*- encoding: utf-8

from math import ceil
import re, string
from arch import Arch
from re import Pattern
from capstone import CsInsn
from typing import Dict, List, Tuple, Callable, Union
from lib.executor import Executor
from lib.misc.helper import Helper
from lib.misc.logger import Logger
from lib import Binary, EmptyInsns, ExePath, Func, InsnMgr, Cache
from config.constant import IB_CALLEE, IB_SCANED_FROM_TAIL, RT_NO_RET, STACK_SATISFIED


class ArmLArch(Arch):
    '''
    Arm小端指令集架构
    '''

    logger:Logger = Logger('Arch.ArmL')

    # 两个函数之间的间距上限
    max_func_gap:int = 16

    @classmethod
    def constants_in_ep(cls, ep:ExePath, bin:Binary, executor:Executor) -> List[Tuple[int, int]]:
        '''
        提取执行路径中的ldr指令所涉及到的常量
        '''
        constants:List[Tuple[int, int]] = []
        for insn in ep.insns:
            # 剔除非ldr与adr指令
            if not (insn.mnemonic[:3] in ['ldr', 'add'] or insn.mnemonic[:4] in ['vldr']): continue
            op_str_parts:List[str] = insn.op_str.split(',')
            # 目前处理 ldr xxx, [pc, #xxx] 与 ldr xxx, [pc] 
            if insn.op_str.endswith(']') and \
                op_str_parts[0] not in ['pc'] and \
                ((len(op_str_parts) == 3 and '#' in op_str_parts[2] and '#-' not in op_str_parts[2] and 'pc' in op_str_parts[1]) or
                (len(op_str_parts) == 2 and op_str_parts[1].strip() == '[pc]')):
                addr:int = 0
                align:int = 8 if insn.mnemonic.startswith('vldr') else 4
                # ldr xxx, [pc, #xxx]
                if len(op_str_parts) == 3: 
                    addr = Helper.align(Helper.align(insn.address)+8)+Helper.to_int(op_str_parts[2].replace(']', ''))
                # ldr xxx, [pc]
                else: 
                    addr = Helper.align(Helper.align(insn.address)+8)
                constants.append((addr, align,))
                # 如果对应地址是一个字符串 那也需要排除掉
                if addr >= bin.text_base and addr < bin.text_base + bin.size:
                    str_addr:int = int.from_bytes(bin.bytes[addr-bin.text_base:addr-bin.text_base+4], byteorder='little')
                    if str_addr >= bin.text_base and str_addr < bin.text_base + bin.size:
                        bs:bytes = cls.is_str(str_addr, bin)
                        if bs is not None:
                            Cache.CONSTANTS = list(set(Cache.CONSTANTS + list(map(lambda i:i*4+str_addr, range(ceil(len(bs)/4))))))
            # 目前处理 add rx, pc, xxx 
            if insn.mnemonic.startswith('add') and \
                op_str_parts[0].strip() not in ['pc'] and \
                len(op_str_parts) == 3 and \
                op_str_parts[1].strip() == 'pc' and \
                '#' in op_str_parts[2]:
                addr:int = Helper.align(Helper.align(insn.address)+8)+Helper.to_int(op_str_parts[2].strip())
                constants.append((addr, 4,))
        return constants

    @classmethod
    def is_str(cls, addr:int, b:Binary, n:int=5) -> Union[bytes, None]:
        '''
        判断该地址是否为一个字符串的起始
        '''
        a:int = addr
        # 必须以字母开始
        if chr(b.bytes[addr-b.text_base]) not in string.ascii_letters + string.digits: return None
        while chr(b.bytes[a-b.text_base]) in string.ascii_letters + string.digits + '_ \t\r\n': a += 1
        if a - addr < n: return None
        return b.bytes[addr-b.text_base:a-b.text_base]

    @classmethod
    def extra_funcs(cls, bin:Binary, funcs:List[Func], done_funcs:List[int], stack_ops:List[Tuple[int, bytes, int, str, str]], op_groups:List[Tuple[int, int]], funcs_map:Dict[int, Func]) -> bool:
        '''
        与指令集架构相关的分析以获取到额外的函数结果
        '''
        changed:bool = False 
        # 根据指令集获取相应的执行器
        executor:Executor = cls.arch2executor[bin.arch]
        # 先把函数按照入口位置升序排序
        funcs.sort(key=lambda f:f.head)
        # 避免重新构造CFG的函数列表
        avoids:List[int] = []
        idx:int = -1
        while idx < len(funcs) - 1:
            idx += 1
            # 当前函数
            func:Func = funcs[idx]
            # 新增加的函数
            new_funcs:List[Func] = []
            if func.head not in avoids:
                try:
                    # 先来一次不使用缓存的、集体的函数CFG更新
                    func.gen_cfg(executor, bin, max_addr=funcs[idx+1].head if idx<len(funcs)-1 else bin.text_base+len(bin.bytes), funcs_map=funcs_map, use_cache=False)
                except EmptyInsns as ei:
                    cls.logger.error(ei) 
                    continue
            # 收集所用的作为相对偏移的常量
            constants:List[Tuple[int, int]] = []
            # 切一切执行路径 最后一个指令只能是ret或者对无返回函数的调用
            for ep in func.cfg: 
                if ep.terminate_due_to_loop or ep.terminate_due_to_insufficient_insns or ep.terminate_due_to_invalid_call: 
                    # 搜寻相对偏移
                    constants.extend(cls.constants_in_ep(ep, bin, executor))
                    continue
                last_index:int = executor.corp_exepath(ep)
                # 搜寻相对偏移
                constants.extend(cls.constants_in_ep(ep, bin, executor))
            func.tail = max(list(map(lambda ep:ep.addr_after_max_insn_addr, func.cfg)))
            # 寻找看看有没有发现什么新的函数
            new_callees:List[int] = list(set(Helper.merge(*map(lambda ep:ep.callees, func.cfg))) - set(done_funcs))
            # 每一个新的被调目标都是一个新的函数
            new_funcs.extend(map(lambda nc: Func(nc, ib=IB_CALLEE), new_callees))
            done_funcs.extend(new_callees)
            # 如果执行路径中有超过了函数头的无条件跳转 则认为跳转目标也是一个函数
            ucjmp_targets:List[int] = list(set(filter(lambda t:t < func.head, Helper.merge(*map(lambda ep:ep.ucjmp_targets, func.cfg))))-set(done_funcs))
            # 每一个新的被调目标都是一个新的函数
            new_funcs.extend(map(lambda nc: Func(nc, ib=IB_CALLEE), ucjmp_targets))
            done_funcs.extend(ucjmp_targets)
            changed = len(new_callees) > 0 or len(ucjmp_targets) > 0 or changed
            constants = list(set(constants))
            Cache.CONSTANTS = list(set(Cache.CONSTANTS + list(map(lambda c:c[0], constants))))
            # 先对用到的常量进行排序
            constants.sort(key=lambda c:c[0])
            # 如果执行路径覆盖了常量地址 并且把几个常量地址当做指令去解析了 那就要进行路径裁剪
            # 如果路径通过跳转等方式 越过了常量位置 没有覆盖常量位置 那么就不需要进行路径裁剪
            # 如果常量数量不足2个 或是找不到两个连续的 就算了
            if len(constants) >= 2 and Helper.any(lambda i: constants[i][0]+constants[i][1] == constants[i+1][0], range(len(constants)-1)):
                i:int = -1
                while i < len(func.cfg)-1:
                    i += 1
                    ep:ExePath = func.cfg[i]
                    # 如果没有覆盖常量位置的指令 或是覆盖到了 但不是那种连续的常量地址 就算了
                    the_index:int = Helper.first_index(lambda insn:insn.address in map(lambda c:c[0], constants), ep.insns)
                    if the_index < 0 or ep.insns[the_index].address+4 not in map(lambda c:c[0], constants): continue
                    the_index -= 1
                    # 休怪我无情 我要裁切执行路径了！ 可能还需要往回缩一下 看看最后结尾到底在哪
                    the_index = executor.corp_exepath(ep, the_index)
                    # 如果找不到相关的指令了 那这条执行路径按理来说就不该要了
                    if the_index < 0: 
                        func.cfg.pop(i)
                        i -= 1
                        continue
                    if Helper.is_int(ep.insns[-1].op_str) and (executor.is_call(ep.insns[-1]) or executor.is_ucjmp(ep.insns[-1], ep.insns[-2] if len(ep.insns) >= 2 else None)):
                        # 不是tail call 就是 调用了无返回 不管怎么说 都确认目标是个函数
                        target:int = Helper.to_int(ep.insns[-1].op_str)
                        the_func:Func = Helper.first(lambda f:f.head == target, funcs)
                        # 未处理过的函数就新增
                        if the_func is None:
                            the_func:Func = Func(target, ib=IB_CALLEE)
                            funcs.append(the_func)
                            done_funcs.append(target)
                        # 无返回函数了
                        if executor.is_call(ep.insns[-1]):
                            changed = the_func.return_type != RT_NO_RET or changed
                            the_func.return_type = RT_NO_RET
                        funcs_map:Dict[int, Func] = dict(list(map(lambda f:(f.head, f,), funcs)))
                    changed = True
                func.tail = max(list(map(lambda ep:ep.addr_after_max_insn_addr, func.cfg)))
            for ep in func.cfg:
                # 如果最后一条指令是无条件跳转 那跳转目标也是一个函数了
                if executor.is_ucjmp(ep.insns[-1], ep.insns[-2] if len(ep.insns) >= 2 else None) and Helper.is_int(ep.insns[-1].op_str):
                    the_callee:int = Helper.to_int(ep.insns[-1].op_str)
                    # 如果没有记录过的函数 那就记录一下
                    if the_callee in done_funcs or the_callee >= func.head: continue
                    new_funcs.append(Func(the_callee, ib=IB_CALLEE))
                    done_funcs.append(the_callee)
            cur_addr:int = func.tail
            if len(constants) > 0 and constants[0][0] == cur_addr + 4:
                if cur_addr not in done_funcs:
                    new_func:Func = Func(cur_addr, ib=IB_SCANED_FROM_TAIL)
                    try:
                        new_func.gen_cfg(executor, bin, max_addr=bin.text_base+len(bin.bytes), funcs_map=funcs_map, use_cache=True)
                        if new_func.tail == constants[0][0]:
                            new_funcs.append(new_func)
                            done_funcs.append(cur_addr)
                    except Exception: pass 
                cur_addr = constants[0][0]
            m:int = 0
            while m < len(constants):
                c = constants[m]
                if cur_addr in Cache.CONSTANTS: 
                    if cur_addr == c[0]: 
                        cur_addr += c[1]
                        m += 1
                        continue
                    cur_addr += 4
                    continue
                if c[0] != cur_addr: break
                cur_addr += c[1]
                m += 1
            # 去掉无效指令
            while True:
                try:
                    the_insn:CsInsn = InsnMgr.insn_at(cur_addr, bin, executor)
                    if not executor.null_insn(the_insn, bin): break
                    cur_addr += the_insn.size
                except Exception: break
            # 从结尾位置开始扫描新函数 设定新的函数
            new_head:int = cur_addr
            # 如果找到了 那就是新的函数了 如果已经处理过 就算了
            if new_head > 0 and new_head not in done_funcs and new_head not in Cache.CONSTANTS:
                new_funcs.append(Func(new_head, ib=IB_SCANED_FROM_TAIL))
                done_funcs.append(new_head)
            if len(new_funcs) <= 0: continue
            new_funcs.sort(key=lambda nf:nf.head, reverse=True)
            # 寻找最早插入的位置
            earlest_index:int = Helper.first_index(lambda f:f.head > new_funcs[-1].head, funcs)
            # 插入！
            for nf in new_funcs:
                index:int = Helper.first_index(lambda f:f.head > nf.head, funcs)
                # 如果找不到 就说明是最大的了 直接加到最后位置
                if index < 0: funcs.append(nf)
                else: funcs.insert(index, nf)
                changed = True
            # 进行下一轮
            idx = min(earlest_index, idx+1) - 1
        return changed 

    @classmethod
    def funcs_in(cls, bin: Binary, tag: str = '') -> List[Func]:
        # 根据指令集获取相应的执行器
        executor:Executor = cls.arch2executor[bin.arch]
        # 先获取识别结果
        funcs:List[Func] = super().funcs_in(bin, tag)
        # 使用栈特性过滤识别结果
        i:int = -1
        while i < len(funcs) - 1:
            i += 1
            func:Func = funcs[i]
            # 如果都超过最大的边界了 或是该函数地址实际上已识别为常量 那就算了
            if ((func.head > bin.text_base + len(bin.bytes) or func.head < bin.text_base) or
                (func.head in Cache.CONSTANTS)):
                cls.logger.dbg(f'Remove OOB function {hex(func.head)}')
                funcs.pop(i)
                i -= 1
                continue
            # 只针对从尾部扫描所得的函数进行分析
            if func.identified_by != IB_SCANED_FROM_TAIL: continue
            # 如果没有cfg 那也算了
            if func.cfg is None: continue
            satisfied_count:int = Helper.count(lambda ep: 
                ep.terminate_due_to_calling_noreturn
                or ep.terminate_due_to_tail_call
                # or ep.terminate_due_to_loop
                or executor.is_stack_satisfied(ep.insns) == STACK_SATISFIED
            , func.cfg)
            if satisfied_count <= 0:
                cls.logger.dbg(f'Remove unsatisfied function {hex(func.head)}')
                funcs.pop(i)
                i -= 1
        return funcs

