# -*- encoding: utf-8

import re
from math import ceil
from arch import Arch
from capstone import CsInsn
from typing import Dict, List, Tuple, Callable, Set
from lib.executor import Executor
from lib.misc.helper import Helper
from lib.misc.logger import Logger
from lib import Binary, EmptyInsns, ExePath, Func, InsnMgr
from config.constant import IB_CALLEE, IB_CALLEE_IN_CALLSITE, IB_SCANED_FROM_TAIL, RT_NO_RET, STACK_SATISFIED, STACK_UNINITIALIZED


class ArmLTArch(Arch):
    '''
    Arm小端指令集架构
    '''

    logger:Logger = Logger('Arch.ArmLT')

    # 两个函数之间的间距上限
    max_func_gap:int = 16

    constants_in_ep:Callable[[ExePath, Binary, Executor], List[Tuple[int, int]]] = lambda ep, bin, executor: list(map(lambda insn: (Helper.align(Helper.align(insn.address)+(8 if insn.size == 4 and insn.mnemonic not in ['vldr', 'ldr.w'] else 4))+Helper.to_int(insn.op_str.split(',')[2].replace(']', '')), 8 if insn.mnemonic.startswith('vldr') else 4,), filter(lambda ins:len(ins.op_str.split(','))==3 and (ins.mnemonic[:3] in ['ldr'] or ins.mnemonic[:4] in ['vldr']) and '#' in ins.op_str.split(',')[2] and '#-' not in ins.op_str.split(',')[2] and ins.op_str.endswith(']') and ins.op_str.split(',')[0] not in ['pc'] and 'pc' in ins.op_str.split(',')[1], ep.insns)))
    
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
                # 如果是附加的 不是从函数入口开始构造的 那就算了
                if len(ep.insns) <= 0 or ep.insns[0].address != func.head: continue
                if ep.terminate_due_to_loop or ep.terminate_due_to_insufficient_insns or ep.terminate_due_to_invalid_call: 
                    # 搜寻相对偏移
                    constants.extend(cls.constants_in_ep(ep, bin, cls))
                    continue
                last_index:int = Helper.last_index(lambda i:executor.is_ret(ep.insns[i]) or executor.is_call(ep.insns[i]) or executor.is_ucjmp(ep.insns[i], ep.insns[i-1] if i > 0 else None), range(len(ep.insns)))
                # 有时候可能由于为了避免循环而提前
                if last_index < 0:
                    cls.logger.error(f'Invalid ExePath')
                    continue
                # 搜寻相对偏移
                constants.extend(cls.constants_in_ep(ep, bin, cls))
            func.tail = max(list(map(lambda ep:ep.addr_after_max_insn_addr, func.cfg)))
            # 寻找看看有没有发现什么新的函数
            all_callees:Set[int] = set(Helper.merge(*map(lambda ep:ep.callees, func.cfg)))
            # 既然是调用到了 那就更改那些函数的识别来源为 IB_CALLEE
            for c in all_callees:
                if c in funcs_map: funcs_map[c].identified_by = IB_CALLEE
            new_callees:List[int] = list(all_callees - set(done_funcs))
            # 每一个新的被调目标都是一个新的函数
            new_funcs.extend(map(lambda nc: Func(nc, ib=IB_CALLEE), new_callees))
            done_funcs.extend(new_callees)
            # 如果执行路径中有超过了函数头的无条件跳转 则认为跳转目标也是一个函数
            all_targets:Set[int] = set(filter(lambda t:t < func.head, Helper.merge(*map(lambda ep:ep.ucjmp_targets, func.cfg))))
            # 既然是调用到了 那就更改那些函数的识别来源为 IB_CALLEE
            for c in all_targets:
                if c in funcs_map: funcs_map[c].identified_by = IB_CALLEE
            ucjmp_targets:List[int] = list(all_targets - set(done_funcs))
            # 每一个新的被调目标都是一个新的函数
            new_funcs.extend(map(lambda nc: Func(nc, ib=IB_CALLEE), ucjmp_targets))
            done_funcs.extend(ucjmp_targets)
            changed = len(new_callees) > 0 or len(ucjmp_targets) > 0 or changed
            constants = list(set(constants))
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
                        # 否则就修改他的识别来源
                        else: the_func.identified_by = IB_CALLEE
                        # 无返回函数了
                        if executor.is_call(ep.insns[-1]):
                            changed = the_func.return_type != RT_NO_RET or changed
                            the_func.return_type = RT_NO_RET
                        funcs_map:Dict[int, Func] = dict(list(map(lambda f:(f.head, f,), funcs)))
                    changed = True
                func.tail = max(list(map(lambda ep:ep.addr_after_max_insn_addr, func.cfg)))
            if len(constants) > 0:
                # 构建出函数结尾到常量之间的指令来
                eps:List[ExePath] = executor.gen_exe_paths_from_addr(func.tail, bin, min_addr=func.tail, max_addr=constants[0][0], funcs_map=funcs_map)
                # 寻找这里面最后的一条指令的地址 当做新的函数结尾
                if len(eps) > 0: 
                    func.tail = max(list(map(lambda ep:ep.addr_after_max_insn_addr, eps)))
            for ep in func.cfg:
                # 如果是附加的 不是从函数入口开始构造的 那就算了
                if len(ep.insns) <= 0 or ep.insns[0].address != func.head: continue
                # 如果最后一条指令是无条件跳转 那跳转目标也是一个函数了
                if executor.is_ucjmp(ep.insns[-1], ep.insns[-2] if len(ep.insns) >= 2 else None) and Helper.is_int(ep.insns[-1].op_str):
                    the_callee:int = Helper.to_int(ep.insns[-1].op_str)
                    # 如果没有记录过的函数 那就记录一下
                    if the_callee in done_funcs or the_callee >= func.head: 
                        if the_callee in funcs_map: funcs_map[the_callee].identified_by = IB_CALLEE
                        continue
                    new_funcs.append(Func(the_callee, ib=IB_CALLEE))
                    done_funcs.append(the_callee)
            alignment:int = min(4, constants[0][1]) if len(constants) > 0 else 2
            cur_addr:int = alignment*ceil(func.tail/alignment)
            for c in constants:
                if c[0] != cur_addr: break
                cur_addr += c[1]
            # 去掉无效指令
            while True:
                try:
                    the_insn:CsInsn = InsnMgr.insn_at(cur_addr, bin, executor)
                    if not executor.null_insn(the_insn, bin): break
                    cur_addr += the_insn.size
                except Exception: break
            # 跳过开始位置的无效指令序列
            try:
                the_insn:CsInsn = InsnMgr.insn_at(cur_addr, bin, executor)
                while executor.null_insn(the_insn, bin):
                    cur_addr += the_insn.size
                    the_insn = InsnMgr.insn_at(cur_addr, bin, executor)
            except Exception as e:
                cls.logger.error(e)
                continue
            # 从结尾位置开始扫描新函数 设定新的函数
            new_head:int = cur_addr
            # 如果找到了 那就是新的函数了 如果已经处理过 就算了
            if new_head > 0 and new_head not in done_funcs:
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
    def funcs_in(cls, bin: Binary, tag:str='') -> List[Func]:
        funcs:List[Func] = super().funcs_in(bin, tag=tag)
        funcs.sort(key=lambda f:f.head)
        funcs_map:Dict[int, Func] = dict(list(map(lambda f:(f.head, f,), funcs)))
        # 根据指令集获取相应的执行器
        executor:Executor = cls.arch2executor[bin.arch]
        i:int = -1
        while i < len(funcs)-1:
            i += 1
            func:Func = funcs[i]
            # 收集函数涉及到的各个常量
            constants:List[Tuple[int, int]] = sorted(list(set(Helper.merge(*list(map(lambda ep: cls.constants_in_ep(ep, bin, executor), filter(lambda ep:len(ep.insns) > 0 and ep.insns[0].address == func.head, func.cfg)))))), key=lambda c:c[0])
            if len(constants) > 0 and constants[0][0] - func.tail < 16:
                cls.__disassemble_the_gap(func, constants, bin, executor, funcs_map=funcs_map)
                the_idx:int = Helper.first_index(lambda f:f.head >= constants[-1][0]+constants[-1][1], funcs, start_at=i+1)
            else:
                the_idx:int = Helper.first_index(lambda f:f.head >= func.tail, funcs, start_at=i+1)
            # 不考虑函数相互重叠了
            if the_idx <= 0: the_idx = len(funcs)
            for j in range(i+1, the_idx)[::-1]: funcs.pop(j)
            alignment:int = min(4, constants[0][1]) if len(constants) > 0 else 2
            cur_addr:int = alignment*ceil(func.tail/alignment)
            for c in constants:
                if c[0] < cur_addr: continue
                if c[0] != cur_addr: break
                cur_addr += c[1]
            # 跳过开始位置的无效指令序列
            try:
                the_insn:CsInsn = InsnMgr.insn_at(cur_addr, bin, executor)
                while executor.null_insn(the_insn, bin):
                    cur_addr += the_insn.size
                    the_insn = InsnMgr.insn_at(cur_addr, bin, executor)
            except Exception as e:
                cls.logger.error(e)
                continue
            # 从末尾开始寻找新函数
            the_idx:int = 0 
            if the_idx >= 0: continue
            # 插入新函数
            the_new_func:Func = Func(cur_addr, ib=IB_SCANED_FROM_TAIL)
            try: 
                the_new_func.gen_cfg(executor, bin, funcs_map=funcs_map)
            except Exception as e:
                cls.logger.error(e)
                continue
            if i+1 < len(funcs): funcs.insert(i+1, the_new_func)
            else: funcs.append(the_new_func)
            funcs_map:Dict[int, Func] = dict(list(map(lambda f:(f.head, f,), funcs)))
        i:int = -1
        while i < len(funcs)-1:
            i += 1
            func:Func = funcs[i]
            # 如果是调用识别到的 那就跳过
            if func.identified_by in [IB_CALLEE, IB_CALLEE_IN_CALLSITE]: continue
            # 检查路径
            # 在扫尾得来的函数中，如果有执行路径是满足栈平衡的，或是其没有使用栈但以函数调用、返回等指令结尾，则其将被保留
            if Helper.any(lambda ep:ep.stack_satisfied(bin, executor) == STACK_SATISFIED, func.cfg): continue
            if all(map(lambda ep: executor.is_ret(ep.insns[-1]) or executor.is_call(ep.insns[-1]) or executor.is_ucjmp(ep.insns[-1]) or executor.is_it(ep.insns[-1]), filter(lambda e:e.stack_satisfied(bin, executor) == STACK_UNINITIALIZED, func.cfg))): continue
            funcs.pop(i)
            i -= 1
        return funcs
    
    @classmethod
    def __disassemble_the_gap(cls, func:Func, constants:List[Tuple[int, int ]], bin:Binary, executor:Executor, funcs_map:Dict[int, Func]={}) -> int:
        start:int = func.tail
        while True:
            try:
                # 构造gap处的指令序列
                eps:List[ExePath] = executor.gen_exe_paths_from_addr(start, bin, max_addr=constants[0][0], funcs_map=funcs_map)
            except Exception as e:
                cls.logger.error(e)
                break
            for ep in eps:
                if len(ep.insns) < 0: continue
                idx:int = len(ep.insns)-1
                while idx >= 0 and not (executor.is_call(ep.insns[idx]) or executor.is_ret(ep.insns[idx]) or executor.is_ucjmp(ep.insns[idx], ep.insns[idx-1] if idx > 0 else None)): idx -= 1
                ep.insns = ep.insns[:idx+1]
            if all(map(lambda ep:len(ep.insns) <= 0, eps)): break
            func.cfg.extend(filter(lambda ep:len(ep.insns) > 0, eps))
            start = max(map(lambda ep:ep.addr_after_max_insn_addr, filter(lambda ep:len(ep.insns) > 0, eps)))
            if start >= constants[0][0]: break 
        func.tail = max(list(map(lambda ep:ep.addr_after_max_insn_addr, func.cfg)))


