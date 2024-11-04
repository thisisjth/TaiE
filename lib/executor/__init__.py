# -*- encoding: utf-8

import math, logging
from re import Pattern
from queue import Queue
from capstone import CsInsn
from angr import Project, SimState
from lib.misc.helper import Helper
from lib.misc.logger import Logger
from config.constant import RT_NO_RET
from abc import abstractclassmethod
from typing import Callable, List, Tuple, Dict, Union
from lib import Binary, Cache, ExePath, Func

# 关闭angr的日志输出
logging.disable(logging.CRITICAL)


class Executor:
    '''
    执行器基类
    '''

    # 日志记录
    logger:Logger = Logger('Executor')

    # 指令集架构名称
    arch_name:str = ''

    # 栈操作指令字节序列的识别规则
    stack_op_regs:Dict[str, Dict[str, Tuple[Pattern, int]]] = {}
    # 无意义指令的规则列表
    null_insn_regs:List[Pattern] = []
    # 条件跳转指令
    cjmps:List[str] = []
    # 非条件跳转指令
    ucjmps:List[str] = []
    # 跳转指令
    jmps:List[str] = cjmps + ucjmps
    # 函数返回指令
    rets:List[str] = []
    # 函数调用指令
    calls:List[str] = []
    # nop指令 
    nops:List[str] = []
    # 函数间填充字节
    paddings:List[int] = []

    @classmethod
    def search_stack_ops(cls, bin:Binary) -> List[Tuple[int, bytes, int, str, str]]:
        '''
        根据规则从二进制中寻找相关的开/退栈操作，并返回操作指令所在位置、指令字节、规则权重、规则名称与栈操作类型
        '''
        # 结果 分别为匹配位置、匹配字节序列、匹配正则规则名称以及对应的操作类型
        results:List[Tuple[int, bytes, int, str, str]] = []
        for op in cls.stack_op_regs:
            for reg in cls.stack_op_regs[op]:
                results.extend(list(map(lambda match:(match.start(), match.group(0), cls.stack_op_regs[op][reg][1], reg, op), cls.stack_op_regs[op][reg][0].finditer(bin.bytes))))
        # 去重
        results = list(set(results))
        # 根据出现次序排序
        results.sort(key=lambda e: e[0])
        return results
    
    @classmethod
    def next_group(cls, ops:List[Tuple[int, bytes, int, str, str]], o:str, start_at:int, l:int) -> Tuple[int, int]:
        '''
        找到相关类型操作聚集位置
        '''
        i:int = start_at
        start_o:int = -1
        end_o:int = -1
        while i < len(ops):
            op = ops[i]
            if op[-1] == o:
                if start_o < 0: start_o = i
                elif op[0] - ops[i-1][0] > 0x10: 
                    if sum(map(lambda sop:sop[2], ops[start_o:i])) >= l: return (start_o, i-1)
                    start_o = i
                i += 1
                continue
            if start_o < 0: 
                i += 1
                continue
            if sum(map(lambda sop:sop[2], ops[start_o:i])) < l:
                start_o = -1
                i += 1
                continue
            end_o = i - 1
            break
        return (start_o, end_o)
    
    @classmethod
    def is_coherent(cls, insns:List[CsInsn]) -> bool:
        '''
        几条指令是否连续
        '''
        for i in range(len(insns)-1):
            if insns[i].address+insns[i].size > insns[i+1].address: return False
        return True

    @classmethod
    def reliable_stack_op_groups(cls, stack_ops:List[Tuple[int, bytes, int, str, str]], bin:Binary, l:int=2) -> List[Tuple[int, int]]:
        '''
        对栈操作进行分组并获取可靠的执行路径
        '''
        op_groups:List[Tuple[int, int]] = []
        idx:int = 0
        while idx <= len(stack_ops)-l:
            # 寻找下一组操作聚集位置
            grp = cls.next_group(stack_ops, 'O', idx, l)
            if grp[0] < 0 or grp[1] < 0: break
            idx = grp[0]+1
            # 检查聚集位置的指令是否连续
            try:
                if not cls.is_coherent(list(map(lambda op:list(bin.disasm.disasm(op[1], bin.text_base+op[0]))[0], stack_ops[grp[0]:grp[1]+1]))): continue
            except IndexError: continue
            op_groups.append(grp)
        return op_groups

    @classmethod
    def merge_exe_paths(cls, addr:int, hist:List[CsInsn], ucjmps:List[int], callees:List[int], exepaths:List[ExePath], bin:Binary, from_func_head:bool, funcs_map:Dict[int, Func]={}, min_addr:int=-1, max_addr:int=math.inf) -> List[ExePath]:
        '''
        将一个执行路径与由该执行路径产生的多条执行路径进行合并
        '''
        merged:List[ExePath] = []
        for exepath in exepaths:
            # 寻找相关地址指令所在位置
            insn_index:int = Helper.first_index(lambda i:i.address == addr, exepath.insns)
            if insn_index < 0: continue
            # 寻找不超过最小地址的位置
            min_insn_index:int = Helper.first_index(lambda i:i.address < min_addr, exepath.insns[insn_index:])
            # 如果找不到这样的越界指令 则路径上的全部指令都需要考虑
            if min_insn_index < 0: min_insn_index = len(exepath.insns)
            else: min_insn_index += insn_index
            # 寻找最后一个指令所在位置
            max_insn_index:int = Helper.first_index(lambda i:i.address >= max_addr, exepath.insns[insn_index:min_insn_index])
            # 如果找不到这样的越界指令 则路径上的全部指令都需要考虑
            if max_insn_index < 0: max_insn_index = min_insn_index
            else: max_insn_index += insn_index
            # 寻找第一个跳转到已知无返回函数的位置
            # jmp_to_nonreturn_func_index:int = Helper.first_index(lambda i:(cls.is_call(i) or cls.is_ucjmp(i)) and Helper.is_int(i.op_str) and Helper.to_int(i.op_str) in funcs_map and funcs_map[Helper.to_int(i.op_str)].return_type == RT_NO_RET, exepath.insns[insn_index:max_insn_index])
            jmp_to_nonreturn_func_index:int = Helper.first_index(lambda i:(cls.is_call(exepath.insns[i]) or cls.is_ucjmp(exepath.insns[i], exepath.insns[i-1] if i > 0 else None)) and Helper.is_int(exepath.insns[i].op_str) and Helper.to_int(exepath.insns[i].op_str) in funcs_map and funcs_map[Helper.to_int(exepath.insns[i].op_str)].return_type == RT_NO_RET, range(insn_index, max_insn_index))
            # 如果能找到这样一个位置 那也需要更改最大的指令位置
            if jmp_to_nonreturn_func_index >= 0: max_insn_index = min(max_insn_index, insn_index+jmp_to_nonreturn_func_index+1)
            # 寻找会jmp到一个已知函数的指令所在位置
            jmp_to_func_index:int = Helper.first_index(lambda i:cls.is_ucjmp(exepath.insns[i], exepath.insns[i-1] if i > 0 else None) and Helper.is_int(exepath.insns[i].op_str) and Helper.to_int(exepath.insns[i].op_str) in funcs_map, range(insn_index, max_insn_index))
            # 如果找到了跳转到已知函数的指令 也需要提前结束执行流
            if jmp_to_func_index >= 0: max_insn_index = min(insn_index+jmp_to_func_index+1, max_insn_index)
            # 寻找的位置
            call_followed_by_null_insn_index:int = Helper.first(lambda i: cls.is_call(exepath.insns[i]) and cls.null_insn(exepath.insns[i+1], bin) and cls.null_insn(exepath.insns[i+2], bin), range(len(exepath.insns[insn_index:max_insn_index])-2))
            # 如果call后面跟着两个及以上无效指令 也需要提前结束执行流
            if call_followed_by_null_insn_index is not None: max_insn_index = min(insn_index+call_followed_by_null_insn_index+1, max_insn_index)
            # 寻找这路径上的跳转目标以及调用目标
            new_ucjmps:List[int] = ucjmps + list(map(lambda i:Helper.to_int(exepath.insns[i].op_str), filter(lambda j: cls.is_ucjmp(exepath.insns[j], exepath.insns[j-1] if j > 0 else None) and Helper.is_int(exepath.insns[j].op_str), range(insn_index, max_insn_index))))
            new_callees:List[int] = callees + list(map(lambda i:Helper.to_int(i.op_str), filter(lambda insn: cls.is_call(insn) and Helper.is_int(insn.op_str) and Helper.to_int(insn.op_str) != insn.address + insn.size, exepath.insns[insn_index:max_insn_index])))
            # 新的执行路径
            new_hist:List[CsInsn] = hist+exepath.insns[insn_index:max_insn_index]
            if len(new_hist) <= 0: continue
            new_exepath:ExePath = ExePath(new_hist, ucjmp_tgts=new_ucjmps, callees=new_callees, 
                                        # 继承路径结束的各情况标志
                                        terminate_due_to_loop=exepath.terminate_due_to_loop,
                                        terminate_due_to_merging=True,
                                        terminate_due_to_insufficient_insns=(max_insn_index == len(exepath.insns) and exepath.terminate_due_to_insufficient_insns),
                                        terminate_due_to_out_of_range=(max_insn_index == len(exepath.insns) and exepath.terminate_due_to_out_of_range),
                                        terminate_due_to_tail_call=max_insn_index == jmp_to_func_index or (max_insn_index == len(exepath.insns) and exepath.terminate_due_to_tail_call),
                                        terminate_due_to_calling_noreturn=max_insn_index == jmp_to_nonreturn_func_index or (max_insn_index == len(exepath.insns) and exepath.terminate_due_to_calling_noreturn),
                                        terminate_due_to_invalid_call=exepath.terminate_due_to_invalid_call,
                                        terminate_due_to_impossible_callee=exepath.terminate_due_to_impossible_callee,
                                        from_func_head=from_func_head)
            merged.append(new_exepath)
        cls.logger.info(f'Generate {len(merged)} New ExePath(s) By Merging With Cache.')
        return merged

    @classmethod
    def gen_exe_paths_from_addr(cls, addr:int, bin:Binary, min_addr:int=-1, max_addr:int=math.inf, funcs_map:Dict[int, Func]={}, ignore_indirect_call:bool=True, extend_on_demand:bool=True, use_cache:bool=True, from_func_head:bool=True) -> List[ExePath]:
        '''
        从指定地址开始构造控制流图
        '''
        # 先给他反汇编个1000字节
        insns:List[CsInsn] = cls.disasm_insns_from(addr, bin, count=1024+16)[:-1]
        # 来吧 按照这些反汇编结果生成这个控制流图吧
        exe_paths:List[ExePath] = cls.gen_exe_paths_on_insns(insns, bin, min_addr=min_addr, max_addr=max_addr, funcs_map=funcs_map, ignore_indirect_call=ignore_indirect_call, extend_on_demand=extend_on_demand, use_cache=use_cache, from_func_head=from_func_head)
        return exe_paths

    @classmethod
    def gen_exe_paths_on_insns(cls, insns:List[CsInsn], bin:Binary, min_addr:int=-1, max_addr:int=math.inf, funcs_map:Dict[int, Func]={}, ignore_indirect_call:bool=True, extend_on_demand:bool=True, use_cache:bool=True, from_func_head:bool=True) -> List[ExePath]:
        '''
        基于指令的反汇编结果构造控制流图
        '''
        # 结果
        exe_paths:List[ExePath] = []
        # 如果指令都空的 那也没啥说的了
        if len(insns) <= 0: return exe_paths
        # 待分析队列
        states:Queue[Tuple[List[CsInsn], int, List[int], List[int]]] = Queue()
        # 已加入队列的情况
        done_states:List[int] = [0]
        states.put_nowait(([], 0, [], []))
        # 指令序列中的最大、最小地址
        max_insn_addr:int = max(map(lambda i:i.address+i.size, insns))
        min_insn_addr:int = min(map(lambda i:i.address, insns))
        while not states.empty():
            history, index, ucjmps, callees = states.get_nowait()
            states.task_done()
            # 是否是为了避免循环而结束的分析
            end_due_to_loop:bool = False
            # 是否由于路径合并得以提前结束分析
            end_due_to_merging:bool = False
            # 是否由于指令不够
            end_due_to_insufficient_insns:bool = False
            # 是否由于跳转到一个已知的无返回函数
            end_due_to_calling_noreturn:bool = False
            while index >= 0:
                if index >= len(insns): 
                    # 如果需要拓展 则拓展
                    if extend_on_demand:
                        # 获取拓展的指令 
                        extended_insns:List[CsInsn] = cls.disasm_insns_from(max_insn_addr, bin, count=512+16)
                        if len(extended_insns) > 1: extended_insns = extended_insns[:-1]
                        # 如果拓展之后还是不够 则放弃 包括放弃拓展出来的指令
                        if len(insns) + len(extended_insns) <= index:
                            cls.logger.warn(f'Extended Instructions Are Still Not Enough')
                            end_due_to_insufficient_insns = True
                            break
                        insns.extend(extended_insns)
                        max_insn_addr = max(map(lambda i:i.address+i.size, insns))
                        min_insn_addr = min(map(lambda i:i.address, insns)) 
                    # 否则就意味着需要提前断掉执行路径了
                    else:
                        cls.logger.warn(f'ExePath Terminate Due To Insufficient Instructions')
                        end_due_to_insufficient_insns = True
                        break
                # 当前指令
                insn:CsInsn = insns[index]
                # 如果已经分析过这条指令 则不再分析
                if Helper.first_index(lambda h:h.address == insn.address, history) >= 0:
                    end_due_to_loop = True
                    break
                # 如果指令超过了最大/最小的地址 也跳过
                if insn.address >= max_addr or insn.address < min_addr: break
                # 检查缓存
                # 康康有没有缓存过的分析结果
                if use_cache and insn.address in Cache.EXEPATH and len(Cache.EXEPATH[insn.address]) > 0:
                    # 好家伙 找到了 那就合并
                    merged_exe_paths:List[ExePath] = cls.merge_exe_paths(insn.address, history, ucjmps, callees, Cache.EXEPATH[insn.address], bin, from_func_head, funcs_map=funcs_map, max_addr=max_addr)
                    end_due_to_merging = True
                    # 将合并后的路径直接添加到结果中
                    exe_paths.extend(merged_exe_paths)
                    break
                history.append(insn)
                # 条件跳转
                if cls.is_cjmp(insn):
                    # 如果是直接跳转
                    if Helper.is_int(insn.op_str):
                        jmp_target:int = Helper.to_int(insn.op_str)
                        if jmp_target >= bin.text_base + len(bin.bytes):
                            cls.logger.warn(f'Target Address {hex(jmp_target)} Is Impossible')
                            index += 1
                            continue
                        # 如果是跳转到一个已确定的无返回函数 则直接分析下一条指令了
                        if jmp_target in funcs_map and funcs_map[jmp_target].return_type == RT_NO_RET:
                            index += 1
                            continue
                        # 寻找跳转目标的指令
                        tgt_insn_idx:int = Helper.first_index(lambda i:i.address == jmp_target, insns)
                        # 如果找得到 就新增加一个状态
                        if tgt_insn_idx >= 0:
                            if tgt_insn_idx not in done_states: 
                                states.put((history.copy(), tgt_insn_idx, ucjmps.copy(), callees.copy()), block=False)
                                done_states.append(tgt_insn_idx)
                        # 如果找不到 并且目标地址比指令序列的最大地址还大 就看看是不是需要拓展指令 从而获取新的分析结果
                        elif jmp_target >= max_insn_addr:
                            if not extend_on_demand:
                                end_due_to_insufficient_insns = True
                                break
                            # 获取拓展的指令 
                            extended_insns:List[CsInsn] = cls.disasm_insns_from(max_insn_addr, bin, count=jmp_target-max_insn_addr+16)
                            if len(extended_insns) > 1: extended_insns = extended_insns[:-1]
                            insns.extend(extended_insns)
                            max_insn_addr = max(map(lambda i:i.address+i.size, insns))
                            min_insn_addr = min(map(lambda i:i.address, insns))
                            # 在拓展的指令中继续寻找跳转目标
                            tgt_insn_idx:int = Helper.first_index(lambda i:i.address == jmp_target, insns)
                            # 如果成功找到了 则增加新状态 
                            if tgt_insn_idx >= 0:
                                if tgt_insn_idx not in done_states: 
                                    states.put((history.copy(), tgt_insn_idx, ucjmps.copy(), callees.copy()), block=False)
                                    done_states.append(tgt_insn_idx)
                            # 还找不到就出问题了
                            else: 
                                # arm中函数内部可能也夹杂着数据 这些数据可能无法构成反汇编结果 可能导致数据之后的指令无法被正确反汇编 最终找不到指令
                                cls.logger.error(f'Target Address {hex(jmp_target)} Not Found In Extended Insns.')
                                break
                        # 如果是跳转地址在已有的地址范围内 但是找不到目标地址 那就有问题了
                        elif jmp_target < max_insn_addr and jmp_target >= min_insn_addr: 
                            cls.logger.error(f'Jump Target {hex(jmp_target)} Exceeds The Address Range Of Instructions')
                            break
                    # 间接跳转需要考虑分析跳转目标
                    else: 
                        # 寻找间接跳转的目标
                        indirect_targets:List[int] = cls.targets_for_indirect_jmp(insn, bin, history)
                        for jmp_target in indirect_targets:
                            # 如果是跳转到一个已确定的无返回函数 则直接分析下一条指令了
                            if jmp_target in funcs_map and funcs_map[jmp_target].return_type == RT_NO_RET:
                                cls.logger.info(f'Indirect Jump To A Non-Return Function')
                                continue
                            # 寻找跳转目标的指令
                            tgt_insn_idx:int = Helper.first_index(lambda i:i.address == jmp_target, insns)
                            # 如果找得到 就新增加一个状态
                            if tgt_insn_idx >= 0:
                                if tgt_insn_idx not in done_states: 
                                    states.put((history.copy(), tgt_insn_idx, ucjmps.copy(), callees.copy()), block=False)
                                    done_states.append(tgt_insn_idx)
                            # 如果找不到 并且目标地址比指令序列的最大地址还大 就看看是不是需要拓展指令 从而获取新的分析结果
                            elif jmp_target >= max_insn_addr:
                                if not extend_on_demand:
                                    end_due_to_insufficient_insns = True
                                    break
                                # 获取拓展的指令 
                                extended_insns:List[CsInsn] = cls.disasm_insns_from(max_insn_addr, bin, count=jmp_target-max_insn_addr+16)
                                if len(extended_insns) > 1: extended_insns = extended_insns[:-1]
                                insns.extend(extended_insns)
                                max_insn_addr = max(map(lambda i:i.address+i.size, insns))
                                min_insn_addr = min(map(lambda i:i.address, insns))
                                # 在拓展的指令中继续寻找跳转目标
                                tgt_insn_idx:int = Helper.first_index(lambda i:i.address == jmp_target, insns)
                                # 如果成功找到了 则增加新状态 
                                if tgt_insn_idx >= 0:
                                    if tgt_insn_idx not in done_states: 
                                        states.put((history.copy(), tgt_insn_idx, ucjmps.copy(), callees.copy()), block=False)
                                        done_states.append(tgt_insn_idx)
                                # 还找不到就出问题了
                                else: cls.logger.error(f'Indirect Target Address {hex(jmp_target)} Not Found In Extended Insns.')
                            # 如果是跳转地址在已有的地址范围内 但是找不到目标地址 那就有问题了
                            elif jmp_target < max_insn_addr and jmp_target >= min_insn_addr: cls.logger.error(f'SOMETHING MUST GONE WRONG!', highlight=True)
                # 无条件跳转
                elif cls.is_ucjmp(insn, insns[index-1] if index > 0 else None):
                    # 如果是直接跳转
                    if Helper.is_int(insn.op_str):
                        jmp_target:int = Helper.to_int(insn.op_str)
                        # 如果比最小地址还小 那就认为是一个函数
                        if jmp_target < min_addr:
                            callees.append(jmp_target)
                            break
                        if jmp_target >= bin.text_base + len(bin.bytes):
                            cls.logger.warn(f'Target Address {hex(jmp_target)} Is Impossible')
                            break
                        # 如果是跳转到一个已确定的函数 则直接分析下一条指令了
                        if jmp_target in funcs_map:
                            cls.logger.info(f'Jump To A Known Function')
                            break
                        # 如果其后跟着两个填充指令 就认为是tail call 
                        if index < len(insns) - 2 and cls.null_insn(insns[index+1], bin) and cls.null_insn(insns[index+2], bin): break
                        # 寻找跳转目标的指令
                        tgt_insn_idx:int = Helper.first_index(lambda op:op.address == jmp_target, insns)
                        # 如果找得到 就跳转过去
                        if tgt_insn_idx >= 0:
                            index = tgt_insn_idx
                            ucjmps.append(jmp_target)
                            continue
                        # 如果找不到 并且目标地址比指令序列的最大地址还大 就看看是不是需要拓展指令 从而获取新的分析结果
                        elif jmp_target >= max_insn_addr:
                            if not extend_on_demand: 
                                end_due_to_insufficient_insns = True
                                break
                            # 获取拓展的指令 
                            extended_insns:List[CsInsn] = cls.disasm_insns_from(max_insn_addr, bin, count=jmp_target-max_insn_addr+16)
                            if len(extended_insns) > 1: extended_insns = extended_insns[:-1]
                            insns.extend(extended_insns)
                            max_insn_addr = max(map(lambda i:i.address+i.size, insns))
                            min_insn_addr = min(map(lambda i:i.address, insns))
                            # 在拓展的指令中继续寻找跳转目标
                            tgt_insn_idx:int = Helper.first_index(lambda i:i.address == jmp_target, insns)
                            # 如果成功找到了 就跳转过去 
                            if tgt_insn_idx >= 0: 
                                index = tgt_insn_idx
                                ucjmps.append(jmp_target)
                                continue
                            # 还找不到就出问题了
                            else: 
                                cls.logger.error(f'Target Address {hex(jmp_target)} Not Found In Extended Insns.')
                                break
                        # 如果是跳转地址在已有的地址范围内 但是找不到目标地址 那就有问题了
                        elif jmp_target >= min_insn_addr: 
                            cls.logger.error(f'SOMETHING MUST GONE WRONG!', highlight=True)
                            break
                        break
                    # 如果是间接跳转
                    else:
                        # 寻找间接跳转的目标
                        indirect_targets:List[int] = cls.targets_for_indirect_jmp(insn, bin, history)
                        for jmp_target in indirect_targets:
                            # 如果是跳转到一个已确定的无返回函数 则直接分析下一条指令了
                            if jmp_target in funcs_map and funcs_map[jmp_target].return_type == RT_NO_RET:
                                cls.logger.info(f'Indirect Jump To A Non-Return Function')
                                continue
                            # 寻找跳转目标的指令
                            tgt_insn_idx:int = Helper.first_index(lambda i:i.address == jmp_target, insns)
                            # 如果找得到 就新增加一个状态
                            if tgt_insn_idx >= 0:
                                if tgt_insn_idx not in done_states: 
                                    states.put((history.copy(), tgt_insn_idx, ucjmps.copy(), callees.copy()), block=False)
                                    done_states.append(tgt_insn_idx)
                            # 如果找不到 并且目标地址比指令序列的最大地址还大 就看看是不是需要拓展指令 从而获取新的分析结果
                            elif jmp_target >= max_insn_addr:
                                if not extend_on_demand:
                                    end_due_to_insufficient_insns = True
                                    break
                                # 获取拓展的指令 
                                extended_insns:List[CsInsn] = cls.disasm_insns_from(max_insn_addr, bin, count=jmp_target-max_insn_addr+16)
                                if len(extended_insns) > 1: extended_insns = extended_insns[:-1]
                                insns.extend(extended_insns)
                                max_insn_addr = max(map(lambda i:i.address+i.size, insns))
                                min_insn_addr = min(map(lambda i:i.address, insns))
                                # 在拓展的指令中继续寻找跳转目标
                                tgt_insn_idx:int = Helper.first_index(lambda i:i.address == jmp_target, insns)
                                # 如果成功找到了 则增加新状态 
                                if tgt_insn_idx >= 0:
                                    if tgt_insn_idx not in done_states: 
                                        states.put((history.copy(), tgt_insn_idx, ucjmps.copy(), callees.copy()), block=False)
                                        done_states.append(tgt_insn_idx)
                                # 还找不到就出问题了
                                else: cls.logger.error(f'Indirect Target Address {hex(jmp_target)} Not Found In Extended Insns.')
                            # 如果是跳转地址在已有的地址范围内 但是找不到目标地址 那就有问题了
                            elif jmp_target < max_insn_addr and jmp_target >= min_insn_addr: break
                        break
                # 函数返回指令
                elif cls.is_ret(insn): 
                    # 如果是有条件返回 就需要分叉执行路径了
                    if cls.has_cond(insn):
                        tgt_insn_idx:int = index + 1
                        if tgt_insn_idx not in done_states: 
                            states.put((history.copy(), tgt_insn_idx, ucjmps.copy(), callees.copy()), block=False)
                            done_states.append(tgt_insn_idx)
                    break
                # 函数调用指令
                elif cls.is_call(insn):
                    # 如果是有条件调用 就需要分叉执行路径了
                    if cls.has_cond(insn):
                        tgt_insn_idx:int = index + 1
                        if tgt_insn_idx not in done_states: 
                            states.put((history.copy(), tgt_insn_idx, ucjmps.copy(), callees.copy()), block=False)
                            done_states.append(tgt_insn_idx)
                    # 直接调用
                    if Helper.is_int(insn.op_str):
                        tgt_addr:int = Helper.to_int(insn.op_str)
                        # 屏蔽 call $+5这种
                        if tgt_addr >= 0 and tgt_addr != insn.address + insn.size: callees.append(tgt_addr)
                        # 如果调用的目标确定是一个无返回函数 则结束当前路径
                        if tgt_addr in funcs_map and funcs_map[tgt_addr].return_type == RT_NO_RET: break
                        # 如果其后跟着两个填充指令 就认为是tail call 
                        if index < len(insns) - 2 and cls.null_insn(insns[index+1], bin) and cls.null_insn(insns[index+2], bin): 
                            # 目标函数也被当做无返回函数
                            end_due_to_calling_noreturn = True
                            break
                    # 间接调用 如果忽略间接调用 否则就需要处理
                    elif not ignore_indirect_call: callees.extend(cls.resolve_indirect_call(insn, bin, history))
                index += 1
            # 如果是合并了缓存 则不需要再次向结果中加入执行路径
            if end_due_to_merging: continue
            exe_paths.append(ExePath(history, ucjmps, callees, terminate_due_to_loop=end_due_to_loop, terminate_due_to_insufficient_insns=end_due_to_insufficient_insns, terminate_due_to_calling_noreturn=end_due_to_calling_noreturn, from_func_head=from_func_head))
        # 如果使用缓存的话
        if use_cache:
            # 将新的分析结果进行缓存
            addrs:List[int] = list(set(Helper.merge(*list(map(lambda exe_path: list(map(lambda insn: insn.address, exe_path.insns)), exe_paths)))))
            for addr in addrs:
                if addr not in Cache.EXEPATH: Cache.EXEPATH[addr] = exe_paths
        return exe_paths

    @classmethod
    def disasm_insns_from(cls, addr:int, bin:Binary, count:int=1024) -> List[CsInsn]:
        '''
        从二进制中的指定位置开始反汇编一定数量的字节

        \param  addr                指定的起始位置
        \param  binary              目标二进制
        \param  count               反汇编的字节数量
        '''
        return list(bin.disasm.disasm(bin.bytes[addr-bin.text_base:addr-bin.text_base+count], addr))

    @classmethod
    def null_insn(cls, insn:CsInsn, bin:Binary) -> bool:
        '''
        是否是一条无意义指令
        '''
        # 指令的完全字符串表达
        insn_str:str = f'{insn.mnemonic} {insn.op_str}'
        # 检查是否有匹配的规则
        for r in cls.null_insn_regs:
            if r.match(insn_str): return True
        return False

    @classmethod
    def is_indirect_jmp(cls, insn:CsInsn) -> bool: 
        '''
        指令是否为间接跳转指令
        '''
        return insn.mnemonic in cls.jmps and not Helper.is_int(insn.op_str)

    @classmethod
    def compute(cls, equation:str, bin:Binary, byteorder:str, size:int=4, signed:bool=True) -> int:
        '''
        给定算式，计算值
        '''
        lefts:List[int] = []
        tmp_equation:str = equation
        sub_equation_values:Dict[str, int] = {}
        for i in range(len(equation)):
            s = equation[i]
            if s == '[': 
                lefts.append(i)
            elif s == ']': 
                # 起头位置
                left:int = lefts.pop(-1)
                # 表达式
                sub_equation:str = equation[left+1:i]
                # 如果没有子表达式 则进行求解
                if sub_equation.count('[') > 0 and sub_equation.count(']') > 0:
                    for k in sub_equation_values: sub_equation = sub_equation.replace(k, str(sub_equation_values[k]))
                value:int = eval(sub_equation)
                sub_equation_values[f'[{sub_equation}]'] = int.from_bytes(bin.bytes[value-bin.text_base:value-bin.text_base+size], byteorder=byteorder, signed=signed)
        for k in sub_equation_values: tmp_equation = tmp_equation.replace(k, str(sub_equation_values[k]))
        cls.logger.info(f'Final Equation: {tmp_equation}')
        return eval(tmp_equation)

    @classmethod
    def lead_to(cls, tgt_addr:int, bin:Binary, start_addr:int, history:List[CsInsn]) -> SimState:
        '''
        加载文件，将其引导至指定状态
        '''
        # 加载文件
        proj:Project = Project(bin.file, main_opts={
            'base_addr': bin.text_base,
            'backend': 'blob',
            'arch': cls.arch_name
        })
        cls.logger.info(f'Binary Loaded With Base Address Of {hex(bin.text_base)}')
        # 创建初始状态
        state:SimState = proj.factory.blank_state(addr=start_addr)
        # 历史走过的地址
        hist_addrs:List[int] = list(map(lambda h:h.address, history))
        hist_idx:int = 0
        while state is not None and state.addr != tgt_addr and hist_idx < len(hist_addrs):
            # 获取执行之后的状态
            successors:List[SimState] = list(state.step())
            # 寻找在历史路径中的状态
            tmp_state:SimState = Helper.first(lambda s:s.addr == hist_addrs[hist_idx], successors)
            # 如果找得到 就继续下去 找不到也得继续下去
            if tmp_state is not None: 
                state = tmp_state
                hist_idx += 1
                cls.logger.info(f'Leaded To {hex(tmp_state.addr)}, {len(hist_addrs)-hist_idx} States Waiting To Be Reached')
            elif len(successors) > 0: 
                cls.logger.info(f'No Matched State In History Addresses')
                state = Helper.first(lambda s:s.addr not in Helper.history(state), successors)
            else: state = None
        return state

    @classmethod
    def neighborred_duplicated_insns(cls, insns:List[CsInsn]) -> bool:
        '''
        指令序列是否存在连续且重复的指令
        '''
        # 判断的标准主要是指令的连续重复情况
        for i in range(len(insns)-1):
            if insns[i].mnemonic == insns[i+1].mnemonic and insns[i].op_str == insns[i+1].op_str: return True
        return False

    @abstractclassmethod
    def callsites_of(cls, addr:int, bin:Binary) -> List[CsInsn]:
        '''
        获取针对特定地址的调用点
        '''
        pass

    @abstractclassmethod
    def targets_for_indirect_jmp(cls, insn:CsInsn, bin:Binary, history:List[CsInsn]) -> List[int]: 
        '''
        获取间接跳转的跳转目标
        '''
        pass

    @abstractclassmethod
    def resolve_indirect_call(cls, insn:CsInsn, bin:Binary, history:List[CsInsn]) -> List[int]: 
        '''
        获取间接调用的调用目标
        '''
        pass

    @abstractclassmethod
    def is_stack_satisfied(cls, stack_op_insns:List[CsInsn]) -> int: 
        '''
        检查指令序列中的栈操作是否满足栈平衡特性
        '''
        pass

    @abstractclassmethod
    def is_ret(cls, insn:CsInsn) -> bool:
        '''
        判断指令是否用于返回执行流
        '''
        pass

    @abstractclassmethod
    def is_call(cls, insn:CsInsn) -> bool:
        '''
        是否为函数调用指令
        '''
        pass 

    @abstractclassmethod
    def is_ucjmp(cls, insn:CsInsn, last_insn:CsInsn=None) -> bool:
        '''
        是否为无条件跳转指令
        '''
        pass 

    @abstractclassmethod
    def is_cjmp(cls, insn:CsInsn) -> bool:
        '''
        是否为条件跳转指令
        '''
        pass 

    @classmethod
    def is_it(cls, insn:CsInsn) -> bool:
        '''
        是否为it指令
        '''
        pass

    @classmethod
    def has_cond(cls, insn:CsInsn) -> bool:
        '''
        指令执行是否有条件
        '''
        return False

    @classmethod
    def corp_exepath(cls, ep:ExePath, idx:int=-1, direct_only:bool=False) -> int:
        '''
        裁剪执行路径 使执行路径以函数调用/返回/直接跳转结尾
        '''
        idx = idx if idx >= 0 else len(ep.insns)-1
        # 只要不是调用、返回、直接跳转 就裁剪
        while idx >= 0 and not (((cls.is_call(ep.insns[idx]) or cls.is_ucjmp(ep.insns[idx], ep.insns[idx-1] if idx > 0 else None)) and (not direct_only or Helper.is_int(ep.insns[idx].op_str))) or cls.is_ret(ep.insns[idx]) or cls.is_it(ep.insns[idx])): idx -= 1
        if idx >= 0: 
            # 裁剪路径
            ep.insns = ep.insns[:idx+1]
            # 根据不同结束情况设置路径的不同结束方式
            if cls.is_call(ep.insns[-1]): ep.terminate_due_to_calling_noreturn = True
            elif cls.is_ucjmp(ep.insns[-1], ep.insns[-2] if len(ep.insns) >= 2 else None): ep.terminate_due_to_tail_call = True
        return idx

from lib.executor.arml import ArmLExecutor
from lib.executor.armlt import ArmLTExecutor
