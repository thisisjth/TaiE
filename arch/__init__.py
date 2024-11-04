# -*- encoding: utf-8

from queue import Queue
from capstone import CsInsn
from lib.executor import Executor
from typing import Dict, List, Tuple
from lib.executor.arml import ArmLExecutor
from lib.executor.armlt import ArmLTExecutor
from lib import Cache, EmptyInsns, Binary, ExePath, Func, Helper, Logger
from config.constant import ARCH_ARML, ARCH_ARML_THUMB, IB_CALLEE, IB_CALLEE_IN_CALLSITE, IB_SCANED_FROM_TAIL, RT_HAS_RET, RT_NO_RET, RT_NONE


class Arch:
    '''
    指令集架构基类
    '''

    # 日志记录
    logger:Logger = Logger('Arch')

    # 指令集到执行器的映射关系
    arch2executor:Dict[int, Executor] = {
        ARCH_ARML: ArmLExecutor,
        ARCH_ARML_THUMB: ArmLTExecutor
    }
    
    @classmethod
    def funcs_in(cls, bin:Binary, tag:str='') -> List[Func]:
        '''
        二进制文件中的函数清单
        '''
        # 根据指令集架构 获取相应的执行器
        executor:Executor = cls.arch2executor[bin.arch]
        # 获取到的所有的、可靠的指令点
        heads:List[int] = []
        # 处理过的入口点
        done_heads:List[int] = []
        # 函数结果
        funcs:List[Func] = []
        # 已经识别所得的函数
        done_funcs:List[int] = []
        # 1. 寻找其中的栈操作
        stack_ops:List[Tuple[int, bytes, int, str, str]] = executor.search_stack_ops(bin)
        # 2. 对栈操作进行分组并寻找满足栈平衡的分组
        op_groups:List[Tuple[int, int]] = executor.reliable_stack_op_groups(stack_ops, bin, l=2)
        # 3. 将可靠分组的起始位置作为可靠指令点
        for opg in op_groups: heads.append(bin.text_base+stack_ops[opg[0]][0])
        recursing:bool = True
        time_for_more_funcs = time_for_identify_return_types = time_for_extra_funcs = time_for_determine_tail = 0
        # 是否是第一轮迭代
        first_round:bool = True
        while recursing:
            recursing = False
            # 函数入口地址与函数实例之间的对应关系
            funcs_map:Dict[int, Func] = dict(list(map(lambda f:(f.head, f,), funcs)))
            # 4. 针对获取到的指令点进行递归分析
            heads = list(set(heads))
            cls.__more_funcs(heads, bin, funcs, done_heads, done_funcs, stack_ops, op_groups, funcs_map=funcs_map)
            orig_func_heads:List[int] = list(map(lambda f:f.head, funcs))
            # 清空原有的指令点
            heads.clear()
            funcs_map:Dict[int, Func] = dict(list(map(lambda f:(f.head, f,), funcs)))
            # 5. 识别无返回函数
            cls.__identify_return_types(funcs, bin, done_funcs, funcs_map=funcs_map)
            # 6. 根据函数边界以及返回类型的识别结果 构造函数的完整控制流图
            # 以后一个函数的入口位置作为当前函数的最大可能出口位置
            funcs.sort(key=lambda f:f.head)
            to_remove:List[int] = []
            for i in range(len(funcs)):
                # 对于最后一个函数 其最大可能出口位置设定在文件结尾
                max_addr:int = max(funcs[i].tail, funcs[i+1].head) if i < len(funcs) - 1 else max(funcs[i].tail, bin.text_base+len(bin.bytes))
                try:
                    funcs[i].gen_cfg(executor, bin, max_addr=max_addr, funcs_map=funcs_map, use_cache=first_round)
                except EmptyInsns as ei:
                    cls.logger.warn(f'CFG Of Function {hex(funcs[i].head)} Does Not Contain Any Instruction: {ei}')
                    if funcs[i].identified_by != IB_CALLEE:
                        to_remove.append(i)
                        recursing = True
                    continue
            # 剔除无法构造CFG的函数
            for tr in to_remove[::-1]: funcs.pop(tr)
            funcs_map:Dict[int, Func] = dict(list(map(lambda f:(f.head, f,), funcs)))
            # 获取与指令集相关的额外分析结果
            recursing = cls.extra_funcs(bin, funcs, done_funcs, stack_ops, op_groups, funcs_map=funcs_map)
            # 获取无返回函数识别过程中新识别到的函数
            new_func_heads:List[int] = list(map(lambda f:f.head, funcs))
            for head in list(set(new_func_heads)-set(orig_func_heads)-set(done_heads)): 
                recursing = True
                heads.append(head)
                done_heads.append(head)
            # 对函数的执行流进行分析 确定结尾位置
            funcs_map:Dict[int, Func] = dict(list(map(lambda f:(f.head, f,), funcs)))
            recursing = cls.__determine_tail(heads, bin, funcs, done_heads, done_funcs, funcs_map) or recursing
            # 开始从结尾处开始扫描
            for i in range(len(funcs)-1):
                func:Func = funcs[i]
                next_func:Func = funcs[i+1]
                # 如果还没有构造cfg 那就构造一下
                if func.cfg is None: func.gen_cfg(executor, bin, max_addr=bin.text_base+len(bin.bytes), funcs_map=funcs_map)
                # 如果当前函数出口和下一个函数入口挨得已经很近了 那就不分析了
                if next_func.head - func.tail < 16: continue
                # 否则分析看看有没有一个可能的入口
                new_head:int = cls.scan_from_tail(func.tail, bin, stack_ops, op_groups, funcs_map=funcs_map)
                if new_head < 0: continue
                # 如果没有分析过 那就分析一下
                if new_head not in done_heads:
                    heads.append(new_head)
                    done_heads.append(new_head)
                    recursing = True
                if new_head not in done_funcs and new_head not in Cache.CONSTANTS:
                    funcs.append(Func(new_head, ib=IB_SCANED_FROM_TAIL))
                    done_funcs.append(new_head)
                    recursing = True
            first_round = False
        return funcs
    
    @classmethod
    def __more_funcs(cls, heads:List[int], bin:Binary, funcs:List[Func], done_heads:List[int], done_funcs:List[int], stack_ops:List[Tuple[int, bytes, int, str, str]], op_groups:List[Tuple[int, int]], funcs_map:Dict[int, Func]={}) -> bool:
        '''
        拓展指令点以及函数识别结果
        '''
        changed:bool = False
        # 根据指令集架构 获取相应的执行器
        executor:Executor = cls.arch2executor[bin.arch]
        # 待分析队列
        heads_queue:Queue[int] = Queue()
        for h in heads: heads_queue.put_nowait(h)
        # 标记为处理过
        done_heads.extend(heads)
        cls.logger.info(f'Function extending started.')
        times = [0, 0, 0, 0, 0]
        while not heads_queue.empty():
            # 获取一个指令点
            head:int = heads_queue.get_nowait()
            heads_queue.task_done()
            # 从指令点开始构造执行路径
            exe_paths:List[ExePath] = executor.gen_exe_paths_from_addr(head, bin, funcs_map=funcs_map)
            cls.logger.info(f'Generated ExePath For Head@{hex(head)}')
            if len(exe_paths) <= 0: 
                cls.logger.warn(f'No ExePath For {hex(head)}')
                continue
            # 如果有哪个执行路径是没有指令的 则放弃
            if any(map(lambda ep:len(ep.insns)<=0, exe_paths)): continue
            # 当前指令点分析所得的执行路径中最大的指令地址
            tmp_exit:int = max(map(lambda exe_path: exe_path.addr_after_max_insn_addr, exe_paths))
            for exe_path in exe_paths:
                if any(map(lambda c:c < bin.text_base or c >= bin.text_base + len(bin.bytes), exe_path.callees)): continue
                # 新的指令片段入口
                new_heads:List[int] = list(set(exe_path.callees) - set(done_heads))
                for c in new_heads: heads_queue.put_nowait(c)
                done_heads.extend(new_heads)
                # 新的函数
                new_funcs:List[int] = list(set(exe_path.callees) - set(done_funcs))
                # 将全部找到的调用对象的识别来源设置成IB_CALLEE 
                for i in set(exe_path.callees):
                    if i in funcs_map: funcs_map[i].identified_by = IB_CALLEE
                funcs.extend(map(lambda c: Func(c, ib=IB_CALLEE), new_funcs))
                done_funcs.extend(new_funcs)
                changed = len(new_funcs) > 0 or changed
            # 获取针对当前指令点的调用
            callsites:List[CsInsn] = executor.callsites_of(head, bin)
            # 从这些callsites开始向后反汇编 寻找更多的函数调用目标
            for callsite in callsites:
                # 从调用点开始分析 寻找之后的其他指令中的调用目标
                exe_paths_from_callsite:List[ExePath] = executor.gen_exe_paths_from_addr(callsite.address, bin, funcs_map=funcs_map)
                for exe_path in exe_paths_from_callsite: 
                    if any(map(lambda c:c < bin.text_base or c >= bin.text_base + len(bin.bytes), exe_path.callees)): continue
                    # 新的指令片段入口
                    new_heads:List[int] = list(set(exe_path.callees) - set(done_heads))
                    for c in new_heads: heads_queue.put_nowait(c)
                    done_heads.extend(new_heads)
                    # 新的函数
                    new_funcs:List[int] = list(set(exe_path.callees) - set(done_funcs))
                    # 将全部找到的调用对象的识别来源设置成IB_CALLEE 
                    for i in set(exe_path.callees):
                        if i in funcs_map: funcs_map[i].identified_by = IB_CALLEE
                    funcs.extend(map(lambda c: Func(c, ib=IB_CALLEE_IN_CALLSITE), new_funcs))
                    done_funcs.extend(new_funcs)
                    changed = len(new_funcs) > 0 or changed
            # 从结尾处开始扫描
            new_head:int = cls.scan_from_tail(tmp_exit, bin, stack_ops, op_groups, funcs_map=funcs_map)
            # 如果找不到就算了
            if new_head < 0: continue
            # 纳入后续分析之中
            if new_head not in done_heads: 
                heads_queue.put_nowait(new_head)
                done_heads.append(new_head)
                changed = True
            # 加入结果之中
            if new_head not in done_funcs and new_head not in Cache.CONSTANTS:
                funcs.append(Func(new_head, ib=IB_SCANED_FROM_TAIL))
                done_funcs.append(new_head)
                changed = True
        cls.logger.info(f'Function extending done.')
        cls.logger.dbg(times)
        if all(map(lambda t:t==0, times)): cls.logger.dbg(bin.file)
        return changed

    @classmethod
    def __identify_return_types(cls, funcs:List[Func], bin:Binary, done_funcs:List[int], funcs_map:Dict[int, Func]={}):
        '''
        识别无返回函数
        '''
        # 根据指令集架构 获取相应的执行器
        executor:Executor = cls.arch2executor[bin.arch]
        recursing:bool = True
        cls.logger.dbg(f'Function returning type identification started.')
        while recursing:
            recursing = False
            # 先按照入口位置升序排序
            funcs.sort(key=lambda f:f.head)
            funcs_map = dict(list(map(lambda f:(f.head, f,), funcs)))
            for func in funcs:
                exe_paths_of_func:List[ExePath] = func.cfg if func.cfg is not None and len(func.cfg) > 0 else executor.gen_exe_paths_from_addr(func.head, bin, min_addr=func.head, funcs_map=funcs_map)
                # 检查函数执行路径是否以函数调用结尾
                # 获取执行路径最后调用到的目标
                callees:List[int] = list(set(map(lambda ep:Helper.to_int(ep.insns[-1].op_str), filter(lambda ep:not ep.terminate_due_to_impossible_callee and not ep.terminate_due_to_insufficient_insns and not ep.terminate_due_to_loop and not ep.terminate_due_to_out_of_range and executor.is_call(ep.insns[-1]) and Helper.is_int(ep.insns[-1].op_str), exe_paths_of_func))))
                for c in callees:
                    the_func_idx:int = Helper.first_index(lambda f:f.head == c, funcs)
                    if the_func_idx >= 0:
                        recursing = funcs[the_func_idx].return_type != RT_NO_RET or recursing
                        funcs[the_func_idx].return_type = RT_NO_RET
                        cls.logger.warn(f'set function {hex(c)} as non-return')
                    else:
                        funcs.append(Func(c, ib=IB_CALLEE, rt=RT_NO_RET))
                        done_funcs.append(c)
                        recursing = True
            for i in range(len(funcs)-1):
                func:Func = funcs[i]
                next_func:Func = funcs[i+1]
                # 如果当前函数的结尾位置与下一个函数的入口位置重叠 就需要特别分析
                exe_paths_of_func:List[ExePath] = func.cfg if func.cfg is not None and len(func.cfg) > 0 else executor.gen_exe_paths_from_addr(func.head, bin, min_addr=func.head, funcs_map=funcs_map)
                # 如果这个执行路径构造不出来 那是有问题的
                if len(exe_paths_of_func) <= 0: 
                    cls.logger.error(f'NO EXEPATH FOR FUNCTION {hex(func.head)}')
                    continue
                # 如果有哪个路径没有指令的 那也不行
                if any(map(lambda ep: len(ep.insns) <= 0, exe_paths_of_func)):
                    cls.logger.error(f'At Least One EXEPATH FOR FUNCTION {hex(func.head)} Contains No Instruction')
                    continue
                # 如果所有执行路径都调用了无返回函数 则当前函数也是无返回函数
                if all(map(lambda exe_path: Helper.first_index(lambda insn: executor.is_call(insn) and Helper.is_int(insn.op_str) and Helper.first(lambda f:f.head == Helper.to_int(insn.op_str), funcs) is not None and Helper.first(lambda f:f.head == Helper.to_int(insn.op_str), funcs).return_type == RT_NO_RET, exe_path.insns) >= 0, exe_paths_of_func)): 
                    recursing = func.return_type != RT_NO_RET or recursing
                    func.return_type = RT_NO_RET
                    cls.logger.warn(f'set function {hex(func.head)} as non-return')
                    continue
                # 获取执行路径中的最大位置
                tmp_exit_of_func:int = max(map(lambda exe_path: exe_path.addr_after_max_insn_addr, exe_paths_of_func))
                # 如果当前函数的出口位置小于下一个函数的入口位置 则视为正常情况
                if tmp_exit_of_func <= next_func.head: continue
                for exe_path in exe_paths_of_func:
                    # 寻找各执行路径中超过了下一个函数入口位置的指令
                    if all(map(lambda insn:insn.address < next_func.head, exe_path.insns)): continue
                    # 寻找最后一条地址小于下一个函数入口位置的指令的下标
                    insn_index:int = Helper.first_index(lambda insn:insn.address >= next_func.head, exe_path.insns) - 1
                    # 逆序搜索 寻找最后一个有效的指令
                    while executor.null_insn(exe_path.insns[insn_index], bin) and exe_path.insns[insn_index].address >= func.head: insn_index -= 1
                    # 如果搜到了发现是一个call 就认为调用的目标是一个无返回函数
                    last_insn:CsInsn = exe_path.insns[insn_index]
                    if executor.is_call(last_insn):
                        # 如果是一个间接调用 则暂时放弃
                        # todo: 解决此处的间接调用问题
                        if not Helper.is_int(last_insn.op_str): 
                            cls.logger.warn(f'An indirect call "{hex(last_insn.address)}\t{last_insn.mnemonic}\t{last_insn.op_str}" located between func.{hex(func.head)} and func.{next_func.head}. Exepath: {",".join(list(map(lambda i:hex(i.address), exe_path.insns)))}')
                            continue
                        # 寻找这个调用的目标
                        the_callee_addr:int = Helper.to_int(last_insn.op_str)
                        # 如果是call $+5这种 则不算一个调用目标
                        if the_callee_addr == last_insn.address + last_insn.size: continue 
                        the_callee_func:Func = Helper.first(lambda f:f.head == the_callee_addr, funcs)
                        # 如果找不到相应的调用目标 则新增加一个函数
                        if the_callee_func is None:
                            if the_callee_addr not in done_funcs: 
                                funcs.append(Func(the_callee_addr, ib=IB_CALLEE, rt=RT_NO_RET))
                                done_funcs.append(the_callee_addr)
                                recursing = True
                        # 如果发现已经确定调用的目标是有返回函数 则这个情况就是多入口函数了
                        elif the_callee_func.return_type == RT_HAS_RET:
                            # 多入口函数 那也更改它的结尾
                            the_callee_func.tail = last_insn.address + last_insn.size
                            continue
                        # 否则修改对应的返回值类型
                        else: 
                            recursing = the_callee_func.return_type != RT_NO_RET or recursing
                            the_callee_func.return_type = RT_NO_RET
                            cls.logger.warn(f'set function {hex(the_callee_func.head)} as non-return')
                    # 如果是其他指令
                    else:
                        # 如果是其他指令却依然使得两个函数重叠 那很可能是多入口函数的情况
                        # 多入口函数的上一部分入口指令序列和下一部分的入口指令序列应该连续 中间应该没有如填充指令之类的东西
                        if last_insn.address + last_insn.size == next_func.head:
                            # 认为是多入口函数
                            # todo: 解决多入口函数的处理
                            continue
        cls.logger.dbg(f'Function returning type identification done.')

    @classmethod
    def __determine_tail(cls, heads:List[int], bin:Binary, funcs:List[Func], done_heads:List[int], done_funcs:List[int], funcs_map:Dict[int, Func]={}) -> bool:
        '''
        分析函数的执行流并确定其结尾位置
        '''
        changed:bool = False
        # 根据指令集架构 获取相应的执行器
        executor:Executor = cls.arch2executor[bin.arch]
        # 梳理已知函数的执行流 如果发现jmp到一个已确定的函数上 则认为是tail call 需要提前终止执行流
        # 如果有任何函数的执行流发生了变化 都需要进行继续的迭代
        funcs_map:Dict[int, Func] = dict(list(map(lambda f:(f.head, f,), funcs)))
        to_remove:List[int] = []
        for i in range(len(funcs)):
            func:Func = funcs[i]
            # 如果还没生成cfg 那就生成一下
            if func.cfg is None: 
                try: func.gen_cfg(executor, bin, max_addr=bin.text_base+len(bin.bytes), funcs_map=funcs_map)
                except EmptyInsns: 
                    if func.identified_by != IB_CALLEE: to_remove.append(i)
                    continue
            to_remove:List[int] = []
            for idx in range(len(func.cfg)):
                exe_path:ExePath = func.cfg[idx]
                # 如果是附加的 不是从函数入口开始构造的 那就算了
                if len(exe_path.insns) <= 0 or exe_path.insns[0].address != func.head: continue
                # 剔除末端的无效指令
                j:int = len(exe_path.insns) - 1
                while j >= 0 and executor.null_insn(exe_path.insns[j], bin): j -= 1
                if j < 0: to_remove.append(idx)
                exe_path.insns = exe_path.insns[:j+1]
                # 寻找会直接跳转到已知函数的指令
                the_invalid_jmp_index:int = Helper.first_index(lambda i: executor.is_ucjmp(exe_path.insns[i], exe_path.insns[i-1] if i > 0 else None) and Helper.is_int(exe_path.insns[i].op_str) and Helper.first(lambda f:f.head == Helper.to_int(exe_path.insns[i].op_str), funcs) is not None, range(len(exe_path.insns)))
                # 如果不存在 就算了
                if the_invalid_jmp_index < 0 or the_invalid_jmp_index == len(exe_path.insns) - 1: continue
                # 否则更新函数的执行路径以及出口位置
                exe_path.insns = exe_path.insns[:the_invalid_jmp_index+1]
                exe_path.terminate_due_to_tail_call = True
                # 继续迭代
                changed = True
            for j in to_remove[::-1]: func.cfg.pop(j)
            if len(func.cfg) <= 0: 
                to_remove.append(i)
                continue
            func.tail = max(list(map(lambda ep:ep.addr_after_max_insn_addr, func.cfg)))
        for i in to_remove[::-1]: funcs.pop(i)
        return changed

    @classmethod
    def scan_from_tail(cls, tail:int, bin:Binary, stack_ops:List[Tuple[int, bytes, int, str, str]], op_groups:List[Tuple[int, int]], funcs_map:Dict[int, Func]={}) -> int:
        '''
        从函数结尾开始扫描 寻找可能的指令
        '''
        # 根据指令集架构 获取相应的执行器
        executor:Executor = cls.arch2executor[bin.arch]
        # 获取执行路径前方最近的栈操作指令聚集位置
        nearest_op_grp:Tuple[int, int] = Helper.first(lambda grp:bin.text_base+stack_ops[grp[0]][0]>=tail and bin.text_base+stack_ops[grp[0]][0]-tail<=16, op_groups)
        if nearest_op_grp is None: return -1
        # 如果能够找到这样的一个片段，检查是否与其之间的指令是否为无效指令
        gap_insns:List[CsInsn] = executor.disasm_insns_from(tail, bin, count=bin.text_base+stack_ops[nearest_op_grp[0]][0]-tail+len(stack_ops[nearest_op_grp[0]][1]))
        # 如果反汇编失败 则跳过(因为指令序列至少是要包含下一个开栈操作的)
        if len(gap_insns) <= 0: return -1
        # 如果gap中的指令都是无效指令 则认为下一个聚集位置也是函数起始位置
        if gap_insns[-1].address != bin.text_base+stack_ops[nearest_op_grp[0]][0] or not all(map(lambda insn: executor.null_insn(insn, bin), gap_insns[:-1])): return -1
        new_head:int = bin.text_base+stack_ops[nearest_op_grp[0]][0]
        return new_head

    @classmethod
    def extra_funcs(cls, bin:Binary, funcs:List[Func], done_funcs:List[int], stack_ops:List[Tuple[int, bytes, int, str, str]], op_groups:List[Tuple[int, int]], funcs_map:Dict[int, Func]) -> bool:
        '''
        与指令集架构相关的分析以获取到额外的函数结果
        '''
        return False






from arch.arml import ArmLArch
from arch.armlt import ArmLTArch
