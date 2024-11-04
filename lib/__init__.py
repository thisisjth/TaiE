#!python3.9
# -*- encoding: utf-8 -*-

import re, math, os
from os import popen
from typing import Any, Dict, List, Literal, Union, Tuple
from capstone import CS_ARCH_ARM, CS_MODE_LITTLE_ENDIAN, CS_MODE_THUMB, CS_MODE_ARM, CS_MODE_MCLASS, Cs, CsInsn
from config.constant import ARCH_ARML, ARCH_ARML_THUMB, IB_NONE, RT_NONE
from lib.misc.helper import Helper
from lib.misc.logger import Logger


# 反汇编器与指令集架构的映射关系
disasm_map:Dict[int, Cs] = {
    ARCH_ARML: Cs(CS_ARCH_ARM, CS_MODE_LITTLE_ENDIAN+CS_MODE_ARM),
    ARCH_ARML_THUMB: Cs(CS_ARCH_ARM, CS_MODE_LITTLE_ENDIAN+CS_MODE_THUMB+CS_MODE_ARM+CS_MODE_MCLASS),
}

class Binary:
    '''
    二进制文件配置
    '''

    def __init__(self, file:str, arch:int, text_base:int=-1, data_base:int=-1) -> None:
        '''
        初始化函数
        '''
        # 文件路径信息
        self.file:str = file 
        # 指令集架构
        self.arch:int = arch
        # 反汇编器
        self.disasm:Cs = disasm_map[self.arch]
        # 文件二进制字节数量
        self.size:int = os.path.getsize(file)

        # 数据缓存
        # 是否已经缓存过数据
        self.__cached:bool = text_base >= 0 and data_base >= 0
        # 文件二进制字节序列
        self.__cached_bytes:bytes = None
        # 缓存的指令加载基址
        self.__cached_text_base:int = max(text_base, 0)
        # 缓存的数据加载基址
        self.__cached_data_base:int = max(data_base, 0)

    @property
    def bytes(self) -> bytes:
        '''
        二进制内容
        ''' 
        # 如果有缓存 就使用缓存 
        if isinstance(self.__cached_bytes, bytes): return self.__cached_bytes
        # 否则读取文件 
        self.__cached_bytes = open(self.file, 'rb').read()
        return self.__cached_bytes
    
    @property
    def text_base(self):
        '''
        借助readelf工具获取指令加载基址
        '''
        if not self.__cached: 
            results:List[Tuple[int, int]] = self.get_text_and_data_base(self.file)
            if results is not None: 
                self.__cached_text_base = results[0][1] - results[0][0]
                self.__cached_data_base = results[1][1] - results[1][0]
                self.__cached = True
        return self.__cached_text_base
    
    @property
    def data_base(self):
        '''
        借助readelf工具获取数据加载基址
        '''
        if not self.__cached: 
            results:List[Tuple[int, int]] = self.get_text_and_data_base(self.file)
            if results is not None: 
                self.__cached_text_base = results[0][1] - results[0][0]
                self.__cached_data_base = results[1][1] - results[1][0]
                self.__cached = True
        return self.__cached_data_base
    
    def __str__(self) -> str:
        return f'<Binary@{self.file}>'

    @classmethod
    def get_text_and_data_base(cls, elf:str) -> List[Tuple[int, int]]:
        '''
        更新指令与数据的加载基址
        '''
        lines:List[str] = popen(f'readelf -l {elf}').readlines()
        started:bool = False
        values:List[int] = []
        # 分析每一行的输出，计算加载基址
        for line in lines:
            # 如果还没有经过Program Headers行
            if not started and not line.startswith('Program Headers:'): continue
            if line.startswith('Program Headers:'):
                started = True
                continue
            try:
                # 切分多个字段
                _, typ, ofst, va = re.sub(r'\s\s+', ' ', line).split(' ')[:4]
                if typ != 'LOAD': continue
                values.append((Helper.to_int(ofst), Helper.to_int(va),))
            except Exception: continue
        if len(values) <= 0: return [(0, 0,), (0, 0,),]
        if len(values) <= 1: return [values[0], values[0],]
        return values[:2]

class ExePath:
    '''
    执行路径
    '''
    def __init__(self, insns:List[CsInsn], ucjmp_tgts:List[int]=[], callees:List[int]=[], 
                terminate_due_to_loop:bool=False, 
                terminate_due_to_merging:bool=False,
                terminate_due_to_invalid_call:bool=False, 
                terminate_due_to_insufficient_insns:bool=False,
                terminate_due_to_tail_call:bool = False,
                terminate_due_to_impossible_callee:bool = False,
                terminate_due_to_calling_noreturn:bool = False,
                terminate_due_to_out_of_range:bool = False,
                from_func_head:bool=False) -> None:
        '''
        初始化函数
        '''
        # 执行路径上的指令们
        self.insns:List[CsInsn] = insns
        # 直接跳转的目标们
        self.ucjmp_targets:List[int] = ucjmp_tgts
        # 调用到的其他函数们
        self.callees:List[int] = callees
        # 是否只是为了避免循环才提前结束了cfg的分析
        self.terminate_due_to_loop:bool = terminate_due_to_loop
        # 是否因为缓存合并而结束
        self.terminate_due_to_merging:bool = terminate_due_to_merging
        # 是否因为遇到了不合理的函数调用才提前结束
        self.terminate_due_to_invalid_call:bool = terminate_due_to_invalid_call
        # 是否由于指令不够了才提前结束
        self.terminate_due_to_insufficient_insns:bool = terminate_due_to_insufficient_insns
        # 是否由于识别出了tail call 
        self.terminate_due_to_tail_call:bool = terminate_due_to_tail_call
        # 是否由于出现了不可能的跳转目标
        self.terminate_due_to_impossible_callee:bool = terminate_due_to_impossible_callee
        # 是否由于跳转到一个已知的无返回函数
        self.terminate_due_to_calling_noreturn:bool = terminate_due_to_calling_noreturn
        # 是否因为指令超过地址范围而中断
        self.terminate_due_to_out_of_range:bool = terminate_due_to_out_of_range
        # 是否从一个确定的函数入口开始构建的
        self.from_func_head:bool = from_func_head
    
    @property
    def max_insn_addr(self) -> int:
        '''
        执行路径上最大的指令地址
        '''
        return Helper.max(lambda insn:insn.address, self.insns).address
    
    @property
    def addr_after_max_insn_addr(self) -> int:
        '''
        执行路径上最大指令地址之后的地址
        '''
        # 否则计算最大的地址
        the_insn:CsInsn = Helper.max(lambda insn:insn.address+insn.size, self.insns)
        return the_insn.address + the_insn.size
    
    @property
    def tail_insn_addr(self) -> int:
        '''
        执行路径的结束指令所在地址
        '''
        return self.insns[-1].address
    
    @property
    def addr_after_tail_insn(self) -> int:
        '''
        执行路径上结束指令之后的地址
        '''
        return self.insns[-1].address+self.insns[-1].size
    
    def __str__(self) -> str:
        return f'<ExePath@{hex(self.insns[0].address)}~{hex(self.addr_after_max_insn_addr)} (terminate_due_to_loop={self.terminate_due_to_loop}, terminate_due_to_merging={self.terminate_due_to_merging}, terminate_due_to_invalid_call={self.terminate_due_to_invalid_call}, terminate_due_to_insufficient_insns={self.terminate_due_to_insufficient_insns}, terminate_due_to_tail_call={self.terminate_due_to_tail_call}, terminate_due_to_impossible_callee={self.terminate_due_to_impossible_callee}, terminate_due_to_calling_noreturn={self.terminate_due_to_calling_noreturn}, terminate_due_to_out_of_range={self.terminate_due_to_out_of_range})>'
    
    def __repr__(self) -> str:
        return f'<ExePath@{hex(self.insns[0].address)}~{hex(self.addr_after_max_insn_addr)} (terminate_due_to_loop={self.terminate_due_to_loop}, terminate_due_to_merging={self.terminate_due_to_merging}, terminate_due_to_invalid_call={self.terminate_due_to_invalid_call}, terminate_due_to_insufficient_insns={self.terminate_due_to_insufficient_insns}, terminate_due_to_tail_call={self.terminate_due_to_tail_call}, terminate_due_to_impossible_callee={self.terminate_due_to_impossible_callee}, terminate_due_to_calling_noreturn={self.terminate_due_to_calling_noreturn}, terminate_due_to_out_of_range={self.terminate_due_to_out_of_range})>'

    def stack_satisfied(self, bin:Binary, executor) -> bool:
        '''
        执行路径上是否满足栈平衡要求
        '''
        return executor.is_stack_satisfied(self.insns)

class Func:
    
    '''
    函数信息类
    '''

    logger:Logger = Logger('Func')

    def __init__(self, head:int, tail:int=-1, ib:int=IB_NONE, rt:int=RT_NONE) -> None:
        '''
        初始化函数

        \param  head            函数入口位置
        \param  tail            函数出口位置
        \param  ib              函数识别来源
        \param  rt              函数返回值类型
        '''
        # 函数起始位置
        self.head:int = head
        # 函数结束位置
        self.tail:int = tail if tail >= 0 else head
        # 识别来源
        self.identified_by:int = ib
        # 返回值类型 是否有返回值
        self.return_type:int = rt
        # 函数中调用到的其他函数
        self.callees:List[Func] = []
        # 函数的被调用点
        self.callsites:List[CsInsn] = []
        # 数据缓存
        self.cfg:List[ExePath] = None
    
    def gen_cfg(self, executor, bin:Binary, max_addr:int=math.inf, funcs_map:Dict[int, Any]={}, use_cache:bool=True) -> None:
        '''
        生成函数CFG控制流图
        '''
        # 如果有缓存 则不再计算
        if use_cache and isinstance(self.cfg, list): return
        # 否则获取CFG
        ma:int = min(math.inf, max_addr)
        self.cfg = executor.gen_exe_paths_from_addr(self.head, bin, min_addr=self.head, max_addr=ma, funcs_map=funcs_map, extend_on_demand=True, use_cache=use_cache, from_func_head=True)
        contain_empty_exepath:bool = Helper.any(lambda ep:len(ep.insns) <= 0, self.cfg)
        if contain_empty_exepath or len(self.cfg) <= 0: raise EmptyInsns(f'contain empty ExePath: {contain_empty_exepath}, no ExePath: {len(self.cfg) <= 0}')
        # 更新调用的目标函数列表
        self.callees = list(set(Helper.merge(*list(map(lambda ep:ep.callees, self.cfg)))))
        # 更新函数出口位置
        self.tail = max(list(map(lambda ep:ep.addr_after_max_insn_addr, self.cfg)))
    
    def __str__(self) -> str:
        '''
        字符串表示
        '''
        return f'({hex(self.head)}, {hex(self.tail)}, {["NONE", "RET", "NORET"][self.return_type]})'

class Cache:
    '''
    缓存类
    '''

    # 反汇编指令缓存
    INSNS:List[Dict[Literal['addr_range', 'insns'], Union[Tuple[int, int], List[CsInsn]]]] = []
    # 执行路径的缓存
    EXEPATH:Dict[int, List[ExePath]] = {}
    # 函数调用指令的缓存
    CALL_INSNS:List[CsInsn] = None
    # 间接跳转点的取值空间缓存
    INDIRECT_JUMP:Dict[int, List[int]] = {}
    # 间接调用的调用目标缓存
    INDIRECT_CALL:Dict[int, List[int]] = {}
    # 所有ldr加载到的常量缓存
    CONSTANTS:List[int] = []

    @classmethod
    def clear(cls):
        '''
        清除历史缓存数据
        '''
        # 清理执行路径的缓存
        cls.EXEPATH.clear()
        # 清理函数调用指令的缓存
        if cls.CALL_INSNS is not None: 
            cls.CALL_INSNS.clear()
            cls.CALL_INSNS = None
        # 清理间接调用的分析缓存
        cls.INDIRECT_CALL.clear()
        # 清理间接跳转点的分析缓存
        cls.INDIRECT_JUMP.clear()
        # 清理反汇编指令缓存
        cls.INSNS.clear()
        # 清理ldr常量缓存
        cls.CONSTANTS.clear()

class InsnMgr:
    '''
    指令反汇编管理
    '''
    
    logger:Logger = Logger('InsnMgr')

    @classmethod
    def insn_at(cls, addr:int, bin:Binary, executor, extend:bool=True) -> CsInsn:
        '''
        返回指定位置的指令
        '''
        # 在缓存中寻找已反汇编的结果
        insns:List[CsInsn] = cls.insns_from(addr, bin, executor)
        return insns[0]

    @classmethod
    def insns_from(cls, addr:int, bin:Binary, executor, extend:bool=True) -> List[CsInsn]:
        '''
        返回从指定位置开始的、已反汇编的指令集合
        '''
        result:List[CsInsn] = []
        # 在缓存中寻找第一个包含了该地址指令的项
        cache:Dict[Literal['addr_range', 'insns'], Union[Tuple[int, int], List[CsInsn]]] = Helper.first(lambda c: Helper.in_range(addr, *c['addr_range']), Cache.INSNS)
        # 如果没有缓存 就需要进行反汇编
        if cache is not None:
            # 从缓存中寻找特定位置的指令 然后返回
            idx:int = Helper.first_index(lambda i:i.address == addr, cache['insns'])
            # 如果找不到 就出问题了
            if idx < 0: raise DisassemblyError(f'Not any instruction located at {hex(addr)}')
            return cache['insns'][idx:]
        # 看看缓存里最接近的片段是什么地址开始的 然后看看和1024比比 谁更靠近就谁来当做反汇编的大小
        before_idx:int =Helper.first_index(lambda c:c['addr_range'][1] == addr, Cache.INSNS)
        after_idx:int = Helper.first_index(lambda c:c['addr_range'][0] >= addr, Cache.INSNS)
        count:int = min(1024, Cache.INSNS[after_idx]['addr_range'][0]-addr+Cache.INSNS[after_idx]['insns'][0].size) if after_idx >= 0 else 1024
        # 获取反汇编结果
        insns:List[CsInsn] = executor.disasm_insns_from(addr, bin, count=count)
        if len(insns) > 1: insns = insns[:-1]
        if len(insns) <= 0: raise EmptyInsns(f'Cannot get any instruction from address {hex(addr)}')
        # 如果反汇编失败
        if insns[0].address != addr: raise DisassemblyError(f'Fail to get instruction at {hex(addr)}')
        # 先插入到列表中
        the_idx:int = 0
        the_item:Dict[Literal['addr_range', 'insns'], Union[Tuple[int, int], List[CsInsn]]] = {'addr_range': (insns[0].address, insns[-1].address+insns[-1].size), 'insns': insns}
        if after_idx >= 0: 
            Cache.INSNS.insert(after_idx, the_item)
            the_idx = after_idx
            after_idx += 1
        else:
            Cache.INSNS.append(the_item)
            the_idx = len(Cache.INSNS)-1
        # 看看合并的情况
        # 如果和后面的紧挨着 那就和后面的合并
        if after_idx >= 0 and Cache.INSNS[the_idx]['addr_range'][1] == Cache.INSNS[after_idx]['addr_range'][0]:
            # 进行合并拼接
            Cache.INSNS[after_idx] = {'addr_range': (Cache.INSNS[the_idx]['addr_range'][0], Cache.INSNS[after_idx]['addr_range'][1]), 'insns': Cache.INSNS[the_idx]['insns']+Cache.INSNS[after_idx]['insns']}
            # 移除新增加的项
            Cache.INSNS.pop(the_idx)
        result = Cache.INSNS[the_idx]['insns']
        # 如果和前面的紧挨着 那就和前面的合并
        if before_idx >= 0 and Cache.INSNS[before_idx]['addr_range'][1] == Cache.INSNS[the_idx]['addr_range'][0]:
            # 进行合并拼接
            Cache.INSNS[before_idx] = {'addr_range': (Cache.INSNS[before_idx]['addr_range'][0], Cache.INSNS[the_idx]['addr_range'][1]), 'insns': Cache.INSNS[before_idx]['insns']+Cache.INSNS[the_idx]['insns']}
            # 移除新增加的项
            Cache.INSNS.pop(the_idx)
        return result


'''
定义一些异常
'''

class EmptyInsns(Exception):
    '''
    空指令序列
    '''
    pass

class UnknownIndirectJump(Exception):
    '''
    未知的间接跳转指令
    '''
    pass

class InvalidAddress(Exception):
    '''
    非法地址
    '''
    pass 

class InsnNotFound(Exception):
    '''
    目标指令找不到
    '''
    pass

class DisassemblyError(Exception):
    '''
    反汇编失败
    '''
    pass 


