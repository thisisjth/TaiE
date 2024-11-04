#!python3.9
# -*- encoding: utf-8 -*-

import math, string, random
from angr import SimState
from typing import Callable, Iterable, List, TypeVar

from capstone import CsInsn

T =TypeVar("T")

class Helper:
    '''
    辅助函数工具类
    '''
    
    @classmethod
    def to_int(cls, s:str) -> int:
        '''
        将字符串转为数字。支持0xABCD ABCDh 1234 类型
        '''
        a:int = 1
        # 特殊处理arm中的常量 
        s = s.strip().lstrip('#')
        if s.startswith('-'):
            a = -1
            s = s[1:]
        if s.startswith('0x'): return int(s, 16)*a
        if s.endswith('h') or s.endswith('H'): return int('0x'+s[:-1], 16)*a
        return int(s)*a
    
    @classmethod
    def is_int(cls, s:str) -> bool:
        '''
        判断是否可被转为数值
        '''
        # 特殊处理arm中的常量 
        s = s.strip().lstrip('#')
        try:
            tmp:int = cls.to_int(s)
            return True
        except Exception:
            return False

    @classmethod
    def align(cls, n:int, a:int=4) -> int:
        return (n//a)*a

    @classmethod
    def visible_char(cls, s:int) -> bool:
        '''
        判断一个字节是否为可见字符
        '''
        # 一个字节也就无所谓大小端
        return chr(s) in string.printable
    
    @classmethod
    def first(cls, func:Callable[[T], bool], iter1:Iterable[T], start_at:int=0) -> T:
        for i in range(start_at, len(iter1)):
            if func(iter1[i]):
                return iter1[i]
        return None

    @classmethod
    def first_index(cls, func:Callable[[T], bool], iter1:Iterable[T], excludes:Iterable[int]=[], start_at:int=0) -> int:
        for i in range(start_at, len(iter1)):
            if func(iter1[i]) and i not in excludes: return i
        return -1

    @classmethod
    def last(cls, func:Callable[[T], bool], iter1:Iterable[T], start_at:int=math.inf) -> T:
        for i in range(min(len(iter1)-1, start_at), -1, -1):
            if func(iter1[i]):
                return iter1[i]
        return None
    
    @classmethod
    def last_index(cls, func:Callable[[T], bool], iter1:Iterable[T], excludes:Iterable[int]=[], start_at:int=math.inf) -> int:
        for i in range(min(len(iter1)-1, start_at), -1, -1):
            if func(iter1[i]) and i not in excludes: return i
        return -1

    @classmethod
    def index(cls, func:Callable[[T], bool], iter1:Iterable[T]) -> int:
        for i in range(len(iter1)):
            if func(iter1[i]):
                return i
        return -1
    
    @classmethod
    def indexes(cls, func:Callable[[T], bool], iter1:Iterable[T]) -> List[int]:
        return list(filter(lambda i: func(iter1[i]), range(len(iter1))))
    
    @classmethod
    def max(cls, func:Callable[[T], T], iter1:Iterable[T]) -> T:
        return sorted(iter1, key=func)[-1]
    
    @classmethod
    def count(cls, func:Callable[[T], bool], iter1:Iterable[T]) -> int:
        count:int = 0
        for i in iter1:
            if func(i): count += 1
        return count
    
    @classmethod
    def any(cls, func:Callable[[T], bool], iter1:Iterable[T]) -> bool:
        return any(map(func, iter1))
    
    @classmethod
    def in_range(cls, n:int, m:int, x:int) -> bool:
        '''
        判断是否属于 [m, x)
        '''
        return n >= m and n < x
    
    @classmethod
    def merge(cls, *args:List[T]) -> List[T]:
        '''
        合并多个列表
        '''
        result:List[T] = []
        for l in args: result.extend(l)
        return result
    
    @classmethod
    def rnd_str(cls, n:int=4, chars:str=string.ascii_letters) -> str:
        '''
        一定长度的随机字符串
        '''
        return ''.join(random.choices(chars, k=n))

    @classmethod
    def history(cls, state:SimState) -> List[int]:
        '''
        Extract Block Address In Execution History
        '''
        addrs = [state.addr]
        cs = state.history
        while cs.addr:
            addrs.append(cs.addr)
            cs = cs.parent
        return addrs[::-1]
    
    @classmethod
    def fmt_insn(cls, insn:CsInsn) -> str:
        '''
        Print An Instruction In Format
        '''
        return f'{hex(insn.address)}\t{insn.mnemonic}\t{insn.op_str}'
    