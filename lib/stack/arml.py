#!python3.9
# -*- encoding: utf-8 -*-

from lib import Helper
from lib.stack import Stack
from typing import List, Dict, Union, Literal
from config.constant import STACK_SATISFIED, STACK_UNINITIALIZED, STACK_UNSATISFIED

class ArmLStack(Stack):
    def __init__(self, full_or_empty:Literal['f', 'e']='f', ace_or_desc:Literal['a', 'd']='d') -> None:
        # 虚拟空间
        self.space:List[str] = ['' for i in range(1000)]
        self.sp:int = 500
        self.fp:int = None
        self.full_or_empty:Literal['f', 'e'] = full_or_empty
        self.ace_or_desc:Literal['a', 'd'] = ace_or_desc
        self.regs:Dict[str, Union[str, int]] = {
            'r0': 'r0',
            'r1': 'r1',
            'r2': 'r2',
            'r3': 'r3',
            'r4': 'r4',
            'r5': 'r5',
            'r6': 'r6',
            'r7': 'r7',
            'r8': 'r8',
            'r9': 'r9',
            'r10': 'r10',
            'r11': 'r11',
            'r12': 'r12',
            'r13': 'r13',
            'r14': 'r14',
            'r15': 'r15',
            'a1': 'a1',
            'a2': 'a2',
            'a3': 'a3',
            'a4': 'a4',
            'v1': 'v1',
            'v2': 'v2',
            'v3': 'v3',
            'v4': 'v4',
            'v5': 'v5',
            'v6': 'v6',
            'sb': 'sb',
            'v7': 'v7',
            'sl': 'sl',
            'v8': 'v8',
            'sp': self.sp,
            'fp': self.fp,
            'pc': 'pc',
            'lr': 'lr',
            'ip': 'ip'
        }
        # 用于保存原始值
        self.orig_regs:Dict[str, Union[str, int]] = {
            'sp': self.sp,
            'fp': self.fp
        }
        self.initialized:bool = False
    
    def stm(self, values:List[str], 
                base_reg:Literal['sp', 'fp'],
                full_or_empty:Literal['f', 'e']='f', 
                ace_or_desc:Literal['a', 'd']='d',
                write_back:bool = False
            ):
        self.before(full_or_empty=full_or_empty, ace_or_desc=ace_or_desc)
        new_values:List[str] = values[::-1] if ace_or_desc == 'd' else values
        typ:str = f'{full_or_empty}{ace_or_desc}'
        base_addr:int = self.regs[base_reg]
        if not isinstance(base_addr, int): return
        if typ == 'ea':
            for v in new_values:
                for i in range(base_addr, base_addr+4):
                    while i >= len(self.space): self.space.append('')
                    self.space[i] = v if v not in self.regs else self.regs[v]
                base_addr += 4
        elif typ == 'fa':
            for v in new_values:
                base_addr += 4
                for i in range(base_addr, base_addr+4):
                    while i >= len(self.space): self.space.append('')
                    self.space[i] = v if v not in self.regs else self.regs[v]
        elif typ == 'ed':
            for v in new_values:
                # for i in range(base_addr-4, base_addr):
                for i in range(base_addr, base_addr+4):
                    self.space[i] = v if v not in self.regs else self.regs[v]
                base_addr -= 4
        elif typ == 'fd':
            for v in new_values:
                base_addr -= 4
                # for i in range(base_addr-4, base_addr):
                for i in range(base_addr, base_addr+4):
                    self.space[i] = v if v not in self.regs else self.regs[v]
        if not write_back: return
        self.regs[base_reg] = base_addr
        setattr(self, base_reg, base_addr)

    def ldm(self, values:List[str], 
                base_reg:Literal['sp', 'fp'],
                full_or_empty:Literal['f', 'e']='f', 
                ace_or_desc:Literal['a', 'd']='d',
                write_back:bool = False
            ):
        self.before(full_or_empty=full_or_empty, ace_or_desc=ace_or_desc)
        new_values:List[str] = values[::-1] if ace_or_desc == 'a' else values
        typ:str = f'{full_or_empty}{ace_or_desc}'
        base_addr:int = self.regs[base_reg]
        if not isinstance(base_addr, int): return
        if typ == 'ea':
            for v in new_values:
                base_addr -= 4
                for i in range(base_addr, base_addr+4):
                    while i >= len(self.space): self.space.append('')
                    self.regs[v] = self.space[i]
                    if v in ['sp', 'fp']: setattr(self, v, self.space[i])
                if v not in self.orig_regs: self.orig_regs[v] = self.regs[v]
        elif typ == 'fa':
            for v in new_values:
                for i in range(base_addr, base_addr+4):
                    while i >= len(self.space): self.space.append('')
                    self.regs[v] = self.space[i]
                    if v in ['sp', 'fp']: setattr(self, v, self.space[i])
                if v not in self.orig_regs: self.orig_regs[v] = self.regs[v]
                base_addr -= 4
        elif typ == 'ed':
            for v in new_values:
                base_addr += 4
                # for i in range(base_addr-4, base_addr):
                for i in range(base_addr, base_addr+4):
                    self.regs[v] = self.space[i]
                    if v in ['sp', 'fp']: setattr(self, v, self.space[i])
                if v not in self.orig_regs: self.orig_regs[v] = self.regs[v]
        elif typ == 'fd':
            for v in new_values:
                # for i in range(base_addr-4, base_addr):
                for i in range(base_addr, base_addr+4):
                    self.regs[v] = self.space[i]
                    if v in ['sp', 'fp']: setattr(self, v, self.space[i])
                if v not in self.orig_regs: self.orig_regs[v] = self.regs[v]
                base_addr += 4
        if not write_back: return
        self.regs[base_reg] = base_addr
        setattr(self, base_reg, base_addr)

    def mov(self, frm:str, to:str,
                full_or_empty:Literal['f', 'e']='f', 
                ace_or_desc:Literal['a', 'd']='d'
            ):
        self.before(full_or_empty=full_or_empty, ace_or_desc=ace_or_desc)
        if frm in self.regs: self.regs[to] = self.regs[frm]
        elif Helper.is_int(frm): self.regs[to] = Helper.to_int(frm)
        else: self.regs[to] = frm
        if to in ['sp', 'fp']: setattr(self, to, self.regs[to])
        if to not in self.orig_regs: self.orig_regs[to] = self.regs[to]
    
    def str(self, frm:str, to:str, offset:str='0', step:str='0',
                full_or_empty:Literal['f', 'e']='f', 
                ace_or_desc:Literal['a', 'd']='d',
                write_back:bool=False
            ):
        self.before(full_or_empty=full_or_empty, ace_or_desc=ace_or_desc)
        v:int = Helper.to_int(offset) if Helper.is_int(offset) else self.regs[offset]
        pos:int = self.regs[to] + v if isinstance(self.regs[to], int) else f'[{self.regs[to]}+{v}]'
        if isinstance(pos, int): 
            for i in range(pos, pos+4): self.space[i] = self.regs[frm]
        if not write_back: return
        self.regs[to] += Helper.to_int(step) if Helper.is_int(step) else self.regs[step]
        if to in ['sp', 'fp']: setattr(self, to, self.regs[to])
        if to not in self.orig_regs: self.orig_regs[to] = self.regs[to]
    
    def ldr(self, frm:str, to:str, offset:str='0', step:str='0',
                full_or_empty:Literal['f', 'e']='f', 
                ace_or_desc:Literal['a', 'd']='d',
                write_back:bool=False
            ):
        self.before(full_or_empty=full_or_empty, ace_or_desc=ace_or_desc)
        v:int = Helper.to_int(offset) if Helper.is_int(offset) else self.regs[offset]
        pos:int = self.regs[frm] + v if isinstance(self.regs[frm], int) else f'[{self.regs[frm]}+{v}]'
        self.regs[to] = self.space[pos] if isinstance(pos, int) else pos
        if not write_back: return
        self.regs[frm] += Helper.to_int(step) if Helper.is_int(step) else self.regs[step]
        if frm in ['sp', 'fp']: setattr(self, frm, self.regs[frm])
        if frm not in self.orig_regs: self.orig_regs[frm] = self.regs[frm]
    
    def sub(self, src:str, dst:str, n:str,
                full_or_empty:Literal['f', 'e']='f', 
                ace_or_desc:Literal['a', 'd']='d'
            ):
        self.before(full_or_empty=full_or_empty, ace_or_desc=ace_or_desc)
        v:int = (Helper.to_int(n) if Helper.is_int(n) else self.regs[n])
        self.regs[dst] = (self.regs[src] - v) if isinstance(self.regs[src], int) else f'{self.regs[src]}-{v}'
        if dst in ['sp', 'fp']: setattr(self, dst, self.regs[dst])
        if dst not in self.orig_regs: self.orig_regs[dst] = self.regs[dst]
    
    def add(self, src:str, dst:str, n:str,
                full_or_empty:Literal['f', 'e']='f', 
                ace_or_desc:Literal['a', 'd']='d'
            ):
        self.before(full_or_empty=full_or_empty, ace_or_desc=ace_or_desc)
        v:int = (Helper.to_int(n) if Helper.is_int(n) else self.regs[n])
        self.regs[dst] = (self.regs[src] + v) if isinstance(self.regs[src], int) else f'{self.regs[src]}+{v}'
        if dst in ['sp', 'fp']: setattr(self, dst, self.regs[dst])
        if dst not in self.orig_regs: self.orig_regs[dst] = self.regs[dst]
    
    def before(self, full_or_empty:Literal['f', 'e']='f', ace_or_desc:Literal['a', 'd']='d'):
        self.initialized = True

    def is_satisfied(self) -> int:
        satisfied:int = STACK_UNSATISFIED
        # pc=lr r0用于返回值
        if self.regs['pc'] in ['pc', 'lr'] and not Helper.any(lambda r: self.regs[r] != self.orig_regs[r], ['sp', 'fp']):
            satisfied = STACK_UNINITIALIZED if not self.initialized else STACK_SATISFIED
        return satisfied

