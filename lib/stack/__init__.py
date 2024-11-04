#!python3.9
# -*- encoding: utf-8 -*-

from abc import abstractclassmethod


class Stack:
    @abstractclassmethod
    def is_satisfied(self) -> int: pass
