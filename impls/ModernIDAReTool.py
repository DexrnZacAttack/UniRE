import logging
from pathlib import Path

from UniRE.impls.IDAReTool import IDAReTool
from UniRE.interfaces.IReTool import IReTool
from UniRE.types.ReSymbol import ReSymbol
from UniRE.types.ReFunction import ReFunction
from UniRE.types.EnvironmentType import EnvironmentType

from typing import override

from UniRE.types.ReSection import ReSection
import ida_kernwin
import idc
import idautils
import idaapi
import ida_ida


class ModernIDAReTool(IDAReTool):
    def __init__(self):
        super().__init__()

        self.environment_type = EnvironmentType.MODERN_IDA

        self._logger = logging.getLogger(f"ReTool.{self.environment_type.name}")

    @override
    def get_minimum_address(self) -> int:
        return ida_ida.inf_get_min_ea()

    @override
    def get_maximum_address(self) -> int:
        return ida_ida.inf_get_max_ea()
