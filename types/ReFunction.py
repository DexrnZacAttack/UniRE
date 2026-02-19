from typing import override
import UniRE
from UniRE.types.ReSymbol import ReSymbol


class ReFunction(ReSymbol):
    tail_count: int

    def __init__(self, name: str, addr: int, end_addr: int, tail_count: int = 0):
        super().__init__(name, addr, end_addr)
        self.tail_count = tail_count

    @override
    def rename(self, tool: "UniRE.interfaces.IReTool", name: str) -> bool:
        """Renames this function to the given name"""
        return tool.rename_function(self.start_addr, name)

    @override
    def delete(self, tool: "UniRE.interfaces.IReTool") -> bool:
        """Deletes this function"""
        return tool.delete_function(self.start_addr)

    def set_end_address(self, tool: "UniRE.interfaces.IReTool", end_addr: int) -> bool:
        """Sets the end address of this function"""
        return tool.set_function_end_address(self.start_addr, end_addr)
