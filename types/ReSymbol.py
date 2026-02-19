from abc import ABC
import UniRE
from UniRE.types.AddressRange import AddressRange


class ReSymbol(ABC, AddressRange):
    name: str

    def __init__(self, name: str, addr: int, end_addr: int):
        super().__init__(addr, end_addr)

        self.name = name

    def rename(self, tool: "UniRE.interfaces.IReTool", name: str) -> bool:
        """Renames this symbol to the given name"""
        return tool.rename_symbol(self.start_addr, name)

    def delete(self, tool: "UniRE.interfaces.IReTool") -> bool:
        """Deletes this symbol"""
        return tool.delete_symbol(self.start_addr)
