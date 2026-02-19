from typing import override
import UniRE
from UniRE.types.ReSymbol import ReSymbol


class ReSection(ReSymbol):
    _flags: dict[str, bool]
    _real_addr: int | None = None  # sections can mirror the executable's data
    _overlay: bool = False

    def __init__(
        self,
        name: str,
        addr: int,
        end_addr: int,
        real_addr: int | None = None,
        overlay: bool = False,
        readable: bool = True,
        writable: bool = True,
        executable: bool = False,
        volatile: bool = False,
        artificial: bool = False,
    ):
        super().__init__(name, addr, end_addr)

        self._real_addr = real_addr
        self._overlay = overlay
        self._flags = {
            "readable": readable,
            "writable": writable,
            "executable": executable,
            "volatile": volatile,
            "artificial": artificial,
        }

    @override
    def rename(self, tool: "UniRE.interfaces.IReTool", name: str) -> bool:
        """Renames this section to the given name"""
        return tool.rename_section(self.name, name)

    @override
    def delete(self, tool: "UniRE.interfaces.IReTool") -> bool:
        """Deletes this section"""
        return tool.delete_section(self.name)
