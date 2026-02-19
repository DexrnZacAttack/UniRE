from abc import abstractmethod
from pathlib import Path
from typing import override

from UniRE import AbstractCallException
from UniRE.interfaces.IReTool import IReTool
from UniRE.types.AddressRange import AddressRange
from UniRE.types.ReFunction import ReFunction
from UniRE.types.EnvironmentType import EnvironmentType

from ghidra.app.script import GhidraScript
from ghidra.program.model.address import Address, AddressFactory
from ghidra.program.model.listing import FunctionManager
from ghidra.program.model.listing import Function
from ghidra.program.model.symbol import Symbol, SymbolTable
from ghidra.program.model.mem import Memory, MemoryBlock
from ghidra.program.model.listing import Program
from ghidra.program.model.symbol import SourceType
from ghidra.app.cmd.function import DeleteFunctionCmd
from ghidra.program.model.address import AddressSet
from ghidra.program.database.mem import AddressSourceInfo
from ghidra.util.task import TaskMonitor
from ghidra.app.util import MemoryBlockUtils 
from ghidra.app.util.bin import FileByteProvider
from ghidra.formats.gfilesystem import FSRL, FileSystemService
from java.nio.file import AccessMode
from java.io import File

from java.io import FileInputStream

import pyghidra

import sys

from UniRE.types.ReSection import ReSection
from UniRE.types.ReSymbol import ReSymbol
from UniRE.Util import address_to_hex


class GhidraReTool(IReTool):
    interpreter: GhidraScript
    program: Program
    function_manager: FunctionManager
    address_factory: AddressFactory
    symbol_table: SymbolTable
    memory: Memory

    def __init__(self):
        super().__init__(EnvironmentType.GHIDRA)

        try:
            import toml  # useless, but we need to tell the user to setup their env if it fails, we only do this because PyGhidra uses it's own venv
        except ImportError:
            raise ImportError(
                f"Please install 'toml' to use UniRE. You can do this by running '{sys.executable} -m pip install toml'."
            )

        pyghidra.start()
        self.interpreter = pyghidra.get_current_interpreter()
        self.program = self.interpreter.getCurrentProgram()
        self.function_manager = self.program.getFunctionManager()
        self.address_factory = self.program.getAddressFactory()
        self.symbol_table = self.program.getSymbolTable()
        self.memory = self.program.getMemory()

    @override
    def rename_symbol(self, addr: int, name: str) -> bool:
        sym: Symbol = self.symbol_table.createLabel(
            self.address_factory.getAddress(address_to_hex(addr)),
            name,
            SourceType.USER_DEFINED,
        )
        return sym is not None

    @override
    def rename_function(self, addr: int, name: str) -> bool:
        func: Function = self.function_manager.getFunctionAt(
            self.address_factory.getAddress(address_to_hex(addr))
        )
        if func:
            func.setName(name, SourceType.USER_DEFINED)
            return True

        return False

    @override
    def rename_section(self, section: str, name: str) -> bool:
        sect: MemoryBlock = self.memory.getBlock(section)
        if sect:
            sect.setName(name)
            return True

        return False

    @override
    def set_function_end_address(self, func: ReFunction, end_addr: int) -> bool:
        return self.set_function_end_address(func.start_addr, end_addr)

    @override
    def set_function_end_address(self, addr: int, end_addr: int) -> bool:
        func: Function = self.function_manager.getFunctionAt(
            self.address_factory.getAddress(address_to_hex(addr))
        )
        if func:
            func.setBody(
                AddressSet(
                    func.getEntryPoint(),
                    self.address_factory.getAddress(address_to_hex(end_addr - 1)),
                )
            )
            return True

        return False

    @override
    def get_function_at_address(self, addr: int) -> ReFunction | None:
        func: Function = self.function_manager.getFunctionAt(
            self.address_factory.getAddress(address_to_hex(addr))
        )
        if func:
            return ReFunction(
                func.getName(),
                func.getEntryPoint().getOffset(),
                func.getBody().getMaxAddress().getOffset() + 1,
            )

        return None

    @override
    def get_symbol_at_address(self, addr: int) -> ReSymbol | None:
        sym: Symbol = self.symbol_table.getPrimarySymbol(
            self.address_factory.getAddress(address_to_hex(addr))
        )
        if sym:
            return ReSymbol(
                sym.getName(),
                sym.getAddress().getOffset(),
                sym.getAddress().getOffset(),
            )

        return None

    @override
    def get_section_at_address(self, addr: int) -> ReSection | None:
        section: MemoryBlock = self.memory.getBlock(
            self.address_factory.getAddress(address_to_hex(addr))
        )
        if section:
            source: AddressSourceInfo = self.memory.getAddressSourceInfo(
                section.getStart()
            )

            return ReSection(
                section.getName(),
                section.getStart().getOffset(),
                section.getEnd().getOffset() + 1,
                source.fileOffset if source else None,
                section.isOverlay(),
                section.isRead(),
                section.isWrite(),
                section.isExecute(),
                section.isVolatile(),
                section.isArtificial(),
            )

        return None

    @override
    def get_section_by_name(self, name: str) -> ReSection | None:
        section = self.memory.getBlock(name)
        if section:
            return ReSection(
                name, section.getStart().getOffset(), section.getEnd().getOffset() + 1
            )

        return None

    @override
    def get_all_functions(self) -> dict[int, ReFunction]:
        f = {}
        for func in self.function_manager.getFunctions(True):
            func: Function
            f[func.getEntryPoint().getOffset()] = self.get_function_at_address(
                func.getEntryPoint().getOffset()
            )

        return f

    @override
    def get_all_data_symbols(self) -> dict[int, ReSymbol]:
        t: Memory = self.memory
        bss = t.getBlock(".bss")

        s = {}
        for data in self.program.getListing().getDefinedData(True):
            addr = data.getAddress()

            if bss.contains(addr):
                sym: Symbol = self.symbol_table.getPrimarySymbol(addr)
                if not sym or sym.getSource() == SourceType.DEFAULT:
                    continue

                s[sym.getAddress().getOffset()] = ReSymbol(
                    sym.getName(),
                    sym.getAddress().getOffset(),
                    sym.getAddress().getOffset(),
                )

        return s

    @override
    def get_all_sections(self) -> dict[int, ReSection]:
        s = {}
        for section in self.memory.getBlocks():
            section: MemoryBlock
            source: AddressSourceInfo = self.memory.getAddressSourceInfo(
                section.getStart()
            )

            s[section.getStart().getOffset()] = ReSection(
                section.getName(),
                section.getStart().getOffset(),
                section.getEnd().getOffset() + 1,
                source.fileOffset if source else None,
                section.isOverlay(),
                section.isRead(),
                section.isWrite(),
                section.isExecute(),
                section.isVolatile(),
                section.isArtificial(),
            )

        return s

    @override
    def get_minimum_address(self) -> int:
        return self.program.getMinAddress().getOffset()

    @override
    def get_maximum_address(self) -> int:
        return self.memory.getMaxAddress().getOffset()

    @override
    def create_function(self, range: AddressRange) -> ReFunction | None:
        addr = self.address_factory.getAddress(address_to_hex(range.start_addr))
        end = self.address_factory.getAddress(address_to_hex(range.end_addr - 1))

        if self.function_manager.createFunction(
            None, addr, AddressSet(addr, end), SourceType.USER_DEFINED
        ):
            return self.get_function_at_address(range.start_addr)

        return None

    @override
    def create_section(
        self,
        name: str,
        range: AddressRange,
        overlay: bool = False,
        readable: bool = True,
        writable: bool = True,
        executable: bool = False,
        volatile: bool = False,
        artificial: bool = False,
        real_addr: int | None = None,
    ) -> ReSection | None:
        start = self.address_factory.getAddress(address_to_hex(range.start_addr))
        size = range.end_addr - range.start_addr

        if real_addr is not None:
            # everytime I try to look for info on ghidra api I just get bombarded with results about random books that people are selling
            f = File(self.program.getExecutablePath())
            b = MemoryBlockUtils.createFileBytes(
                self.program,
                FileByteProvider(f, FileSystemService.getInstance().getLocalFSRL(f), AccessMode.READ),
                real_addr,
                size,
                TaskMonitor.DUMMY
            )

            sect: MemoryBlock = self.memory.createInitializedBlock(
                name, start, b, 0, size, overlay
            )
        else:
            sect: MemoryBlock = self.memory.createUninitializedBlock(
                name, start, size, overlay
            )

        if sect:
            sect.setRead(readable)
            sect.setWrite(writable)
            sect.setExecute(executable)
            sect.setVolatile(volatile)
            sect.setArtificial(artificial)

            return ReSection(
                name,
                range.start_addr,
                range.end_addr,
                overlay,
                readable,
                writable,
                executable,
                volatile,
                artificial,
                real_addr,
            )

        return None

    @override
    def delete_section(self, name) -> bool:
        sect: MemoryBlock = self.memory.getBlock(name)

        if sect:
            return self.memory.removeBlock(sect, TaskMonitor.DUMMY)

        return False

    def delete_section_by_address(self, addr: int) -> bool:
        sect: MemoryBlock = self.memory.getBlock(
            self.address_factory.getAddress(address_to_hex(addr))
        )
        if sect:
            return self.memory.removeBlock(sect, TaskMonitor.DUMMY)

        return False

    @override
    def delete_function(self, addr: int) -> bool:
        func: Function = self.function_manager.getFunctionAt(
            self.address_factory.getAddress(address_to_hex(addr))
        )
        return self.function_manager.removeFunction(func.getEntryPoint())

    @override
    def delete_symbol(self, addr: int) -> bool:
        sym: Symbol = self.symbol_table.getPrimarySymbol(
            self.address_factory.getAddress(address_to_hex(addr))
        )
        if sym:
            return sym.delete()

        return False

    @override
    def open_file_picker(self, title: str, allowed_files: str = "*.*") -> Path | None:
        return askFile(title, "Open").getPath() #untested lmao
