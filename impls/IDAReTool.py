from pathlib import Path

from UniRE.interfaces.IReTool import IReTool
from UniRE.types.AddressRange import AddressRange
from UniRE.types.ReSymbol import ReSymbol
from UniRE.types.ReFunction import ReFunction
from UniRE.types.EnvironmentType import EnvironmentType

from typing import override

from UniRE.types.ReSection import ReSection
import ida_kernwin
import idc
import idautils
import idaapi
import ida_bytes
import ida_segment
import ida_loader


IDA_BAD_ADDR = idaapi.BADADDR


class IDAReTool(IReTool):
    def __init__(self):
        super().__init__(EnvironmentType.IDA)

    @override
    def rename_symbol(self, addr: int, name: str) -> bool:
        return idc.set_name(addr, name, idc.SN_CHECK)

    @override
    def rename_function(self, addr: int, name: str) -> bool:
        return self.rename_symbol(addr, name)

    @override
    def rename_section(self, section: str, name: str) -> bool:
        seg = idaapi.get_segm_by_name(section)
        if seg:
            return idaapi.set_segm_name(seg, name)

        return False

    @override
    def set_function_end_address(self, addr: int, end_addr: int) -> bool:
        return idc.set_func_end(addr, end_addr)

    @override
    def get_function_at_address(self, addr: int) -> ReFunction | None:
        func = idaapi.get_func(addr)
        if func:
            return ReFunction(
                func.name, addr, idc.get_func_attr(addr, idc.FUNCATTR_END), func.tailqty
            )

        return None

    @override
    def get_symbol_at_address(self, addr: int) -> ReSymbol | None:
        name = idc.get_name(addr)
        if name:
            return ReSymbol(name, addr, addr + idc.get_item_size(addr))

        return None

    @override
    def get_section_at_address(self, addr: int) -> ReSection | None:
        real_addr = ida_loader.get_fileregion_offset(addr)
        if real_addr == -1:
            real_addr = None

        seg = idaapi.getseg(addr)
        return ReSection(
            idc.get_segm_name(addr),
            seg.start_ea,
            seg.end_ea,
            real_addr,
            False,
            seg.perm & ida_segment.SEGPERM_READ,
            seg.perm & ida_segment.SEGPERM_WRITE,
            seg.perm & ida_segment.SEGPERM_EXEC,
            False,
            False,
        )

    @override
    def get_section_by_name(self, name: str) -> ReSection | None:
        seg = idaapi.get_segm_by_name(name)
        if seg:
            real_addr = ida_loader.get_fileregion_offset(seg.start_ea)
            if real_addr == -1:
                real_addr = None

            return ReSection(
                idc.get_segm_name(seg.start_ea),
                seg.start_ea,
                seg.end_ea,
                real_addr,
                False,
                seg.perm & ida_segment.SEGPERM_READ,
                seg.perm & ida_segment.SEGPERM_WRITE,
                seg.perm & ida_segment.SEGPERM_EXEC,
                False,
                False,
            )

        return None

    @override
    def get_all_functions(self) -> dict[int, ReFunction]:
        f = {}
        for func_addr in idautils.Functions():
            f[func_addr] = self.get_function_at_address(func_addr)

        return f

    @override
    def get_all_data_symbols(self) -> dict[int, ReSymbol]:
        seg = self.get_section_by_name(".bss")

        s = {}

        for ea, sym in idautils.Names():
            if seg.contains_addr(ea):
                if not sym:
                    continue

                s[ea] = ReSymbol(sym, ea, ea + idc.get_item_size(ea))

        return s

    @override
    def get_all_sections(self) -> dict[int, ReSection]:
        sections = {}
        for addr in idautils.Segments():
            seg = idaapi.getseg(addr)

            real_addr = ida_loader.get_fileregion_offset(seg.start_ea)
            if real_addr == -1:
                real_addr = None

            sections[addr] = ReSection(
                idc.get_segm_name(addr),
                seg.start_ea,
                seg.end_ea,
                real_addr,
                False,
                seg.perm & ida_segment.SEGPERM_READ,
                seg.perm & ida_segment.SEGPERM_WRITE,
                seg.perm & ida_segment.SEGPERM_EXEC,
                False,
                False,
            )

        return sections

    @override
    def get_minimum_address(self) -> int:
        return idaapi.cvar.inf.min_ea

    @override
    def get_maximum_address(self) -> int:
        return idaapi.cvar.inf.max_ea

    @override
    def create_section(
        self,
        name: str,
        range: AddressRange,
        real_addr: int | None = None,
        overlay: bool = False,
        readable: bool = True,
        writable: bool = True,
        executable: bool = False,
        volatile: bool = False,
        artificial: bool = False,
    ) -> ReSection | None:
        perm = 0
        if readable:
            perm |= ida_segment.SEGPERM_READ
        if writable:
            perm |= ida_segment.SEGPERM_WRITE
        if executable:
            perm |= ida_segment.SEGPERM_EXEC

        if ida_segment.add_segm(0, range.start_addr, range.end_addr, name, perm):
            real_addr = ida_loader.get_fileregion_offset(range.start_addr)
            if real_addr == -1:
                real_addr = None

            return ReSection(
                name,
                range.start_addr,
                range.end_addr,
                real_addr,
                False,
                readable,
                writable,
                executable,
                False,
                False,
            )

        return None

    def create_function(self, range: AddressRange) -> ReFunction | None:
        if idc.add_func(range.start_addr, range.end_addr):
            f = self.get_function_at_address(range.start_addr)
            if f:
                if range.end_addr != idaapi.BADADDR:
                    idc.set_func_end(range.start_addr, range.end_addr)
                return f

        return None

    @override
    def delete_section(self, name) -> bool:
        seg = idaapi.get_segm_by_name(name)
        if seg:
            return ida_segment.del_segm(seg.start_ea, ida_segment.SEGMOD_KILL)

        return False

    @override
    def delete_section_by_address(self, addr: int) -> bool:
        return ida_segment.del_segm(addr, ida_segment.SEGMOD_KILL)

    @override
    def delete_function(self, addr: int) -> bool:
        return idc.del_func(addr)

    @override
    def delete_symbol(self, addr: int) -> bool:
        return ida_bytes.del_items(addr)

    @override
    def open_file_picker(self, title: str, allowed_files: str = "*.*") -> Path | None:
        return ida_kernwin.ask_file(1, allowed_files, title)
