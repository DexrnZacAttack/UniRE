# Provides a common interface for functions that both RE tools implement
# @author Dexrn ZacAttack

from abc import ABC, abstractmethod
from enum import Enum
import logging
from pathlib import Path
from UniRE.AbstractCallException import AbstractCallException
from UniRE.types.AddressRange import AddressRange
from UniRE.types.ReSymbol import ReSymbol
from UniRE.types.ReSection import ReSection
from UniRE.types.EnvironmentType import EnvironmentType
from UniRE.types.ReFunction import ReFunction


class IReTool(ABC):
    environment_type: EnvironmentType
    _logger: logging.Logger

    def __init__(self, env: EnvironmentType):
        self.environment_type = env

        self._logger = logging.getLogger(env.name)

    @abstractmethod
    def rename_symbol(self, addr: int, name: str) -> bool:
        """Renames a symbol"""
        raise AbstractCallException()

    @abstractmethod
    def rename_function(self, addr: int, name: str) -> bool:
        """Renames a function"""
        raise AbstractCallException()

    @abstractmethod
    def rename_section(self, section: str, name: str) -> bool:
        """Renames a section"""
        raise AbstractCallException()

    @abstractmethod
    def set_function_end_address(self, func: ReFunction, end_addr: int) -> bool:
        """Sets the end address of a function"""
        raise AbstractCallException()

    @abstractmethod
    def set_function_end_address(self, addr: int, end_addr: int) -> bool:
        """Sets the end address of a function"""
        raise AbstractCallException()

    @abstractmethod
    def get_function_at_address(self, addr: int) -> ReFunction | None:
        """Gets a function at the given address"""
        raise AbstractCallException()

    @abstractmethod
    def get_symbol_at_address(self, addr: int) -> ReSymbol | None:
        """Gets the primary symbol at the given address"""
        raise AbstractCallException()

    @abstractmethod
    def get_section_at_address(self, addr: int) -> ReSection | None:
        """Gets the section that contains the given address"""
        raise AbstractCallException()

    @abstractmethod
    def get_section_by_name(self, name: str) -> ReSection | None:
        """Gets a section by its name"""
        raise AbstractCallException()

    @abstractmethod
    def get_all_functions(self) -> dict[int, ReFunction]:
        """Returns all functions"""
        raise AbstractCallException()

    @abstractmethod
    def get_all_data_symbols(self) -> dict[int, ReSymbol]:
        """Returns all data symbols"""
        raise AbstractCallException()

    @abstractmethod
    def get_all_sections(self) -> dict[int, ReSection]:
        """Returns all sections"""
        raise AbstractCallException()

    @abstractmethod
    def get_minimum_address(self) -> int:
        """Gets the minimum (base) address of the binary"""
        raise AbstractCallException()

    @abstractmethod
    def get_maximum_address(self) -> int:
        """Gets the maximum address of the binary"""
        raise AbstractCallException()

    @abstractmethod
    def create_function(self, range: AddressRange) -> ReFunction | None:
        """Creates a function with the given address range"""
        raise AbstractCallException()

    @abstractmethod
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
        """Creates a section with the given name, address range, and flags"""
        raise AbstractCallException()

    @abstractmethod
    def delete_function(self, addr: int) -> bool:
        """Deletes a function"""
        raise AbstractCallException()

    @abstractmethod
    def delete_symbol(self, addr: int) -> bool:
        """Deletes a symbol"""
        raise AbstractCallException()

    @abstractmethod
    def delete_section(self, name: str) -> bool:
        """Deletes a section by its name"""
        raise AbstractCallException()

    @abstractmethod
    def delete_section_by_address(self, addr: int) -> bool:
        """Deletes a section by it's address"""
        raise AbstractCallException()

    @abstractmethod
    def open_file_picker(self, title: str, allowed_files: str = "*.*") -> Path | None:
        """Opens a file picker dialog and returns the selected file path (or None if cancelled)"""
        raise AbstractCallException()
