import logging
from UniRE.interfaces.IReTool import IReTool
from UniRE.types.EnvironmentType import EnvironmentType


def use_default_logging_config():
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s | %(name)s] %(message)s",
        datefmt="%H:%M:%S",
    )


def detect_environment() -> EnvironmentType:
    try:
        import ida_ida

        return EnvironmentType.MODERN_IDA
    except ImportError:
        pass

    try:
        import ida_kernwin

        return EnvironmentType.IDA
    except ImportError:
        pass

    try:
        from ghidra.app.script import GhidraScript

        return EnvironmentType.GHIDRA
    except ImportError:
        pass

    return EnvironmentType.UNKNOWN


def is_default_function_name(tool: IReTool, name: str) -> bool:
    if tool.environment_type == EnvironmentType.IDA:
        return name.startswith(("sub_", "nullsub_", "j_"))

    if tool.environment_type == EnvironmentType.GHIDRA:
        return name.startswith(("FUN_"))

    return False


def address_to_hex(addr: int) -> str:
    return f"0x{hex(addr)[2:].zfill(16)}"
