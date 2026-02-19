import enum


class EnvironmentType(enum.Enum):
    UNKNOWN = -1
    IDA = 0
    MODERN_IDA = 1
    GHIDRA = 2
