class AddressRange:
    def __init__(self, start: int, end: int):
        self.start_addr = start
        self.end_addr = end

    def contains_address(self, addr: int) -> bool:
        return self.start_addr <= addr < self.end_addr

    def get_size(self) -> int:
        return self.end_addr - self.start_addr
