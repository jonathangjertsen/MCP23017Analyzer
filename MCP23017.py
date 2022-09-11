from enum import Enum, auto
from dataclasses import dataclass
from saleae.analyzers import HighLevelAnalyzer, AnalyzerFrame, StringSetting, NumberSetting, ChoicesSetting
from saleae.data import GraphTime

START_ADDRESS = 0x20
N_ADDRESSES = 8

IOCON_BITS = {
    "INTPOL": 1,
    "ODR": 2,
    "HAEN": 3,
    "DISSLW": 4,
    "SEQOP": 5,
    "MIRROW": 6,
    "BANK": 7,
}

def iocon_bit_test(reg, string):
    return (reg & (1 << IOCON_BITS[string])) != 0

MAP = {
    0: {
        0x00: "IODIRA",
        0x01: "IODIRB",
        0x02: "IPOLA",
        0x03: "IPOLB",
        0x04: "GPINTENA",
        0x05: "GPINTENB",
        0x06: "DEFVALA",
        0x07: "DEFVALB",
        0x08: "INTCONA",
        0x09: "INTCONB",
        0x0a: "IOCON",
        0x0b: "IOCON",
        0x0c: "GPPUA",
        0x0d: "GPPUB",
        0x0e: "INTFA",
        0x0f: "INTFB",
        0x10: "INTCAPA",
        0x11: "INTCAPB",
        0x12: "GPIOA",
        0x13: "GPIOB",
        0x14: "OLATA",
        0x15: "OLATB",
    },
    1: {
        0x00: "IODIRA",
        0x10: "IODIRB",
        0x01: "IPOLA",
        0x11: "IPOLB",
        0x02: "GPINTENA",
        0x12: "GPINTENB",
        0x03: "DEFVALA",
        0x13: "DEFVALB",
        0x04: "INTCONA",
        0x14: "INTCONB",
        0x05: "IOCON",
        0x15: "IOCON",
        0x06: "GPPUA",
        0x16: "GPPUB",
        0x07: "INTFA",
        0x17: "INTFB",
        0x08: "INTCAPA",
        0x18: "INTCAPB",
        0x09: "GPIOA",
        0x19: "GPIOB",
        0x0a: "OLATA",
        0x1a: "OLATB",
    }
}


class LLState(Enum):
    IDLE  = auto()
    START = auto()
    DATA  = auto()


@dataclass
class LLFrame:
    start_time: GraphTime
    end_time: GraphTime
    data: bytearray
    read: bool
    address: int


class MCP23017(HighLevelAnalyzer):
    result_types = {
        "MCP23017": {
            "format": "Addr. {{data.address}}: {{data.read}} {{{data.data}}}"
        },
    }

    iocon_bank_setting = ChoicesSetting(label='Initial state of IOCON.BANK', choices=["0", "1"])
    show_bits_setting  = ChoicesSetting(label='Show individual bits of IOCON register', choices=["0", "1"])

    def __init__(self):
        self.iocon_bank_setting = int(self.iocon_bank_setting)
        self.show_bits_setting = int(self.show_bits_setting)
        self.IOCON_BANK = {
            addr: self.iocon_bank_setting
            for addr in range(START_ADDRESS, START_ADDRESS + N_ADDRESSES)
        }
        self.reset()

    def reset(self):
        self.state      = LLState.IDLE
        self.address    = None
        self.data       = bytearray()
        self.start_time = None
        self.read       = False

    def ll_fsm(self, frame):
        out = None
        if self.state == LLState.IDLE:
            if frame.type == "start":
                self.state = LLState.START
                self.start_time = frame.start_time
                return out
        elif self.state == LLState.START:
            if frame.type == "address" and frame.data["ack"]:
                self.read |= frame.data["read"]
                self.address = frame.data["address"][0]
                if START_ADDRESS <= self.address < START_ADDRESS + N_ADDRESSES:
                    self.state = LLState.DATA
                    return out
        elif self.state == LLState.DATA:
            if frame.type == "data":
                self.data.extend(frame.data["data"])
                return out
            elif frame.type == "start":
                self.state = LLState.START
                return out
            elif frame.type == "stop":
                self.state = LLState.IDLE
                out = LLFrame(
                    start_time=self.start_time,
                    end_time=frame.end_time,
                    read=self.read,
                    data=self.data,
                    address=self.address
                )
        self.reset()
        return out

    def decode(self, frame: AnalyzerFrame):
        if i2c_frame := self.ll_fsm(frame):
            start_reg = i2c_frame.data[0]
            iocon_bank = self.IOCON_BANK[i2c_frame.address]
            data = []
            for regaddr, regval in enumerate(i2c_frame.data[1:], start=start_reg):
                reg_name = MAP[iocon_bank].get(regaddr, f"{regaddr:#04x}?")
                if reg_name == "IOCON":
                    if not i2c_frame.read:
                        self.IOCON_BANK[i2c_frame.address] = iocon_bit_test(regval, "BANK")
                    if self.show_bits_setting:
                        data.extend(f"{key}={iocon_bit_test(regval, key)}" for key in IOCON_BITS)
                    else:
                        data.append(f"{reg_name}={regval:#04x}")
                else:
                    data.append(f"{reg_name}={regval:#04x}")
            return AnalyzerFrame(
                "MCP23017",
                i2c_frame.start_time,
                i2c_frame.end_time,
                {
                    "address": i2c_frame.address,
                    "read": "read" if i2c_frame.read else "write",
                    "data": "; ".join(data),
                }
            )
        return None
