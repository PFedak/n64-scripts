import argparse
import binascii
import collections
import enum
import math
import sys

RomConfig = collections.namedtuple("RomConfig", ["header_length", "ram_offset"])

mario_config = RomConfig(header_length=0x40, ram_offset=0x245000)


class DiffFormatter:
    def __init__(self, max_run, max_gap, formatter, out):
        self.run = max_run
        self.gap = max_gap
        self.formatter = formatter
        self.out = out
        self.buffer = []
        self.match = []
        self.start = 0

    def add_diff(self, address, byte):
        if not self.buffer:
            self.start = address
            self.buffer = [byte]
            self.match = []
        else:
            if self.match:
                self.buffer += self.match
                self.match = []
            self.buffer.append(byte)
            if len(self.buffer) == self.run:
                self.flush()

    def add_same(self, byte):
        if self.buffer:
            if len(self.match) < self.gap:
                self.match.append(byte)
            else:
                self.flush()

    def flush(self):
        if self.buffer:
            self.out.write(self.formatter(self.start, bytes(self.buffer)))
            self.buffer = []
            self.match = []


def gameshark_format(out):
    return DiffFormatter(
        max_run=2,
        max_gap=0,
        formatter=lambda addr, data: "A{}{:06X} {:04X}\n".format(
            len(data) - 1, addr, int.from_bytes(data, byteorder="big")
        ),
        out=out,
    )


def stroop_format(out):
    return DiffFormatter(
        max_run=math.inf,
        max_gap=16,
        formatter=lambda addr, data: "80{:06X}: {}\n".format(
            addr, str(binascii.hexlify(data), "ascii")
        ),
        out=out,
    )


class ByteSwapper:
    def __init__(self, f):
        self.file = f
        self.buffer = b""

    def read(self, n):
        assert n == 1
        if self.buffer:
            x = self.buffer
            self.buffer = b""
            return x
        x = self.file.read(2)
        if len(x) < 2:
            return b""  # silently ignore odd length for now
        self.buffer = x[:1]
        return x[1:]

    def seek(self, d, w):
        self.file.seek(d, w)
        if self.file.tell() % 2 == 0:
            self.buffer = b""
        else:
            self.file.seek(-1, 1)
            self.read(1)


def ordered_file(f):
    magic = f.read(4)
    f.seek(0, 0)
    if len(magic) < 4:
        raise ValueError("File way too short")
    if magic[0] == 0x80:
        return f
    if magic[0] == 0x37:
        return ByteSwapper(f)


def compute_diff(base, hack, diff, rom_config):
    base = ordered_file(base)
    hack = ordered_file(hack)
    base.seek(rom_config.header_length, 0)
    hack.seek(rom_config.header_length, 0)

    address = rom_config.header_length + rom_config.ram_offset

    while True:
        b, h = base.read(1), hack.read(1)
        if not b or not h:
            if b or h:
                print("File length mismatch, ending early", file=sys.stderr)
            break
        if b != h:
            diff.add_diff(address, h[0])
        else:
            diff.add_same(h[0])
        address += 1
    diff.flush()


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument(
        "--base", type=str, required=True, help="Base file to compare against"
    )
    ap.add_argument(
        "--hack", type=str, required=True, help="Hack file to create a patch for"
    )
    ap.add_argument(
        "--stroop",
        dest="fmt",
        action="store_const",
        default=gameshark_format,
        const=stroop_format,
        help="Generate a diff in STROOP's .hck format",
    )
    ap.add_argument("--header", type=int, help="Length of header to ignore (in bytes)")
    args = ap.parse_args()
    base = open(args.base, "rb")
    hack = open(args.hack, "rb")

    compute_diff(base, hack, args.fmt(sys.stdout), mario_config)

