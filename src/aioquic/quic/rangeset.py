from bisect import bisect_left, bisect_right
from collections.abc import Iterable, Iterator, Sequence
from operator import attrgetter
from typing import Any, overload

# Ranges are stored in blocks which are split once they exceed twice this
# size. Inserting or removing a range then only moves the ranges of a single
# block, instead of all the ranges of a flat list. This keeps the cost of
# reassembling many small out-of-order CRYPTO or STREAM fragments linear in
# their number, instead of quadratic.
_BLOCK_SIZE = 128


class RangeSet(Sequence):
    def __init__(self, ranges: Iterable[range] = []):
        self.__blocks: list[list[range]] = []
        # The highest stop value of each block, used to locate the block which
        # may contain or follow a given value.
        self.__stops: list[int] = []
        self.__size = 0
        for r in ranges:
            assert r.step == 1
            self.add(r.start, r.stop)

    def add(self, start: int, stop: int | None = None) -> None:
        if stop is None:
            stop = start + 1
        assert stop > start

        # Find the first block containing a range which does not end before
        # the added range starts.
        b = bisect_left(self.__stops, start)

        # The added range is entirely after all existing ranges, append it.
        if b == len(self.__blocks):
            if self.__blocks:
                self.__blocks[-1].append(range(start, stop))
                self.__stops[-1] = stop
                self.__split_block(len(self.__blocks) - 1)
            else:
                self.__blocks.append([range(start, stop)])
                self.__stops.append(stop)
            self.__size += 1
            return

        block = self.__blocks[b]
        i = bisect_left(block, start, key=_stop)
        r = block[i]

        # The added range is entirely before the range, insert it.
        if stop < r.start:
            block.insert(i, range(start, stop))
            self.__size += 1
            self.__split_block(b)
            return

        # The added range touches existing ranges, merge them into a single
        # range. Ranges are disjoint and sorted, so the merged ranges are
        # contiguous in the block list.
        start = min(start, r.start)
        stop = max(stop, r.stop)
        removed = 1
        b2, i2 = b, i
        while True:
            next_b2, next_i2 = b2, i2 + 1
            if next_i2 == len(self.__blocks[next_b2]):
                if next_b2 + 1 == len(self.__blocks):
                    break
                next_b2 += 1
                next_i2 = 0
            r2 = self.__blocks[next_b2][next_i2]
            if r2.start > stop:
                break
            stop = max(stop, r2.stop)
            removed += 1
            b2, i2 = next_b2, next_i2

        # Replace the merged ranges, which may span several blocks.
        if b2 == b:
            block[i : i2 + 1] = [range(start, stop)]
            self.__stops[b] = block[-1].stop
        else:
            self.__blocks[b][i:] = [range(start, stop)]
            del self.__blocks[b2][: i2 + 1]
            last = b2 + 1 if not self.__blocks[b2] else b2
            del self.__blocks[b + 1 : last]
            del self.__stops[b + 1 : last]
            self.__stops[b] = self.__blocks[b][-1].stop
        self.__size += 1 - removed

    def bounds(self) -> range:
        return range(self.__blocks[0][0].start, self.__blocks[-1][-1].stop)

    def shift(self) -> range:
        block = self.__blocks[0]
        r = block.pop(0)
        if not block:
            del self.__blocks[0]
            del self.__stops[0]
        self.__size -= 1
        return r

    def subtract(self, start: int, stop: int) -> None:
        assert stop > start

        b = 0
        while b < len(self.__blocks):
            block = self.__blocks[b]

            # The removed range is entirely before the block, stop here.
            if stop <= block[0].start:
                return

            # The removed range is entirely after the block, keep looking.
            if start >= self.__stops[b]:
                b += 1
                continue

            # Rewrite the block, trimming or splitting the ranges which the
            # removed range touches.
            new_block = []
            for r in block:
                if stop <= r.start or start >= r.stop:
                    new_block.append(r)
                else:
                    if r.start < start:
                        new_block.append(range(r.start, start))
                    if r.stop > stop:
                        new_block.append(range(stop, r.stop))
            self.__size += len(new_block) - len(block)
            if new_block:
                self.__blocks[b] = new_block
                self.__stops[b] = new_block[-1].stop
                self.__split_block(b)
                b += 1
            else:
                del self.__blocks[b]
                del self.__stops[b]

    def __bool__(self) -> bool:
        raise NotImplementedError

    def __contains__(self, val: Any) -> bool:
        # Only the first block whose ranges extend beyond the value can
        # contain it.
        b = bisect_right(self.__stops, val)
        if b == len(self.__blocks):
            return False
        block = self.__blocks[b]
        i = bisect_right(block, val, key=_start) - 1
        return i >= 0 and val < block[i].stop

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, RangeSet):
            return NotImplemented

        return list(self) == list(other)

    @overload
    def __getitem__(self, key: int) -> range: ...

    @overload
    def __getitem__(self, key: slice) -> list[range]: ...

    def __getitem__(self, key: Any) -> range | list[range]:
        if isinstance(key, slice):
            return list(self)[key]
        if key < 0:
            key += self.__size
        if key < 0 or key >= self.__size:
            raise IndexError("RangeSet index out of range")
        for block in self.__blocks:
            if key < len(block):
                return block[key]
            key -= len(block)
        raise IndexError("RangeSet index out of range")

    def __iter__(self) -> Iterator[range]:
        for block in self.__blocks:
            yield from block

    def __len__(self) -> int:
        return self.__size

    def __repr__(self) -> str:
        return f"RangeSet({list(self)!r})"

    def __split_block(self, b: int) -> None:
        block = self.__blocks[b]
        if len(block) > 2 * _BLOCK_SIZE:
            half = len(block) // 2
            self.__blocks[b : b + 1] = [block[:half], block[half:]]
            self.__stops[b : b + 1] = [block[half - 1].stop, block[-1].stop]


# Created once, as creating them in each call to `add()` doubles the cost of the
# search for small sets.
_start = attrgetter("start")
_stop = attrgetter("stop")
