from dataclasses import dataclass
from typing import Callable, Generic, List, Tuple, TypeVar, Union

from sortedcontainers import SortedKeyList

T = TypeVar('T')


@dataclass
class Node(Generic[T]):
    start: int
    end: int  # exclusive
    value: T


class IntervalTree(Generic[T]):
    def __init__(self, merge: Callable[[List[T]], T]):
        self.store = SortedKeyList(key=lambda node: node.end)
        self.merge = merge

    @staticmethod
    def _key2range(key: Union[int, slice]) -> Tuple[int, int]:
        if isinstance(key, int):
            return key, key + 1
        elif isinstance(key, slice):
            if key.step is not None and key.step != 1:
                raise ValueError(f'Step must be 1: {key.step}')
            return key.start, key.stop
        else:
            raise TypeError('Index must be either an int or a slice')

    def __getitem__(self, key: Union[int, slice]) -> T:
        start, end = self._key2range(key)
        nodes = []
        for node in self.store.irange_key(start + 1):
            if node.start >= end:
                break
            nodes.append(node.value)
        return self.merge(nodes)

    def __setitem__(self, key: Union[int, slice], value: T) -> None:
        start, end = self._key2range(key)
        nodes: List[Node[T]] = [Node(start, end, value)]
        first_idx = self.store.bisect_key_left(start + 1)
        last_idx = first_idx
        for node in self.store.islice(first_idx):
            if node.start >= end:
                break
            if start <= node.start:
                if end < node.end:
                    # Left overlap
                    nodes.append(Node(end, node.end, node.value))
                else:
                    # Outer overlap
                    pass
            else:
                if end < node.end:
                    # Inner overlap
                    nodes.append(Node(node.start, start, node.value))
                    nodes.append(Node(end, node.end, node.value))
                else:
                    # Right overlap
                    nodes.append(Node(node.start, start, node.value))
            last_idx += 1
        del self.store[first_idx:last_idx]
        self.store.update(nodes)

    def __iter__(self):
        return iter(self.store)
