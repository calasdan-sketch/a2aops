"""Map finding paths (``skills[2].tags``, ``skills[id=x].inputModes``) to source lines.

SARIF annotations need a line. The earlier lookup searched for the last key
name anywhere in the file, so ``skills[2].tags`` landed on the first skill's
``tags``. This is a small tokenizer that records where every key and array
element starts, so the annotation lands on the right line. Best effort: any
surprise returns an empty index and the caller falls back to line 1.
"""

from __future__ import annotations

import bisect
import json
import re
from typing import Optional

_TOKEN = re.compile(r'"(?:[^"\\\n]|\\.)*"|[{}\[\],:]|[^\s{}\[\],:"]+')
_PATH_TOKEN = re.compile(r"([A-Za-z_][\w\-]*)|\[(\d+)\]|\[id=([^\]]*)\]")
MAX_TEXT = 4 << 20   # bigger files fall back to line 1; annotations are not worth seconds of CI


class LineIndex:
    def __init__(self, text: str):
        self.paths: dict[tuple, int] = {}
        self.ids: dict[tuple, tuple] = {}
        if len(text) > MAX_TEXT:
            return
        try:
            self._scan(text)
        except Exception:  # noqa: BLE001 - best effort by design
            self.paths, self.ids = {}, {}

    def _scan(self, text: str) -> None:
        nl = [m.start() for m in re.finditer("\n", text)]
        stack: list[list] = []   # [kind, key, idx, expect_key]

        def here(pos: int) -> int:
            return bisect.bisect_left(nl, pos) + 1

        def cur() -> tuple:
            return tuple((f[1] if f[0] == "o" else f[2]) for f in stack)

        for m in _TOKEN.finditer(text):
            tok = m.group()
            top = stack[-1] if stack else None
            if tok in "{[" and len(tok) == 1:
                if top is not None and top[0] == "a":
                    self.paths.setdefault(cur(), here(m.start()))
                stack.append(["o" if tok == "{" else "a", None, 0, True])
            elif tok in "}]" and len(tok) == 1:
                if stack:
                    stack.pop()
            elif tok == ",":
                if top is not None:
                    if top[0] == "a":
                        top[2] += 1
                    else:
                        top[3] = True
            elif tok == ":":
                if top is not None:
                    top[3] = False
            elif top is not None:
                if top[0] == "o" and top[3] and tok.startswith('"'):
                    top[1] = json.loads(tok)
                    self.paths.setdefault(cur(), here(m.start()))
                else:
                    if top[0] == "a":
                        self.paths.setdefault(cur(), here(m.start()))
                    elif top[1] == "id" and tok.startswith('"'):
                        obj_path = cur()[:-1]
                        if obj_path and isinstance(obj_path[-1], int):
                            self.ids.setdefault((obj_path[:-1], json.loads(tok)), obj_path)

    def line(self, path: str) -> Optional[int]:
        if not self.paths or not path:
            return None
        node: tuple = ()
        best: Optional[int] = None
        for m in _PATH_TOKEN.finditer(path):
            key, idx, ident = m.groups()
            if key is not None:
                node += (key,)
            elif idx is not None:
                node += (int(idx),)
            else:
                found = self.ids.get((node, ident))
                if found is None:
                    break
                node = found
            if node in self.paths:
                best = self.paths[node]
            else:
                break
        return best
