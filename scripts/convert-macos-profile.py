"""将公开的 macOS dsymutil/vtypes ZIP 转为 StarMem 显式符号 JSON，不执行配置代码。"""
import argparse
import ast
import hashlib
import io
import json
import re
import tokenize
import zipfile
from pathlib import Path


def convert(path, banner):
    with path.open('rb') as stream:
        data = stream.read(16 * 1024 * 1024 + 1)
    if len(data) > 16 * 1024 * 1024:
        raise ValueError("输入 ZIP 超过 16 MiB")
    # 解析与来源哈希使用同一份有界输入，避免读取期间路径内容变化。
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        def read_suffix(suffix):
            names = [n for n in archive.namelist() if n.endswith(suffix)]
            if len(names) != 1 or archive.getinfo(names[0]).file_size > 16 * 1024 * 1024:
                raise ValueError("结构或符号文件缺失、重复或超限：" + suffix)
            return archive.read(names[0]).decode("utf-8")

        tokens = list(tokenize.generate_tokens(io.StringIO(read_suffix(".vtypes")).readline))
        # Python 3 将 Python 2 的长整数后缀拆为 NUMBER + NAME。
        # 仅移除紧邻数字的 L，保持字符串、注释和标识符原样。
        source = tokenize.untokenize([token for index, token in enumerate(tokens)
            if not (token.type == tokenize.NAME and token.string == 'L' and index > 0
                    and tokens[index - 1].type == tokenize.NUMBER
                    and tokens[index - 1].end == token.start)])
        tree = ast.parse(source)
        literals = {}
        for statement in tree.body:
            if (not isinstance(statement, ast.Assign) or len(statement.targets) != 1
                    or not isinstance(statement.targets[0], ast.Name)
                    or statement.targets[0].id not in ("mac_types", "mac_gvars")):
                raise ValueError("vtypes 仅允许 mac_types/mac_gvars 字面量赋值，禁止执行 Python")
            name = statement.targets[0].id
            if name in literals:
                raise ValueError("vtypes 赋值重复：" + name)
            literals[name] = ast.literal_eval(statement.value)
        types = literals["mac_types"]
        symbols = {}
        for line in read_suffix(".symbol.dsymutil").splitlines():
            match = re.search(r"\s([a-f0-9]{16})\s+'([^']+)'$", line)
            if match:
                name, address = match[2], int(match[1], 16)
                if name in symbols and symbols[name] != address:
                    raise ValueError("同名符号地址冲突：" + name)
                symbols[name] = address
    if not banner.startswith("Darwin Kernel Version ") or len(banner) <= 40:
        raise ValueError("须提供与该 KDK 对应的完整 Darwin banner")
    return {"format": "starmem-macos-symbols-v1", "expected_banner": banner,
            "source": {"archive": path.name, "sha256": hashlib.sha256(data).hexdigest(),
                       "conversion": "AST literal data only; dsymutil symbol addresses"},
            "types": types, "symbols": symbols}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("archive", type=Path)
    parser.add_argument("--banner", required=True, help="完整预期 Darwin 内核版本字符串")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    profile = convert(args.archive, args.banner)
    with args.output.open("x", encoding="utf-8") as stream:
        json.dump(profile, stream, ensure_ascii=False, separators=(",", ":"))
