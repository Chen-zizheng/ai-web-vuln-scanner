"""双击启动入口：起一个只监听本机的服务，并用默认浏览器打开界面。"""
from __future__ import annotations

import sys

import webui


def main(argv: list) -> int:
    port = 0
    open_browser = True
    rest = list(argv)
    for i, arg in enumerate(rest):
        if arg == "--port" and i + 1 < len(rest):
            port = int(rest[i + 1])
        elif arg == "--no-browser":
            open_browser = False
    webui.serve(port=port, open_browser=open_browser)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
