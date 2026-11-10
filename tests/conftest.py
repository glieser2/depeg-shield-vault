import atexit
import os
import sys


if sys.platform == "win32":
    # 兼容 Windows 平台下 gltest Direct Mode 将临时文件 dup2 到 fd 0 后立即 unlink 触发的句柄占用问题
    _orig_unlink = os.unlink

    def _win_safe_unlink(path, *args, **kwargs):
        try:
            _orig_unlink(path, *args, **kwargs)
        except PermissionError:
            atexit.register(lambda p=path: _quiet_cleanup(p))

    def _quiet_cleanup(path):
        try:
            _orig_unlink(path)
        except OSError:
            pass

    os.unlink = _win_safe_unlink
