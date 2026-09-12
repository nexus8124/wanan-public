"""pytest 全局夹具：隔离运行时模型配置文件。

测试必须永远从内置厂商目录 + 各用例显式构造的 Settings 出发，
不受本机 data/model_config.json（配置页保存过）影响，
因此在导入任何 app 模块前把 MODEL_CONFIG_PATH 指向空临时目录。
"""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

_ISOLATED_DIR = Path(tempfile.mkdtemp(prefix="xh-model-config-test-"))
os.environ["MODEL_CONFIG_PATH"] = str(_ISOLATED_DIR / "model_config.json")
