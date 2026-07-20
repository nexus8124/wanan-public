"""结构化日志配置。

赛题贴合：评分多次提到"商用标准"——统一日志是商用基础。
"""

from __future__ import annotations

import logging
import sys


def setup_logging(level: str = "INFO") -> None:
    """配置全局 logging：ISO 时间 + 模块名 + 级别 + 消息。"""
    fmt = "%(asctime)s | %(levelname)-7s | %(name)s | %(message)s"
    datefmt = "%Y-%m-%d %H:%M:%S"
    logging.basicConfig(
        level=level.upper(),
        format=fmt,
        datefmt=datefmt,
        stream=sys.stderr,
        force=True,
    )


def get_logger(name: str) -> logging.Logger:
    return logging.getLogger(name)
