# _*_ coding:utf-8 _*_

import colorlog
import logging
import sys


# def setup_logger():
#     formatter = colorlog.ColoredFormatter(
#         "%(cyan)s[%(asctime)s] %(log_color)s%(levelname)s%(reset)s %(message)s",
#         datefmt="%Y-%m-%d %H:%M:%S",
#         reset=True,
#         log_colors={
#             'DEBUG': 'cyan',
#             'INFO': 'green',
#             'WARNING': 'yellow',
#             'ERROR': 'red',
#             'CRITICAL': 'red,bg_white',
#         },
#         secondary_log_colors={},
#         style='%'
#     )
#
#     logger = colorlog.getLogger('example')
#     handler = logging.StreamHandler(sys.stdout)
#     handler.setFormatter(formatter)
#     logger.addHandler(handler)
#     logger.setLevel(logging.INFO)
#
#     return logger

def setup_logger():
    logger = colorlog.getLogger()
    handler = logging.StreamHandler()

    # 创建一个记录器格式，设置 logger.info 输出为红色
    formatter = colorlog.ColoredFormatter(
        "%(cyan)s[%(asctime)s]%(log_color)s %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
        log_colors={
            'INFO': 'green',  # 'red' 这里设置输出颜色为红色
            'ERROR': 'red',
            'WARNING': 'yellow'
        }
    )
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    # 设置日志级别
    logger.setLevel(logging.INFO)
    return logger
