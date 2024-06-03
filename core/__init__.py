# _*_ coding:utf-8 _*_

import os

from core.common.log import setup_logger

logger = setup_logger()


def WebPocYamlPath():
    """
    :return: WEB POC yaml 文件夹的路径
    """
    current_file_path = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(current_file_path, '..', 'pocs')
