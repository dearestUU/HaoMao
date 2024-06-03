# _*_ coding:utf-8 _*_

import os
import yaml
from dataclasses import dataclass
from prettytable import PrettyTable

from core import WebPocYamlPath


@dataclass
class PocCode:
    """
    解析 fscan 中的yaml POC
    """
    name: str = 'default'  # 漏洞名称
    set: dict = 'default'  # 设置的变量
    transport: str = 'default'  # 通信协议
    rules: list = 'default'  # 规则
    groups: dict = 'default'  #
    detail: dict = 'default'  # 漏洞细节
    manual: bool = False  # 是否自动执行，默认False，代表默认执行，True表示手动执行
    search: str = 'default'


@dataclass
class PocRules:
    """Yaml POC 中的 'rules' """
    follow_redirects: bool = False
    method: str = 'default'
    path: str = 'default'
    headers: dict = 'default'
    body: str = 'default'
    expression: str = 'default'


def PrintDetail(content):
    """
    :param content:
    :return: 以表格的形式打印Yaml POC中的detail
    """
    if content != 'default':
        if isinstance(content, dict):
            kk = []
            vv = []
            for k, v in content.items():
                kk.append(k)
                if isinstance(v, list):
                    vv.append('\n'.join(v))
                else:
                    vv.append(v)
            table = PrettyTable()
            table.field_names = kk
            table.add_row(vv)
            return table
        else:
            return "No Detail."
    else:
        return "No Detail."


@dataclass
class PocName:
    name: str = ''



def LoadAllPoc(poc_gen=None) -> list:
    """
    :return: 加载所有yaml文件的路径,返回一个列表
    """
    if poc_gen is None:
        poc_gen_path = WebPocYamlPath()
    else:
        poc_gen_path = poc_gen
    poc_name = [_ for _ in os.listdir(poc_gen_path) if _.endswith('.yml') or _.endswith('.yaml')]
    return [os.path.join(poc_gen_path, _) for _ in poc_name]


def LoadAllPocName(poc_gen) -> list:
    """
    :return: 加载所有poc 的 name，返回一个list
    """
    if poc_gen is None:
        poc_gen_path = WebPocYamlPath()
    else:
        poc_gen_path = poc_gen
    poc_name = [_ for _ in os.listdir(poc_gen_path) if _.endswith('.yml') or _.endswith('.yaml')]
    return [_ for _ in poc_name]


def LoadMatchPoc(key: str, poc_gen=None):
    """
    :param poc_gen: poc 根路径
    :param key: poc名字的关键字。模糊查询
    :return:
    """
    if poc_gen is None:
        poc_gen_path = WebPocYamlPath()
    else:
        poc_gen_path = poc_gen
    poc_name = [_ for _ in os.listdir(poc_gen_path) if _.endswith('.yml') or _.endswith('.yaml')]
    matches = list(filter(lambda x: key in x, poc_name))  # 模糊查询
    return [_ for _ in matches]


def LoadSinglePoc(poc_name: str, poc_gen=None):
    """
    :param poc_gen: poc文件夹路径
    :param poc_name: 加载指定的poc name
    :return:
    """
    if poc_gen is None:
        poc_gen_path = WebPocYamlPath()
    else:
        poc_gen_path = poc_gen

    if poc_name in os.listdir(poc_gen_path):
        return os.path.join(poc_gen_path,poc_name)
    else:
        return None


def is_valid_yaml(file):
    try:
        with open(file, 'r') as stream:
            yaml_content = yaml.safe_load(stream)
        return True, yaml_content  # 返回 True 和 poc-yaml 的内容
    except Exception as e:
        return False

# if __name__ == '__main__':
#     print(LoadSinglePoc(poc_name='74cms-sqli-1.yml'))
