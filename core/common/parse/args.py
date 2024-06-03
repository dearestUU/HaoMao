# _*_ coding:utf-8 _*_

import argparse
import os
import sys
from pprint import pprint

import yaml
from prettytable import PrettyTable

from core import logger
from core.common.parse.yml import LoadAllPocName, LoadMatchPoc, LoadSinglePoc, is_valid_yaml
from core.common.parse.yml.rules import ExecuteSinglePoc
from concurrent.futures import ThreadPoolExecutor


def parse_custom_args(args):
    url = args.url
    proxy = args.proxies
    # cookie = args.cookies
    # threads = args.threads
    urlFile = args.urlFile
    timeout = args.webTimeout
    pocPath = args.pocPath
    pocMatch = args.match
    is_print = args.print
    pocName = args.poc
    # is_detail = args.detail

    if pocMatch is not None:
        MatchPocs(matchKey=pocMatch,pocPath=pocPath,isPrint=is_print,url=url,urlFile=urlFile, proxy=proxy)  # 执行 关键字 相关的poc
    elif pocName is not None:
        SinglePoc(pocName=pocName,pocPath=pocPath,isPrint=is_print,url=url,urlFile=urlFile, proxy=proxy)  # 执行 指定的poc
    else:
        AllPoc(pocPath=pocPath,isPrint=is_print,url=url,urlFile=urlFile, proxy=proxy)


def AllPoc(pocPath,isPrint,urlFile,url, proxy):
    allPocs = LoadAllPocName(poc_gen=pocPath)
    pocs_count = len(allPocs)
    if isPrint is True:
        PrintTable(yaml_list=allPocs)
    if url is not None and urlFile is None:
        logger.info(f'[+] 开始加载所有poc-yaml,共计{pocs_count}个.')
        with ThreadPoolExecutor(max_workers=pocs_count) as executor:
            future1 = [executor.submit(ExecuteSinglePoc,url,_,pocPath,proxy) for _ in allPocs]
            for f in future1:
                f_res = f.result()
                if f_res[0] is True:
                    logger.info(f'[+] SUCCESS! {f_res[1]} {f_res[2]}')
                else:
                    logger.error(f'[+] FAILED!  {f_res[1]} {f_res[2]}')

    elif urlFile is not None and url is None:
        logger.info(f'[+] 开始加载所有poc-yaml,共计{pocs_count}个.')
        url_list = UrlFiles(filePath=urlFile)  # 从文件获取的url列表
        url_count = len(url_list)
        if url_count <= 0:
            logger.info(f'[+] 文件`{urlFile}`中没有url.')
        else:
            for uu in url_list:
                with ThreadPoolExecutor(max_workers=url_count) as poc_executor:
                    future1 = [poc_executor.submit(ExecuteSinglePoc,uu,_,pocPath,proxy) for _ in allPocs]
                    for f in future1:
                        f_res = f.result()
                        if f_res[0] is True:
                            logger.info(f'[+] SUCCESS! {f_res[1]} {f_res[2]}')
                        else:
                            logger.error(f'[+] FAILED!  {f_res[1]} {f_res[2]}')


def SinglePoc(pocName,pocPath,isPrint,url,urlFile, proxy):

    MY_RESULT = []
    if pocName is None:
        return None
    else:
        poc = LoadSinglePoc(poc_name=pocName,poc_gen=pocPath)
        if poc is None:
            logger.error(f'[+] 未找到`{pocName}`文件!')
        else:
            is_poc = is_valid_yaml(poc)
            if is_poc[0] is False:
                logger.error(f'[+] 解析`{pocName}`出错')
            else:
                if isPrint is True:
                    yml_content = is_poc[1]
                    logger.info('-'*50)
                    print()
                    print(yaml.dump(yml_content,default_flow_style=False,sort_keys=False))
                    logger.info('-'*50)

                if url is not None and urlFile is None:
                    exec_res = ExecuteSinglePoc(url=url,poc_name=pocName,poc_gen=pocPath,proxy=proxy)
                    if exec_res[0] is True:
                        logger.info(f' [+] SUCCESS! {url} {pocName}')
                        MY_RESULT.append([url,pocName])
                    else:
                        logger.error(f'[+] FAILED!  {url} {pocName}')

                elif urlFile is not None and url is None:
                    url_list = UrlFiles(filePath=urlFile)  # 从文件获取的url列表
                    url_count = len(url_list)
                    if len(url_list) <= 0:
                        logger.info(f'[+] 文件`{urlFile}`中没有url.')
                    else:
                        with ThreadPoolExecutor(max_workers=url_count) as executor:
                            future1 = [executor.submit(ExecuteSinglePoc,_,pocName,pocPath,proxy=proxy) for _ in url_list]
                            for f in future1:
                                f_res = f.result()
                                if f_res[0] is True:
                                    logger.info(f'[+] SUCCESS! {f_res[1]} {f_res[2]}')
                                else:
                                    logger.error(f'[+] FAILED!  {f_res[1]} {f_res[2]}')
                else:
                    pass


def MatchPocs(matchKey,pocPath,isPrint,url,urlFile,proxy):
    """
    :param urlFile: 传入的url文件
    :param url: 传入的url
    :param matchKey: 匹配poc 的关键字
    :param pocPath: 指定的poc路径
    :param isPrint: 是否打印出来
    :return:
    """
    matchPocList = LoadMatchPoc(key=matchKey,poc_gen=pocPath)
    count = len(matchPocList)
    if len(matchPocList) <= 0:
        logger.warning(f'[+] 未找到与关键字`{matchKey}`相匹配的poc-yaml.')
    else:
        if isPrint is True:
            # logger.info(f'[+] 以上是`{matchKey}`相关的{count}个poc-yaml')
            PrintTable(yaml_list=matchPocList)
        if url is not None and urlFile is None:
            # 开始对扫描这个url
            logger.info(f'[+] 开始执行与`{matchKey}`相关的{count}个poc-yaml')
            with ThreadPoolExecutor(max_workers=count) as executor:
                future1 = [executor.submit(ExecuteSinglePoc,url,_,pocPath,proxy) for _ in matchPocList]
                for f in future1:
                    f_res = f.result()
                    if f_res[0] is True:
                        logger.info(f'[+] SUCCESS! {f_res[1]} {f_res[2]}')
                    else:
                        logger.error(f'[+] FAILED!  {f_res[1]} {f_res[2]}')

        elif urlFile is not None and url is None:
            logger.info(f'[+] 开始执行与`{matchKey}`相关的{len(matchPocList)}个poc-yaml')
            url_list = UrlFiles(filePath=urlFile)  # 从文件获取的url列表
            url_count = len(url_list)
            if url_count <= 0:
                logger.info(f'[+] 文件`{urlFile}`中没有url.')
            else:
                for uu in url_list:
                    with ThreadPoolExecutor(max_workers=count) as poc_executor:
                        future1 = [poc_executor.submit(ExecuteSinglePoc,uu,_,pocPath,proxy) for _ in matchPocList]
                        for f in future1:
                            f_res = f.result()
                            if f_res[0] is True:
                                logger.info(f'[+] SUCCESS! {f_res[1]} {f_res[2]}')
                            else:
                                logger.error(f'[+] FAILED!  {f_res[1]} {f_res[2]}')

        else:
            pass


def PrintTable(yaml_list:list):
    table = PrettyTable()
    table.field_names = ["Index", "POC-YAML"]
    for index,value in enumerate(yaml_list):
        table.add_row([index+1, value])
    print(table)


def PrintAllPocs(poc_gen):
    pocs = LoadAllPocName(poc_gen=poc_gen)
    table = PrettyTable()
    table.field_names = ["Index", "POC-YAML"]
    for index,value in enumerate(pocs):
        table.add_row([index+1, value])
    print(table)


def UrlFiles(filePath):
    """
    :param filePath: 读取文件
    :return: 返回一个 url 的列表
    """
    print(os.path.dirname(filePath))
    with open(filePath,'r',encoding='utf-8') as file:
        urls = file.read().splitlines()
    return urls
