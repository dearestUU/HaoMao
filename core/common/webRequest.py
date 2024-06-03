# _*_ coding:utf-8 _*_


import json
import time
import requests
from requests.models import Response
import warnings

from core import logger

warnings.filterwarnings('ignore')


class WebRequest:
    def __init__(self):
        self.response = Response()

    @property
    def header(self):
        """
        :return: 定义请求头
        """
        return {
            "User-Agent": "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/38.0.2125.122",
            "Accept": "application/json, text/plain, */*",
            "Connection": "keep-alive",
            "Accept-Language": "zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2"
        }

    def request(self, method: str, target_url, header=None, retry_time=2, timeout=5, **kwargs):
        """
        :param method:  GET
                        HEAD
                        POST
                        PUT
                        DELETE
                        CONNECT
                        OPTIONS
                        TRACE
                        PATCH
                        PURGE
                        DEBUG
        :param target_url: 目标url
        :param header: 请求头
        :param retry_time: 重连次数。请求失败时，默认执行2次
        :param timeout: 网络超时时间
        :return:
        """
        headers = self.header
        if header and isinstance(header, dict):
            headers.update(header)  # 更新headers中的内容
        while True:
            try:
                if target_url.split(':')[0] not in ('http', 'https'):
                    target_url = "http://" + target_url  # 如果没有前缀没有http 或 https，默认加上http://
                if method is None or method == 'default':
                    raise RequestMethodIsNone
                elif method.lower() == "get":
                    self.response = requests.get(url=target_url, headers=headers, timeout=timeout, **kwargs,verify=False)
                elif method.lower() == "post":
                    self.response = requests.post(url=target_url, headers=headers, timeout=timeout, **kwargs,verify=False)
                elif method.lower() == "head":
                    self.response = requests.head(url=target_url, headers=headers, timeout=timeout, **kwargs,verify=False)
                elif method.lower() == "put":
                    self.response = requests.put(url=target_url, headers=headers, timeout=timeout, **kwargs,verify=False)
                elif method.lower() == "delete":
                    self.response = requests.delete(url=target_url, headers=headers, timeout=timeout, **kwargs,verify=False)
                elif method.lower() == "options":
                    self.response = requests.options(url=target_url, headers=headers, timeout=timeout, **kwargs,verify=False)
                elif method.lower() == "patch":
                    self.response = requests.patch(url=target_url, headers=headers, timeout=timeout, **kwargs,verify=False)
                elif method.lower() == "connect":
                    self.response = requests.request(method='CONNECT',url=target_url,headers=headers, timeout=timeout, **kwargs,verify=False)
                elif method.lower() == "trace":
                    self.response = requests.request(method='TRACE',url=target_url,headers=headers, timeout=timeout, **kwargs,verify=False)
                elif method.lower() == "purge":
                    self.response = requests.request(method='PURGE',url=target_url,headers=headers, timeout=timeout, **kwargs,verify=False)
                elif method.lower() == "debug":
                    self.response = requests.request(method='DEBUG',url=target_url,headers=headers, timeout=timeout, **kwargs,verify=False)
                elif method.lower() == "move":
                    self.response = requests.request(method='MOVE',url=target_url,headers=headers, timeout=timeout, **kwargs,verify=False)
                else:
                    raise NoThisRequestMethod
                return self
            except RequestMethodIsNone:
                logger.error(f"[+] HTTP请求方法为空.")
                return
            except NoThisRequestMethod:
                logger.error(f"[+] 没有这个HTTP请求方法: {method}")
                return
            except Exception as ex:
                # logger.warning(f"[+] 尝试请求失败: {target_url} 原因: {ex}")
                retry_time -= 1
                if retry_time <= 0:
                    # logger.error(f"[+] 请求失败: {target_url} 请求体:{kwargs}")
                    return self


class RequestMethodIsNone(Exception):
    pass


class NoThisRequestMethod(Exception):
    pass
