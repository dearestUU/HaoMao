# _*_ coding:utf-8 _*_


def enum_url(url:str):
    if ',' in url:
        return [_.strip('/') for _ in url.split(',')]
    else:
        return url.strip('/')
