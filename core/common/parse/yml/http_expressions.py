# _*_ coding:utf-8 _*_
import regex
import base64
import hashlib
import random
import re
import string
from urllib.parse import quote, unquote
from requests import Response

class Custom_Func:
    @staticmethod
    def matches_(s1: str, s2: str) -> bool:
        # 使用正则表达式s1来匹配s2，返回bool类型匹配结果
        return True if re.match(s1,s2) else False

    @staticmethod
    def bmatches_(pattern, b_string):
        s1 = b_string.decode('utf-8')  # Decode bytes to string
        return bool(re.search(pattern, s1))

    @staticmethod
    def startsWith_(s1: str, s2: str) -> bool:
        # 判断s1是否由s2开头
        return s1.startswith(s2)

    @staticmethod
    def endsWith_(s1: str, s2: str) -> bool:
        # 判断s1是否由s2结尾
        return s1.endswith(s2)

    @staticmethod
    def in_(key, you_dict: str) -> bool:
        # map 中是否包含某个 key，目前只有 headers 是 map 类型
        return key in you_dict

    @staticmethod
    def md5_(s1:str) -> str:
        # 字符串的 md5 (以下都是 0.13.0 版本新增)
        m = hashlib.md5()
        m.update(s1.encode('utf-8'))
        return m.hexdigest()

    @staticmethod
    def randomInt_(min: int, max: int) -> str:
        # 两个范围内的随机数
        # print(f"randomInt {min}  {max}")
        return str(random.randint(min, max))

    @staticmethod
    def randomLowercase_(length: int) ->str:
        # 指定长度的小写字母组成的随机字符串
        letters = string.ascii_lowercase
        return ''.join(random.choice(letters) for _ in range(length))

    @staticmethod
    def base64_(data: [bytes,str]):
        # 将字符串或 bytes 进行 base64 编码
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
    def substr_(s1:str, start:int,length:int) -> str:
        # 截取字符串
        return s1[start:start+length]

    @staticmethod
    def bytes_(str1:str) -> bytes:
        return str1.encode('utf-8')

    @staticmethod
    def string_(unknown) -> str:
        return str(unknown)

    @staticmethod
    def contains_(s1, s2):
        return s2 in s1

    @staticmethod
    def bcontains_(s1:bytes, s2:bytes):
        return s2 in s1

class ResponseHeadersHV:
    def __init__(self, headers):
        self.headers = headers

    def hv(self, key):
        return self.headers.get(key, "")

class RESP:
    def __init__(self, resp: Response):
        self.status = resp.status_code
        self.body = resp.content
        self.headers = resp.headers
        self.content_type = resp.headers['content-type'] if 'content-type' in resp.headers else ''

def parse_expression(expr):

    # 匹配括号内的内容
    pattern = r'\((?:[^()]|(?R))*\)'
    brackets = regex.findall(pattern, expr)

    # 将括号内的内容替换为占位符
    for i, bracket in enumerate(brackets):
        expr = expr.replace(bracket, f'BRACKET{i}')

    # 根据 || 和 && 分割字符串，使用非捕获组 (?:...)
    delimiters = r'(\|\||&&)'
    result = re.split(delimiters, expr)

    # 将占位符替换回原来的括号内容
    for i, bracket in enumerate(brackets):
        result = [item.replace(f'BRACKET{i}', bracket) for item in result]
    return result

def parse_expression_again(expr):
    expr_list = parse_expression(expr=expr)
    for index, element in enumerate(expr_list):
        element = element.strip()

        # 传入的表达式没有括号
        if '||' not in element:
            expr_list[index] = MatchFunc(element=element)
        elif '&&' in element:
            expr_list[index] = MatchFunc(element=element)
        elif element == '&&' or element == '||':
            pass
        else:
            new_expr = re.sub(r'^\((.*)\)$', r'\1', element)  # 去掉首尾 括号
            new_element = parse_expression_again(expr=new_expr)
            expr_list[index] = '(' + ' '.join(new_element) + ')'  # 替换成功
    return expr_list

def MatchFunc(element):
    res = element.replace('response.status','response_status').replace('response.body','response_body').replace('response.headers','response_headers').replace('response.content_type','response_content_type')
    if 'bcontains' in element:
        pattern = re.compile(r"(.*?).bcontains\((.*?)\)")
        return re.sub(pattern, r"bcontains(\1, \2)", res)
    elif 'contains' in element:
        pattern = re.compile(r"(.*?).contains\((.*?)\)")
        return re.sub(pattern, r"contains(\1, \2)", res)
    elif 'bmatches' in element:
        pattern = re.compile(r"(.*?).bmatches\((.*?)\)")
        return re.sub(pattern, r"bmatches(\1, \2)", res)
    elif 'matches' in element:
        pattern = re.compile(r"(.*?).matches\((.*?)\)")
        return re.sub(pattern, r"matches(\1, \2)", res)
    elif 'startsWith' in element:
        pattern = re.compile(r"(.*?).startsWith\((.*?)\)")
        return re.sub(pattern, r"startsWith(\1, \2)", res)
    elif 'endsWith' in element:
        pattern = re.compile(r"(.*?).endsWith\((.*?)\)")
        return re.sub(pattern, r"endsWith(\1, \2)", res)
    elif ' in ' in element:
        res1 = res.split(' in ')
        res2 = res1[0]
        res3 = res1[1]
        return f'ins({res2}, {res3})'
    else:
        return res

def finally_parse(expr:str):
    headers_pattern = r'response\.headers\["(.*?)"\]'
    expr1 = re.sub(headers_pattern, r'response.headers_hv.hv("\1")', expr)
    parse_str = parse_expression_again(expr=expr1)
    finally_str = ' '.join(parse_str).replace('||', 'or').replace('&&','and')
    return finally_str


def execute_expression(resp:Response,expr:str) ->bool:
    """
    :param resp: HTTP的响应
    :param expr: 待执行的表达式
    :return: 返回执行结果 bool 值
    """
    parse_str = finally_parse(expr=expr)  # expr 表达式最终的结果
    # print(parse_str)
    response_status = RESP(resp).status
    response_headers = RESP(resp).headers
    response_body = RESP(resp).body
    response_ct = RESP(resp).content_type
    response_headers_hv = ResponseHeadersHV(response_headers)

    context = {
        "response_status": response_status,
        "response_headers":response_headers,
        "response_body":response_body,
        "response_ct":response_ct,
        "response_headers_hv":response_headers_hv,
        "response_content_type":response_ct,
        "matches":Custom_Func.matches_,
        "bmatches":Custom_Func.bmatches_,
        "startswith":Custom_Func.startsWith_,
        "startsWith":Custom_Func.startsWith_,
        "endsWith":Custom_Func.endsWith_,
        "endswith":Custom_Func.endsWith_,
        "ins":Custom_Func.in_,
        "md5":Custom_Func.md5_,
        "randomInt":Custom_Func.randomInt_,
        "randomLowercase":Custom_Func.randomLowercase_,
        "base64":Custom_Func.base64_,
        "base64Decode":Custom_Func.base64Decode_,
        "urlencode":Custom_Func.urlencode_,
        "urldecode":Custom_Func.urldecode_,
        "bytes":Custom_Func.bytes_,
        "string":Custom_Func.string_,
        "substr":Custom_Func.substr_,
        "bcontains":Custom_Func.bcontains_,
        "contains":Custom_Func.contains_
    }
    exec('result = ' + parse_str, context)
    return context['result']


# if __name__ == '__main__':

    # str1 = 'response.body.bcontains(b"uid") || (response.status == 200 || response.status == 400) && (response.content_type.contains("text/html") || response.content_type.contains("application"))'
    # str1 = 'response_status == 200 && "X-Xss-Protection" in response.headers && (response.headers["Server"].contains("BWS") || response.headers["Server"].contains("bfe")) && "X-Ua-Compatible" in response.headers && response.body.bcontains(b"<!DOCTYPE html>") && response_body.bcontains(bytes(substr(string("<!DOCTYPE html>"), 0, 31)))'

    # str1 = '"^(.*?)/1".bmatches(bytes(response.headers["Server"]))'
    # str1 = 'response.body.bcontains(b"\"kubeletVersion\": \"v") && response.body.bcontains(b"\"containerRuntimeVersion\"")'


    # from core.common.parse.yml.rules import InitSinglePocCode
    #
    # inits = InitSinglePocCode(poc_name='74cms.yml')
    # str1 = inits[5][0]['expression']
    # print(str1)
    #
    # import requests
    #
    # response = requests.get(url='https://baidu.com',verify=False)
    # #print(response.content)
    # print(execute_parse(resp=response,expr=str1))



