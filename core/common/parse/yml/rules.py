# _*_ coding:utf-8 _*_
import ast
import json
import os

from core import logger
from core.common.parse.yml import is_valid_yaml, PocCode, PocRules, WebPocYamlPath
import dacite

from core.common.parse.yml.http_expressions import execute_expression
from core.common.webRequest import WebRequest
from core.common.parse.yml.parse_set import ParseSet


def InitSinglePocCode(poc_name,poc_gen):
    """
    :param poc_name: 传入 poc 的 name. 初始化POC
    :return:
    """
    if poc_gen is None:
        poc_gen_path = WebPocYamlPath()
    else:
        poc_gen_path = poc_gen

    if poc_gen_path is not None:
        poc_content = is_valid_yaml(file=os.path.join(poc_gen_path, poc_name))
        if poc_content[0] is True:
            poc_content = poc_content[1]
            init = dacite.from_dict(data_class=PocCode, data=poc_content)
            # print(init.search)
            return init.name, init.transport, init.set, init.groups, init.rules, init.detail, init.manual, init.search
        else:
            return None
    else:
        return None


def ExecuteSinglePoc(url,poc_name,poc_gen,proxy):
    """
    :param proxy:
    :param poc_gen:
    :param url: 执行单个POC
    :param poc_name: POC文件的名字
    :return:
    """
    if poc_gen is None:
        poc_gen_path = WebPocYamlPath()
    else:
        poc_gen_path = poc_gen

    res = ParsePocParam(url=url,poc_name=poc_name,poc_gen_path=poc_gen_path, proxy=proxy)
    return res, url, poc_name


def ParsePocParam(url, poc_name, poc_gen_path, proxy):
    """
    :param proxy:
    :param poc_gen_path:
    :param url: 待验证的url
    :param poc_name: poc文件名
    :return: 解析poc中的参数，如 name transport  set groups rules details
    """

    init = InitSinglePocCode(poc_name=poc_name,poc_gen=poc_gen_path)
    if init is None:
        logger.error("[+] poc里面没东西哦!")
    else:
        vuln_name = init[0]   # 漏洞名称
        vuln_transport = init[1]  # 漏洞通信协议；默认http
        vuln_set = init[2]  # poc中的变量
        vuln_groups = init[3]  # 规则组；表示只要有一个执行成功即可,多个poc
        vuln_rules = init[4]  # 规则组，是一个 list，表示需同时满足才行
        vuln_detail = init[5]  # 漏洞细节
        vuln_search = init[6]  # 搜索请求体

        try:
            new_vuln_set = ParseParamSet(vuln_set=vuln_set)  # 处理过后的变量值，是个列表，列表中有几个元素就表示要请求几次。如果是 default 则说明没有变量
        except:
            logger.error(f"[+] 0x06 无法解析你写poc中的变量！{poc_name}")
            return

        if vuln_transport in ('http','https','default'):  # 表示这个poc走的是http协议
            if vuln_rules == 'default' and vuln_groups == 'default':
                logger.error(f"[+] poc里没有设置表达式哦!没有 rules/groups .{poc_name}")
            elif isinstance(vuln_rules,list) and vuln_groups == 'default':
                # 说明 rules 中有规则
                if len(vuln_rules) == 1:  # 说明rules 中只有一个规则
                    return ParseParamRulesOrGroupsByHTTP(url=url,rules=vuln_rules[0],param=new_vuln_set,r_or_g='rules', proxy=proxy)    # 进行一次规则验证；返回bool值
                elif len(vuln_rules) > 1:  # 说明rules 中有多个规则
                    exec_res = [ParseParamRulesOrGroupsByHTTP(url=url,rules=single_rule,param=new_vuln_set,r_or_g='rules', proxy=proxy) for single_rule in vuln_rules]
                    final_result = [str(exec_res[0])]
                    for i in range(1, len(exec_res)):
                        final_result.extend(['and', str(exec_res[i])])
                    # print(eval(' '.join(final_result)))
                    return eval(' '.join(final_result))   # 多个规则的返回结果
                else:
                    logger.error("[+] 0x01 无法解析你写的rules！")
            elif isinstance(vuln_groups,dict) and vuln_rules == 'default':   # 处理 groups中的内容
                groups = len(vuln_groups.keys())
                if groups < 1:
                    logger.error("[+] 0x02 无法解析你写的groups！")
                else:
                    fes = []   # finally exec result
                    for key, value in vuln_groups.items():  # 只遍历 规则组dict中的值，不关心键名称是啥
                        exec_res = [ParseParamRulesOrGroupsByHTTP(url=url,rules=vv,param=new_vuln_set,r_or_g='groups',proxy=proxy) for vv in value] # 开始解析解析http
                        final_result = [str(exec_res[0])]
                        for i in range(1, len(exec_res)):
                            final_result.extend(['or', str(exec_res[i])])
                        fes.append(eval(' '.join(final_result)))
                    ffes = [str(fes[0])]
                    for j in range(1,len(fes)):
                        ffes.extend(['or',str(fes[j])])
                    return eval(' '.join(ffes))
            else:
                logger.error("[+] 0x03 无法解析你写的poc-yaml！")
        else:
            pass  # 说明走的是其他协议


def ParseParamRulesOrGroupsByHTTP(url, rules,param,r_or_g, proxy):
    """
    :param cookie:
    :param proxy:
    :param r_or_g: 表示这是个 rules 还是 groups
    :param param: POC 中自定义的变量,就是 ParsePocParam.new_vuln_set 变量
    :param url: 待验证的url
    :param rules: 每次执行一个规则
    :return:
    """
    # print(f"{url}??????????")
    try:
        if url == '':
            raise Exception("你输入的 url 为空！")
        if url.startswith('http://') or url.startswith('https://'):  # 如果没有指明是http、https；则默认http
            pass
        else:
            url = 'http://' + url

        parse = dacite.from_dict(data_class=PocRules,data=rules)  # 开始解析解析http

        # print(parse.path)

        if proxy is None:
            proxy = {"http":proxy,"https":proxy}

        if param == 'default':  # 说明没有变量
            return SingleHttpRequest(http_url=url,method=parse.method,path=parse.path,headers=parse.headers,body=parse.body,expression=parse.expression,follow_redirects=parse.follow_redirects,proxies=proxy)
        else:
            exec_result = []
            # print(param)
            # 说明有变量。这里的 params 是一个列表，列表中有几个元素就代表要请求几次,一个元素是一个dict
            for pp in param:  # 遍历 params 这个list
                http_path = parse.path
                http_method = parse.method
                http_headers = parse.headers
                http_body = parse.body
                follow_redirects = parse.follow_redirects
                http_expression = parse.expression

                for key,value in pp.items():  # list中每个元素都是dict
                    # print('{{' + key + '}}')  # 类似 {{var1}}
                    if '{{' + key + '}}' in http_expression:
                        http_expression = http_expression.replace('{{' + key + '}}', value)
                    if '{{' + key + '}}' in http_path:
                        http_path = http_path.replace('{{' + key + '}}', value)
                        # print(http_path)
                    if '{{' + key + '}}' in str(http_headers):
                        for key1,value1 in http_headers.items():
                            http_headers[key1] = value1.replace('{{' + key + '}}', value)
                    if '{{' + key + '}}' in str(http_body):
                        if isinstance(http_body,dict):
                            for key2,value2 in http_body.items():
                                http_body[key2] = value2.replace('{{' + key + '}}', value)
                        else:
                            http_body = http_body.replace('{{' + key + '}}', value)

                http_res = SingleHttpRequest(http_url=url,method=http_method,path=http_path,headers=http_headers,body=http_body,expression=http_expression,follow_redirects=follow_redirects,proxies=proxy)
                exec_result.append(http_res)  # 将每个规则执行的结果存入

                # if http_res is False and r_or_g == 'rules':  # rules中如果执行失败，就不执行了，rules中的每一个
                #     break
                # elif http_res is True and r_or_g == 'groups':  # groups中如果有一个执行成功，则说明漏洞存在
                #     break

            final_result = [str(exec_result[0])]  # 最终结果，类似 ['False', 'or', 'False', 'or', 'True']

            if r_or_g == 'rules':
                for i in range(1, len(exec_result)):
                    final_result.extend(['and', str(exec_result[i])])
            else:
                for i in range(1, len(exec_result)):
                    final_result.extend(['and', str(exec_result[i])])
            return eval(' '.join(final_result))

    except Exception as ex:
        logger.error(f"[+] 0x04 无法解析你写的rules！{ex}")  # 默认返回 False

def ParseParamSet(vuln_set):
    """
    :param vuln_set: 解析 poc 中 set的值
    :return:
    """
    new_dict = {}

    if vuln_set != 'default':
        for key, value in vuln_set.items():
            # print(key,value,new_dict)
            new_dict[key] = ParseSet().exec(value,new_dict)
        # print(new_dict)
        return ParseParamSetUtil(vuln_set_dict=new_dict)

    else:
        return 'default'


def ParseParamSetUtil(vuln_set_dict:dict) -> list:
    """
    :param vuln_set_dict: ParseParamSet 传来的
    :return: 返回
    """
    x = {}  # 新的 vuln_set_dict
    flag = ''
    for key, value in vuln_set_dict.items():
        if isinstance(value,list):
            flag = key
        else:
            x[key] = value
    if flag == '':
        return [x]
    else:
        y = []  # 返回新的  new_vuln_set
        for _ in vuln_set_dict[flag]:
            x.update({flag: _})
            # print(z)
            y.append(str(x))   # 防止更新本身的字典

        z = []
        for _ in y:
            _ = ast.literal_eval(_)
            z.append(_)
        return z


def SingleHttpRequest(method,follow_redirects,path, headers, body, http_url: str, expression:str,**kwargs):
    """
    :param body: http请求体
    :param headers:  http请求头
    :param path: http请求路径
    :param method: http 请求方法
    :param follow_redirects: 是否跟随302跳转
    :param expression: 表达式
    :param http_url: 请求的url
    :return:
    """
    # print(method,follow_redirects,path,headers,body,http_url,expression)

    if path == 'default':
        url = f"{http_url.rstrip('/')}"
    else:
        url = f"{http_url.rstrip('/')}{path}"

    try:
        json.loads(body)
    except json.decoder.JSONDecodeError:
        if method.lower() == 'get':
            resp = WebRequest().request(method=method,target_url=url,header=headers,allow_redirects=follow_redirects,**kwargs).response
        else:
            resp = WebRequest().request(method=method,target_url=url,header=headers,data=body,allow_redirects=follow_redirects,**kwargs).response
    else:
        if method.lower() == 'get':
            resp = WebRequest().request(method=method,target_url=url,header=headers,allow_redirects=follow_redirects,**kwargs).response
        else:
            resp = WebRequest().request(method=method,target_url=url,header=headers,json=body,allow_redirects=follow_redirects,**kwargs).response

    # print(execute_expression(resp=resp,expr=expression))
    # print(expression)
    # print(resp.headers)
    # print(expression)

    try:
        exec_res = execute_expression(resp=resp,expr=expression)  # 返回表达式执行的结果
        return exec_res
    except Exception as ex1:
        # logger.error(f"[+] 0x06 poc中expression表达式执行出错. 错误原因: {ex1}")
        return False


if __name__ == '__main__':
    InitSinglePocCode(poc_name='joomla-cnvd-2019-34135-rce.yml',poc_gen=None)

#     ExecuteSinglePoc(url="https://baidu.com",poc_name="74cms.yml")
    # import requests
    # res = requests.get(url='https://baidu.com',verify=False)
    # print(res.status_code)

    # for _ in LoadAllPocName():
    #     try:
    #         inits = InitSinglePocCode(poc_name=_)
    #         if inits[3] != 'default':
    #             print(_)
    #             # for vars in inits[4]:
    #             #     print(vars)
    #             #     rr = dacite.from_dict(data_class=PocRules,data=vars)
    #             #     if rr.headers != 'default':
    #             #         print(_)
    #     except:
    #         pass

