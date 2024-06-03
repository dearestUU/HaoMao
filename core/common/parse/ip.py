# _*_ coding:utf-8 _*_
import ipaddress
from core import logger


def parse_ip1(ip_str: str):
    """
    :param ip_str: 提供单IP字符串 192.168.1.1
    :return: {"flag": 1,"status":"success"} 或 {"flag": -1,"status":"fail"}
    """

    try:
        # 检查是否为 192.168.1.1 的格式
        assert ipaddress.ip_address(ip_str).version == 4
    except ValueError as ex:
        return {"flag": -1, "status": "fail", "result": ex}
    else:
        return {"flag": 1, "status": "success", "result": [ip_str]}


def parse_ip2(ip_str: str):
    """
    :param ip_str: 192.168.1.1/8    192.168.1.1/16    192.168.1.1/24
    :return:  {"flag": 2,"status":"success","result":ip_str}   或   {"flag": -2,"status":"fail","result":ex}
    """
    try:
        if '/' not in ip_str:
            raise ValueError("not this type.")
        tmp = ipaddress.ip_network(ip_str, strict=False)
        assert tmp
    except ValueError as ex:
        return {"flag": -2, "status": "fail", "result": ex}
    else:
        return {"flag": 2, "status": "success", "result": [str(_) for _ in tmp.hosts()]}


def parse_ip3(ip_str: str):
    """
    :param ip_str: 192.168.1.1, 192.168.1.2
    :return: {"flag": 3,"status":"success","result":res1}
    """
    if ',' not in ip_str:
        return {"flag": -3, "status": "fail", "result": "not this type."}
    else:
        if '-' in ip_str or '/' in ip_str:
            return {"flag": -3, "status": "fail", "result": "not this type."}
        else:
            tmp = ip_str.split(',')
            res1 = []  # 正确的IPV4
            res2 = []  # 错误的IPV4
            for var in tmp:
                var = var.strip()
                try:
                    assert ipaddress.ip_address(var).version == 4
                except ValueError:
                    res2.append(var)
                else:
                    res1.append(var)
            if len(res1) > 0:
                return {"flag": 3, "status": "success", "result": res1}
            else:

                return {"flag": -3, "status": "success", "result": "error ip, check you ip."}

def parse_ip4(ip_str: str):
    """
    :param ip_str:
            flag=4: 192.168.1.1-192.168.255.255
            flag=5: 192.168.1.1-255
    :return:
    """
    if '-' not in ip_str:
        return {"flag": -4, "status": "fail", "result": "not this type."}
    else:
        ips = ip_str.split('-')
        tmp_ip_0 = ips[0].strip()
        tmp_ip_1 = ips[1].strip()

        try:
            assert ipaddress.ip_address(tmp_ip_0).version == 4
        except ValueError:
            return {"flag": -4, "status": "fail", "result": "error first position."}
        else:
            try:
                assert ipaddress.ip_address(tmp_ip_1).version == 4
            except ValueError:
                try:
                    if int(tmp_ip_1) in range(0,255+1):

                        ip_parts = tmp_ip_0.split('.')
                        ip_parts[-1] = tmp_ip_1
                        ip_end = '.'.join(ip_parts)

                        ip1__ = int(ipaddress.ip_address(tmp_ip_0))
                        ip2__ = int(ipaddress.ip_address(ip_end))

                        return {"flag": 5, "status": "success", "result": [str(ipaddress.ip_address(_)) for _ in range(ip1__,ip2__+1)]}
                    else:
                        raise ValueError
                except ValueError:
                    return {"flag": -5, "status": "fail", "result":"error range."}
            else:
                ip1_ = int(ipaddress.ip_address(tmp_ip_0))
                ip2_ = int(ipaddress.ip_address(tmp_ip_1))
                if ip1_ < ip2_:
                    return {"flag": 4, "status": "success", "result": [str(ipaddress.ip_address(_)) for _ in range(ip1_,ip2_+1)]}
                else:
                    return {"flag": -4, "status": "fail", "result": "not error range."}


def parse_ip5(ip_str:str):
    """
    :param ip_str: 192.168.1.1-5,192.168.2.1, 192.168.5.1/24
    :return:
    """
    if (',' in ip_str) and ('-' in ip_str) and ('/' in ip_str):
        tmp = [_ for _ in ip_str.split(',')]
        tmp_res = []
        for _ in tmp:
            if '-' not in _ and '/' not in _:
                tmp_parse_1 = parse_ip1(ip_str=_)
                if tmp_parse_1['status'] == "success":
                    tmp_res += tmp_parse_1['result']
            if '/' in _:
                tmp_parse_2 = parse_ip2(ip_str=_)
                if tmp_parse_2['status'] == "success":
                    tmp_res += tmp_parse_2['result']
            if '-' in _:
                tmp_parse_3 = parse_ip4(ip_str=_)
                if tmp_parse_3['status'] == "success":
                    tmp_res += tmp_parse_3['result']
        if len(tmp_res) > 0:
            return {"flag": 6, "status": "success", "result":tmp_res}
        else:
            return {"flag": -6, "status": "fail", "result":"not error range."}
    else:
        return {"flag": -6, "status": "fail", "result":"not this type."}


def parse_ip6(ip_str:str):
    """
    :param ip_str: 192.168.1.1-5,192.168.2.1
    :return:
    """
    if (',' in ip_str) and ('-' in ip_str):
        tmp = [_ for _ in ip_str.split(',')]
        tmp_res = []
        for _ in tmp:
            if '-' not in _:
                tmp_parse_1 = parse_ip1(ip_str=_)
                if tmp_parse_1['status'] == "success":
                    tmp_res += tmp_parse_1['result']
            else:
                tmp_parse_3 = parse_ip4(ip_str=_)
                if tmp_parse_3['status'] == "success":
                    tmp_res += tmp_parse_3['result']
        if len(tmp_res) > 0:
            return {"flag": 7, "status": "success", "result":tmp_res}
        else:
            return {"flag": -7, "status": "fail", "result":"not error range."}
    else:
        return {"flag": -7, "status": "fail", "result":"not this type."}


def parse_ip7(ip_str:str):
    """
    :param ip_str: 192.168.2.1, 192.168.3.1/29
    :return:
    """
    if (',' in ip_str) and ('/' in ip_str):
        tmp = [_ for _ in ip_str.split(',')]
        tmp_res = []
        for _ in tmp:
            if '/' not in _:
                tmp_parse_1 = parse_ip1(ip_str=_)
                if tmp_parse_1['status'] == "success":
                    tmp_res += tmp_parse_1['result']
            else:
                tmp_parse_3 = parse_ip2(ip_str=_)
                if tmp_parse_3['status'] == "success":
                    tmp_res += tmp_parse_3['result']
        if len(tmp_res) > 0:
            return {"flag": 8, "status": "success", "result":tmp_res}
        else:
            return {"flag": -8, "status": "fail", "result":"not error range."}
    else:
        return {"flag": -8, "status": "fail", "result":"not this type."}


def _util(res: dict):
    if res['status'] == "success":
        return True,res
    else:
        return False,res


def enum_ip(ip_str: str) -> list:
    """
    :param ip_str:
    :return: 返回一个list，如果是空列表，则说明传值错误！
    """
    var1 = _util(parse_ip1(ip_str))
    if var1[0] is True:
        return var1[1]['result']
    else:
        var2 = _util(parse_ip2(ip_str))
        if var2[0] is True:
            return var2[1]['result']
        else:
            var3 = _util(parse_ip3(ip_str))
            if var3[0] is True:
                return var3[1]['result']
            else:
                var4 = _util(parse_ip4(ip_str))
                if var4[0] is True:
                    return var4[1]['result']
                else:
                    var5 = _util(parse_ip5(ip_str))
                    if var5[0] is True:
                        return var5[1]['result']
                    else:
                        var6 = _util(parse_ip6(ip_str))
                        if var6[0] is True:
                            return var6[1]['result']
                        else:
                            var7 = _util(parse_ip7(ip_str))
                            if var7[0] is True:
                                return var7[1]['result']
                            else:
                                return []
