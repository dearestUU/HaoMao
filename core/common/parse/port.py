# _*_ coding:utf-8 _*_
from core import logger

def _check_range(port) -> bool:
    """
    :param port: 端口检查是不是在0-65536这个范围
    :return: bool
    """
    try:
        if int(port) in range(0,65535+1):
            return True
        else:
            logger.error(f"wrong port range -> {port}")
            return False
    except ValueError:
        logger.error(f"wrong port value -> {port}")
        return False


def parse_port1(port_str:str):
    """
    :param port_str: 样例：80,8080,3306
    :return:
    """
    if ',' not in port_str:
        return {"flag": -1, "status": "fail", "result": "not this type."}
    else:
        tmp = port_str.split(',')
        res1 = []
        res2 = []
        for var in tmp:
            var = var.strip()
            if _check_range(port=var) is True:
                res1.append(var)
            else:
                res2.append(var)
        if len(res1) > 0:
            return {"flag": 1, "status": "success", "result": res1}
        else:
            return {"flag": -1, "status": "fail", "result": "error port, check you port."}


def parse_port2(port_str:str):
    """
    :param port_str: 样例: 80-100
    :return:
    """
    if '-' not in port_str:
        return {"flag": -2, "status": "fail", "result": "not this type."}
    else:
        tmp = port_str.split('-')
        port1 = tmp[0].strip()
        port2 = tmp[1].strip()
        if _check_range(port=port1) is True:
            if _check_range(port=port2) is True:
                return {"flag": 2, "status": "success", "result": [_ for _ in range(int(port1),int(port2)+1)]}
            else:
                return {"flag": -2, "status": "fail", "result": "error port second position, check you port."}
        else:
            return {"flag": -2, "status": "fail", "result": "error port first position, check you port."}


def parse_port3(port_str:str):
    """
    :param port_str: 单个端口
    :return:
    """
    if _check_range(port=port_str) is True:
        return {"flag": 3, "status": "success", "result": [int(port_str)]}
    else:
        return {"flag": -3, "status": "fail", "result": "not this type."}


def parse_port4(port_str:str):
    """
    :param port_str:  25,90,8000-8005
    :return:
    """
    if ('-' in port_str) and (',' in port_str):
        tmp = [_ for _ in port_str.split(',')]
        tmp_res = []
        for _ in tmp:
            if '-' not in _:
                if _check_range(port=_) is True:
                    tmp_res.append(int(_))
            else:
                if parse_port2(port_str=_)['status'] == "success":
                    tmp_res += parse_port2(port_str=_)['result']
        if len(tmp_res)>0:
            return {"flag": 4, "status": "success", "result": tmp_res}
        else:
            return {"flag": -4, "status": "fail", "result": "check you port."}
    else:
        return {"flag": -4, "status": "fail", "result": "not this type."}


def _util(res:dict):
    if res['status'] == "success":
        return True,res
    else:
        return False,res


def enum_port(port_str:str):
    var1 = _util(res=parse_port1(port_str))
    if var1[0] is True:
        return var1[1]['result']
    else:
        var2 = _util(res=parse_port2(port_str))
        if var2[0] is True:
            return var2[1]['result']
        else:
            var3 = _util(res=parse_port3(port_str))
            if var3[0] is True:
                return var3[1]['result']
            else:
                var4 = _util(res=parse_port4(port_str))
                if var4[0] is True:
                    return var4[1]['result']
                else:
                    return []

