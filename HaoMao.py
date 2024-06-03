# _*_ coding:utf-8 _*_
import argparse
import sys

from core.common.parse.args import parse_custom_args


def command_line_parse(argv=None):
    if not argv:
        argv = sys.argv

    parser = argparse.ArgumentParser(prog='Tools', usage="Tools [options]",add_help=True)

    # parser.add_argument("-h","--host",type=str,help="主机IP")
    # parser.add_argument("-p","--port",type=str,default="21,22,80,81,135,139,443,445,1433,3306,5432,6379,7001,8000,8080,8089,9000,9200,11211,27017", help="Select a port,for example: 22 | 1-65535 | 22,80,3306")
    parser.add_argument("-u","--url", type=str,help="验证路径")
    parser.add_argument("-proxy","--proxies", type=str,help="设置代理")
    # parser.add_argument("-cookie","--cookies",type=str, help="设置cookie")
    # parser.add_argument("-t","--threads",type=int,default=100, help="线程数")
    parser.add_argument("-uf","--urlFile",type=str,help="线程数")
    parser.add_argument("-timeout","--webTimeout",type=int,default=5,help="web访问超时时间")
    parser.add_argument("-pocpath","--pocPath",type=str,help="指定poc路径")
    parser.add_argument("-print","--print", help="打印出来已知的poc列表",action="store_true")
    parser.add_argument("-match","--match",help="模糊匹配poc")
    parser.add_argument("-poc","--poc",help="执行指定的poc-yaml")
    # parser.add_argument("-detail","--detail", help="打印出指定poc的细节", action="store_true")
    args = parser.parse_args()
    parse_custom_args(args)  # 开始执行


if __name__ == '__main__':
    command_line_parse()
    # import requests
    # resp = requests.get(url="https://alibaba.com",verify=False,allow_redirects=True)
    # print(resp.headers)
