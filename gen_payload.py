# -*- coding: utf-8 -*-
# author: linsen
# time:{DATE}{TIME}
import argparse
import re
from urllib.parse import urlparse
import sys

usage="""
------------------------------------------------
gp poc生成工具   
   ___      ___              ___                  
  / __|    | _ \    o O O   | _ \   ___     __    
 | (_ |    |  _/   o        |  _/  / _ \   / _|   
  \___|   _|_|_   TS__[O]  _|_|_   \___/   \__|_  

基本命令:
gp.exe -u "http://a.com/api?k=1&v=2" -p xss

提取域名:
gp.exe -u "http://a.com/api?k=1&v=2" -nh True

提取域名以及协议:
gp.exe -u "http://a.com/api?k=1&v=2" -nh True -ns True

组合命令:
type url.txt |gp.exe -p xss

组合命令:
cat url.txt |gp.exe -p xss

                        Code_By_Captain0X
------------------------------------------------

"""

parser = argparse.ArgumentParser(usage=usage)
# 管理系统启动脚本命令:python xx/xx/xx/main_file.py 123123123ffdhasd
parser.add_argument('-p',default="xss", type=str, help='需要加载的poc')
parser.add_argument('-u', default="", type=str, help='链接地址url')
parser.add_argument('-r', default="a", type=str, help='poc插入方式 a:附加 r:替换')
parser.add_argument('-nh', default=False, type=bool, help='提取域名')
parser.add_argument('-ns', default=False, type=str, help='提取域名前缀')
parser.add_argument('stdin',type=argparse.FileType('r'),nargs='?',default=sys.stdin)
args = parser.parse_args()
u=args.__dict__.get('u')
def gen_url_rule(url,just_host=False,scheme=False):
    '''生成url规则字典
    返回域名+正则表达式的字典

    '''
    parse_url=urlparse(url)
    host=parse_url.netloc
    if '@' in host:   #非法的域名
        return ""
    if just_host:
        if scheme:
            return parse_url.scheme+"://"+host
        else:
            return host
    re_key_list=['\d+','\w+','\w+\.\w+','\w+\d+']
    key_re = []
    arg_key = re.findall('[?&](.*?)=', url)
    for x in parse_url.path.split('/'):
        if x:
            key_len=len(x)
            for rk in re_key_list:
                fr=re.findall(rk,x)
                if fr:
                    if len(fr[0])==key_len:  #命中规则
                        key_re.append(rk+"*"+str(key_len))
                        break
    return f'{host}{"/".join(key_re)}?{"&".join(arg_key)}'
if not u:
    urls=args.__dict__.get('stdin').readlines()
else:
    urls=[u]
payload=args.__dict__.get('p')
mode=args.__dict__.get('r')
uri_set=[]
for url in urls:
    url=url.strip()
    nh=args.__dict__.get('nh')   #是否组要域名
    ns=args.__dict__.get('ns')   #是否需要协议
    uri_key=gen_url_rule(url,just_host=nh,scheme=ns)
    if not uri_key:
        continue
    if uri_key in uri_set:
        continue
    uri_set.append(uri_key)
    if nh:
        print(uri_key)
        continue
    payload = payload.strip()
    parse_url = urlparse(url)
    if not parse_url.query:
        continue
    query_list = parse_url.query.split('&')
    for idx,kw in enumerate(query_list):
        try:
            k, v = kw.split('=')
        except:
            k=kw.split('=')[0]
            v=""
        if mode=='a':
            nv = v + payload # 插入payload后的参数
        else:
            nv = payload # 插入payload后的参数
        inject = k + '=' + nv
        # 重组xss url
        query_list.pop(idx)
        query_list.insert(idx, inject)
        new_url = url.replace(kw, inject)
        #恢复原来组合
        query_list.pop(idx)
        query_list.insert(idx, kw)
        print(new_url)

#python gen_payload.py -u http://a.com/api?k=1&v=2 -p xss