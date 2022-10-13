#gp参数注入辅助工具
       

1.自动去除重复url，过滤不存在参数的url;

2.支持a附加和r替换模式的参数注入;

3.每注入一个参数会生成一个新的url;

4.支持stdin和手动输入参数;


##使用案例





基本命令:

`gp.exe -u "http://a.com/api?k=1&v=2" -p xss`

组合命令:

`type url.txt |gp.exe -p xss`

组合命令:

`cat url.txt |gp.exe -p xss`


```
optional arguments:
  -h, --help  show this help message and exit
  -p P        需要加载的poc
  -u U        链接地址url
  -r R        poc插入方式 a:附加 r:替换```