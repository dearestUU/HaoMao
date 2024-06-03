## HaoMao工具

### 1. 简介
用python3解析fscan样式的poc，主要就是poc验证，其他功能待开发，安装后就能用，写这个也就图一乐。
对GO语言不熟悉，不然就可以魔改个fscan，开个玩笑~~~
### 2. 使用命令
```python
python3 HaoMao.py -h  # 打印帮助信息
python3 HaoMao.py -u https://baidu.com  # 加载所有pocs进行扫描探测
python3 HaoMao.py -uf urls.txt # 加载文件中的url进行扫描（一行一个）
python3 HaoMao.py -u https://baidu.com -poc 74cms-sqli.yml  # 加载指定的poc
python3 HaoMao.py -u https://baidu.com -match 74cms -print  # 模糊匹配关于 `74cms` 关键字的poc并打印出来poc名字
python3 HaoMao.py -u https://baidu.com -match 74cms -print -proxy http://127.0.0.1:8080  # 设置代理访问
python3 HaoMao.py -u https://baidu.com -pocpath /home/you_pocs_folder   # 设置poc的目录
```
### 3. 安装python3.9相关模块
```python
pip install -r requirements.txt
```
### 4. 有问题就留言