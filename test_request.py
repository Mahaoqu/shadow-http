import requests

proxies = {"https": "http://127.0.0.1:3107"} # 使用本地监听地址

r = requests.get("https://www.baidu.com/", proxies=proxies).text
print(r)

