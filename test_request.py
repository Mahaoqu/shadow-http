import requests

proxies = {"https": "http://127.0.0.1:8086"} # 使用本地监听地址

r = requests.get("https://www.google.com/", proxies=proxies).text
print(r)

