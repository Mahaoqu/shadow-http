import requests

proxies = {"https": "http://127.0.0.1:1080"} # 使用本地监听地址

r = requests.get("https://www.ustb.edu.cn/", proxies=proxies).text
print(r)

