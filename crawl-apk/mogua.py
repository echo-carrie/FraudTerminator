import requests
from bs4 import BeautifulSoup
import pandas as pd
from collections import *


def crawl_mogua(package_name):
    url = "https://mogua.co/souku?key={}&type=package".format(package_name)
    print(url)
    r = requests.get(url)
    soup = BeautifulSoup(r.text, "html.parser")
    results = soup.find_all("a", {"class": "btn btn-primary"})
    if len(results) == 0:
        return []
    if len(results[0].get("href").split("?")) < 2:
        return []
    url = "https://mogua.co/static_analyzer/?" + results[0].get("href").split("?")[1]
    r = requests.get(url)
    soup = BeautifulSoup(r.text, "html.parser")
    table = soup.find_all("table", {"id": "table_permissions"})
    #     <tbody>
    #
    #                           <tr>
    #                           <td>android.permission.INTERNET</td>
    #                           <td>

    # 找到所有td中的内容，并返回一个列表
    permissions = []
    for row in table[0].find_all("tr")[1:]:
        permissions.append(row.find_all("td")[0].text.strip())
    return permissions


# print(crawl_mogua("com.baidu.appsearch"))

# 读取whitelist.txt文件，获取白名单列表，最后保存到result.csv文件中

if __name__ == "__main__":
    # 创建新的DataFrame
    df = pd.DataFrame(columns=["package_name", "permissions"])

    map3gram_kind = {}
    count = 1
    with open("whitelist.txt", "r") as f:
        lines = f.readlines()
        for line in lines[0:1000]:
            package_name = line.strip()
            count += 1
            map3gram_kind[package_name] = crawl_mogua(package_name)
            print(package_name, map3gram_kind[package_name])

    cc = Counter([])
    for d, lists in map3gram_kind.items():
        for _list in lists:
            cc[_list] += 1

    selectedfeatures = {}
    tc = 0
    for k, v in cc.items():
        # if v >= 100:
        selectedfeatures[k] = v
        print(k, v)
        tc += 1
    dataframelist = []
    for fid, op3gram in map3gram_kind.items():
        standard = {"Class": 0}
        for feature in selectedfeatures:
            if feature in op3gram:
                standard[feature] = 1
            else:
                standard[feature] = 0
        dataframelist.append(standard)
    df = pd.DataFrame(dataframelist)
    df.to_csv("result.csv", index=False)
