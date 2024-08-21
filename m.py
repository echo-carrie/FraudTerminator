from androguard.core.apk import APK
from androguard.core.apk import ARSCParser

def extract_strings_from_apk(apk_file):
    apk = APK(apk_file)
    arsc_parser = ARSCParser(apk.get_file("resources.arsc"))

    # strings_dict = []

    # 遍历所有的包名
    return arsc_parser.get_resolved_strings()

    # return strings_dict

# 示例使用
apk_file_path = "AZCRcpgMh6wn_HCy2KmJ.apk"
strings_dict = extract_strings_from_apk(apk_file_path)

# 转换为jsonarray
import json
json_str = json.dumps(strings_dict)

print(json_str)
# 保存到1.json文件
with open("1.json", "w") as f:
    f.write(json_str)