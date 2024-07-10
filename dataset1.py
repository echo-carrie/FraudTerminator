import hashlib
from collections import defaultdict, Counter
import os
import pandas as pd

# 新版已经把APK模块移到了androguard.core中
# from androguard.core.bytecodes import apk

from androguard.core import apk

# 定义类别和对应的目录
categories = ["sex", "black", "gamble", "scam", "white"]
dirs = {category: f"F:\\softwarecup\\{category}\\{category}" for category in categories}  # 修复路径

# 日志文件路径
log_file_path = "dataset\\logs\\failed_apks.log"

# 初始化存储结构
map3grams = {category: defaultdict(str) for category in categories}
category_to_index = {category: index for index, category in enumerate(categories)}

# 计数器初始化
count = 1

# 遍历每个类别的目录
for category, dir_path in dirs.items():
    print(f"Processing {category} category...")
    if not os.path.exists(dir_path):  # 检查目录是否存在
        print(f"Directory not found: {dir_path}")
        continue
    for file in os.listdir(dir_path):
        if file.endswith(".apk"):  # 确保是APK文件
            try:
                print(f"Counting the permissions of the {count} file...")
                print(file)
                count += 1
                apk_path = os.path.join(dir_path, file)

                # 计算APK的MD5哈希值
                with open(apk_path, 'rb') as f:
                    apk_content = f.read()
                    apk_md5 = hashlib.md5(apk_content).hexdigest()

                # 使用Androguard加载APK
                app = apk.APK(apk_path)
                permissions = app.get_permissions()  # 获取权限列表
                package_name = app.get_package()  # 获取包名

                # 存储每个APK的详细信息
                map3grams[category][file] = {
                    'permissions': permissions,
                    'md5': apk_md5,
                    'package_name': package_name
                }
            except Exception as e:
                # 记录失败的APK处理
                with open(log_file_path, "a",encoding='utf-8') as log_file:
                    log_file.write(f"Error processing {file}: {e}\n")
                print(f"Error processing {file}: {e}")


# 统计所有类别的权限出现次数
cc = Counter()
for category, files_data in map3grams.items():
    for _, data in files_data.items():
        for permission in data['permissions']:
            cc[permission] += 1

# 选择出现次数大于等于1的特征（这里你可以根据需要调整条件）
selectedfeatures = {k: v for k, v in cc.items() if v >= 1}

# 创建数据框架
dataframelist = []
for category, files_data in map3grams.items():
    for file, data in files_data.items():
        permissions = data['permissions']
        apk_md5 = data['md5']
        package_name = data['package_name']

        apk_name = os.path.splitext(file)[0]  # 去掉.apk扩展名，获取APK名称

        standard = {
            "APK Name": apk_name,  # 添加APK名称列
            "MD5": apk_md5,
            "Category": category,
            "Package Name": package_name,
            "Class": category_to_index[category],
        }
        for feature in selectedfeatures:
            standard[feature] = 1 if feature in permissions else 0
        dataframelist.append(standard)

# 转换为DataFrame并导出
df = pd.DataFrame(dataframelist)
output_path = "dataset\\permissions.csv"  # 确保路径存在
if not os.path.exists(os.path.dirname(output_path)):
    os.makedirs(os.path.dirname(output_path))  # 创建不存在的目录
df.to_csv(output_path, index=False,encoding='utf-8')
print(f"Dataframe has been saved to {output_path}")