# pip3 install androguard
import hashlib
import os
from flask_cors import CORS

from zhipuai import ZhipuAI

# python扫描二维码
import pyzbar.pyzbar as pyzbar
from PIL import Image

# androguard
from androguard.core.apk import APK
# flask
from flask import Flask, request
import random
import requests
from pymongo import MongoClient
from bson.objectid import ObjectId
import json

# 连接mongodb数据库
client = MongoClient('mongodb://root:mongodb@m1.oboard.eu.org:27017/')
db = client['fraud_terminator']

reports_collection = db['reports']
lists_collection = db['list']

app = Flask(__name__)
CORS(app)


class JSONEncoder(json.JSONEncoder):
    """
    解决TypeError: Object of type 'ObjectId' is not JSON serializable
    """

    # ensure_ascii解决中文乱码问题，根据自己情况天假
    def __init__(self, ensure_ascii=False):
        super().__init__(ensure_ascii=False)

    def default(self, o):
        if isinstance(o, ObjectId):
            return str(o)
        return json.JSONEncoder.default(self, o)


# 解决TypeError: Object of type 'ObjectId' is not JSON serializable
jsonify = JSONEncoder(ensure_ascii=True).encode

q_headers = {
    'Accept': 'application/json, text/plain, */*',
    'Accept-Language': 'zh-CN,zh;q=0.9',
    'Connection': 'keep-alive',
    'DNT': '1',
    'Origin': 'https://sandbox.ti.qianxin.com',
    'Referer': 'https://sandbox.ti.qianxin.com/sandbox/page',
    'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36'
}


# 通过上传apk链接的二维码扫描后上传文件
@app.route('/files/upload/qrcode', methods=['POST'])
def upload_qrcode():
    if request.method == 'POST':
        f = request.files['file']

        # 读取二维码
        img = Image.open(f)
        qrcodes = pyzbar.decode(img)
        if len(qrcodes) == 0:
            return jsonify({'msg': 'not a qrcode'})
        qrcode = qrcodes[0]
        qrcode_data = qrcode.data.decode('utf-8')

        # 下载文件
        response = requests.get(qrcode_data)
        # 保存文件到本地
        # 随机生成一个文件id
        fileId = str(random.randint(1000000000, 9999999999))
        with open(fileId + '.apk', 'wb') as f:
            f.write(response.content)

        # 上传分析
        response = uploadToQianXin(fileId + '.apk')

        _id = response['data']['id']

        # 修改文件名
        new_filename = _id + '.apk'
        os.rename(fileId + '.apk', new_filename)

        # 返回apk_path
        return jsonify({'id': _id})


# 通过apk链接上传文件
@app.route('/files/upload/url', methods=['POST'])
def upload_url():
    if request.method == 'POST':
        url = request.form.get('url')
        # 下载文件
        response = requests.get(url)
        # 保存文件到本地
        # 随机生成一个文件id
        fileId = str(random.randint(1000000000, 9999999999))
        with open(fileId + '.apk', 'wb') as f:
            f.write(response.content)

        # 上传分析
        response = uploadToQianXin(fileId + '.apk')
        # {
        #     "data": {
        #         "id": "AZCIHlwQONZSmF3-yCZm",
        #         "md5": "3bcd92277a42a9bb2b298d531b144aa9",
        #         "sha1": "7d06bd1e64f6b9a021d200ff883a88bfae86e016",
        #         "type": "file"
        #     },
        #     "msg": "ok",
        #     "status": 10000
        # }

        _id = response['data']['id']

        # 修改文件名
        new_filename = _id + '.apk'
        os.rename(fileId + '.apk', new_filename)

        # 返回apk_path
        return jsonify({'id': _id})


# 上传文件
@app.route('/files/upload', methods=['POST'])
def upload():
    if request.method == 'POST':
        f = request.files['file']
        # 保存文件到本地
        # 随机生成一个文件id
        fileId = str(random.randint(1000000000, 9999999999))
        f.filename = fileId + '.apk'
        f.save(f.filename)

        # 上传分析
        response = uploadToQianXin(f.filename)
        _id = response['data']['id']

        # 修改文件名
        new_filename = _id + '.apk'
        os.rename(f.filename, new_filename)

        # 返回apk_path
        return jsonify({'id': _id})


def uploadToQianXin(filename):
    url = "https://sandbox.ti.qianxin.com/sandbox/fileupload?env=&time=1&analyzer=&zip_pwd="
    files = [
        ('file', ('1ef3b972-5c47-4ff0-9241-afd333ad884c', open(filename, 'rb'), 'application/octet-stream'))
    ]
    response = requests.request("POST", url, headers=q_headers, data={}, files=files)
    print(response.json())
    return response.json()


def get_static_analysis(id):
    url = "https://sandbox.ti.qianxin.com/sandbox/report/dynamic/get/static_analyze/file/" + id

    response = requests.request("GET", url, headers=q_headers, data={})
    return response.json()


def get_threat_analysis(id):
    url = "https://sandbox.ti.qianxin.com/sandbox/report/dynamic/get/threat_analyze/file/" + id
    response = requests.request("GET", url, headers=q_headers, data={})
    return response.json()


@app.route('/reports/get', methods=['GET'])
def app_info():
    id = str(request.args.get('id'))
    apk = APK(id + '.apk')
    package_name = apk.get_package()
    application_name = apk.get_app_name()
    version_name = apk.get_androidversion_name()
    version_code = apk.get_androidversion_code()
    target_sdk_version = apk.get_target_sdk_version()
    sha1 = apk.get_certificate(apk.get_signature_name()).sha1_fingerprint
    permissions = apk.get_permissions()
    activities = apk.get_activities()
    architecture = {
        "armeabi": False,
        "armeabi-v7a": False,
        "arm64-v8a": False,
        "x86": False,
        "x86_64": False
    }
    apk_files = apk.get_files()
    for file in apk_files:
        for key, value in architecture.items():
            if value is False and file.startswith('lib/' + key + '/'):
                architecture[key] = True

    md5 = hashlib.md5(open(id + '.apk', 'rb').read()).hexdigest()

    result_dict = {
        'qid': id,
        'application_name': application_name,
        'package_name': package_name,
        'md5': md5,
        'version_code': version_code,
        'version_name': version_name,
        'target_sdk_version': target_sdk_version,
        'architecture': architecture,
        'SHA1': sha1,
        'permissions': permissions,
        'activities': activities,
        'static_analysis': get_static_analysis(id),
        'threat_analysis': get_threat_analysis(id)
    }

    # 这是宇航的API Key，节省一点使用 🥺🥺🥺🥺🥺🥺
    client = ZhipuAI(api_key="a0166a5c17216218cf0ac15889dfe327.uu0rgI10O9HWD0jM")

    response = client.chat.completions.create(
        model="glm-4-flash",
        messages=[
            {
                "role": "system",
                "content": "你是一个软件分析专家，请参考下面的分析内容猜测这个软件是否有害， 你的回答不能有“无法确定 XXX APP 是否有害”的说法，也不要回答“结合其他安全工具或平台对  APP 进行更全面的安全评估。”，相信你的判断"
            },
            {
                "role": "user",
                "content": json.dumps(result_dict)
            }
        ],
        top_p=0.7,
        temperature=0.95,
        max_tokens=1024,
        tools=[{"type": "web_search", "web_search": {"search_result": True}}],
        stream=False,
    )

    ai_response = response.choices[0].message.content
    # for trunk in response:
    #     ai_response += trunk['text'] + '\n'

    result_dict['ai_response'] = ai_response

    return jsonify(result_dict)


# 名单部分
# GET /api/lists/search?name={appName}&type={md5 | name | package}：通过md5、app名称、包名、搜索软件包
#
# GET /api/lists/whitelist：获取白名单列表。
# GET /api/lists/blacklist：获取黑名单列表。
#
# POST /api/lists/add：添加软件包到名单。
# DELETE /api/lists/{id}：删除软件包。

@app.route('/lists/search', methods=['GET'])
def search_list():
    value = request.args.get('value')
    search_type = request.args.get('type')
    if search_type == 'md5':
        result = lists_collection.find({'md5': value})
    elif search_type == 'name':
        # 名称用模糊搜索，不区分大小写
        result = lists_collection.find({'apkName': {'$regex': value, '$options': 'i'}})
    elif search_type == 'package':
        result = lists_collection.find({'packageName': value})
    else:
        result = None

    if result:
        return jsonify(list(result))
    else:
        return jsonify({'msg': 'not found'})


@app.route('/lists/whitelist', methods=['GET'])
def get_whitelist():
    # type为white或者zj_white
    result = lists_collection.find({'type': {'$in': ['white', 'zj_white']}})
    return jsonify(list(result))


@app.route('/lists/blacklist', methods=['GET'])
def get_blacklist():
    # type不是white或者zj_white
    result = lists_collection.find({'type': {'$nin': ['white', 'zj_white']}})
    return jsonify(list(result))


@app.route('/lists/add', methods=['POST'])
def add_to_list():
    data = request.get_json()
    if 'name' not in data or 'package' not in data or 'md5' not in data:
        return jsonify({'msg': 'name, package, md5 are required'})
    result = lists_collection.insert_one(data)
    return jsonify({'msg': 'ok', 'id': str(result.inserted_id)})


@app.route('/lists/<string:id>', methods=['DELETE'])
def delete(id):
    result = lists_collection.delete_one({'_id': ObjectId(id)})
    if result.deleted_count == 1:
        return jsonify({'msg': 'ok'})
    else:
        return jsonify({'msg': 'not found'})


if __name__ == '__main__':
    # app.run(host='0.0.0.0', port=5000, debug=True)
    app.run(host='0.0.0.0', port=5001)
