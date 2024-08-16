# pip3 install androguard
import hashlib
import json
import os
import random
import zipfile

# python扫描二维码
import pyzbar.pyzbar as pyzbar
import requests
from PIL import Image
# androguard
from androguard.core.apk import APK
from androguard.misc import AnalyzeAPK
from bson.objectid import ObjectId
# flask
from flask import Flask, request
from flask import send_file, jsonify
from flask_cors import CORS
from lxml import etree
from pymongo import MongoClient
from werkzeug.utils import secure_filename
from zhipuai import ZhipuAI

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
    return response.json()['data']


def get_threat_analysis(id):
    url = "https://sandbox.ti.qianxin.com/sandbox/report/dynamic/get/threat_analyze/file/" + id
    response = requests.request("GET", url, headers=q_headers, data={})
    return response.json()['data']


def get_host_behavior(id):
    url = "https://sandbox.ti.qianxin.com/sandbox/report/dynamic/get/host_behavior/file/" + id
    response = requests.request("GET", url, headers=q_headers, data={})
    return response.json()['data']


# network_behavior
def get_network_behavior(id):
    url = "https://sandbox.ti.qianxin.com/sandbox/report/dynamic/get/network_behavior/file/" + id
    response = requests.request("GET", url, headers=q_headers, data={})
    return response.json()['data']


# dropfile
def get_dropfile(id):
    url = "https://sandbox.ti.qianxin.com/sandbox/report/dynamic/get/dropfile/file/" + id
    response = requests.request("GET", url, headers=q_headers, data={})
    return response.json()['data']


def get_screenshot(id):
    url = "https://sandbox.ti.qianxin.com/sandbox/report/dynamic/get/screenshot/file/" + id
    response = requests.request("GET", url, headers=q_headers, data={})
    return response.json()['data']


@app.route('/reports/list', methods=['GET'])
def get_report_list():
    # 获取所有报告列表，只需要qid, application_name, package_name, md5, target_sdk_version
    result = reports_collection.find({}, {'_id': 0, 'qid': 1, 'application_name': 1, 'package_name': 1, 'md5': 1,
                                          'target_sdk_version': 1})
    return jsonify(list(result))


@app.route('/reports/get', methods=['GET'])
def app_info():
    qid = str(request.args.get('id'))

    # 检查mongodb中的记录是否存在

    result_dict = reports_collection.find_one({'qid': qid})
    if not result_dict:
        apk = APK(qid + '.apk')
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

        md5 = hashlib.md5(open(qid + '.apk', 'rb').read()).hexdigest()

        result_dict = {
            'qid': qid,
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
        }

        # 这是宇航的API Key，节省一点使用 🥺🥺🥺🥺🥺🥺
        client = ZhipuAI(api_key="c4472a36cdbf78c3a1b1e36a7972bb13.tiwiEJXjl9tyeqoc")

        response = client.chat.completions.create(
            model="glm-4-flash",
            messages=[
                {
                    "role": "system",
                    "content": "你是一个软件分析专家，请参考下面的分析内容猜测这个软件是否有诈骗行为，并具体指出哪些内容可能存在诈骗风险， 你的回答不能有“无法确定 XXX APP 是否有诈骗行为”、“不建议安装 XXX APP”的说法，也不要回答“结合其他安全工具或平台对  APP 进行更全面的安全评估。”，相信你的判断"
                },
                {
                    "role": "user",
                    "content": json.dumps(result_dict)
                }
            ],
            top_p=0.7,
            temperature=0.95,
            max_tokens=300,
            tools=[{"type": "web_search", "web_search": {"search_result": True}}],
            stream=False,
        )

        ai_response = response.choices[0].message.content
        # for trunk in response:
        #     ai_response += trunk['text'] + '\n'
        result_dict['ai_response'] = ai_response

        # 保存到mongodb，如果存在则更新
        reports_collection.update_one({'qid': qid, }, {'$set': result_dict}, upsert=True)

    return jsonify(result_dict)


@app.route('/reports/get_more', methods=['GET'])
def get_more_info():
    qid = str(request.args.get('id'))
    result_dict = dict(reports_collection.find_one({'qid': qid}))
    if result_dict:
        result_dict.update(
            {
                'static_analysis': get_static_analysis(qid),
                'threat_analysis': get_threat_analysis(qid),
                'host_behavior': get_host_behavior(qid),
                'network_behavior': get_network_behavior(qid),
                'dropfile': get_dropfile(qid),
                'screenshot': get_screenshot(qid)
            }
        )
        reports_collection.update_one({'qid': qid, }, {'$set': result_dict}, upsert=True)
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


UPLOAD_FOLDER = 'uploads'
DECOMPILED_FOLDER = 'decompiled'
ZIP_FOLDER = 'zips'

# 创建必要的文件夹
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(DECOMPILED_FOLDER, exist_ok=True)
os.makedirs(ZIP_FOLDER, exist_ok=True)

UPLOAD_FOLDER = 'uploads'
DECOMPILED_FOLDER = 'decompiled'
ZIP_FOLDER = 'zips'

# 创建必要的文件夹
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(DECOMPILED_FOLDER, exist_ok=True)
os.makedirs(ZIP_FOLDER, exist_ok=True)


def save_apk_content(apk, output_folder):
    os.makedirs(output_folder, exist_ok=True)

    # 保存 APK 的资源文件
    for file_name in apk.get_files():
        file_path = os.path.join(output_folder, file_name)
        os.makedirs(os.path.dirname(file_path), exist_ok=True)
        with open(file_path, 'wb') as f:
            f.write(apk.get_file(file_name))

    # 如果需要，还可以提取更多信息，比如解析 AndroidManifest.xml 等
    with open(os.path.join(output_folder, "AndroidManifest.xml"), 'wb') as f:
        # 将 Element 对象转换为字符串
        xml_str = etree.tostring(apk.get_android_manifest_xml(), pretty_print=True, encoding='utf-8')
        f.write(xml_str)


@app.route('/upload_to_decompile', methods=['POST'])
def upload_to_decompile():
    if 'file' not in request.files:
        return jsonify({"error": "No file part in the request"}), 400

    file = request.files['file']
    if file.filename == '':
        return jsonify({"error": "No selected file"}), 400

    filename = secure_filename(file.filename)
    apk_path = os.path.join(UPLOAD_FOLDER, filename)
    file.save(apk_path)

    # 反编译 APK 文件
    output_folder = os.path.join(DECOMPILED_FOLDER, filename.rsplit('.', 1)[0])
    os.makedirs(output_folder, exist_ok=True)

    a, d, dx = AnalyzeAPK(apk_path)
    save_apk_content(a, output_folder)

    # 创建 ZIP 文件
    zip_filename = f"{filename.rsplit('.', 1)[0]}.zip"
    zip_filepath = os.path.join(ZIP_FOLDER, zip_filename)

    with zipfile.ZipFile(zip_filepath, 'w') as zipf:
        for root, dirs, files in os.walk(output_folder):
            for file in files:
                file_path = os.path.join(root, file)
                arcname = os.path.relpath(file_path, output_folder)
                zipf.write(file_path, arcname)

    return jsonify({"download_url": f"/download/{zip_filename}"}), 200


@app.route('/download/<filename>', methods=['GET'])
def download_file(filename):
    zip_filepath = os.path.join(ZIP_FOLDER, filename)
    if os.path.exists(zip_filepath):
        return send_file(zip_filepath, as_attachment=True)
    else:
        return jsonify({"error": "File not found"}), 404


if __name__ == '__main__':
    # app.run(host='0.0.0.0', port=5000, debug=True)
    app.run(host='0.0.0.0', port=5000)
