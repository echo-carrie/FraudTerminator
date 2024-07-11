# pip3 install androguard
import hashlib
import os

from androguard.core.apk import APK
# flask
from flask import Flask, request, jsonify
import random
import requests

app = Flask(__name__)

q_headers = {
    'Accept': 'application/json, text/plain, */*',
    'Accept-Language': 'zh-CN,zh;q=0.9',
    'Connection': 'keep-alive',
    'DNT': '1',
    'Origin': 'https://sandbox.ti.qianxin.com',
    'Referer': 'https://sandbox.ti.qianxin.com/sandbox/page',
    'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36'
}


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

    return jsonify({
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
    })


if __name__ == '__main__':
    # app.run(host='0.0.0.0', port=5000, debug=True)
    app.run(host='0.0.0.0', port=5000)
