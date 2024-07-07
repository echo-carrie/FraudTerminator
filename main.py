# pip3 install androguard

from androguard.core.apk import APK
# flask
from flask import Flask, request, jsonify
import random

app = Flask(__name__)


# 上传文件
@app.route('/upload', methods=['POST'])
def upload():
    if request.method == 'POST':
        f = request.files['file']
        # 保存文件到本地
        # 随机生成一个文件id
        fileId = str(random.randint(1000000000, 9999999999))
        f.filename = fileId + '.apk'
        f.save(f.filename)
        # 返回apk_path
        return jsonify({'apk_path': f.filename})


@app.route('/app_info', methods=['GET'])
def app_info():
    apk_path = str(request.args.get('apk_path'))
    apk = APK(apk_path)
    package_name = apk.get_package()
    application_name = apk.get_app_name()
    version_name = apk.get_androidversion_name()
    version_code = apk.get_androidversion_code()
    target_sdk_version = apk.get_target_sdk_version()
    sha1 = apk.get_certificate(apk.get_signature_name()).sha1_fingerprint
    permissions = apk.get_permissions()
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
    return jsonify({
        'application_name': application_name,
        'package_name': package_name,
        'version_code': version_code,
        'version_name': version_name,
        'target_sdk_version': target_sdk_version,
        'architecture': architecture,
        'SHA1': sha1,
        'permissions': permissions
    })


if __name__ == '__main__':
    app.run(debug=True)
