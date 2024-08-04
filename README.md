# FraudTerminator

# README

## 项目概述

本项目是一个使用 Flask 框架构建的后端应用程序，主要包含文件上传、模型训练、预测等功能。

## 运行说明

1. **克隆项目**:
   ```bash
   git clone https://github.com/echo-carrie/FraudTerminator.git
   ```
2. **Docker 安装依赖**:
   ```bash
   sudo apt-get install docker.io
   ```
3. **构建并运行 Docker 容器**:
   ```bash
   ./build_and_update.sh
   ```
   将运行在5000端口，可通过浏览器访问 `http://localhost:5000` 进行测试。

## 主要组件说明

- **Dockerfile**: 定义了项目的 Docker 容器构建过程。
- **README.md**: 项目说明文件。
- **build_and_update.sh**: 构建和更新项目的脚本。
- **build_docker.sh**: Docker 构建脚本。
- **crawl-apk**: APK 抓取相关脚本和文件。
    - **mogua.py**: 抓取 APK 的 Python 脚本。
    - **result.csv**: 抓取结果的 CSV 文件。
    - **whitelist.txt**: 白名单文件。
- **dataset**: 模型训练数据集。
    - **combined_df.csv**: 综合数据集。
    - **logs**: 日志文件夹。
        - **failed_apks.log**: 失败 APK 日志。
    - **permissions.csv**: 权限数据集。
- **dataset1.py**: 数据集处理脚本。
- **main.py**: Flask 应用的主程序。
- **models**: 模型文件。
    - **model_10_59.pth**: 训练好的模型文件。
- **predict.ipynb**: 预测脚本。
- **requirements.txt**: 项目依赖。
- **test.ipynb**: 测试脚本。
- **train.ipynb**: 训练脚本。
- **training_loss.png**: 训练过程中损失函数的变化图。
- **xgboost.ipynb**: 使用 XGBoost 进行模型测试的 Jupyter 笔记本。
- **xgboost_model.json**: XGBoost 模型的 JSON 描述文件。
- **zhipu_test.py**: LLM测试脚本。

## 功能说明

- **后端程序**: 通过 Flask 应用与前端对接。
- **模型测试**: 使用 `xgboost.ipynb` 测试 XGBoost 模型。
