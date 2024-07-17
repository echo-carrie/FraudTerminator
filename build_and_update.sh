#!/bin/bash

# 设置镜像名称
IMAGE_NAME="fraud_terminator"

# 构建Docker镜像
echo "Building Docker image..."
docker build -t $IMAGE_NAME .

# 检查构建是否成功
if [ $? -ne 0 ]; then
    echo "Docker image build failed!"
    exit 1
fi

# 停止并删除旧的容器
echo "Stopping and removing old containers..."
docker ps -a -q --filter "ancestor=$IMAGE_NAME" | xargs -r docker stop | xargs -r docker rm

# 启动新的容器
echo "Running new container..."
docker run -d --name $IMAGE_NAME -p 5000:5000 $IMAGE_NAME

# 检查是否成功启动
if [ $? -ne 0 ]; then
    echo "Failed to run the new container!"
    exit 1
fi

echo "Docker image built and updated successfully!"
