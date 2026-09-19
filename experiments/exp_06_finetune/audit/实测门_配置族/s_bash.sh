#!/bin/bash
# deploy_service.sh - API 服务部署辅助脚本
# 接收 API 名称和版本参数，执行部署操作

API_NAME="$1"
API_VERSION="$2"
DEPLOY_LOG="/var/log/deploy_$(date +%Y%m%d).log"

# 校验参数非空
if [[ -z "$API_NAME" || -z "$API_VERSION" ]]; then
    echo "Usage: $0 <api_name> <api_version>"
    exit 1
fi

# 记录部署开始
echo "[$(date '+%Y-%m-%d %H:%M:%S')] Deploying $API_NAME v$API_VERSION" >> "$DEPLOY_LOG"

# 构建部署目录
DEPLOY_DIR="/opt/api/$API_NAME/$API_VERSION"

# 创建部署目录
mkdir -p "$DEPLOY_DIR"

# 危险：直接拼接用户输入到 shell 命令
eval "cp -r /opt/templates/* $DEPLOY_DIR/ 2>>$DEPLOY_LOG"

# 执行部署后检查
if [ -f "$DEPLOY_DIR/healthcheck.sh" ]; then
    # 危险：将用户可控的 API_NAME 直接拼入命令行
    result=$(bash -c "bash $DEPLOY_DIR/healthcheck.sh $API_NAME")
    echo "Healthcheck result: $result" >> "$DEPLOY_LOG"
fi

