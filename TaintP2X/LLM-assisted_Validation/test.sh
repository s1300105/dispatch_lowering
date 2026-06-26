#!/bin/bash
# --------------------------
# 配置区（按需修改）
# --------------------------
# 从命令行参数获取 扫描文件 的值
WORK_DIR="${1}"  # 工作目录路径
ISSUE_NUMBER="${2}"
PYSARUNS="${3}"  # 第一个命令行参数作为 扫描文件 的值

TAINT_FILE="./taint-output.json"  # 污点分析输出文件
DB_NAME="sapp.db"                # 分析数据库名称
LOG_FILE="sapp_interaction.log"  # 全局日志文件

# 检查是否提供了必要的参数
if [ -z "$PYSARUNS" ] || [ -z "$ISSUE_NUMBER" ]; then
    echo "错误：缺少必要的参数。"
    echo "用法：$0 <检测目标> <检测问题编号>"
    echo "示例：$0 litellm-1.40.12 issue 1"
    exit 1
fi

# --------------------------
# 阶段1：静态代码分析
# --------------------------
echo "[阶段1] 正在执行静态分析..." | tee -a $LOG_FILE
cd $WORK_DIR || exit 1  # 切换到工作目录，失败则退出

# 执行SAPP分析并记录日志（tee命令同时输出到屏幕和文件）
sapp analyze $TAINT_FILE 2>&1 | tee -a $LOG_FILE

# --------------------------
# 阶段2：交互式会话捕获
# --------------------------
echo -e "\n[阶段2] 启动交互式分析..." | tee -a $LOG_FILE

mkdir /home/hejunjie/llm_web_serve/LLM_determine/log/${PYSARUNS}/${2}

# 使用script命令记录终端会话（-q参数静默模式）
# typescript为临时记录文件（系统自动生成）
script -c "sapp --database-name $DB_NAME explore" -q /home/hejunjie/llm_web_serve/LLM_determine/log/${PYSARUNS}/${2}/sapp_session.log << EOF
issue ${ISSUE_NUMBER}
trace
quit
EOF

# --------------------------
# 阶段3：日志处理
# --------------------------
echo -e "\n[阶段3] 处理分析结果..." | tee -a $LOG_FILE

# 提取issue 1相关日志（从包含'issue ${ISSUE_NUMBER}'到'quit'之间的内容）
INTERACTION_LOG=$(sed -n "/issue ${ISSUE_NUMBER}/,/quit/p" /home/hejunjie/llm_web_serve/LLM_determine/log/${PYSARUNS}/${2}/sapp_session.log | grep -v 'exit' | grep -v '')

echo "$INTERACTION_LOG" > /home/hejunjie/llm_web_serve/LLM_determine/log/${PYSARUNS}/${2}/output.log