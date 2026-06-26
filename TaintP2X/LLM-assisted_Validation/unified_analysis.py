import os
import json
import sys

# 导入重构后的类
from .ds_llm_source_determine_mul import SourceDeterminer
from .ds_llm_fully_determine_mul import FullyDeterminer

# 全局变量
LOG_DIR = "log_zhipu"
PROJECT_NAMES = ["a_project_name"]  # 替换为实际的项目名称列表
PROJECT_BASE_PATH = "..\\dataset\\real_world"
LOG_BASE_PATH = "..\\logs" # 统一的日志基础路径

def main():
    source_determiner = SourceDeterminer(PROJECT_BASE_PATH, LOG_DIR)
    fully_determiner = FullyDeterminer(PROJECT_BASE_PATH, LOG_DIR)

    all_unified_results = {}

    for project_name in PROJECT_NAMES:
        print(f"\n--- 开始统一分析项目: {project_name} ---")

        # 1. 运行测试脚本以生成污点日志 (假设 test.sh 能够处理多个项目或有其他机制)
        # 注意：这里需要根据实际情况调整 run_test_script 的调用方式，
        # 如果 test.sh 是针对单个项目运行的，可能需要在此处循环调用或调整其逻辑。
        print(f"1. 运行测试脚本为项目 {project_name} 生成日志...")
        # 假设 run_test_script 能够为当前 project_name 生成日志到 LOG_BASE_PATH/LOG_DIR/project_name/
        # 这里需要一个实际的 test_script_path，或者 run_test_script 内部有默认逻辑
        # 为了简化，暂时不传入 test_script_path 和 issue_number，假设它能生成所有项目的日志
        source_determiner.run_test_script(project_name=project_name) # 假设 run_test_script 接受 project_name
        print("测试脚本运行完成。")

        # 假设日志文件路径是固定的，或者可以从 run_test_script 返回
        project_log_dir = os.path.join(LOG_BASE_PATH, LOG_DIR, project_name)
        taint_output_file_pattern = os.path.join(project_log_dir, "*_output.log")
        trace_chain_log_file_pattern = os.path.join(project_log_dir, "*_trace_chain.log")

        # 查找所有生成的 output.log 和 trace_chain.log 文件
        import glob
        taint_output_files = glob.glob(taint_output_file_pattern)
        trace_chain_log_files = glob.glob(trace_chain_log_file_pattern)

        if not taint_output_files or not trace_chain_log_files:
            print(f"警告：未找到项目 {project_name} 的污点日志或调用链日志。跳过。")
            continue

        # 假设每个 output.log 对应一个 trace_chain.log，并且可以通过文件名关联
        # 这里需要更健壮的逻辑来匹配文件，暂时简化处理
        # 假设文件名格式为 <issue_number>_output.log 和 <issue_number>_trace_chain.log
        project_issues = {}
        for taint_file in taint_output_files:
            issue_id_str = os.path.basename(taint_file).split('_')[0]
            try:
                issue_id = int(issue_id_str)
            except ValueError:
                print(f"警告：无法从文件名 {taint_file} 提取 issue ID。跳过。")
                continue

            trace_file = os.path.join(project_log_dir, f"{issue_id}_trace_chain.log")
            if not os.path.exists(trace_file):
                print(f"警告：未找到 issue {issue_id} 的调用链日志 {trace_file}。跳过。")
                continue

            # 2. 提取文件路径和行号 (从 taint_file)
            print(f"  处理 Issue {issue_id}: 提取文件路径和行号...")
            extracted_results = source_determiner.extract_file_paths_and_lines(taint_file)
            if not extracted_results:
                print(f"    未提取到 Issue {issue_id} 的任何文件路径和行号。跳过。")
                continue

            # 3. 提取行号附近的上下文内容 (SourceDeterminer)
            print(f"  处理 Issue {issue_id}: 提取上下文内容...")
            context_content = source_determiner.extract_context_content(extracted_results, project_name)
            if not context_content:
                print(f"    未提取到 Issue {issue_id} 的上下文内容。跳过。")
                continue

            # 4. 与 DeepSeek 交互进行源确定 (SourceDeterminer)
            print(f"  处理 Issue {issue_id}: 与 DeepSeek 交互进行源确定...")
            source_determination_result = source_determiner.interact_with_deepseek(issue_id, context_content, taint_file, project_name, issue_id)
            print(f"    源确定结果: {source_determination_result}")

            # 5. 解析 trace_chain.log 文件，提取调用链信息 (FullyDeterminer)
            print(f"  处理 Issue {issue_id}: 解析调用链信息...")
            all_trace_chains = fully_determiner.parse_trace_chain(trace_file)
            current_trace_chain = all_trace_chains.get(issue_id)

            if not current_trace_chain:
                print(f"    在 {trace_file} 中未找到 Issue {issue_id} 的调用链。跳过。")
                continue
            print("    调用链信息解析完成。")

            # 6. 提取调用链中每个函数的具体实现内容 (FullyDeterminer)
            print(f"  处理 Issue {issue_id}: 提取调用链中函数的具体实现...")
            for call in current_trace_chain:
                file_path = os.path.join(PROJECT_BASE_PATH, project_name, call['file_path'])
                if os.path.exists(file_path):
                    call['content'] = fully_determiner.extract_method_by_line(file_path, int(call['start_line']))
                else:
                    print(f"    警告：找不到文件 {file_path}，无法提取函数内容。")
                    call['content'] = "函数实现不可见或文件不存在"
            print("    函数实现内容提取完成。")

            # 7. 使用 DeepSeek 分析调用链并评估污点传播可靠性 (FullyDeterminer)
            print(f"  处理 Issue {issue_id}: 使用 DeepSeek 分析污点传播...")
            taint_propagation_result = fully_determiner.analyze_trace_with_deepseek(current_trace_chain, taint_file, project_name)
            print(f"    污点传播分析结果: {taint_propagation_result}")

            project_issues[issue_id] = {
                "source_determination": source_determination_result,
                "taint_propagation": taint_propagation_result,
                "extracted_file_info": extracted_results,
                "context_content": context_content,
                "trace_chain": current_trace_chain
            }
        all_unified_results[project_name] = project_issues

    # 8. 将所有项目的统一分析结果写入文件
    output_file = os.path.join(LOG_BASE_PATH, "unified_analysis_results.json")
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(all_unified_results, f, ensure_ascii=False, indent=4)
    print(f"\n所有项目的统一分析结果已写入到 {output_file}")

    print("\n--- 统一分析过程完成 ---")

if __name__ == "__main__":
    main()