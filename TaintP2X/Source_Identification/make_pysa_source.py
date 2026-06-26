import json
import os
import re

def extract_and_format_llm_paths(json_file_path, output_file_path):
    """
    从JSON文件中提取LLM函数的full_method_path和参数，并格式化写入文件。
    """
    llm_functions = []
    try:
        with open(json_file_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
    except FileNotFoundError:
        print(f"错误：文件未找到：{json_file_path}")
        return
    except json.JSONDecodeError:
        print(f"错误：无法解码JSON文件：{json_file_path}")
        return

    for entry in data:
        if entry.get('is_llm_call') == True:
            full_method_path = entry.get('full_method_path')
            # 直接从 entry 中获取 method_params
            params = entry.get('method_params')
            if full_method_path and params:
                # 格式化输出，使用提取到的参数
                formatted_line = f"def {full_method_path}( {params} ) -> TaintSource[LLMControlled]: ..."
                llm_functions.append(formatted_line)

    if llm_functions:
        with open(output_file_path, 'w', encoding='utf-8') as f:
            for line in llm_functions:
                f.write(line + '\n')
        print(f"成功将LLM函数路径写入：{output_file_path}")
    else:
        print("未找到任何is_llm_call为true的LLM函数。")

if __name__ == "__main__":
    project_name = 'langchain-0.0.327'

    project_type = 'SSRF'

    json_file = f'/llm_web_serve/base_server/{project_type}/source/{project_name}/llm_analysis_{project_name}.json'
    output_file = f'/llm_web_serve/base_server/{project_type}/source/{project_name}/self_llm_source_{project_name}.pysa'

    extract_and_format_llm_paths(json_file, output_file)