import json
import os
import requests

def extract_method_by_line(file_path: str, target_line: int) -> str:
    """根据指定行号提取内容，小文件取全部，大文件取前200行+目标行上下文，并标明行号和文件名"""
    try:
        with open(file_path, 'r') as file:
            lines = file.readlines()
            
        total_lines = len(lines)
        
        output_content = []
        output_content.append(f"文件: {file_path}\n")

        if total_lines <= 400:
            for i, line in enumerate(lines):
                output_content.append(f"{i + 1:4d}: {line}")
        else:
            # 获取前200行
            for i, line in enumerate(lines[:200]):
                output_content.append(f"{i + 1:4d}: {line}")
            output_content.append("...") # 添加省略号表示中间有省略
            
            # 计算目标行上下文范围
            context_start = max(0, target_line - 101)  # 前100行
            context_end = min(total_lines, target_line + 100)  # 后100行
            
            # 确保上下文不与前200行重叠
            if context_start < 200:
                context_start = 200

            for i in range(context_start, context_end):
                output_content.append(f"{i + 1:4d}: {lines[i]}")
        
        return "".join(output_content)
        
    except FileNotFoundError:
        return "文件不存在"
    except Exception as e:
        return f"提取内容时出错：{str(e)}"

def find_target_function_and_extract_code(json_file_path: str, project_base_path: str):
    try:
        with open(json_file_path, 'r', encoding='utf-8') as f:
            data = json.load(f)

        extracted_code_content = ""
        output_dir = ""
        line_number = None

        # 遍历数据，从后往前查找
        # 优先查找三个line_number相同的函数
        if len(data) >= 3: # 确保至少有三个元素可以检查
            for i in range(len(data) - 1, 1, -1): # 从倒数第二个元素开始往前遍历，确保有i-2, i-1, i
                # 检查当前元素、前一个元素和前两个元素的line_number是否相同
                if data[i]['line_number'] == data[i-1]['line_number'] and data[i-1]['line_number'] == data[i-2]['line_number']:
                    # 找到三个line_number相同的函数，提取这三个函数中第一个函数的代码 (即 data[i-2])
                    target_func_info = data[i-2]
                    file_path_relative = target_func_info['file_path']
                    line_number = target_func_info['line_number']
                    full_file_path = os.path.join(project_base_path, file_path_relative)

                    print(f"找到目标函数（三个相同行号中的第一个）：\n  文件路径: {full_file_path}\n  记录行号: {line_number}\n  函数名: {target_func_info['function_name']}")
                    extracted_code_content += f"下面是一些代码片段，你要在这些代码片段中判断出第一个函数的代码中的第{line_number}行函数传入的提示词是否是用户可控的。\n"
                    extracted_code_content += f"用户可控的提示词一般是由函数的参数传入的,提示词最开始是从参数传入就视为用户可控，如果是函数参数传入提示词模板得到也可以视为用户可控，如果有历史内容，那么也视为用户可控\n"
                    extracted_code_content += f"用户不可控的提示词是指提示词是固定的或者由用户不可控因素决定的\n"
                    extracted_code_content += f"做出判断后，你要以json格式返回判断结果和原因，格式如下：\n"
                    extracted_code_content += """{"is_user_controlled": bool,"reason": "提示词通过函数参数 `user_input` 传入，因此是用户可控的。"}\n"""
                    extracted_code_content += f"### 第一个函数的代码 ###\n"
                    extracted_code_content += extract_method_by_line(full_file_path, line_number)
                    extracted_code_content += "\n\n"
                    
                    # 继续向前遍历，找到第一个行号不同的函数
                    next_diff_func_found = False
                    for k in range(i + 1, len(data)): # 从当前三个相同行号的最后一个函数之后开始遍历
                        if data[k]['line_number'] != data[i]['line_number']:
                            diff_func_info = data[k]
                            diff_file_path_relative = diff_func_info['file_path']
                            diff_line_number = diff_func_info['line_number']
                            diff_full_file_path = os.path.join(project_base_path, diff_file_path_relative)
                            
                            print(f"找到第一个行号不同的函数：\n  文件路径: {diff_full_file_path}\n  行号: {diff_line_number}\n  函数名: {diff_func_info['function_name']}")
                            extracted_code_content += f"### 第二个函数的代码 ###\n"
                            extracted_code_content += extract_method_by_line(diff_full_file_path, diff_line_number)
                            extracted_code_content += "\n\n"
                            next_diff_func_found = True
                            break
                    
                    print("\n提取到的代码内容：")
                    print(extracted_code_content)
                    break # 找到并处理完后跳出循环

        # 如果没有找到三个相同的，或者找到了但extracted_code_content为空，回退到查找两个line_number相同的函数
        if not extracted_code_content and len(data) >= 2:
            for i in range(len(data) - 1, 0, -1):
                # 检查当前元素和前一个元素的line_number是否相同
                if data[i]['line_number'] == data[i-1]['line_number']:
                    # 找到两个line_number相同的函数，取其前一个函数
                    if i - 2 >= 0:
                        target_func_info = data[i-2]
                        file_path_relative = target_func_info['file_path']
                        line_number = target_func_info['line_number']

                        full_file_path = os.path.join(project_base_path, file_path_relative)

                        print(f"找到目标函数（两个相同行号的前一个）：\n  文件路径: {full_file_path}\n  记录行号: {line_number}\n  函数名: {target_func_info['function_name']}")
                        extracted_code_content += f"下面是一些代码片段，你要在这些代码片段中判断出第{line_number}行函数传入的提示词是否是用户可控的。\n"
                        extracted_code_content += f"用户可控的提示词一般是由函数的参数传入的,提示词最开始是从参数传入就视为用户可控,如果是函数参数传入提示词模板得到也可以视为用户可控，如果有历史内容，那么也视为用户可控\n"
                        extracted_code_content += f"用户不可控的提示词是指提示词是固定的或者由用户不可控因素决定的\n"
                        extracted_code_content += f"做出判断后，你要以json格式返回判断结果和原因，格式如下：\n"
                        extracted_code_content += """{"is_user_controlled": bool,"reason": "提示词通过函数参数 `user_input` 传入，因此是用户可控的。"}\n"""
                        extracted_code_content += extract_method_by_line(full_file_path, line_number)
                        print("\n提取到的代码内容：")
                        print(extracted_code_content)
                        break # 找到后跳出循环

        if not extracted_code_content:
            print("未找到符合条件的函数。")
            return None, None

        # 从json_file_path中解析出项目名称和issue编号
        parts = json_file_path.split(os.sep)
        if len(parts) >= 4 and parts[-4] == 'prompt_from_user2':
            project_name = parts[-3]
            issue_number = parts[-2]
            output_dir = os.path.join(os.path.dirname(__file__), 'prompt_from_user2', project_name, issue_number)
        else:
            output_dir = os.path.join(os.path.dirname(__file__), "issue")

        os.makedirs(output_dir, exist_ok=True)
        output_file_path = os.path.join(output_dir, "extracted_code_issue.txt")
        with open(output_file_path, 'w', encoding='utf-8') as outfile:
            outfile.write(extracted_code_content)
        print(f"\n提取到的代码已保存到：{output_file_path}")
        
        return output_dir, line_number

    except FileNotFoundError:
        print(f"错误：文件 {json_file_path} 不存在。")
        return None, None
    except json.JSONDecodeError:
        print(f"错误：文件 {json_file_path} 不是有效的 JSON 格式。会导致 {json_file_path} 文件无法被解析。")
        return None, None
    except Exception as e:
        print(f"发生错误：{str(e)}")
        return None, None

def call_deepseek_api(prompt: str) -> dict:
    """调用DeepSeek API进行分析"""
    url = "https://api.siliconflow.cn/v1/chat/completions"
    payload = {
        "model": "Pro/deepseek-ai/DeepSeek-V3",
        "messages": [
            {
                "role": "user",
                "content": prompt
            }
        ],
        "temperature": 0,
        "max_tokens": 1024,
        "response_format": {"type": "json_object"}
    }
    headers = {
        "Authorization": "Bearer sk-123",
        "Content-Type": "application/json"
    }

    try:
        response = requests.request("POST", url, json=payload, headers=headers)
        response.raise_for_status()  # Raise HTTPError for bad responses (4xx or 5xx)
        response_data = response.json()
        if 'choices' not in response_data or not response_data['choices']:
            print("DeepSeek API返回数据格式错误")
            return {"error": "DeepSeek API返回数据格式错误"}
        
        json_content = response_data['choices'][0]['message']['content']
        return json.loads(json_content)
    except requests.exceptions.RequestException as e:
        print(f"DeepSeek API调用出错: {e}")
        return {"error": f"DeepSeek API调用出错: {e}"}
    except json.JSONDecodeError as e:
        print(f"JSON解析错误，原始内容：\n{response.text if 'response' in locals() else '无响应内容'}")
        print(f"错误详情：{e}")
        return {"error": f"JSON解析错误: {e}"}

def process_with_deepseek(output_dir: str, line_number: int):
    """将提取的代码发送给DeepSeek API并保存结果"""
    if not output_dir:
        print("无效的输出目录")
        return
    
    input_file = os.path.join(output_dir, "extracted_code_issue.txt")
    output_file = os.path.join(output_dir, "deepseek_response.json")
    
    try:
        with open(input_file, 'r', encoding='utf-8') as f:
            prompt_content = f.read()
        
        print("\n正在将代码发送给DeepSeek API进行分析...")
        response = call_deepseek_api(prompt_content)
        
        print("\nDeepSeek API响应：")
        print(json.dumps(response, indent=2, ensure_ascii=False))
        
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(response, f, indent=2, ensure_ascii=False)
        
        print(f"\nDeepSeek API响应已保存到：{output_file}")
        
    except FileNotFoundError:
        print(f"错误：文件 {input_file} 不存在。")
    except Exception as e:
        print(f"处理DeepSeek响应时出错：{str(e)}")

def check_vulnerability_status(repo_name: str, issue_number: str, info_file_path: str) -> bool:
    """
    检查 simple_issues_info.txt 文件中指定仓库和issue是否存在漏洞。
    :param repo_name: 仓库名称。
    :param issue_number: Issue编号。
    :param info_file_path: simple_issues_info.txt 文件的路径。
    :return: 如果存在漏洞返回True，否则返回False。
    """
    try:
        with open(info_file_path, 'r', encoding='utf-8') as f:
            # 跳过标题行
            next(f)
            for line in f:
                parts = line.strip().split('\t')
                if len(parts) == 3:
                    current_repo_name, current_issue_number, has_vulnerability = parts
                    if current_repo_name == repo_name and current_issue_number == issue_number:
                        # 修改此处，将字符串 'True' 识别为 True，'False' 识别为 False
                        return has_vulnerability.lower() == 'true'
        return False
    except FileNotFoundError:
        print(f"错误：信息文件 {info_file_path} 不存在。")
        return False
    except Exception as e:
        print(f"读取信息文件时发生错误：{str(e)}")
        return False

def process_all_projects(prompt_user_dir: str, project_base_path: str):
    """
    遍历prompt_user_dir目录下的所有项目，处理每个项目中的issue
    :param prompt_user_dir: 包含多个项目的目录（如prompt_from_user2）
    :param project_base_path: 项目基础路径（servers1的父目录）
    """
    # simple_issues_info.txt 文件的路径
    simple_issues_info_path = os.path.join(os.path.dirname(__file__), 'prompt_from_user2', 'simple_issues_info.txt')

    # 遍历prompt_user_dir下的所有项目
    for project_name in os.listdir(prompt_user_dir):
        project_path = os.path.join(prompt_user_dir, project_name)
        
        # 确保是目录
        if not os.path.isdir(project_path):
            continue
            
        print(f"\n处理项目: {project_name}")
        
        # 遍历项目中的issue目录
        for issue_name in os.listdir(project_path):
            issue_path = os.path.join(project_path, issue_name)
            
            # 确保是目录
            if not os.path.isdir(issue_path):
                continue
                
            json_file = os.path.join(issue_path, 'file_paths_and_lines.json')
            
            if os.path.exists(json_file):
                print(f"  处理issue: {issue_name}")
                
                # 检查是否存在漏洞
                if check_vulnerability_status(project_name, issue_name, simple_issues_info_path):
                    print(f"    Issue {issue_name} 存在漏洞，继续处理...")
                    # 提取代码并保存到文件
                    output_dir, line_number = find_target_function_and_extract_code(json_file, project_base_path)
                    
                    # 如果成功提取代码，则发送给DeepSeek API
                    if output_dir and line_number:
                        process_with_deepseek(output_dir, line_number)
                else:
                    print(f"    Issue {issue_name} 不存在漏洞，跳过处理。")
            else:
                print(f"  issue {issue_name} 中未找到file_paths_and_lines.json文件")

if __name__ == "__main__":
    # 请根据您的实际情况调整这两个路径
    # json_file = 'llm_web_serve/LLM_determine/prompt_from_user/Mbonea-Mjema__VividCut-AI/1/file_paths_and_lines.json'
    # project_base_path 应该是 servers1 目录的父目录，即 /llm_web_serve/
    # project_base = '/llm_web_serve/' 
    
    # # 提取代码并保存到文件
    # output_dir, line_number = find_target_function_and_extract_code(json_file, project_base)
    
    # # 如果成功提取代码，则发送给DeepSeek API
    # if output_dir and line_number:
    #     process_with_deepseek(output_dir, line_number)

    # 调用新的函数来处理所有项目
    prompt_from_user2_dir = '/llm_web_serve/LLM_determine/prompt_from_user2'
    project_base_for_all = '/llm_web_serve/' # 根据实际情况调整
    process_all_projects(prompt_from_user2_dir, project_base_for_all)