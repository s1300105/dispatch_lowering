import re
import json
import subprocess
import os
from openai import OpenAI
from ..Source_Identification.llm_client import LLMClient


class SourceDeterminer:
    def __init__(self, project_base_path, log_dir):
        self.project_base_path = project_base_path
        self.log_dir = log_dir
        self.llm_client = LLMClient(api_key="sk-123") # Replace with your actual API key
        self.system_prompt = """
您是一位专门识别代码中污点源函数的软件安全专家。为了进行精确分析，您需要具备扎实的Python编程能力和污点流分析技能。
现在，您的任务是检查一个开源项目（使用Python编写）中的函数是否是请求大模型对话API的函数。判断标准如下：

1. 直接调用大模型API的函数：
   - OpenAI API (openai.OpenAI.chat.completions.create)
   - Anthropic API (anthropic.Anthropic.messages.create)
   - DeepSeek API
   - 其他类似的大模型API调用

2. 间接请求大模型API的函数：
   - 使用requests.post/get请求大模型API端点
   - URL包含明显的大模型API特征（如openai.com, api.anthropic.com, api.deepseek.com等）
   - 请求头包含API密钥（Authorization: Bearer sk-...）
   - 请求体包含模型名称、messages等典型大模型API参数
   - 特别要注意区分是请求大模型对话服务还是大模型生成图像服务，如果是大模型生成图像服务则舍弃

3. 使用第三方封装库调用大模型API：
   - LiteLLM (litellm.completion, litellm.completion_with_retries)
   - LangChain (LLMChain, ChatOpenAI等)
   - 其他类似的API封装库（如transformers, autotrain等）

您只需要判断给定的函数是否符合以上标准。
您要判断的函数为调用链中的第一个函数。

请以以下JSON格式返回您的分析：
{
    "issue_number": <问题编号>,
    "is_vulnerability": <true或false>,
    "reason": "<为什么是或不是大模型请求函数的原因>",
    "triggering_conditions": "<如果是大模型请求函数，描述其调用方式和参数>"
}
返回的"reason"和"triggering_conditions"内容需要使用中文。
以下是您需要分析的可疑代码片段和调用链：
"""

    def process_project(self, project_name, taint_output_file):
        """
        直接处理项目的 taint-output.json 文件，执行完整的分析流程。
        """
        print(f"--- 开始 LLM Source 验证: {project_name} ---")
        
        project_log_dir = os.path.join(self.log_dir, project_name)
        self.create_folder(project_log_dir)
        
        # 读取 taint-output.json
        issues = []
        try:
            with open(taint_output_file, 'r') as f:
                content = f.read()
                try:
                    data = json.loads(content)
                    if isinstance(data, list):
                        issues = [i for i in data if i.get('kind') == 'issue']
                    elif isinstance(data, dict) and data.get('kind') == 'issue':
                        issues = [data]
                except json.JSONDecodeError:
                    for line in content.splitlines():
                        if not line.strip(): continue
                        try:
                            item = json.loads(line)
                            if item.get('kind') == 'issue':
                                issues.append(item)
                        except:
                            pass
        except Exception as e:
            print(f"读取 taint-output.json 失败: {e}")
            return

        print(f"共发现 {len(issues)} 个 issue。")

        for i, issue_data in enumerate(issues, 1):
            issue_dir = os.path.join(project_log_dir, str(i))
            self.create_folder(issue_dir)
            
            with open(os.path.join(issue_dir, "issue_data.json"), "w") as f:
                json.dump(issue_data, f, indent=2)

            source_info = self._extract_source_info_from_issue(issue_data)
            
            if not source_info:
                print(f"Issue {i}: 无法提取 Source 信息，跳过。")
                continue
                
            with open(os.path.join(issue_dir, "file_paths_and_lines.json"), "w") as f:
                json.dump([source_info], f, indent=4)
                
            target_path = source_info['file_path']
            # 尝试查找文件的绝对路径
            potential_paths = [
                os.path.join(self.project_base_path, project_name, target_path),
                os.path.join(self.project_base_path, target_path),
                os.path.abspath(target_path)
            ]
            if not os.path.isabs(target_path):
                 potential_paths.append(os.path.join(self.project_base_path, target_path))

            final_path = None
            for p in potential_paths:
                if os.path.exists(p):
                    final_path = p
                    break
            
            if not final_path:
                print(f"警告: 无法找到文件 {target_path}")
                continue
            
            method_content = self.extract_method_by_line(final_path, source_info['line_number'])
            
            context_file = os.path.join(issue_dir, "context_output.txt")
            with open(context_file, "w") as f:
                f.write(f"File: {final_path}, Line: {source_info['line_number']}\n")
                f.write("方法内容：\n")
                f.write(method_content)
                
            self.interact_with_deepseek(i, method_content, project_name, i)

        self.check_and_merge_duplicate_issues(project_name)

    def _extract_source_info_from_issue(self, issue_data):
        try:
            traces = issue_data.get('data', {}).get('traces', [])
            for trace in traces:
                if trace.get('name') == 'source':
                    roots = trace.get('roots', [])
                    if roots:
                        root = roots[0]
                        location = root.get('location')
                        if not location and root.get('leaves'):
                            location = root['leaves'][0].get('location')
                        
                        if location:
                            filename = location.get('filename')
                            if filename and filename.startswith('/'):
                                filename = filename[1:]
                            return {
                                "file_path": filename,
                                "line_number": int(location.get('line')),
                                "function_name": issue_data.get('data', {}).get('callable', 'unknown')
                            }
            return None
        except Exception as e:
            print(f"提取 Source 信息出错: {e}")
            return None

    def count_issues(self, taint_output_file):
        try:
            with open(taint_output_file, "r") as file:
                content = file.read()
            target_string = '"kind":"issue"'
            issue_count = content.count(target_string)
            print(f"检测到 {issue_count} 个 'kind':'issue'。")
            return issue_count
        except FileNotFoundError:
            print(f"错误：文件 {taint_output_file} 未找到。")
            return 0
        except Exception as e:
            print(f"未知错误：{e}")
            return 0

    def create_folder(self, folder_path):
        if not os.path.exists(folder_path):
            os.mkdir(folder_path)
            print(f"文件夹已创建：{folder_path}")
        else:
            print(f"文件夹已存在，跳过创建：{folder_path}")

    def run_test_script(self, project_name):
        test_script_path = ".\\test.sh" 
        try:
            print(f"正在运行 test.sh 脚本，为项目 {project_name} 生成日志...")
            
            # 确保目标目录存在，这里不再创建 issue 相关的子目录，因为 test.sh 应该自己处理
            output_dir = os.path.join(self.log_dir, project_name)
            self.create_folder(output_dir)
                
            # 运行脚本，只传入 project_name
            result = subprocess.run(
                [test_script_path, project_name], 
                check=True, 
                stdout=subprocess.PIPE, 
                stderr=subprocess.PIPE
            )
            
            print(f"test.sh 脚本运行成功，请检查 {output_dir} 目录下的日志文件！")
            
        except subprocess.CalledProcessError as e:
            print(f"test.sh 脚本运行失败！错误信息：{e.stderr.decode().strip()}")
        except Exception as e:
            print(f"运行脚本时发生错误：{str(e)}")

    def extract_file_paths_and_lines(self, input_file, output_file=None):
        try:
            with open(input_file, "r") as file:
                content = file.read()
        except FileNotFoundError:
            print(f"错误：文件 {input_file} 未找到。")
            return []

        # 使用正则表达式匹配文件路径、行号和函数名
        # 匹配格式：servers1/sweep/sweepai/utils/github_utils.py:76|24|23 这样的格式
        pattern = r'([^\s]+\.py):(\d+)\|(\d+)\|(\d+)\s*'
        matches = re.findall(pattern, content)
        results = []
        
        # 使用另一个正则表达式匹配函数名
        func_pattern = r'(\S+)\s+(?:formal|result|leaf|root)'
        func_matches = re.findall(func_pattern, content)
        
        # 合并结果
        for i, (file_path, line_num, _, _) in enumerate(matches):
            func_name = func_matches[i] if i < len(func_matches) else "unknown"
            # 去除函数名中的前缀路径
            func_name = func_name.split('.')[-1] if '.' in func_name else func_name
            
            results.append({
                "file_path": file_path, 
                "line_number": int(line_num),
                "function_name": func_name
            })

        if output_file:
            with open(output_file, "w") as file:
                json.dump(results, file, indent=4)
            print(f"提取结果已写入 {output_file}")
        return results

    def extract_method_by_line(self, file_path: str, target_line: int) -> str:
        """根据指定行号提取整个方法内容"""
        try:
            with open(file_path, 'r') as file:
                lines = file.readlines()
                
            # 确保目标行在文件范围内
            if target_line < 1 or target_line > len(lines):
                return "目标行号超出文件范围"
                
            # 检查目标行是否为空行
            if not lines[target_line - 1].strip():
                return "目标行是空行"
                
            # 向上查找方法开始
            start_line = target_line - 1
            method_found = False
            while start_line >= 0:
                if lines[start_line].strip().startswith('def '):
                    method_found = True
                    break
                start_line -= 1
                
            # 如果没有找到方法定义，返回上下文各5行
            if not method_found:
                context_start = max(0, target_line - 6)  # -6是因为行号从1开始
                context_end = min(len(lines), target_line + 5)  # +5是为了包含目标行后的5行
                return f"目标行不在任何方法内部，显示上下文：\n" + ''.join(lines[context_start:context_end])
                
            # 向下查找方法结束（通过缩进判断）
            method_indent = len(lines[start_line]) - len(lines[start_line].lstrip())
            end_line = target_line
            
            # 检查目标行的缩进是否属于该方法
            target_line_content = lines[target_line - 1].rstrip()
            if not target_line_content:  # 空行
                context_start = max(0, target_line - 6)
                context_end = min(len(lines), target_line + 5)
                return f"目标行是空行，显示上下文：\n" + ''.join(lines[context_start:context_end])
                
            target_indent = len(lines[target_line - 1]) - len(lines[target_line - 1].lstrip())
            if target_indent <= method_indent:
                # 如果目标行不在方法内部，返回上下文各5行
                context_start = max(0, target_line - 6)
                context_end = min(len(lines), target_line + 5)
                return f"目标行不在任何方法内部，显示上下文：\n" + ''.join(lines[context_start:context_end])
                
            while end_line < len(lines):
                # 跳过空行
                if not lines[end_line].strip():
                    end_line += 1
                    continue
                # 如果遇到同级或更低级的缩进，说明方法结束
                current_indent = len(lines[end_line]) - len(lines[end_line].lstrip())
                if current_indent <= method_indent:
                    break
                end_line += 1
                
            # 提取方法内容
            method_content = ''.join(lines[start_line:end_line])
            return method_content
            
        except FileNotFoundError:
            return "文件不存在"
        except Exception as e:
            return f"提取方法时出错：{str(e)}"

    def extract_context_content(self, extracted_results, project_name):
        if not extracted_results:
            print("未找到匹配项以提取上下文。")
            return ""

        first_result = extracted_results[0]
        file_path = os.path.join(self.project_base_path, project_name, first_result['file_path'])
        line_number = first_result['line_number']

        method_content = self.extract_method_by_line(file_path, line_number)
        if method_content:
            return method_content
        else:
            return ""

        full_target_file = os.path.join(self.project_base_path, target_file.lstrip('/'))

        try:
            # 使用extract_method_by_line函数提取完整方法
            method_content = self.extract_method_by_line(full_target_file, target_line)

            with open(context_output_file, "w") as file:
                file.write(f"File: {full_target_file}, Line: {target_line}\n")
                file.write("方法内容：\n")
                file.write(method_content)

            print(f"方法内容已写入 {context_output_file}")
        except Exception as e:
            print(f"提取方法内容时出错：{e}")

    def count_checked_issues(self, project_name):
        """
        统计已经检查过的 issue 个数。
        :param project_name: 项目名称。
        :return: 已检查过的 issue 个数。
        """
        base_dir = os.path.join(self.log_dir, project_name)
        issue_count = 0

        # 检查目标目录是否存在
        if not os.path.exists(base_dir):
            print(f"目录 {base_dir} 不存在。")
            return issue_count

        # 遍历目录下的所有文件夹
        for item in os.listdir(base_dir):
            item_path = os.path.join(base_dir, item)
            if os.path.isdir(item_path):
                issue_count += 1

        print(f"已检查过的 issue 个数：{issue_count}")
        return issue_count

    def is_file_path_checked(self, file_path, project_name):
        """
        检查 file_path 是否已经检查过。
        :param file_path: 需要检查的文件路径。
        :param project_name: 当前项目名称。
        :return: 如果已检查过，返回对应的 response_output.json 文件路径；否则返回 None。
        """
        base_dir = os.path.join(self.log_dir, project_name)

        issue_checked = self.count_checked_issues(project_name)
        
        # 遍历所有 issue 文件夹
        for issue_number in range(1, issue_checked + 1):  
            paths_and_lines_file = os.path.join(base_dir, str(issue_number), "file_paths_and_lines.json")
            
            # 检查 file_paths_and_lines.json 文件是否存在
            if not os.path.exists(paths_and_lines_file):
                continue
            
            # 读取 file_paths_and_lines.json 文件
            with open(paths_and_lines_file, "r") as file:
                try:
                    data = json.load(file)
                    if data and data[0]["file_path"] == file_path:
                        # 如果 file_path 匹配，返回对应的 response_output.json 文件路径
                        response_file = os.path.join(base_dir, str(issue_number), "response_output.json")
                        if os.path.exists(response_file):
                            return response_file
                except json.JSONDecodeError as e:
                    print(f"解析 {paths_and_lines_file} 时出错：{e}")
        
        # 如果未找到匹配的 file_path，返回 None
        return None

    def check_and_merge_duplicate_issues(self, project_name):
        """检查并合并重复的issues"""
        base_dir = os.path.join(self.log_dir, project_name)
        issue_count = self.count_checked_issues(project_name)
        issue_info = {}  # 存储每个issue的首尾信息
        duplicates = {}  # 用于存储重复的issues

        # 首先收集所有issue的首尾信息
        for i in range(1, issue_count + 1):
            paths_file = os.path.join(base_dir, str(i), "file_paths_and_lines.json")
            if not os.path.exists(paths_file):
                continue

            try:
                with open(paths_file, 'r') as f:
                    data = json.load(f)
                    if not data:  # 跳过空文件
                        continue
                    
                    # 获取第一个和最后一个记录
                    first_record = data[0]
                    last_record = data[-1]
                    issue_info[i] = {
                        'first': f"{first_record['file_path']}:{first_record['line_number']}:{first_record['function_name']}",
                        'last': f"{last_record['file_path']}:{last_record['line_number']}:{last_record['function_name']}"
                    }
                    
            except Exception as e:
                print(f"处理文件 {paths_file} 时出错: {e}")

        # 比较不同issue之间的首尾记录
        for i in range(1, issue_count + 1):
            if i not in issue_info:
                continue
            
            for j in range(i + 1, issue_count + 1):
                if j not in issue_info:
                    continue
                    
                # 如果两个issue的首尾记录相同
                if (issue_info[i]['first'] == issue_info[j]['first'] and 
                    issue_info[i]['last'] == issue_info[j]['last']):
                    # 使用首尾特征组合作为key
                    key = f"{issue_info[i]['first']}|{issue_info[i]['last']}"
                    if key not in duplicates:
                        duplicates[key] = []
                    if i not in duplicates[key]:
                        duplicates[key].append(i)
                    if j not in duplicates[key]:
                        duplicates[key].append(j)

        # 合并重复的issues
        for key, issue_numbers in duplicates.items():
            if len(issue_numbers) > 1:
                # 保留编号最小的issue
                keep_issue = min(issue_numbers)
                remove_issues = [i for i in issue_numbers if i != keep_issue]
                print(f"发现重复issues {issue_numbers}，保留编号最小的 {keep_issue}")
                
                # 删除其他重复的issue文件夹
                for remove_issue in remove_issues:
                    remove_dir = os.path.join(base_dir, str(remove_issue))
                    try:
                        if os.path.exists(remove_dir):
                            import shutil
                            shutil.rmtree(remove_dir)
                            print(f"已删除重复issue目录: {remove_dir}")
                    except Exception as e:
                        print(f"删除目录 {remove_dir} 时出错: {e}")

        return duplicates

    def interact_with_deepseek(self, issue_number, context, project_name, i):
        try:
            # 构造目标文件路径
            response_file = os.path.join(self.log_dir, project_name, str(i), "response_output.json")

            # 检查目标文件是否存在且有内容
            if os.path.exists(response_file) and os.path.getsize(response_file) > 0:
                print(f"文件 {response_file} 已存在且有内容，跳过分析。")
                return

            # 读取 file_paths_and_lines.json 文件，获取第一个 file_path
            paths_and_lines_file = os.path.join(self.log_dir, project_name, str(i), "file_paths_and_lines.json")
            with open(paths_and_lines_file, "r") as file:
                file_path_data = json.load(file)
                first_file_path = file_path_data[0]["file_path"] if file_path_data else None
                first_function_name = file_path_data[0]["function_name"] if file_path_data else None

                # 检查 file_paths_and_lines 文件中最后一个函数的 file_path 是否有效
                # 读取 output.log 文件内容
                output_log_path = os.path.join(self.log_dir, project_name, str(i), "output.log")
                output_log_content = ""
                if os.path.exists(output_log_path):
                    with open(output_log_path, 'r') as f:
                        output_log_content = f.read()

                # 检查 output.log 中最后一个函数的文件路径是否无效
                # 假设无效路径的模式是 "*:" 或 "leaf:*" 出现在 output.log 的最后几行
                # 这里需要根据实际 output.log 的格式进行调整
                # 暂时使用一个简单的字符串匹配作为示例
                if "*:" in output_log_content or "leaf:*" in output_log_content:
                    # 进一步细化，检查是否是最后一个函数的位置无效
                    # 这需要更复杂的解析逻辑，例如查找最后一个函数调用的模式
                    # 暂时简化为只要包含这些字符串就认为是无效
                    print(f"Issue {i} 的 output.log 中检测到无效函数位置，跳过分析。")
                    default_response = {
                        "issue_number": i,
                        "is_vulnerability": False,
                        "reason": "调用链最后一个函数位置无效，无法准确判断",
                        "triggering_conditions": ""
                    }
                    with open(response_file, 'w') as f:
                        json.dump(default_response, f, indent=2, ensure_ascii=False)
                    return

            # 检查 first_file_path 是否已经检查过
            if first_file_path:
                checked_response_file = self.is_file_path_checked(first_file_path, project_name)
                if checked_response_file:
                    # 如果已检查过，直接复制 response_output.json 文件
                    import shutil
                    shutil.copyfile(checked_response_file, response_file)
                    print(f"文件 {first_file_path} 已检查过，直接复制 {checked_response_file} 到 {response_file}。")
                    return

            # 构造发送给 DeepSeek 的内容（直接使用传入的context字符串）
            deepseek_input = f"Issue {issue_number}\n{self.system_prompt}\n\ncode snippet:\n {context}\n"

            try:
                response_data = self.llm_client.chat_completion(
                    model="deepseek-ai/DeepSeek-V3",
                    messages=[
                        {
                            "role": "user",
                            "content": deepseek_input
                        }
                    ],
                    temperature=0,
                    max_tokens=1024,
                    response_format={"type": "json_object"}
                )

                if 'choices' not in response_data or not response_data['choices']:
                    print("DeepSeek API返回数据格式错误")
                    sys.exit(1)

                # 去掉内容中的 Markdown 格式（```json```）和换行符
                json_content = response_data['choices'][0]['message']['content']

                # 将响应内容写入文件
                with open(response_file, "w") as file:
                    file.write(json_content)

                print(f"DeepSeek 的响应已保存到 {response_file}")

            except Exception as api_error:
                error_message = str(api_error)
                print(f"与 DeepSeek API 交互时发生错误：{error_message}")
                if "json.decoder.JSONDecodeError" in error_message:
                    with open(response_file.replace(".json", "_raw.txt"), "w") as f_raw:
                        f_raw.write(str(response_data))
                    print(f"原始响应已保存到 {response_file.replace(".json", "_raw.txt")}")
                sys.exit(1)
        except Exception as e:
                print(f"处理 issue {issue_number} 时发生未知错误：{str(e)}")





# if __name__ == "__main__":
#     # 示例用法
#     # 假设 project_name, test_script_path, test_script_arg1, test_script_arg2 都是从外部传入的
#     # 例如：python your_script.py my_project /path/to/test.sh arg1 1
#     if len(sys.argv) != 5:
#         print("用法: python ds_llm_source_determine_mul.py <project_name> <test_script_path> <test_script_arg1> <issue_number>")
#         sys.exit(1)

#     project_name = sys.argv[1]
#     test_script_path = sys.argv[2]
#     test_script_arg1 = sys.argv[3]
#     issue_number = int(sys.argv[4])

#     # 创建文件夹
#     output_dir = f"log_zhipu/{project_name}/{issue_number}"
#     create_folder(output_dir)

#     # 运行 test.sh 脚本
#     run_test_script(test_script_path, test_script_arg1, issue_number, project_name)

#     # 提取文件路径和行号
#     taint_output_file = f"log_zhipu/{project_name}/{issue_number}/output.log"
#     file_paths_and_lines_file = f"log_zhipu/{project_name}/{issue_number}/file_paths_and_lines.json"
#     results = extract_file_paths_and_lines(taint_output_file, file_paths_and_lines_file)

#     # 提取行号附近的上下文内容
#     context_output_file = f"log_zhipu/{project_name}/{issue_number}/context_output.txt"
#     extract_context_content(results, project_name, context_output_file)

#     # 与 DeepSeek 交互
#     interact_with_deepseek(issue_number, context_output_file, taint_output_file, project_name, issue_number)

#     # 检查并合并重复的 issues
#     check_and_merge_duplicate_issues(project_name)




