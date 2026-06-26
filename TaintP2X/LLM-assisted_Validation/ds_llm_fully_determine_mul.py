import json
import os
from openai import OpenAI
from zhipuai import ZhipuAI
import requests
import sys
import re
from typing import Dict
from ..Source_Identification.llm_client import LLMClient


class FullyDeterminer:
    def __init__(self, project_base_path, log_dir):
        self.project_base_path = project_base_path
        self.log_dir = log_dir
        self.llm_client = LLMClient(api_key="sk-123") # Replace with your actual API key
        self.system_prompt = """
您是一位专门识别代码中污点传播路径的软件安全专家。为了进行精确分析，您需要具备扎实的Python编程能力和污点流分析技能。
现在，您的任务是检查一个开源项目（使用Python编写）中的函数是否存在污点传播。判断标准如下：

1. 污点源：
   - 任何用户可控的输入（如HTTP请求参数、用户上传的文件内容、命令行参数等）
   - 敏感信息（如API密钥、数据库凭据、个人身份信息等）

2. 污点汇聚点（Sink）：
   - 代码执行函数（如eval(), exec(), os.system(), subprocess.run()等）
   - 数据库操作函数（如SQL查询、ORM操作等）
   - 文件操作函数（如open(), write(), read()等）
   - 网络请求函数（如requests.get(), requests.post()等）
   - 模板渲染函数（如Jinja2, Django templates等）
   - 反序列化函数（如pickle.loads(), yaml.load()等）

3. 污点传播路径：
   - 污点数据从源头流向汇聚点，期间可能经过多个函数调用、变量赋值、数据结构传递等。
   - 污点数据在传播过程中未经过充分的净化或验证。

您需要分析给定的代码片段和调用链，判断是否存在污点传播，并说明污点源、传播路径和汇聚点。

请以以下JSON格式返回您的分析：
{
    "issue_number": <问题编号>,
    "is_vulnerability": <true或false>,
    "reason": "<为什么是或不是污点传播的原因>",
    "triggering_conditions": "<如果是污点传播，描述其调用方式和参数>"
}
返回的"reason"和"triggering_conditions"内容需要使用中文。
以下是您需要分析的可疑代码片段和调用链：
"""

    def process_project(self, project_name, taint_output_file, source_determiner_log_dir):
        """
        处理项目的 taint-output.json，根据 SourceDeterminer 的结果进一步分析完整调用链。
        """
        print(f"--- 开始 LLM Fully 验证: {project_name} ---")
        
        project_log_dir = os.path.join(self.log_dir, project_name)
        if not os.path.exists(project_log_dir):
            os.makedirs(project_log_dir)

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

        vulnerable_issues = self._get_vulnerable_issues(project_name, source_determiner_log_dir)
        print(f"SourceDeterminer 确定的可疑 issue: {vulnerable_issues}")
        
        for issue_num in vulnerable_issues:
            if issue_num < 1 or issue_num > len(issues): continue
            
            issue_data = issues[issue_num - 1]
            issue_dir = os.path.join(project_log_dir, str(issue_num))
            if not os.path.exists(issue_dir):
                os.makedirs(issue_dir)
            
            trace_chain = self._extract_trace_chain(issue_data)
            self._interact_with_llm(issue_num, trace_chain, project_name, issue_dir)

    def _get_vulnerable_issues(self, project_name, source_log_dir):
        vulnerable_issues = []
        base_dir = os.path.join(source_log_dir, project_name)
        if not os.path.exists(base_dir): return []
        for item in os.listdir(base_dir):
            if not os.path.isdir(os.path.join(base_dir, item)): continue
            try:
                response_file = os.path.join(base_dir, item, "response_output.json")
                if os.path.exists(response_file):
                    with open(response_file, "r") as f:
                        if json.load(f).get("is_vulnerability", False):
                            vulnerable_issues.append(int(item))
            except: pass
        return sorted(vulnerable_issues)

    def _extract_trace_chain(self, issue_data):
        chain = []
        try:
            # 简化版 Trace 提取
            chain.append(f"Callable: {issue_data.get('data', {}).get('callable')}")
            # 可以扩展更详细的 trace 提取
        except Exception as e:
            chain.append(f"Error extracting trace: {e}")
        return "\n".join(chain)

    def _interact_with_llm(self, issue_number, context, project_name, issue_dir):
        response_file = os.path.join(issue_dir, "response_output.json")
        if os.path.exists(response_file): return

        deepseek_input = f"Issue {issue_number}\n{self.system_prompt}\n\nTrace info:\n {context}\n"
        try:
            response_data = self.llm_client.chat_completion(
                model="deepseek-ai/DeepSeek-V3",
                messages=[{"role": "user", "content": deepseek_input}],
                temperature=0,
                max_tokens=1024,
                response_format={"type": "json_object"}
            )
            if 'choices' in response_data and response_data['choices']:
                with open(response_file, "w") as f:
                    f.write(response_data['choices'][0]['message']['content'])
                print(f"DeepSeek 响应已保存: {response_file}")
        except Exception as e:
            print(f"LLM 交互出错: {e}")

    def get_project_names_starting_with_a(self, base_path):
        """
        获取指定目录下所有以 'a' 开头的项目名称。
        :param base_path: 包含项目目录的根路径。
        :return: 以 'a' 开头的项目名称列表。
        """
        project_names = []
        if not os.path.exists(base_path):
            print(f"错误：路径 {base_path} 不存在。")
            return project_names

        for item in os.listdir(base_path):
            if os.path.isdir(os.path.join(base_path, item)) and item.lower().startswith('a'):
                project_names.append(item)
        return project_names

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

    def extract_vulnerable_issues(self, project_name):
        # 获取所有 issue 的文件夹
        base_dir = os.path.join(self.log_dir, project_name)
        vulnerable_issues = []

        # 遍历实际存在的文件夹
        for item in os.listdir(base_dir):
            folder_path = os.path.join(base_dir, item)
            if not os.path.isdir(folder_path):
                continue
                
            issue_number = int(item)
            response_file = os.path.join(folder_path, "response_output.json")
            
            # 检查文件是否存在
            if not os.path.exists(response_file):
                continue

            # 读取文件内容
            with open(response_file, "r") as file:
                try:
                    data = json.load(file)
                    # 检查 is_vulnerability 是否为 true
                    if data.get("is_vulnerability", False):
                        vulnerable_issues.append(issue_number)
                except json.JSONDecodeError as e:
                    print(f"解析 {response_file} 时出错：{e}")

        # 输出结果
        if vulnerable_issues:
            print("以下 issue 的 is_vulnerability 为 true：")
            for issue in vulnerable_issues:
                print(f"Issue {issue}")
        else:
            print("未找到 is_vulnerability 为 true 的 issue。")

        return vulnerable_issues

    def parse_trace_chain(self, log_file_path):
        """
        解析 trace_chain.log 文件，提取每个 issue 的调用链信息。
        :param log_file_path: trace_chain.log 文件的路径。
        :return: 包含所有 issue 调用链信息的字典。
        """
        issues_trace_chains = {}
        current_issue = None
        current_chain = []

        try:
            with open(log_file_path, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line.startswith('Issue'):
                        if current_issue is not None:
                            issues_trace_chains[current_issue] = current_chain
                        current_issue = int(line.split(' ')[1])
                        current_chain = []
                    elif current_issue is not None and line:
                        current_chain.append(line)
                if current_issue is not None:
                    issues_trace_chains[current_issue] = current_chain
        except FileNotFoundError:
            print(f"错误：文件 {log_file_path} 未找到。")
        except Exception as e:
            print(f"解析文件 {log_file_path} 时出错：{e}")

        return issues_trace_chains

    def get_pure_function_name(self, full_function_name):
        """
        从完整的函数名中提取纯函数名。
        例如：'module.submodule.ClassName.method_name' -> 'method_name'
        'module.function_name' -> 'function_name'
        """
        return full_function_name.split('.')[-1]

    def find_function_implementation(self, function_name: str, project_path: str) -> list:
        """
        在项目中查找函数的具体实现
        """
        results = []

        for root, _, files in os.walk(project_path):
            for file in files:
                if not file.endswith('.py'):
                    continue

                file_path = os.path.join(root, file)
                try:
                    with open(file_path, 'r', encoding='utf-8') as f:
                        lines = f.readlines()

                    for i, line in enumerate(lines):
                        if line.strip().startswith(f'def {function_name}') or \
                           line.strip().startswith(f'async def {function_name}'):
                            method_indent = len(line) - len(line.lstrip())
                            end_line = i + 1

                            while end_line < len(lines):
                                if not lines[end_line].strip():
                                    end_line += 1
                                    continue
                                current_indent = len(lines[end_line]) - len(lines[end_line].lstrip())
                                if current_indent <= method_indent:
                                    break
                                end_line += 1

                            results.append({
                                'file_path': file_path,
                                'content': ''.join(lines[i:end_line]),
                                'line_number': i + 1
                            })

                except Exception as e:
                    print(f"读取文件 {file_path} 时出错: {str(e)}")

        return results

    def get_sanitizer_implementations(self, analysis_results, trace_chain, project_name) -> dict:
        """
        获取分析中提到但未在调用链中出现的过滤函数的具体实现

        Args:
            analysis_results: 分析结果列表
            trace_chain: 调用链列表

        Returns:
            dict: 过滤函数名称及其实现的字典
        """
        # 收集所有提到的过滤函数，但排除已经在调用链中的函数
        sanitizer_functions = set()
        existing_functions = {self.get_pure_function_name(call['function']) for call in trace_chain}

        for result in analysis_results:
            if result['analysis'].get('has_sanitizer') and result['analysis'].get('sanitizer_functions'):
                sanitizer_functions.update(
                    func for func in result['analysis']['sanitizer_functions'] 
                    if func not in existing_functions
                )

        # 查找过滤函数的具体实现
        sanitizer_implementations = {}
        if sanitizer_functions:
            print(f"\n发现以下过滤函数：{sanitizer_functions}")
            project_path = os.path.join(self.project_base_path, project_name)

            for func_name in sanitizer_functions:
                impls = self.find_function_implementation(func_name, project_path)
                if impls:
                    # 如果找到多个实现，使用第一个
                    sanitizer_implementations[func_name] = impls[0]['content']
                    if len(impls) > 1:
                        print(f"警告：函数 {func_name} 找到多个实现，使用第一个实现")
                        for i, impl in enumerate(impls, 1):
                            print(f"实现 #{i} 位于: {impl['file_path']}:{impl['line_number']}")
                else:
                    print(f"未找到函数 {func_name} 的实现")

        return sanitizer_implementations

    def analyze_trace_with_deepseek(self, trace_chain: list, log_file: str, project_name) -> dict:
        """
        使用DeepSeek分析调用链并评估污点传播可靠性

        Args:
            trace_chain: 调用链列表
            log_file: 原始调用链日志文件路径
        """
        # 检查 analysis_results.json 是否已存在
        analysis_results_file = os.path.join(os.path.dirname(log_file), 'analysis_results.json')
        if os.path.exists(analysis_results_file) and os.path.getsize(analysis_results_file) > 0:
            print(f"文件 {analysis_results_file} 已存在且有内容，跳过分析。")
            try:
                with open(analysis_results_file, 'r', encoding='utf-8') as f:
                    return json.load(f)
            except Exception as e:
                print(f"读取已存在的分析结果时出错: {str(e)}")
                # 如果读取出错，继续进行新的分析

        # 读取原始调用链日志
        with open(log_file, 'r') as f:
            output_log_content = f.read()

        analysis_results = []
        print(f"\n开始分析调用链，共 {len(trace_chain)} 个函数...")

        # 提取漏洞类型
        vuln_type = None
        response_json = os.path.join(os.path.dirname(log_file), 'response_output.json')
        if os.path.exists(response_json):
            try:
                with open(response_json, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    if 'vulnerability_types' in data:
                        vuln_type = data['vulnerability_types']
            except Exception as e:
                print(f"读取漏洞类型时出错: {str(e)}")

        # 根据漏洞类型添加特定提示
        type_specific_prompts = {
            "Code_Execution": """
请特别关注以下几点：
1. 是否存在命令拼接或eval类执行函数
2. 命令参数是否经过严格过滤
3. 是否使用了安全的命令执行方式
4. 是否限制了可执行的命令范围
5. 如果通过eval实现的命令执行，污点是否被限制为正确的json格式
6. 污点可以控制的内容是否能影响命令或代码的执行，有些污点即使能传播到sink函数，也不能影响执行何种命令或代码的执行
7. 对于sink点为subprocess.Popen时，要注意shell的值是否为True""",

            "SQL_Injection": """
请特别关注以下几点：
1. SQL语句是否使用参数化查询
2. 是否存在直接字符串拼接
3. 是否对特殊字符进行转义
4. 是否限制了SQL语句的类型""",

            "File_Operation": """
请特别关注以下几点：
1. 文件路径是否进行了规范化处理
2. 是否限制了文件操作的目录范围
3. 是否存在路径穿越的可能

然后你需要分析文件操作的类型是读取文件还是写入文件，这点很重要。

对于写入文件的sink：
1. 污点是否能同时控制文件路径和写入内容
2. 如果污点只能控制其中一个（路径或内容），则不构成有效的漏洞利用
3. 即使其他条件都满足，只要不满足同时控制路径和内容的条件，也必须判定为无效

对于读取文件的sink：
1. 污点是否能控制文件路径，导致任意文件读取
2. 是否对读取的文件路径进行了白名单校验
3. 是否限制了可读取的文件类型和目录范围""",

            "XSS": """
请特别关注以下几点：
1. 输出是否进行了HTML编码
2. 是否使用了安全的模板引擎
3. 是否对大模型的输出进行了严格的过滤""",

            "SSRF": """
1. 检查这些请求的目标地址是否可控，例如是否从用户输入、配置文件或环境变量中获取。
2. 确认是否存在对内部网络资源（如内网IP、本地文件、内部服务）的访问。
3. 评估是否存在绕过URL白名单或黑名单的技巧，例如使用特殊协议（file://, gopher://）、重定向或DNS重绑定。
4. 检查是否存在对请求返回内容的处理，以判断是否可能导致信息泄露或进一步的攻击。
"""
        }

        # 在函数开始处添加已分析函数集合
        analyzed_functions = set()

        for i, call in enumerate(trace_chain, 1):
            # 只使用函数实现内容作为唯一标识
            func_content = call.get('content', '函数实现不可见')

            # 如果已经分析过相同的函数实现，则跳过
            if func_content in analyzed_functions:
                print(f"\n[{i}/{len(trace_chain)}] 跳过重复函数: {call['function']}")
                continue

            print(f"\n[{i}/{len(trace_chain)}] 正在分析函数: {call['function']}")
            analyzed_functions.add(func_content)

            # 构建基础提示信息
            base_prompt = f"""请分析以下调用链中的片段里的污点传播是否有效，请注意，污点源是由用户可控的大模型输出，
在污点传播到sink函数的过程中，可能有过滤函数对污点进行消毒，对于这种过滤函数请你仔细判断污点是否能被消毒成功。
对于污点流，你要分析流入sink函数的污点是否是source的大模型输出可控的，并且还要考虑污点是否有能力触发sink函数导致的漏洞。
注意只需要具体分析片段中的内容。
"""

            # 添加漏洞类型特定的提示
            if vuln_type and isinstance(vuln_type, list):
                for vtype in vuln_type:
                    if vtype in type_specific_prompts:
                        base_prompt += "\n" + type_specific_prompts[vtype]

            # 完整提示信息
            prompt = base_prompt + f"""

请详细分析以下几点：
1. 污点经过的每个函数的具体功能和调用意图
2. 每个函数是如何处理和传递污点数据的
3. 函数之间的调用关系和数据流转过程
4. 是否存在对污点数据的校验或过滤

完整调用链信息：
{output_log_content}

具体调用链片段：

函数名: {call['function']}
参数信息: {call['params']}
函数实现:
{call['content'] if 'content' in call else '函数实现不可见'}

请以JSON格式返回分析结果：
{{
    "issue_number": <调用链编号>,
    "is_taint_valid": true/false,
    "has_sanitizer": true/false,
    "sanitizer_functions": [<过滤函数名称列表>],
    "function_analysis": [
        {{
            "function_name": <函数名>,
            "purpose": <函数调用意图和功能（中文）>,
            "taint_handling": <污点处理方式（中文）>
        }}
    ],
    "analysis_reason": <有效或无效的原因（中文）>
}}
"""

            # 调用DeepSeek进行分析
            try:
                messages = [
                    {"role": "user", "content": prompt}
                ]
                response = self.llm_client.chat_completion(
                    messages=messages,
                    temperature=0,
                    max_tokens=1024,
                    response_format={"type": "json_object"}
                )

                # response = requests.request("POST", url, json=payload, headers=headers)
                # response.raise_for_status()
                # response_json = response.json()

                # if response_json and 'choices' in response_json and response_json['choices']:
                #     message_content = response_json['choices'][0].get('message', {}).get('content')
                #     if message_content:
                #         try:
                #             extracted_analysis = json.loads(message_content)
                #             print("--- LLM Call Analysis Extracted JSON ---")
                #             print(json.dumps(extracted_analysis, indent=4))
                #             call.update(extracted_analysis)
                #             analysis_results.append(call)
                #         except json.JSONDecodeError:
                #             print("Error: Could not decode nested JSON from LLM response content.")
                #             analysis_results.append({"error": "JSON decode error in LLM content", **call})
                #     else:
                #         print("Warning: 'content' field is missing or empty in LLM response message.")
                #         analysis_results.append({"error": "Empty or missing content in LLM response", **call})
                # else:
                #     print("Warning: Unexpected LLM response structure or empty choices.")
                #     analysis_results.append({"error": "Unexpected LLM response structure", **call})

                if response and 'choices' in response and response['choices']:
                    message_content = response['choices'][0].get('message', {}).get('content')
                    if message_content:
                        try:
                            extracted_analysis = json.loads(message_content)
                            print("--- LLM Call Analysis Extracted JSON ---")
                            print(json.dumps(extracted_analysis, indent=4))
                            call.update(extracted_analysis)
                            analysis_results.append(call)
                        except json.JSONDecodeError:
                            print("Error: Could not decode nested JSON from LLM response content.")
                            analysis_results.append({"error": "JSON decode error in LLM content", **call})
                    else:
                        print("Warning: 'content' field is missing or empty in LLM response message.")
                        analysis_results.append({"error": "Empty or missing content in LLM response", **call})
                else:
                    print("Warning: Unexpected LLM response structure or empty choices.")
                    analysis_results.append({"error": "Unexpected LLM response structure", **call})

            except Exception as e:
                print(f"调用DeepSeek API时出错: {str(e)}")
                analysis_results.append({"error": f"DeepSeek API call error: {str(e)}", **call})

        try:
            final_response = self.llm_client.chat_completion(
                messages=[
                    {
                        "role": "user", 
                        "content": chain_prompt + "\n请务必以严格的JSON格式返回结果，不要包含任何其他文本或Markdown标记。确保JSON格式正确且可解析。"
                    }
                ],
                temperature=0,
                max_tokens=1024,
                response_format={"type": "json_object"}
            )

            if final_response and 'choices' in final_response and final_response['choices']:
                json_content = final_response['choices'][0]['message']['content']
                try:
                    final_analysis = json.loads(json_content)
                except json.JSONDecodeError as je:
                    print(f"JSON解析错误，原始内容：\n{json_content}")
                    print(f"错误详情：{str(je)}")
                    final_analysis = {
                        "issue_number": os.path.basename(os.path.dirname(log_file)),
                        "is_vulnerability": False,
                        "reason": "JSON解析错误，无法完成分析",
                        "triggering_conditions": "无法确定",
                        "poc": "无法生成"
                    }
            else:
                print("Warning: Unexpected LLM response structure or empty choices for final analysis.")
                final_analysis = {
                    "issue_number": os.path.basename(os.path.dirname(log_file)),
                    "is_vulnerability": False,
                    "reason": "LLM响应结构异常，无法完成分析",
                    "triggering_conditions": "无法确定",
                    "poc": "无法生成"
                }
                sys.exit(1)  # JSON解析错误也直接退出

        except Exception as e:
            print(f"调用 DeepSeek 进行综合分析时出错: {str(e)}")
            final_analysis = {
                "issue_number": os.path.basename(os.path.dirname(log_file)),
                "is_vulnerability": False,
                "reason": f"DeepSeek API调用错误: {str(e)}",
                "triggering_conditions": "无法确定",
                "poc": "无法生成"
            }

        # 构建输出JSON
        output_json = {
            'issue_id': os.path.basename(os.path.dirname(log_file)),  # 从log_file路径提取issue_id
            'trace_chain': trace_chain,
            'analysis': {
                'individual_analysis': analysis_results,
                'chain_analysis': final_analysis
            }
        }

        # 输出JSON结果
        output_file = os.path.join(os.path.dirname(log_file), 'analysis_results.json')
        os.makedirs(os.path.dirname(output_file), exist_ok=True)

        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(output_json, f, ensure_ascii=False, indent=2)

        print(f"分析结果已保存到: {output_file}")

        return {
            'individual_analysis': analysis_results,
            'chain_analysis': final_analysis
        }


