import subprocess
import os
import shutil
import time
import json
from concurrent.futures import ThreadPoolExecutor
import threading

def is_valid_git_repo(path):
    """检查是否为有效的git仓库"""
    try:
        result = subprocess.run(
            ["git", "rev-parse", "--git-dir"],
            cwd=path,
            capture_output=True,
            text=True
        )
        return result.returncode == 0
    except:
        return False

def run_pysa_check(folder):
    """对指定文件夹运行 pysa 检查"""
    config = {
        "site_package_search_strategy": "pep561",
        "source_directories": [folder],
        "taint_models_path": ["./Taint_Propagation/taint",
    "{folder}/source"],
        "search_path": ["./Taint_Propagation/stubs"],
    }
    
    # 写入配置文件
    with open("./Taint_Propagation/.pyre_configuration", "w") as f:
        json.dump(config, f, indent=2)
    
    folder_name = os.path.basename(folder)
    output_dir = f"{folder}/pysa-runs_{folder_name}"
    
    # 运行检查，添加20分钟超时限制
    command = f"pyre analyze --no-verify --save-results-to {output_dir}"
    try:
        result = subprocess.run(command, shell=True, cwd=".", timeout=1200)  # 1200秒 = 20分钟
    except subprocess.TimeoutExpired:
        print(f"检查超时（超过20分钟），跳过项目：{folder_name}")
        if os.path.exists(output_dir):
            shutil.rmtree(output_dir)
        return False
    
    if result.returncode == 0:
        # 检查结果
        taint_output_file = os.path.join(output_dir, "taint-output.json")
        if os.path.exists(taint_output_file):
            with open(taint_output_file, "r") as f:
                content = f.read()
                if '"kind":"issue"' in content:
                    # 复制结果到保存目录
                    target_dir = "./pysa_result"
                    if not os.path.exists(target_dir):
                        os.makedirs(target_dir)
                    target_folder = os.path.join(target_dir, f"pysa-runs_{folder_name}")
                    if os.path.exists(target_folder):
                        shutil.rmtree(target_folder)
                    shutil.copytree(output_dir, target_folder)
                    return True
    return False

def backup_checked_repos(checked_repos_file):
    """备份检查记录文件"""
    if os.path.exists(checked_repos_file):
        backup_dir = os.path.join(os.path.dirname(checked_repos_file), "backups")
        if not os.path.exists(backup_dir):
            os.makedirs(backup_dir)
        timestamp = time.strftime("%Y%m%d_%H%M%S")
        backup_file = os.path.join(backup_dir, f"checked_repos_{timestamp}.json")
        shutil.copy2(checked_repos_file, backup_file)

def process_github_repo(repo, download_dir, max_retries=3):
    """下载并检查GitHub仓库"""
    start_time = time.time()  # 记录开始时间
    timeout = 1200  # 20分钟超时(1200秒)
    
    # 从完整的repo_url中解析出 owner/repo_name
    # 例如：https://github.com/owner/repo_name.git -> owner/repo_name
    full_repo_name = repo.replace("https://github.com/", "").replace(".git", "")
    # 使用 full_repo_name 作为目录名，并将斜杠替换为下划线，避免路径问题
    unique_dir_name = full_repo_name.replace("/", "__")
    target_dir = os.path.join(download_dir, unique_dir_name)
    
    # 使用 full_repo_name 作为 checked_repos.json 中的键
    repo_key = full_repo_name
    
    # 检查是否已经分析过
    checked_repos_file = "./checked_repos.json"
    
    # 使用文件锁读取检查记录
    with file_lock:
        checked_repos = {}
        if os.path.exists(checked_repos_file):
            try:
                with open(checked_repos_file, 'r') as f:
                    content = f.read().strip()
                    if content:  # 确保文件不是空的
                        checked_repos = json.loads(content)
            except json.JSONDecodeError:
                print(f"警告: checked_repos.json 格式错误，将重新创建")
                # backup_checked_repos(checked_repos_file)
            except Exception as e:
                print(f"警告: 读取 checked_repos.json 时出错: {str(e)}")
                # backup_checked_repos(checked_repos_file)

    if repo_key in checked_repos:
        print(f"仓库 {full_repo_name} 已经分析过，跳过下载和分析")
        return True
        
    # 检查是否已存在且完整
    if os.path.exists(target_dir):
        if is_valid_git_repo(target_dir):
            print(f"仓库已存在，跳过检查: {target_dir}")
            return True
        else:
            print(f"发现不完整仓库，删除: {target_dir}")
            shutil.rmtree(target_dir)
    
    # 下载仓库
    for attempt in range(max_retries):
        try:
            # 检查是否超时
            if time.time() - start_time > timeout:
                print(f"总时间超过20分钟，跳过仓库: {full_repo_name}")
                return False
                
            print(f"克隆 {full_repo_name} 到 {target_dir}... (尝试 {attempt + 1}/{max_retries})")
            subprocess.run(["git", "clone", repo, target_dir], check=True, timeout=timeout - (time.time() - start_time))
            print(f"下载成功: {target_dir}")
            
            # 检查是否超时
            if time.time() - start_time > timeout:
                print(f"总时间超过20分钟，跳过仓库: {full_repo_name}")
                shutil.rmtree(target_dir)
                return False
                
            # 调用 analyze_assignments.py 进行分析
            try:
                # 导入 analyze_assignments 模块
                from Source_Identification.analyze_assignments import run_analysis
                print(f"开始对仓库 {full_repo_name} 进行 AST 分析...")
                # 调用 run_analysis 函数，传入下载的仓库路径
                run_analysis(target_dir)
                print(f"仓库 {full_repo_name} 的 AST 分析完成。")
            except ImportError:
                print("错误: 无法导入 analyze_assignments 模块。请确保 analyze_assignments.py 在正确的路径下。")
            except Exception as e:
                print(f"对仓库 {full_repo_name} 进行 AST 分析时发生错误: {str(e)}")

            # 调用 confirm_source.py 进行检查
            try:
                from Source_Identification.confirm_source import run_confirm_source
                print(f"开始对仓库 {full_repo_name} 进行 LLM 调用确认...")
                # project_name 可以从 full_repo_name 获取
                run_confirm_source(target_dir)
                print(f"仓库 {full_repo_name} 的 LLM 调用确认完成。")
            except ImportError:
                print("错误: 无法导入 confirm_source 模块。请确保 confirm_source.py 在正确的路径下。")
            except Exception as e:
                print(f"对仓库 {full_repo_name} 进行 LLM 调用确认时发生错误: {str(e)}")

            # 调用 make_pysa_source.py 生成 pysa source
            try:
                from Source_Identification.make_pysa_source import extract_and_format_llm_paths
                print(f"开始为仓库 {full_repo_name} 生成 Pysa Source...")
                project_name = unique_dir_name # project_name 就是 unique_dir_name
                json_file = f'{target_dir}/source/llm_analysis_{project_name}.json'
                output_file = f'{target_dir}/source/self_llm_source_{project_name}.pysa'
                extract_and_format_llm_paths(json_file, output_file)
                print(f"仓库 {full_repo_name} 的 Pysa Source 生成完成。")
            except ImportError:
                print("错误: 无法导入 make_pysa_source 模块。请确保 make_pysa_source.py 在正确的路径下。")
            except Exception as e:
                print(f"为仓库 {full_repo_name} 生成 Pysa Source 时发生错误: {str(e)}")

            # 检查是否有问题
            has_issue = run_pysa_check(target_dir)

            if has_issue:
                try:
                    # 集成 LLM 验证
                    import sys
                    llm_val_dir = os.path.abspath("LLM-assisted_Validation")
                    if llm_val_dir not in sys.path:
                        sys.path.append(llm_val_dir)
                    
                    from ds_llm_source_determine_mul import SourceDeterminer
                    from ds_llm_fully_determine_mul import FullyDeterminer
                    
                    print(f"开始对仓库 {full_repo_name} 进行 LLM 深度验证...")
                    log_dir = os.path.abspath("./llm_validation_logs")
                    if not os.path.exists(log_dir): os.makedirs(log_dir)
                    
                    # 实例化
                    source_determiner = SourceDeterminer(os.path.abspath(download_dir), log_dir)
                    fully_determiner = FullyDeterminer(os.path.abspath(download_dir), log_dir)
                    
                    taint_output_file = os.path.abspath(f"./pysa_result/pysa-runs_{unique_dir_name}/taint-output.json")
                    
                    if os.path.exists(taint_output_file):
                        source_determiner.process_project(unique_dir_name, taint_output_file)
                        fully_determiner.process_project(unique_dir_name, taint_output_file, log_dir)
                        print(f"仓库 {full_repo_name} 的 LLM 深度验证完成。")
                    else:
                        print(f"警告: 未找到污点分析结果文件 {taint_output_file}")
                        
                except Exception as e:
                    print(f"LLM 验证出错: {e}")
                    import traceback
                    traceback.print_exc()
            
            # 使用文件锁更新检查记录
            with file_lock:
                # 重新读取最新记录
                current_records = {}
                if os.path.exists(checked_repos_file):
                    with open(checked_repos_file, 'r') as f:
                        content = f.read().strip()
                        if content:
                            current_records = json.loads(content)
                
                # 更新记录
                current_records[repo_key] = {
                    "checked_time": time.time(),
                    "has_issues": has_issue
                }
                
                # 备份并写入更新后的记录
                # backup_checked_repos(checked_repos_file)
                with open(checked_repos_file, 'w') as f:
                    json.dump(current_records, f, indent=2)
            
            # 如果没有问题，删除结果
            if not has_issue:
                print(f"未发现问题，删除仓库: {target_dir}")
                shutil.rmtree(target_dir)
                output_dir = f"./pysa_result/pysa-runs_{unique_dir_name}"
                if os.path.exists(output_dir):
                    shutil.rmtree(output_dir)


            return True
            
        except subprocess.TimeoutExpired:
            print(f"操作超时，跳过仓库: {full_repo_name}")
            if os.path.exists(target_dir):
                shutil.rmtree(target_dir)
            return False
        except subprocess.CalledProcessError as e:
            print(f"尝试 {attempt + 1} 失败: {e}")
            if os.path.exists(target_dir):
                shutil.rmtree(target_dir)
            
            if attempt < max_retries - 1:
                print("等待 5 秒后重试...\n")
                time.sleep(5)
            else:
                print(f"达到最大重试次数，放弃下载 {full_repo_name}\n")
                return False

def read_repos_from_json(file_path):
    """从 JSON 文件读取仓库列表"""
    with open(file_path, "r") as f:
        data = json.load(f)
        repos = set()  # 使用集合去重
        # popular_projects.json 是一个列表，每个元素是一个字典
        for repo_info in data:
            # 提取 "nameWithOwner" 字段作为仓库名称
            # 提取完整的 git clone URL
            repo_url = repo_info.get("url")
            if repo_url:
                repos.add(repo_url)
    return list(repos)

# 添加线程锁用于同步文件写入
file_lock = threading.Lock()

def process_github_repo_with_lock(repo_url, download_dir, max_retries=3):
    """带有文件锁的仓库处理函数"""
    try:
        return process_github_repo(repo_url, download_dir, max_retries)
    except Exception as e:
        # 从 URL 中解析出 full_repo_name 用于错误日志
        full_repo_name = repo_url.replace("https://github.com/", "").replace(".git", "")
        print(f"处理仓库 {repo_url} 时发生错误: {str(e)}")
        return False

if __name__ == "__main__":
    json_path = "./test_source.json"
    download_dir = "./project"
    
    if not os.path.exists(download_dir):
        os.makedirs(download_dir)
    
    # 从 JSON 文件读取仓库列表
    repos = read_repos_from_json(json_path)
    failed_repos = []
    
    print(f"找到 {len(repos)} 个仓库需要处理")
    
    # 使用线程池执行下载和检测任务
    max_workers = 4  # 可以根据需要调整线程数
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        # 提交所有任务并获取Future对象
        future_to_repo = {
            executor.submit(process_github_repo_with_lock, repo, download_dir): repo 
            for repo in repos
        }
        
        # 收集失败的仓库
        for future in future_to_repo:
            repo = future_to_repo[future]
            try:
                success = future.result()
                if not success:
                    failed_repos.append(repo)
            except Exception as e:
                print(f"处理仓库 {repo} 时发生异常: {str(e)}")
                failed_repos.append(repo)
    
    if failed_repos:
        print("\n下载失败的仓库:")
        for repo in failed_repos:
            print(f"- {repo}")
    else:
        print("\n所有仓库处理完成")
