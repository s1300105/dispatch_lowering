import ast
import os
import json

class AssignmentAnalyzer(ast.NodeVisitor):
    def __init__(self):
        self.results = []
        self.attribute_uses = []
        self.current_file = None
        self.current_class = None
        self.current_method = None
        self._method_stack = [] # Stack to keep track of method names and their line numbers
        self.asyncio_assigned_attributes = set()
        self.class_hierarchy = {}  # 存储类继承关系 {class_name: [parent_classes]}
        self.classes_with_async_attrs = set()  # 存储包含AsyncOpenAI赋值的类
        self.llm_client_keywords = {
            'AsyncOpenAI',
            'OpenAI',
            'ZhipuAI',
            'Anthropic',
            'GenerativeModel',
            'Mistral',
            'AsyncMistral',
            'Groq',
            'AsyncGroq',
            'Portkey',
            'litellm',
            'Llama',
            'AsyncLlama',
            'ChatCompletion',
            # 可以根据需要添加更多关键词
        }

    def visit_ClassDef(self, node):
        # 记录类继承关系
        parent_classes = []
        for base in node.bases:
            if isinstance(base, ast.Name):
                parent_classes.append(base.id)
        self.class_hierarchy[node.name] = parent_classes
        
        # 进入类定义
        original_class = self.current_class
        self.current_class = node.name
        self.generic_visit(node)
        self.current_class = original_class

    def visit_FunctionDef(self, node):
        # 处理同步函数和被装饰的类/静态方法
        original_method = self.current_method

        # 处理嵌套函数命名
        if self.current_method:
            self.current_method = f"{self.current_method}.{node.name}"
        else:
            self.current_method = node.name
        
        # 获取方法参数并转换为字符串格式
        method_params_list = [arg.arg for arg in node.args.args]
        if node.args.vararg:
            method_params_list.append(f"*{node.args.vararg.arg}")
        if node.args.kwarg:
            method_params_list.append(f"**{node.args.kwarg.arg}")
        method_params_list.extend([kw.arg for kw in node.args.kwonlyargs])
        method_params = ", ".join(method_params_list)

        # 将当前函数信息压入栈，包括参数
        self._method_stack.append((self.current_method, node.lineno, node.end_lineno, method_params))

        # 检查是否是类方法或静态方法
        is_classmethod = any(
            isinstance(d, ast.Name) and d.id == 'classmethod'
            or (isinstance(d, ast.Attribute) and d.attr == 'classmethod')
            for d in node.decorator_list
        )
        
        is_staticmethod = any(
            isinstance(d, ast.Name) and d.id == 'staticmethod'
            or (isinstance(d, ast.Attribute) and d.attr == 'staticmethod')
            for d in node.decorator_list
        )
        
        # 存储方法类型信息
        self.current_method_type = 'sync'
        if is_classmethod:
            self.current_method_type = 'classmethod'
        elif is_staticmethod:
            self.current_method_type = 'staticmethod'
            
        self.generic_visit(node)
        # Restore the original method after visiting the function body
        self.current_method = original_method
        # 弹出当前函数信息
        self._method_stack.pop()
        self.current_method_type = None

    def visit_AsyncFunctionDef(self, node):
        # 处理异步函数
        original_method = self.current_method

        # 处理嵌套函数命名
        if self.current_method:
            self.current_method = f"{self.current_method}.{node.name}"
        else:
            self.current_method = node.name

        # 获取方法参数并转换为字符串格式
        method_params_list = [arg.arg for arg in node.args.args]
        if node.args.vararg:
            method_params_list.append(f"*{node.args.vararg.arg}")
        if node.args.kwarg:
            method_params_list.append(f"**{node.args.kwarg.arg}")
        method_params_list.extend([kw.arg for kw in node.args.kwonlyargs])
        method_params = ", ".join(method_params_list)

        # 将当前函数信息压入栈，包括参数
        self._method_stack.append((self.current_method, node.lineno, node.end_lineno, method_params))

        # 检查是否是类方法或静态方法 (虽然不常见，但语法上允许)
        is_classmethod = any(
            isinstance(d, ast.Name) and d.id == 'classmethod'
            or (isinstance(d, ast.Attribute) and d.attr == 'classmethod')
            for d in node.decorator_list
        )
        
        is_staticmethod = any(
            isinstance(d, ast.Name) and d.id == 'staticmethod'
            or (isinstance(d, ast.Attribute) and d.attr == 'staticmethod')
            for d in node.decorator_list
        )

        # 存储方法类型信息
        self.current_method_type = 'async'
        if is_classmethod:
             # 异步类方法
             self.current_method_type = 'async_classmethod'
        elif is_staticmethod:
             # 异步静态方法
             self.current_method_type = 'async_staticmethod'

        self.generic_visit(node)
        # Restore the original method after visiting the function body
        self.current_method = original_method
        # 弹出当前函数信息
        self._method_stack.pop()
        self.current_method_type = None

    def visit_Lambda(self, node):
        # 对于lambda函数，保留当前方法上下文但不设置新方法名
        # Lambda没有独立的node.lineno/end_lineno，其行号通常是定义它的语句的行号
        # 为了简化，这里不将lambda压入方法栈，它会继承其父级函数的上下文
        original_method = self.current_method
        self.generic_visit(node)
        self.current_method = original_method

    def visit_Attribute(self, node):
        # 在第二阶段分析时才检查属性使用
        if hasattr(self, '_phase') and self._phase == 2:
            if isinstance(node.value, ast.Name) and node.value.id == 'self':
                if node.attr in self.asyncio_assigned_attributes:
                    # 检查当前类是否在继承链中
                    if self.current_class and self._is_in_class_hierarchy(self.current_class):
                        # 获取上一级函数的行号和参数，如果存在嵌套
                        method_start_line = None
                        method_end_line = None
                        method_params = []
                        if len(self._method_stack) > 1:
                            # 获取栈中倒数第二个元素（上一级函数）的行号和参数
                            _, method_start_line, method_end_line, method_params = self._method_stack[-2]
                        elif len(self._method_stack) == 1:
                            # 如果只有一层函数，则获取当前函数的行号和参数
                            _, method_start_line, method_end_line, method_params = self._method_stack[-1]

                        self.attribute_uses.append({
                            'file': self.current_file,
                            'class': self.current_class,
                            'method': self.current_method, # 记录完整的嵌套方法名
                            'method_type': self.current_method_type,  # 新增方法类型信息
                            'attribute': node.attr,
                            'line': node.lineno, # 记录属性使用的具体行号
                            'code': ast.unparse(node).strip(),
                            'method_start_line': method_start_line,
                            'method_end_line': method_end_line,
                            'method_params': method_params # 新增方法参数
                        })
        self.generic_visit(node)

    def _find_llm_keyword_in_expr(self, node):
        """递归遍历表达式，查找是否存在llm_client_keywords中的关键词。"""
        if isinstance(node, ast.Name):
            if node.id in self.llm_client_keywords:
                return node.id
        elif isinstance(node, ast.Attribute):
            # 检查属性名本身是否是关键词
            if node.attr in self.llm_client_keywords:
                return node.attr
            # 递归检查属性的value部分
            return self._find_llm_keyword_in_expr(node.value)
        elif isinstance(node, ast.Call):
            # 检查函数调用本身
            found_keyword = self._find_llm_keyword_in_expr(node.func)
            if found_keyword:
                return found_keyword
            # 检查函数调用的参数
            for arg in node.args:
                found_keyword = self._find_llm_keyword_in_expr(arg)
                if found_keyword:
                    return found_keyword
            for kwarg in node.keywords:
                found_keyword = self._find_llm_keyword_in_expr(kwarg.value)
                if found_keyword:
                    return found_keyword
        elif isinstance(node, (ast.List, ast.Tuple, ast.Set)):
            for element in node.elts:
                found_keyword = self._find_llm_keyword_in_expr(element)
                if found_keyword:
                    return found_keyword
        elif isinstance(node, ast.Dict):
            for key, value in zip(node.keys, node.values):
                found_keyword = self._find_llm_keyword_in_expr(key)
                if found_keyword:
                    return found_keyword
                found_keyword = self._find_llm_keyword_in_expr(value)
                if found_keyword:
                    return found_keyword
        return None

    def visit_Assign(self, node):
        # 在第一阶段分析时才处理赋值语句
        if hasattr(self, '_phase') and self._phase == 1:
            target = node.targets[0]
            client_name = None
            attribute_name = None

            # Case 1: self.attribute = ...
            if isinstance(target, ast.Attribute):
                if isinstance(target.value, ast.Name) and target.value.id == 'self':
                    attribute_name = target.attr
                    client_name = self._find_llm_keyword_in_expr(node.value)
            # Case 2: dict['key'] = ... or dict.get('key') = ...
            elif isinstance(target, ast.Subscript):
                # Check if the subscript is on a Name (e.g., 'values')
                if isinstance(target.value, ast.Name):
                    dict_name = target.value.id
                    # Extract the key from the slice
                    if isinstance(target.slice, ast.Constant):
                        attribute_name = target.slice.value # For Python 3.8+
                    elif isinstance(target.slice, ast.Str):
                        attribute_name = target.slice.s # For Python < 3.8
                    
                    # Only proceed if the dictionary name is 'values' and the key is 'client'
                    # Or if it's a common pattern for LLM client storage
                    if dict_name == 'values' and attribute_name == 'client':
                        client_name = self._find_llm_keyword_in_expr(node.value)

            if client_name and attribute_name:

                    print(f"[DEBUG] Current file: {self.current_file}, Line: {node.lineno}")
                    print(f"[DEBUG] Assigned attribute: {attribute_name}")
                    print(f"[DEBUG] Identified client name: {client_name}")

                    # 记录相关赋值
                    self.results.append({
                        'file': self.current_file,
                        'class': self.current_class,
                        'attribute': attribute_name,
                        'client_type': client_name, # 新增客户端类型
                        'line': node.lineno,
                        'code': ast.unparse(node).strip()
                    })
                    # 将此属性标记为包含 LLM 客户端实例
                    self.asyncio_assigned_attributes.add(attribute_name)
                    # 记录包含 LLM 客户端赋值的类
                    if self.current_class:
                        self.classes_with_async_attrs.add(self.current_class)
        self.generic_visit(node)

    def _is_in_class_hierarchy(self, class_name):
        """检查类是否在包含AsyncOpenAI赋值的类的继承链中"""
        if class_name in self.classes_with_async_attrs:
            return True
        
        # 检查是否是父类
        for cls in self.classes_with_async_attrs:
            if class_name in self._get_all_parents(cls):
                return True
        
        # 检查是否是子类
        if class_name in self.class_hierarchy:
            for cls in self.classes_with_async_attrs:
                if cls in self._get_all_children(class_name):
                    return True
        
        return False

    def _get_all_parents(self, class_name):
        """获取类的所有父类（递归）"""
        parents = set()
        if class_name in self.class_hierarchy:
            for parent in self.class_hierarchy[class_name]:
                parents.add(parent)
                parents.update(self._get_all_parents(parent))
        return parents

    def _get_all_children(self, class_name):
        """获取类的所有子类（递归）"""
        children = set()
        for child, parents in self.class_hierarchy.items():
            if class_name in parents:
                children.add(child)
                children.update(self._get_all_children(child))
        return children

def analyze_project(project_path):
    # 第一阶段：收集类继承关系和LLM客户端赋值
    phase1_analyzer = AssignmentAnalyzer()
    phase1_analyzer._phase = 1 # 设置阶段标志
    for root, _, files in os.walk(project_path):
        for file in files:
            if file.endswith('.py'):
                file_path = os.path.join(root, file)
                try:
                    with open(file_path, 'r', encoding='utf-8') as f:
                        tree = ast.parse(f.read(), filename=file_path)
                    phase1_analyzer.current_file = file_path
                    phase1_analyzer.visit(tree)
                except Exception as e:
                    print(f"Error parsing {file_path} in Phase 1: {e}")

    # 第二阶段：查找属性使用，并利用第一阶段收集的信息
    phase2_analyzer = AssignmentAnalyzer()
    # 复制第一阶段收集到的关键信息
    phase2_analyzer.class_hierarchy = phase1_analyzer.class_hierarchy
    phase2_analyzer.classes_with_async_attrs = phase1_analyzer.classes_with_async_attrs
    phase2_analyzer.asyncio_assigned_attributes = phase1_analyzer.asyncio_assigned_attributes
    phase2_analyzer._phase = 2 # 设置阶段标志

    for root, _, files in os.walk(project_path):
        for file in files:
            if file.endswith('.py'):
                file_path = os.path.join(root, file)
                try:
                    with open(file_path, 'r', encoding='utf-8') as f:
                        tree = ast.parse(f.read(), filename=file_path)
                    phase2_analyzer.current_file = file_path
                    phase2_analyzer.visit(tree)
                except Exception as e:
                    print(f"Error parsing {file_path} in Phase 2: {e}")

    return phase2_analyzer.results, phase2_analyzer.attribute_uses

def run_analysis(project_root):
    print(f"Analyzing project at: {project_root}")
    found_assignments, found_uses = analyze_project(project_root)

    output_data = {
        "assignments": found_assignments,
        "attribute_uses": found_uses
    }

    # 确保 project_name 是 project_root 的最后一个目录名
    project_name = os.path.basename(project_root)

    output_filename = f"{project_root}/source/analysis_source_{project_name}.json"
    try:
        os.makedirs(os.path.dirname(output_filename), exist_ok=True)
        with open(output_filename, 'w', encoding='utf-8') as f:
            json.dump(output_data, f, indent=4, ensure_ascii=False)
        print(f"\nAnalysis results saved to {output_filename}")
    except Exception as e:
        print(f"Error saving results to JSON: {e}")

    if found_assignments:
        print("\nFound relevant assignments (LLM client instances):")
        for item in found_assignments:
            print(f"  File: {item['file']}")
            print(f"  Class: {item['class']}")
            print(f"  Attribute: {item['attribute']}")
            print(f"  Client Type: {item['client_type']}")
            print(f"  Line: {item['line']}")
            print(f"  Code: {item['code']}\n")
    else:
        print("\nNo relevant assignments found.")

    if found_uses:
        print("\nFound class attribute uses in class hierarchy (self.attribute):")
        for item in found_uses:
            print(f"  File: {item['file']}")
            print(f"  Class: {item['class']}")
            print(f"  Method (Full Name): {item['method']}")
            print(f"  Method Type: {item['method_type']}")
            print(f"  Attribute: {item['attribute']}")
            print(f"  Line (Attribute Use): {item['line']}")
            print(f"  Code: {item['code']}")
            print(f"  Parent Method Start Line: {item.get('method_start_line', 'N/A')}")
            print(f"  Parent Method End Line: {item.get('method_end_line', 'N/A')}")
            print(f"  Method Parameters: {item.get('method_params', 'N/A')}\n")
    else:
        print("\nNo class attribute uses found.")

if __name__ == "__main__":
    # 示例用法，可以根据需要修改
    project_name = 'docetl'
    project_root = f'/llm_web_serve/servers/{project_name}'
    run_analysis(project_root, project_type)