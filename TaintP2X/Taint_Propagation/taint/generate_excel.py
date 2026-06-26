from contextlib import nullcontext
import re
import openpyxl

def extract_functions_to_excel(pysa_file_path, excel_file_path):
    workbook = openpyxl.Workbook()
    sheet = workbook.active
    sheet.title = "LLM Sources"

    # Write headers
    sheet['A1'] = "Category"
    sheet['B1'] = "Name"
    sheet['C1'] = "Source"

    current_category = "Unknown"
    row_num = 2

    with open(pysa_file_path, 'r', encoding='utf-8') as f:
        lines = f.readlines()

    for i, line in enumerate(lines):
        line = line.strip()
        if line.startswith('# 定义'):
            current_category = line.replace('# 定义 ', '').replace(' 的模型输出为 Source', '').strip()
        elif line.startswith('#'):
            current_category = line.replace('# ', '').strip()
        elif line.startswith('def '):
            # Find the end of the function signature, which is usually '): ...' or ')-> TaintSource[...]: ...'
            # We need to capture the entire signature, potentially spanning multiple lines
            full_signature_lines = [line]
            j = i + 1
            while j < len(lines) and not (lines[j].strip().startswith(')') and lines[j].strip().endswith(': ...')):
                full_signature_lines.append(lines[j])
                j += 1
            if j < len(lines): # Add the closing parenthesis and return type if it's on the next line
                full_signature_lines.append(lines[j])
            
            full_signature = " ".join([l.strip() for l in full_signature_lines]).replace('  ', ' ')
            
            # Extract function name
            match = re.match(r'def\s+([a-zA-Z0-9_.]+)\s*\(', full_signature)
            if match:
                function_name = match.group(1)
                sheet[f'A{row_num}'] = " "
                sheet[f'B{row_num}'] = current_category
                sheet[f'C{row_num}'] = function_name
                row_num += 1

    workbook.save(excel_file_path)
    print(f"Successfully extracted functions to {excel_file_path}")

if __name__ == "__main__":
    pysa_file = "e:\\TaintP2X\\Taint_Propagation\\taint\\llms_sources.pysa"
    excel_file = "e:\\TaintP2X\\Taint_Propagation\\taint\\llm_sources.xlsx"
    extract_functions_to_excel(pysa_file, excel_file)