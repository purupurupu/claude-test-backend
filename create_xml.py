import os
import fnmatch
import chardet

def is_binary(file_path):
    with open(file_path, 'rb') as file:
        return b'\0' in file.read(1024)

def read_file_contents(file_path):
    encodings = ['utf-8', 'shift_jis']
    for encoding in encodings:
        try:
            with open(file_path, 'r', encoding=encoding) as file:
                print(f'Reading file: {file_path}')
                return file.read()
        except UnicodeDecodeError:
            pass
    return ''

def is_ignored(path, project_dir, gitignore_patterns, summaryignore_patterns, additional_ignore_patterns):
    relative_path = os.path.relpath(path, project_dir)
    for pattern in gitignore_patterns + summaryignore_patterns + additional_ignore_patterns:
        pattern = f"*{pattern}*"
        if fnmatch.fnmatch(relative_path, pattern) or fnmatch.fnmatch(f'{os.sep}{relative_path}', pattern):
            return True
    return False

def generate_project_summary(project_dir):
    project_name = os.path.basename(project_dir)
    xml_output = f'<{project_name}>\n'

    gitignore_patterns = read_gitignore(project_dir)
    summaryignore_patterns = read_summaryignore(project_dir)
    additional_ignore_patterns = ['generate_project_summary.py','.summaryignore', f'{project_name}_project_summary.txt', '.git']

    def traverse_directory(root):
        nonlocal xml_output
        for item in os.listdir(root):
            item_path = os.path.join(root, item)
            if os.path.isdir(item_path):
                if not is_ignored(item_path, project_dir, gitignore_patterns, summaryignore_patterns, additional_ignore_patterns):
                    traverse_directory(item_path)
            else:
                if not is_ignored(item_path, project_dir, gitignore_patterns, summaryignore_patterns, additional_ignore_patterns):
                    if not is_binary(item_path):
                        content = read_file_contents(item_path)
                        if content.strip():
                            # ファイル名をプロジェクト名からの相対パスで表示
                            relative_file_path = os.path.relpath(item_path, project_dir)
                            # XML形式でファイル内容を出力
                            xml_output += f'  <FileName>{relative_file_path}</FileName>\n  <Content>\n{content}\n  </Content>\n'

    traverse_directory(project_dir)

    xml_output += f'</{project_name}>'

    with open(f'project_summary.xml', 'w', encoding='utf-8') as file:
        file.write(xml_output)

def read_gitignore(project_dir):
    gitignore_path = os.path.join(project_dir, '.gitignore')
    if os.path.exists(gitignore_path):
        with open(gitignore_path, 'r') as file:
            patterns = [line.strip() for line in file if line.strip() and not line.startswith('#')]
            expanded_patterns = []
            for pattern in patterns:
                expanded_patterns.append(pattern)
                if '/' in pattern:
                    expanded_patterns.append(pattern.replace('/', '\\'))
                if '\\' in pattern:
                    expanded_patterns.append(pattern.replace('\\', '/'))
            return expanded_patterns
    return []

def read_summaryignore(project_dir):
    summaryignore_path = os.path.join(project_dir, '.summaryignore')
    if os.path.exists(summaryignore_path):
        with open(summaryignore_path, 'r') as file:
            patterns = [line.strip() for line in file if line.strip() and not line.startswith('#')]
            expanded_patterns = []
            for pattern in patterns:
                expanded_patterns.append(pattern)
                if '/' in pattern:
                    expanded_patterns.append(pattern.replace('/', '\\'))
                if '\\' in pattern:
                    expanded_patterns.append(pattern.replace('\\', '/'))
            return expanded_patterns
    return []

if __name__ == '__main__':
    project_directory = input('Enter the project directory path (leave blank for current directory): ')
    if not project_directory:
        project_directory = os.getcwd()
    generate_project_summary(project_directory)
