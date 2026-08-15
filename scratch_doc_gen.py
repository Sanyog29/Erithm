import ast
import os
from pathlib import Path

def generate_docs(src_dir, output_dir):
    src_path = Path(src_dir)
    out_path = Path(output_dir)
    out_path.mkdir(parents=True, exist_ok=True)
    
    for root, _, files in os.walk(src_path):
        for file in files:
            if not file.endswith(".py") or file == "__init__.py":
                continue
                
            file_path = Path(root) / file
            rel_path = file_path.relative_to(src_path)
            
            with open(file_path, "r", encoding="utf-8") as f:
                try:
                    tree = ast.parse(f.read(), filename=str(file_path))
                except SyntaxError:
                    continue
            
            doc_content = f"# Documentation for `{rel_path}`\n\n"
            
            # Module docstring
            module_doc = ast.get_docstring(tree)
            if module_doc:
                doc_content += f"## Module Overview\n\n{module_doc}\n\n"
            
            # Classes and Functions
            for node in tree.body:
                if isinstance(node, ast.ClassDef):
                    doc_content += f"## Class: `{node.name}`\n\n"
                    cls_doc = ast.get_docstring(node)
                    if cls_doc:
                        doc_content += f"{cls_doc}\n\n"
                    
                    for method in node.body:
                        if isinstance(method, ast.FunctionDef):
                            doc_content += f"### Method: `{method.name}`\n\n"
                            method_doc = ast.get_docstring(method)
                            if method_doc:
                                doc_content += f"{method_doc}\n\n"
                                
                elif isinstance(node, ast.FunctionDef):
                    doc_content += f"## Function: `{node.name}`\n\n"
                    func_doc = ast.get_docstring(node)
                    if func_doc:
                        doc_content += f"{func_doc}\n\n"
            
            # Write out to markdown
            out_md_name = str(rel_path).replace(os.sep, "_").replace(".py", ".md")
            out_md_path = out_path / out_md_name
            with open(out_md_path, "w", encoding="utf-8") as f:
                f.write(doc_content)

if __name__ == "__main__":
    generate_docs("/home/shiva/Desktop/Projects/Erithm/erithm", "/home/shiva/Desktop/Projects/Erithm/About_cbase")
    print("Documentation generated in About_cbase/")
