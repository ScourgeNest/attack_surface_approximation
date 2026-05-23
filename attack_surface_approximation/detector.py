import sys
import re
import subprocess
from pycparser import c_parser, c_ast
from attack_surface_approximation.configuration import Colors, StaticAnalysisConfig

class FormatStringVisitor(c_ast.NodeVisitor):
    def __init__(self):
        self.directives = 0
        self.vulnerabilities = []
        self.currFunc = "Global"

    def visit_FuncDef(self, node: c_ast.FuncDef):
        parentFunc = node.decl.name

        oldFunc = self.currFunc
        self.currFunc = parentFunc

        self.generic_visit(node)
        self.currFunc = oldFunc

    def visit_FuncCall(self, node: c_ast.FuncCall):
        funcName = get_func_name(node)
        if funcName in StaticAnalysisConfig.FORMAT_STRING_FUNCTIONS:
            vuln_arg = get_args(node, funcName)
            if vuln_arg is not None and not isinstance(vuln_arg, c_ast.Constant):
                self.vulnerabilities.append(
                    {
                        "function": funcName,
                        "containing_function": self.currFunc,
                        "arg_type": type(vuln_arg).__name__,
                        "line": node.coord.line if node.coord else "?",
                        "column": node.coord.column if node.coord else "?"
                    }
                )
        self.generic_visit(node)
                
def is_user_function(func_name):
    if func_name.startswith("_") and not func_name.startswith("_Z"):
        return False
    if "@" in func_name:
        return False
    if "." in func_name:
        return False
    if func_name in StaticAnalysisConfig.LIBC_EXACT_NAMES:
        return False
    return True
    
def extract_dynamic_functions(elf):
    functions = set()

    try:
        nm_result = subprocess.run(['nm', '-D', elf], capture_output=True, text=True, check=True)
        lines = nm_result.stdout.splitlines()
        for line in lines:
            symbol = line.split()
            if symbol[0] == 'U':
                func_name = symbol[1].split('@')
                functions.add(func_name[0])
        StaticAnalysisConfig.LIBC_EXACT_NAMES.extend(list(functions))

    except subprocess.CalledProcessError:
        print(f"{Colors.RED}[~]{Colors.RESET} nm -D nu a gasit simboluri dinamice (probabil executabil static).")
    except FileNotFoundError:
        print(f"{Colors.RED}[!]{Colors.RESET} Eroare: Utilitarul 'nm' nu este instalat pe sistemul tau Linux.")

def get_func_names(elf_path):
    from elftools.elf.elffile import ELFFile
    from elftools.elf.sections import SymbolTableSection
    functions = []
    with open(elf_path, 'rb') as file:
        elf = ELFFile(file)
        for section in elf.iter_sections():
            if not isinstance(section, SymbolTableSection):
                continue
            for symbol in section.iter_symbols():
                if symbol['st_info']['type'] == 'STT_FUNC' and symbol.name:
                    if is_user_function(symbol.name):
                        functions.append(symbol.name)
    return functions


            
def sanitize_ghidra_code(ghidra_code):
    lines = []
    for line in ghidra_code.splitlines():
        if "/* WARNING" in line:
            continue
        lines.append(line + "\n")
    code = "".join(lines)

    code = re.sub(r"__attribute__\s*\(\(.*?\)\)", "", code)

    code = re.sub(r"\b__extension__\b", "", code)
    for ghidra_type, c_type in StaticAnalysisConfig.GHIDRA_TYPE_REPLACEMENTS:
        code = re.sub(r"\b" + re.escape(ghidra_type) + r"\b", c_type, code)

    return code

def analyze_ghidra_func(code_func):
    sanitized = sanitize_ghidra_code(code_func)

    full_code = StaticAnalysisConfig.GHIDRA_PREAMBLE + "\n" + sanitized

    parser = c_parser.CParser()
    try:
        ast = parser.parse(full_code, filename="<ghidra>")
    except Exception as e:
        print(f"{Colors.YELLOW}[~]{Colors.RESET} Skipping unparseable function. Error: {e}")
        return []
    visitor = FormatStringVisitor()
    visitor.visit(ast)
    if len(visitor.vulnerabilities) == 0:
        print(f"{Colors.GREEN}[✔]{Colors.RESET} Done — {len(visitor.vulnerabilities)} findings\n")
    else:
        print(f"{Colors.YELLOW}[!]{Colors.RESET} Done — {len(visitor.vulnerabilities)} finding(s)\n")
    return visitor.vulnerabilities


def find_all_vulns(analysis, func_names):
    vulns = []
    print(f"{Colors.CYAN}[!]{Colors.RESET} Total Functions to be scanned: {Colors.BOLD}{len(func_names)}{Colors.RESET}\n")
    for func_name in func_names:
        code_func = analysis.decompile_function(func_name)
        if code_func.strip():
            print(f"{Colors.CYAN}[*]{Colors.RESET} Scanning function: {Colors.BOLD}{func_name}{Colors.RESET}")
            func_vulns = analyze_ghidra_func(code_func)
            vulns.extend(func_vulns)
    return vulns


def get_args(node: c_ast.FuncCall, funcName):
    if node.args is None:
        return None
    if funcName == "printf":
        if len(node.args.exprs) < 1:
            return None
        return node.args.exprs[0]
    
    if funcName in ("fprintf", "sprintf", "dprintf"):
        if len(node.args.exprs) < 2:
            return None
        return node.args.exprs[1]
    
    if funcName in ("snprintf"):
        if len(node.args.exprs) < 3:
            return None
        return node.args.exprs[2]


def get_func_name(node: c_ast.FuncCall):
    func = node.name
    if isinstance(func, c_ast.ID):
        return func.name
    return ""


def read_c_file(filepath):
    valid_code = ""
    with open(filepath, 'r') as Cfile:
        for line in Cfile:
            l = line
            if l.strip().startswith("#") or l.strip().startswith("//"):
                
                continue
            valid_code += l
    return valid_code

def analyze_valid_code(filepath):

    valid_code = read_c_file(filepath)
    parser = c_parser.CParser()

    ast = parser.parse(valid_code, filepath)

    visitor = FormatStringVisitor()

    visitor.visit(ast)

    return visitor.vulnerabilities

def print_analysis(vulns):

    if not vulns:
        print(f"{Colors.BOLD}{Colors.GREEN} [✔] No CWE-134 format-string vulnerabilities detected.{Colors.RESET}\n")
    else:
        print(f"{Colors.BOLD}{Colors.RED}[!] {len(vulns)} CWE-134 vulnebilities detected:{Colors.RESET}")

        print("\n")

        for i, vuln in enumerate(vulns, start=1):
            containing_func = vuln.get("containing_function", "")
            func = vuln.get("function", "")
            arg_type = vuln.get("arg_type", "")
            line = vuln.get("line", "")
            column = vuln.get("column", "")
            print(
                f"{Colors.BOLD}{Colors.YELLOW} [{i}]{Colors.RESET} "
                f"{Colors.BOLD}{func}(){Colors.RESET} "
                f"in function {Colors.BOLD}{Colors.CYAN}'{containing_func}'{Colors.RESET} "
                f"at line {Colors.BOLD}{line - StaticAnalysisConfig.GHIDRA_PREAMBLE_LEN}{Colors.RESET}, "
                f"col {Colors.BOLD}{column}{Colors.RESET}"
            )
            print(f"     Format arg is a {Colors.RED}{arg_type}{Colors.RESET} (not a string) => {Colors.BOLD} CWE-134 {Colors.RESET}")
            print("\n")

        print(f"{Colors.BOLD}{Colors.RED} [X]{Colors.RESET} How to Fix: Always use a constant format string.")
        print(f"      Ex: {Colors.BOLD}{Colors.GREEN}printf(\"%s\", user_input);{Colors.RESET}")
        print(f"      Instead of: {Colors.BOLD}{Colors.RED}printf(user_input);{Colors.RESET}\n")

def print_intro(filepath):

    print("\n")
    print(f"{Colors.BOLD}{Colors.CYAN} ╔══════════════════════════════════════════════╗{Colors.RESET}")
    print(f"{Colors.BOLD}{Colors.CYAN} ║          OpenCRS - CWE-134 Detector          ║{Colors.RESET}")
    print(f"{Colors.BOLD}{Colors.CYAN} ╚══════════════════════════════════════════════╝{Colors.RESET}")

    print("\n\n")

    print(f"{Colors.BOLD}{Colors.CYAN}[*]{Colors.RESET} Target: {Colors.BOLD}{filepath}{Colors.RESET}")


def main():
    if len(sys.argv) < 2:
        print("Usage: python3 detector.py <file.c/cpp>")
        return;

    print_intro(sys.argv[1])

    vulns = analyze_valid_code(sys.argv[1])
    print_analysis(vulns)


if __name__ == "__main__":
    main()