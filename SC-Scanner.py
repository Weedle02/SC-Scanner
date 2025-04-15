#!/usr/bin/env python3

import os
import json
import subprocess
import tempfile
import shutil
import sys
import argparse
import concurrent.futures
from git import Repo, GitCommandError
from colorama import Fore, Style, init

init(autoreset=True)

TOOLS = {
    "trufflehog": {
        "command": "trufflehog git --only-verified --json {repo_url}",
        "timeout": 3600,
        "output_key": None
    },
    "gitleaks": {
        "command": "gitleaks detect --source {repo_dir} --no-git --exit-code 0 --report-format json",
        "timeout": 600,
        "output_key": "Findings"
    }
}

def check_tools_installed():
    missing_tools = [tool for tool in TOOLS if not shutil.which(tool)]
    if missing_tools:
        print(Fore.RED + f"Missing tools: {', '.join(missing_tools)}")
        exit(1)

def clone_and_scan(repo_url):
    results = {
        'findings': {},
        'status': {},
        'error': None
    }
    
    try:
        with tempfile.TemporaryDirectory() as temp_dir:
            repo_dir = clone_repo(repo_url, temp_dir)
            if not repo_dir:
                results['error'] = f"Clone failed: {repo_url}"
                return results

            for tool, config in TOOLS.items():
                command = config["command"].format(
                    repo_dir=repo_dir,
                    repo_url=repo_url
                )
                tool_results = run_tool(tool, command, repo_dir, repo_url)
                
                results['findings'][tool] = tool_results
                results['status'][tool] = "Timed out" if tool_results == "timeout" else \
                                        f"{len(tool_results)} findings" if tool_results else "Clean"

    except Exception as e:
        results['error'] = f"Error scanning {repo_url}: {str(e)}"
    
    return results

def clone_repo(repo_url, temp_dir):
    try:
        repo_name = repo_url.split("/")[-1].replace(".git", "")
        repo_dir = os.path.join(temp_dir, repo_name)
        Repo.clone_from(repo_url, repo_dir)
        return repo_dir
    except Exception as e:
        print(Fore.RED + f"Clone failed: {repo_url}")
        print(Fore.YELLOW + f"Error: {str(e)}")
        return None

def run_tool(tool_name, command, repo_dir, repo_url):
    try:
        result = subprocess.run(
            command,
            shell=True,
            capture_output=True,
            text=True,
            timeout=TOOLS[tool_name]["timeout"],
            env=os.environ.copy()
        )
    except subprocess.TimeoutExpired:
        print(Fore.YELLOW + f"{tool_name} timed out")
        return "timeout"

    output = []
    if result.stdout.strip():
        try:
            # Handle line-delimited JSON for trufflehog
            for line in result.stdout.strip().split('\n'):
                if line.strip():
                    parsed_line = json.loads(line)
                    output.append(parsed_line)
        except json.JSONDecodeError as e:
            print(Fore.YELLOW + f"{tool_name} JSON error: {e} (line: {line[:200]})")
            return None

    output_key = TOOLS[tool_name]["output_key"]
    if output_key:
        # Handle nested keys for tools like gitleaks
        try:
            # Assuming output is a single dict (gitleaks case)
            data = output[0] if output else {}
            keys = output_key.split('.')
            for key in keys:
                data = data.get(key, {})
            return data if data else None
        except AttributeError:
            return []
    return output if output else None

def format_report(global_report):
    report = []
    has_findings = False
    
    for repo_url, data in global_report.items():
        repo_has_findings = False
        repo_output = []
        
        if data.get('error'):
            repo_output.append(Fore.RED + f"\nERROR: {data['error']}")
            has_findings = True
            repo_has_findings = True
            
        for tool, status in data['status'].items():
            findings = data['findings'].get(tool)
            if findings and findings != "timeout":
                has_findings = True
                repo_has_findings = True
                repo_output.append(Fore.CYAN + f"\n{repo_url}")
                repo_output.append(Fore.WHITE + "-" * 50)
                break
                
        if repo_has_findings:
            for tool, findings in data['findings'].items():
                if not findings or findings == "timeout":
                    continue
                
                repo_output.append(Fore.YELLOW + f"\n{tool.upper()} Findings:")
                
                if tool == "trufflehog":
                    for secret in findings:
                        repo_output.append(Fore.RED + f"Secret: {secret.get('DetectorName', 'N/A')}")
                        metadata = secret.get('SourceMetadata', {}).get('Data', {}).get('Git', {})
                        repo_output.append(Fore.WHITE + f"File: {metadata.get('file', 'N/A')}")
                        repo_output.append(Fore.WHITE + f"Commit: {metadata.get('commit', 'N/A')}")
                        
                elif tool == "gitleaks":
                    for leak in findings:
                        repo_output.append(Fore.RED + f"Leak: {leak.get('RuleID', 'N/A')}")
                        repo_output.append(Fore.WHITE + f"File: {leak.get('File', 'N/A')}:{leak.get('StartLine', 'N/A')}")

        if repo_has_findings:
            report.extend(repo_output)
    
    if not has_findings:
        return Fore.GREEN + "\nNo findings across all repositories"
    
    return "\n".join(report)

def main(input_file):
    check_tools_installed()
    global_report = {}
    
    with open(input_file, "r") as f:
        repos = [line.strip() for line in f if line.strip()]

    with concurrent.futures.ThreadPoolExecutor() as executor:
        future_to_url = {executor.submit(clone_and_scan, url): url for url in repos}
        
        for future in concurrent.futures.as_completed(future_to_url):
            repo_url = future_to_url[future]
            try:
                result = future.result()
                global_report[repo_url] = result
            except Exception as e:
                global_report[repo_url] = {'error': str(e)}

    report_body = format_report(global_report)
    print(report_body)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Security Scanner")
    parser.add_argument("input_file", help="File with repo URLs")
    args = parser.parse_args()
    main(args.input_file)
