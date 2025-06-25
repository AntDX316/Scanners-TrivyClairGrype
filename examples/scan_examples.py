#!/usr/bin/env python3
"""
Example usage of the vulnerability scanner with different targets
"""

import os
import sys
sys.path.append('..')
from scan_all import VulnerabilityScanner

def example_docker_image_scan():
    """Example: Scan a Docker image"""
    print("🐳 Example: Scanning Docker image...")
    scanner = VulnerabilityScanner("nginx:latest", "results/docker_example")
    scanner.scan_all()

def example_local_directory_scan():
    """Example: Scan local directory"""
    print("📁 Example: Scanning local directory...")
    scanner = VulnerabilityScanner(".", "results/local_example")
    scanner.scan_all()

def example_git_repository_scan():
    """Example: Scan Git repository"""
    print("🔗 Example: Scanning Git repository...")
    scanner = VulnerabilityScanner(
        "https://github.com/dvwa/dvwa", 
        "results/git_example"
    )
    scanner.scan_all()

def example_specific_image_scan():
    """Example: Scan specific vulnerable image for testing"""
    print("🧪 Example: Scanning vulnerable test image...")
    scanner = VulnerabilityScanner(
        "vulnerables/web-dvwa:latest", 
        "results/vulnerable_example"
    )
    scanner.scan_all()

if __name__ == "__main__":
    print("🔍 Vulnerability Scanner Examples")
    print("=" * 40)
    
    examples = [
        ("1", "Docker Image (nginx:latest)", example_docker_image_scan),
        ("2", "Local Directory", example_local_directory_scan),
        ("3", "Git Repository", example_git_repository_scan),
        ("4", "Vulnerable Test Image", example_specific_image_scan),
    ]
    
    print("\nAvailable examples:")
    for num, desc, _ in examples:
        print(f"  {num}. {desc}")
    
    choice = input("\nSelect example (1-4) or 'all' to run all: ").strip()
    
    if choice.lower() == 'all':
        for _, _, func in examples:
            func()
            print("\n" + "="*50 + "\n")
    else:
        for num, _, func in examples:
            if choice == num:
                func()
                break
        else:
            print("Invalid choice!")
