#!/usr/bin/env python3
"""
HiveLLM BIP-04: Secure Script Execution Environment
Setup configuration for Python package
"""

from setuptools import setup, find_packages
import os

# Read README for long description
def read_readme():
    with open("README.md", "r", encoding="utf-8") as f:
        return f.read()

# Read requirements
def read_requirements():
    with open("requirements.txt", "r", encoding="utf-8") as f:
        return [line.strip() for line in f if line.strip() and not line.startswith("#")]

setup(
    name="hivellm-secure-execution",
    version="1.0.0",
    description="BIP-04: Secure Script Execution Environment for HiveLLM",
    long_description=read_readme(),
    long_description_content_type="text/markdown",
    author="HiveLLM Team",
    author_email="team@hivellm.org",
    url="https://github.com/hivellm/hive-py-env-security",
    
    packages=find_packages(),
    python_requires=">=3.8",
    install_requires=read_requirements(),
    
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Security",
        "Topic :: System :: Systems Administration",
        "Topic :: Software Development :: Libraries :: Python Modules",
    ],
    
    keywords=[
        "security", "sandboxing", "script-execution", 
        "governance", "hivellm", "bip-04", "monitoring",
        "audit", "compliance", "isolation"
    ],
    
    entry_points={
        "console_scripts": [
            "hivellm-secure=executor:main",
            "hivellm-audit=audit:main", 
            "hivellm-monitor=monitor:main",
            "hivellm-validate=validate_deployment:main",
        ],
    },
    
    extras_require={
        "dev": [
            "pytest>=7.4.0",
            "pytest-cov>=4.1.0", 
            "black>=23.7.0",
            "flake8>=6.0.0",
            "mypy>=1.5.0",
        ],
        "monitoring": [
            "prometheus-client>=0.17.0",
            "grafana-api>=1.0.3",
        ],
        "container": [
            "docker>=6.1.0",
            "kubernetes>=27.2.0",
        ],
    },
    
    package_data={
        "": ["*.yml", "*.yaml", "*.json", "*.md", "*.txt"],
    },
    
    include_package_data=True,
    zip_safe=False,
)
