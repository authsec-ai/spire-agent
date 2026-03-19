"""Setup configuration for ICP Agent."""

from setuptools import setup, find_packages

setup(
    name="icp-agent",
    version="0.1.0",
    description="ICP Agent - SPIRE Agent replacement for multi-tenant M2M authentication",
    author="AuthSec AI",
    author_email="support@authsec.ai",
    packages=find_packages(),
    python_requires=">=3.9",
    install_requires=[
        "fastapi>=0.115.0",
        "uvicorn[standard]>=0.24.0",
        "pydantic>=2.5.0",
        "pydantic-settings>=2.1.0",
        "httpx>=0.25.1",
        "cryptography>=42.0.4",
        "pyyaml>=6.0.1",
        "python-dotenv>=1.0.0",
        "structlog>=23.2.0",
        "python-json-logger>=2.0.7",
        "pyjwt>=2.8.0",
        "grpcio>=1.60.0",
        "protobuf>=4.25.0",
        "kubernetes>=28.1.0",
        "docker>=7.0.0",
        "aiohttp>=3.9.0",
    ],
    entry_points={
        "console_scripts": [
            "icp-agent=icp_agent.main:run",
        ],
    },
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
    ],
)
