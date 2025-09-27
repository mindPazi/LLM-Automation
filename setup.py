from setuptools import setup, find_packages

setup(
    name="git-secret-scanner",
    version="0.1.0",
    packages=find_packages(),
    install_requires=[
        "gitpython>=3.1.0",
        "langchain>=0.0.208",
        "openai>=0.28.0",
        "transformers>=4.30.0",
        "click>=8.0.0",
    ],
    entry_points={
        "console_scripts": [
            "scan=scan:main",
        ],
    },
    author="mindPazi",
    author_email="gitmind87@gmail.com",
    description="LLM-powered tool to scan Git repositories for secrets",
    keywords="git, security, llm, secrets",
    python_requires=">=3.8",
)
