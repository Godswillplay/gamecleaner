from pathlib import Path
from setuptools import setup, find_packages

readme_path = Path(__file__).parent / "README.md"
long_description = readme_path.read_text(encoding="utf-8") if readme_path.exists() else ""

setup(
    name="gamecleaner",
    version="1.0.0",
    description="Automated defensive security triage, malware isolation, and clean emulator containment framework for PC games.",
    long_description=long_description,
    long_description_content_type="text/markdown",
    author="GameCleaner Project",
    license="MIT",
    packages=find_packages(),
    include_package_data=True,
    entry_points={
        "console_scripts": [
            "gamecleaner=gamecleaner.cli:main",
        ],
    },
    install_requires=[
        "pefile>=2024.8.26",
        "rich>=13.0.0",
        "requests>=2.28.0",
        "capstone>=5.0.0",
    ],
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Environment :: Win32 (MS Windows)",
        "Intended Audience :: End Users/Desktop",
        "Operating System :: Microsoft :: Windows :: Windows 10",
        "Operating System :: Microsoft :: Windows :: Windows 11",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Security",
        "Topic :: Games/Entertainment",
    ],
    python_requires=">=3.10",
)

