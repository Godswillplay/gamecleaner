from setuptools import setup, find_packages

setup(
    name="gamecleaner",
    version="1.0.0",
    description="Security triage, malware isolation, and containment utility for games.",
    author="GameCleaner Project",
    packages=find_packages(),
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
    python_requires=">=3.8",
)
