from setuptools import setup, find_packages

setup(
    name="jito-agent",
    version="0.1.0",
    description="JITO Agent SDK — plug any AI into the JITO blockchain marketplace",
    long_description=open("jito_agent/README.md").read(),
    long_description_content_type="text/markdown",
    author="JITO Labs",
    url="https://explorer.flowpe.io",
    packages=find_packages(exclude=["tests*", "examples*"]),
    python_requires=">=3.8",
    install_requires=[
        "cryptography>=41.0",
    ],
    extras_require={
        "dev": ["pytest", "twine", "build"],
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Topic :: Software Development :: Libraries :: Python Modules",
        "Topic :: Scientific/Engineering :: Artificial Intelligence",
    ],
    keywords="blockchain ai agent jito marketplace",
)
