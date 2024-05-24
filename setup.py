from setuptools import setup, find_packages

setup(
    name="ropchain_generator",
    version="0.1.0",
    packages=find_packages(),
    author="esp0xdeadbeef",
    author_email="deadbeef@your.esp",
    description="A Python helper package for generating ROP chains from gadget collections.",
    long_description=open('README.md').read(),
    long_description_content_type='text/markdown',
    url="https://github.com/esp0xdeadbeef/ropchain-generator",
    install_requires=[
        "keystone-engine",
    ],
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Windows (tested)",
    ],
    python_requires='>=3.6',
)