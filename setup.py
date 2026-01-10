import os
from setuptools import setup, find_packages
from setuptools_rust import RustExtension

# Get the project version from the Rust crate to ensure they are always in sync.
cargo_toml_path = os.path.join(os.path.dirname(__file__), "src/pyspector/_rust_core/Cargo.toml")
with open(cargo_toml_path, "r") as f:
    for line in f:
        if line.startswith("version ="):
            version = line.strip().split("=")[1].strip().strip('"')
            break
    else:
        raise RuntimeError("Could not find version in Cargo.toml")

setup(
    name="pyspector",
    version=version,
    author="ParzivalHack",
    keywords="static analysis security python rust",
    description="A high-performance, security-focused static analysis tool for Python, powered by Rust.",
    readme="README.md",
    license="MIT",
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    rust_extensions=[
        RustExtension(
            "pyspector._rust_core",
            path=cargo_toml_path,
        )
    ],
    python_requires=">=3.8",
    install_requires=[
        "click>=8.0",
        "toml>=0.10",
        "sarif-om>=1.0",
        "jinja2>=3.0",
        "textual>=0.60",
        'importlib_resources; python_version < "3.9"',
    ],
    entry_points={
        "console_scripts": [
            "pyspector = pyspector.cli:cli",
        ],
    },
    include_package_data=True,
    package_data={
        "pyspector": ["rules/*.toml"],
    },
    zip_safe=False,
)
