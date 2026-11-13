from setuptools import find_packages, setup

setup(
    name="surfacescope",
    version="2.0.0",
    description="Web & API attack surface scanner (OWASP Top 10 / API Top 10)",
    url="https://github.com/Ayan946/SurfaceScope",
    packages=find_packages(exclude=["tests"]),
    python_requires=">=3.9",
    install_requires=["requests", "beautifulsoup4"],
    entry_points={"console_scripts": ["surfacescope=surfacescope.cli:main"]},
)
