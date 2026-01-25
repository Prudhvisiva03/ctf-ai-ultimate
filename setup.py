from setuptools import setup, find_packages

setup(
    name="ctf-ai-ultimate",
    version="2.2.0",
    description="AI-Powered CTF Challenge Solver",
    author="Prudhvi Siva",
    packages=find_packages(),
    install_requires=[
        "groq>=1.0.0",
        "python-magic>=0.4.27",
        "Pillow>=10.0.0",
        "pytesseract>=0.3.10",
    ],
    entry_points={
        'console_scripts': [
            'ctf-ai=ctf-ai:main',
        ],
    },
    python_requires='>=3.8',
)
