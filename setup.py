from distutils.core import setup

setup(
    name = "jwt-python",
    version = "0.1",
    author = "Andrew Ekstedt",
    author_email = "andrew.ekstedt@gmail.com",
    description = "JSON Web Token",
    license = "MIT",
    url = "http://github.com/magical/jwt-python",
    py_modules=['jwt'],
    classifiers=[
        "Development Status :: 3 - Alpha",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 2",
        "Topic :: Security :: Cryptography",
    ],
)
