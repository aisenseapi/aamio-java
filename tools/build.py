"""Compile aamio-java, run the shared-vector checks and make the jar, with a JDK and nothing else.

    python tools/build.py            # compile, check against the vectors and the fake service, jar
    python tools/build.py --live     # then the live checks against aamio.at (AAMIO_HOST overrides)

The JDK is found through AAMIO_JDK, then JAVA_HOME, then PATH. Java 17 or
newer. Output goes to build/: classes, test-classes and aamio-<version>.jar.
"""

import glob
import os
import shutil
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
VERSION = "0.2.7"
JDK = os.environ.get("AAMIO_JDK") or os.environ.get("JAVA_HOME")


def tool(name):
    return os.path.join(JDK, "bin", name) if JDK else name


def run(*cmd):
    print("+ " + " ".join(os.path.basename(c) if i == 0 else c for i, c in enumerate(cmd) if not c.endswith(".java")))
    subprocess.run(cmd, check=True, cwd=ROOT)


def main():
    build = os.path.join(ROOT, "build")
    classes = os.path.join(build, "classes")
    tests = os.path.join(build, "test-classes")
    shutil.rmtree(build, ignore_errors=True)
    os.makedirs(classes)
    os.makedirs(tests)
    main_sources = sorted(glob.glob(os.path.join(ROOT, "src", "main", "java", "at", "aamio", "*.java")))
    test_sources = sorted(glob.glob(os.path.join(ROOT, "src", "test", "java", "at", "aamio", "*.java")))
    run(tool("javac"), "--release", "17", "-encoding", "UTF-8", "-Xlint:all", "-d", classes, *main_sources)
    run(tool("javac"), "--release", "17", "-encoding", "UTF-8", "-Xlint:all", "-cp", classes, "-d", tests, *test_sources)
    run(tool("jar"), "--create", "--file", os.path.join(build, "aamio-%s.jar" % VERSION), "-C", classes, ".")
    classpath = os.pathsep.join([classes, tests])
    run(tool("java"), "-Dstdout.encoding=UTF-8", "-cp", classpath, "at.aamio.Vectors", os.path.join(ROOT, "testdata", "vectors.json"))
    run(tool("java"), "-Dstdout.encoding=UTF-8", "-cp", classpath, "at.aamio.Reader", os.path.join(ROOT, "testdata", "vectors.json"))
    run(tool("java"), "-Dstdout.encoding=UTF-8", "-cp", classpath, "at.aamio.ReadLimits")
    if "--live" in sys.argv:
        run(tool("java"), "-Dstdout.encoding=UTF-8", "-cp", classpath, "at.aamio.Live")
    print("jar: build/aamio-%s.jar" % VERSION)


if __name__ == "__main__":
    try:
        main()
    except subprocess.CalledProcessError as error:
        sys.exit(error.returncode)
