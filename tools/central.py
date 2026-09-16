"""Build the Maven Central bundle for aamio-java, and make the key that signs it.

    python tools/central.py --keygen    # once: a release signing key in AAMIO_GPG_HOME, its public half sent to keyserver.ubuntu.com
    python tools/central.py             # build/central/aamio-<version>-bundle.zip: pom, jar, sources, javadoc, md5, sha1 and asc for each

The bundle is what "Publish Component" at https://central.sonatype.com takes,
and what its publisher API takes. The version is read from pom.xml.

Environment: AAMIO_JDK or JAVA_HOME for javac, javadoc and jar; AAMIO_GPG_HOME
for the GnuPG home that holds the release key, kept outside the repository;
GPG for the gpg binary, when it is not on PATH (Git for Windows has one).
"""

import glob
import hashlib
import os
import shutil
import subprocess
import sys
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
import zipfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
JDK = os.environ.get("AAMIO_JDK") or os.environ.get("JAVA_HOME")
GPG_HOME = os.environ.get("AAMIO_GPG_HOME")
GPG = os.environ.get("GPG") or shutil.which("gpg") or r"C:\Program Files\Git\usr\bin\gpg.exe"
KEYSERVER = "https://keyserver.ubuntu.com"


def tool(name):
    return os.path.join(JDK, "bin", name) if JDK else name


def run(cmd, **kw):
    shown = cmd[3:] if os.path.basename(cmd[0]) == "bash.exe" else cmd
    print("+ " + " ".join(os.path.basename(c) if i == 0 else c for i, c in enumerate(shown) if not c.endswith(".java")))
    return subprocess.run(cmd, check=True, cwd=ROOT, **kw)


def gpg(*args, **kw):
    if not GPG_HOME:
        raise SystemExit("set AAMIO_GPG_HOME to the GnuPG home that holds (or will hold) the release key")
    command = [GPG, "--batch", "--yes", "--homedir", GPG_HOME, *args]
    bash = os.path.join(os.path.dirname(GPG), "bash.exe")
    if os.name == "nt" and os.path.exists(bash):
        # Git for Windows' gpg reaches its agent only from inside its own shell, and wants POSIX paths there.
        convert = 'for a in "$@"; do case "$a" in [A-Za-z]:*) set -- "$@" "$(cygpath -u "$a")";; *) set -- "$@" "$a";; esac; shift; done; exec gpg "$@"'
        command = [bash, "-c", convert, "gpg", "--batch", "--yes", "--homedir", GPG_HOME, *args]
    return run(command, **kw)


def coordinates():
    ns = {"m": "http://maven.apache.org/POM/4.0.0"}
    pom = ET.parse(os.path.join(ROOT, "pom.xml")).getroot()
    return pom.find("m:groupId", ns).text, pom.find("m:artifactId", ns).text, pom.find("m:version", ns).text


def fingerprint():
    out = gpg("--list-secret-keys", "--with-colons", capture_output=True).stdout.decode("utf-8", "replace")
    for line in out.splitlines():
        if line.startswith("fpr:"):
            return line.split(":")[9]
    raise SystemExit("no secret key in %s; run with --keygen first" % GPG_HOME)


def keygen():
    os.makedirs(GPG_HOME, exist_ok=True)
    batch = os.path.join(GPG_HOME, "keygen.batch")
    with open(batch, "w", encoding="utf-8") as f:
        f.write("%no-protection\nKey-Type: eddsa\nKey-Curve: ed25519\nKey-Usage: sign\nName-Real: AI SENSE AS aamio release signing\nExpire-Date: 0\n%commit\n")
    gpg("--generate-key", batch)
    fpr = fingerprint()
    public = gpg("--armor", "--export", fpr, capture_output=True).stdout
    with open(os.path.join(GPG_HOME, "aamio-release-public.asc"), "wb") as f:
        f.write(public)
    # The secret half as text, to be copied somewhere safe and nowhere else: it has no passphrase.
    secret = gpg("--armor", "--export-secret-keys", fpr, capture_output=True).stdout
    with open(os.path.join(GPG_HOME, "aamio-release-secret.asc"), "wb") as f:
        f.write(secret)
    data = urllib.parse.urlencode({"keytext": public.decode("ascii")}).encode("ascii")
    with urllib.request.urlopen(KEYSERVER + "/pks/add", data=data, timeout=60) as answer:
        print("%s: %s" % (KEYSERVER, answer.status))
    print("fingerprint: " + fpr)
    print("public key: " + os.path.join(GPG_HOME, "aamio-release-public.asc"))


def checksum(path, algorithm):
    h = hashlib.new(algorithm)
    with open(path, "rb") as f:
        h.update(f.read())
    with open(path + "." + algorithm, "w") as f:
        f.write(h.hexdigest())


def bundle():
    group, artifact, version = coordinates()
    fpr = fingerprint()
    out = os.path.join(ROOT, "build", "central")
    shutil.rmtree(out, ignore_errors=True)
    classes = os.path.join(out, "classes")
    javadoc = os.path.join(out, "javadoc")
    os.makedirs(classes)
    os.makedirs(javadoc)
    sources = sorted(glob.glob(os.path.join(ROOT, "src", "main", "java", "at", "aamio", "*.java")))
    run([tool("javac"), "--release", "17", "-encoding", "UTF-8", "-d", classes, *sources])
    run([tool("javadoc"), "-quiet", "-Xdoclint:none", "-encoding", "UTF-8", "-d", javadoc, *sources])
    manifest = os.path.join(out, "MANIFEST.MF")
    with open(manifest, "w") as f:
        f.write("Automatic-Module-Name: " + group + "\n")
    base = os.path.join(out, artifact + "-" + version)
    jar = base + ".jar"
    sources_jar = base + "-sources.jar"
    javadoc_jar = base + "-javadoc.jar"
    pom = base + ".pom"
    run([tool("jar"), "--create", "--file", jar, "--manifest", manifest, "-C", classes, "."])
    run([tool("jar"), "--create", "--file", sources_jar, "-C", os.path.join(ROOT, "src", "main", "java"), "."])
    run([tool("jar"), "--create", "--file", javadoc_jar, "-C", javadoc, "."])
    shutil.copyfile(os.path.join(ROOT, "pom.xml"), pom)
    files = []
    for path in (pom, jar, sources_jar, javadoc_jar):
        gpg("--armor", "--detach-sign", "--local-user", fpr, "--output", path + ".asc", path)
        checksum(path, "md5")
        checksum(path, "sha1")
        files += [path, path + ".asc", path + ".md5", path + ".sha1"]
    zip_path = base + "-bundle.zip"
    folder = group.replace(".", "/") + "/" + artifact + "/" + version + "/"
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as z:
        for path in files:
            z.write(path, folder + os.path.basename(path))
    print("bundle: " + os.path.relpath(zip_path, ROOT) + " (%d files, signed by %s)" % (len(files), fpr))


if __name__ == "__main__":
    try:
        if "--keygen" in sys.argv:
            keygen()
        else:
            bundle()
    except subprocess.CalledProcessError as error:
        sys.exit(error.returncode)
