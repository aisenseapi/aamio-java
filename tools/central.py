"""Build the Maven Central bundle for aamio-java, and make the key that signs it.

    python tools/central.py --keygen    # once: a release signing key in AAMIO_GPG_HOME, its public half sent to keyserver.ubuntu.com
    python tools/central.py             # build/central/aamio-<version>-bundle.zip: pom, jar, sources, javadoc, md5, sha1 and asc for each
    python tools/central.py --upload    # build it, then send it to Central and wait for the verdict

The bundle is what "Publish Component" at https://central.sonatype.com takes,
and what its publisher API takes. The version is read from pom.xml.

--upload does the API route, so a release needs no browser. It reads the
Central user token from AAMIO_CENTRAL_TOKEN_FILE, or from secrets/central.token
beside this repository, as one line of "username:password" exactly as
the portal prints the pair under Account, Generate User Token. The token is
never printed. Upload is POST /api/v1/publisher/upload with the zip as the
multipart field "bundle", and the deployment is then polled with POST
/api/v1/publisher/status until it is published or fails. --upload-only skips
the build and sends the bundle that is already there.

Environment: AAMIO_JDK or JAVA_HOME for javac, javadoc and jar; AAMIO_GPG_HOME
for the GnuPG home that holds the release key, kept outside the repository;
GPG for the gpg binary, when it is not on PATH (Git for Windows has one);
AAMIO_CENTRAL_TOKEN_FILE for the token file, when it is somewhere else.
"""

import base64
import glob
import hashlib
import json
import os
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
import xml.etree.ElementTree as ET
import zipfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
JDK = os.environ.get("AAMIO_JDK") or os.environ.get("JAVA_HOME")
GPG_HOME = os.environ.get("AAMIO_GPG_HOME")
GPG = os.environ.get("GPG") or shutil.which("gpg") or r"C:\Program Files\Git\usr\bin\gpg.exe"
KEYSERVER = "https://keyserver.ubuntu.com"
CENTRAL = "https://central.sonatype.com/api/v1/publisher"
TOKEN_FILE = os.environ.get("AAMIO_CENTRAL_TOKEN_FILE") or os.path.join(os.path.dirname(ROOT), "secrets", "central.token")


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

    return zip_path, group, artifact, version


def token():
    """The Central user token as the API wants it, read from a file and never printed.

    Two shapes are taken, because the portal gives one and the docstring asked for
    the other: a line of username:password, or the <server> block the portal prints
    for settings.xml, pasted whole. Anything else is refused rather than guessed at,
    since a wrong guess is an authorization header built from rubbish and a 401 that
    says nothing about why. The value is never printed, not even in an error.
    """
    if not os.path.isfile(TOKEN_FILE):
        sys.exit(
            "no Central token at " + TOKEN_FILE + ". Make one at https://central.sonatype.com under "
            "Account, Generate User Token, and save it as one line of username:password, or paste "
            "the <server> block the portal shows. Point AAMIO_CENTRAL_TOKEN_FILE somewhere else if "
            "you keep it elsewhere."
        )
    # utf-8-sig: Notepad writes a byte order mark, and it would land in the username.
    with open(TOKEN_FILE, encoding="utf-8-sig") as handle:
        pair = handle.read().strip()

    if "<username>" in pair and "<password>" in pair:
        try:
            server = ET.fromstring(pair)
        except ET.ParseError as broken:
            sys.exit(TOKEN_FILE + " looks like the portal's <server> block but does not parse: %s" % broken)

        found = { tag: server.findtext( tag ) for tag in ( "username", "password" ) }

        if not all( ( found[ tag ] or "" ).strip() for tag in found ):
            sys.exit(TOKEN_FILE + " has a <server> block with an empty username or password")

        pair = found[ "username" ].strip() + ":" + found[ "password" ].strip()

    if pair.count(":") != 1 or not all(part.strip() for part in pair.split(":")):
        sys.exit(TOKEN_FILE + " should hold one line of username:password from the portal, or the <server> block it prints, and nothing else")

    return base64.b64encode(pair.encode("utf-8")).decode("ascii")


def call(url, bearer, body=None, content_type=None):
    request = urllib.request.Request(url, data=body, method="POST")
    request.add_header("Authorization", "Bearer " + bearer)
    if content_type:
        request.add_header("Content-Type", content_type)
    try:
        with urllib.request.urlopen(request, timeout=600) as answer:
            return answer.status, answer.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as error:
        return error.code, error.read().decode("utf-8", "replace")


def upload(zip_path, group, artifact, version):
    """Send the bundle to Central and follow the deployment to its end."""
    bearer = token()
    # The same label Central writes when the name is left out, so the list of
    # deployments reads the same whoever made them.
    name = group + ":" + artifact + ":" + version
    boundary = uuid.uuid4().hex
    with open(zip_path, "rb") as handle:
        blob = handle.read()
    body = b"".join([
        ("--" + boundary + "\r\n").encode(),
        ('Content-Disposition: form-data; name="bundle"; filename="' + os.path.basename(zip_path) + '"\r\n').encode(),
        b"Content-Type: application/octet-stream\r\n\r\n",
        blob,
        ("\r\n--" + boundary + "--\r\n").encode(),
    ])
    query = urllib.parse.urlencode({"name": name, "publishingType": "AUTOMATIC"})
    status, answer = call(CENTRAL + "/upload?" + query, bearer, body, "multipart/form-data; boundary=" + boundary)
    if status not in (200, 201):
        sys.exit("upload refused: %s %s" % (status, answer[:400]))
    deployment = answer.strip().strip('"')
    print("uploaded " + name + " as deployment " + deployment)

    # PENDING and VALIDATING are on the way. PUBLISHING means Central took it
    # and the artifacts appear in the central repository within the hour.
    for _ in range(60):
        status, answer = call(CENTRAL + "/status?" + urllib.parse.urlencode({"id": deployment}), bearer)
        if status != 200:
            sys.exit("status refused: %s %s" % (status, answer[:400]))
        state = json.loads(answer).get("deploymentState", "UNKNOWN")
        print("  " + state)
        if state in ("PUBLISHING", "PUBLISHED"):
            print("done: " + name + " is " + state.lower() + " on Central")
            return
        if state == "FAILED":
            sys.exit("Central refused the deployment: " + answer[:800])
        time.sleep(10)
    sys.exit("still not published after ten minutes. The deployment is " + deployment + " at https://central.sonatype.com/publishing/deployments")


if __name__ == "__main__":
    try:
        if "--keygen" in sys.argv:
            keygen()
        elif "--upload-only" in sys.argv:
            group, artifact, version = coordinates()
            upload(os.path.join(ROOT, "build", "central", artifact + "-" + version + "-bundle.zip"), group, artifact, version)
        elif "--upload" in sys.argv:
            upload(*bundle())
        else:
            bundle()
    except subprocess.CalledProcessError as error:
        sys.exit(error.returncode)
