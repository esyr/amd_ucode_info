#!/usr/bin/python3

# Test various released microcode blobs and their concatenation.
#
# SPDX-License-Identifier: MIT License
# Copyright (C) 2025 amd_ucode_info developers

import errno
import hashlib
import os
import pathlib
import pytest
import requests
import shutil
import subprocess
import tarfile
import warnings


CONTAINER_DATA = {
    # name: (sha256_sum, url, tar_path)
    "microcode_amd_20090120": (
     "da7b21c031a3c3ab3dacbb23c3cb8f0ec19161f9adb22c5c619b7b1471ba57cd",
     "http://web.archive.org/web/20160726141516/" +
     "http://www.amd64.org/microcode/amd-ucode-2009-01-20.tar",
     "amd-ucode-2009-01-20/microcode_amd.bin"),
    "microcode_amd_20110111": (
     "4551c30e4eabe838e783484b173366c4e8c448b4cdc9770bb5719907246c19b4",
     "http://web.archive.org/web/20160726141516/" +
     "http://www.amd64.org/microcode/amd-ucode-2011-01-11.tar",
     "amd-ucode-2011-01-11/microcode_amd.bin"),
    "microcode_amd_20120117": (
     "2d3cbc267ddcb7fee54d2302fafaa5f19b02b501db011ab87f2901abb9e1d1dc",
     "http://web.archive.org/web/20160726141516/" +
     "http://www.amd64.org/microcode/amd-ucode-2012-01-17.tar",
     "amd-ucode-2012-01-17/microcode_amd.bin"),
    "microcode_amd_fam15h_20120117": (
     "0029f635a56413e945e4f364b01e9ed93ec97963b2f3209fcbbfc5735eab673d",
     "http://web.archive.org/web/20160726141516/" +
     "http://www.amd64.org/microcode/amd-ucode-2012-01-17.tar",
     "amd-ucode-2012-01-17/microcode_amd_fam15h.bin"),
    "microcode_amd_fam15h_20130711": (
     "8b0f67c59157dbf5075fd5f8078b8a43eba1c8d978286a98ebb9b476e4594db2",
     "http://web.archive.org/web/20160726141516/" +
     "http://www.amd64.org/microcode/amd-ucode-2013-07-11.tar.bz2",
     "amd-ucode/microcode_amd_fam15h.bin"),
    "microcode_amd_solaris_20120910": (
     "ce18c411ca5873b872291177c73a8237aa26c2c21b03b25e333865555a26b304",
     "http://web.archive.org/web/20160726141516/" +
     "http://www.amd64.org/microcode/amd-ucode-2012-09-10.tar",
     "amd-ucode-2012-01-17/microcode_amd_solaris.bin"),
    "microcode_amd_latest": (
     "8a9d9e8b788e31e61cddc03cb1eeab5db99e0f667128943ff0780e6437d2e43e",
     ("https://git.kernel.org/pub/scm/linux/kernel/git/firmware/" +
      "linux-firmware.git/plain/amd-ucode/microcode_amd.bin",
      "https://gitlab.com/kernel-firmware/" +
      "linux-firmware/-/raw/main/amd-ucode/microcode_amd.bin"),
     None),
    "microcode_amd_fam15h_latest": (
     "9d4a668410e72a4bdb86dc23e4261eca04daa83456ada02504115223f356981a",
     ("https://git.kernel.org/pub/scm/linux/kernel/git/firmware/" +
      "linux-firmware.git/plain/amd-ucode/microcode_amd_fam15h.bin",
      "https://gitlab.com/kernel-firmware/" +
      "linux-firmware/-/raw/main/amd-ucode/microcode_amd_fam15h.bin"),
     None),
    "microcode_amd_fam16h_latest": (
     "e02ad653b39c975d6c52674b50f23727bb6706bab7b4e5b391a4ce229e7ff121",
     ("https://git.kernel.org/pub/scm/linux/kernel/git/firmware/" +
      "linux-firmware.git/plain/amd-ucode/microcode_amd_fam16h.bin",
      "https://gitlab.com/kernel-firmware/" +
      "linux-firmware/-/raw/main/amd-ucode/microcode_amd_fam16h.bin"),
     None),
    "microcode_amd_fam17h_20241121": (
     "966e4b796ec689c618868d08f8a37f347b0e7bfce4ae9df793e08471d363b7d0",
     ("https://git.kernel.org/pub/scm/linux/kernel/git/firmware/" +
      "linux-firmware.git/plain/amd-ucode/microcode_amd_fam17h.bin" +
      "?id=48bb90cceb882cab8e9ab692bc5779d3bf3a13b8",
      "https://gitlab.com/kernel-firmware/" +
      "linux-firmware/-/raw/48bb90cceb882cab8e9ab692bc5779d3bf3a13b8/" +
      "amd-ucode/microcode_amd_fam17h.bin"),
     None),
    "microcode_amd_fam19h_20241121": (
     "bcc4ea74dede10b2e0750780cf644ec0e3f9cfa240c0527e85a8853106c56af3",
     ("https://git.kernel.org/pub/scm/linux/kernel/git/firmware/" +
      "linux-firmware.git/plain/amd-ucode/microcode_amd_fam19h.bin" +
      "?id=48bb90cceb882cab8e9ab692bc5779d3bf3a13b8",
      "https://gitlab.com/kernel-firmware/" +
      "linux-firmware/-/raw/48bb90cceb882cab8e9ab692bc5779d3bf3a13b8/" +
      "amd-ucode/microcode_amd_fam19h.bin"),
     None),
}
# The list of containers to run test_released_container on
CONTAINERS = CONTAINER_DATA.keys()
CONTAINER_SETS = {
    # (name, [containers], sha256)
    "microcode_amd_concat": (
     ("microcode_amd_20090120", "microcode_amd_20110111",
      "microcode_amd_20120117", "microcode_amd_solaris_20120910",
      "microcode_amd_latest"),
     "e72151bef4cb15f3f64c05cae4cca57c38a4e94c527bbe0d2cc238e7bb311f83"),
    "microcode_amd_all_families": (
     ("microcode_amd_latest",
      "microcode_amd_fam15h_latest",
      "microcode_amd_fam16h_latest",
      "microcode_amd_fam17h_20241121",
      "microcode_amd_fam19h_20241121"),
     "fbf3ec696d6bbc9d50c4c3c295876a4c72817931ffde6b59012d863cd8492ca6"),
}
# The list of containers to run test_concatenated_container on
CONCAT_CONTAINERS = CONTAINER_SETS.keys()
# Test vectors for test_multiple_containers
MULTIPLE_CONTAINERS = [
    ("microcode_amd_20090120", "microcode_amd_20110111",
     "microcode_amd_20120117", "microcode_amd_solaris_20120910",
     "microcode_amd_latest"),
    CONTAINER_SETS.keys(),
    ("microcode_amd_fam17h_20241121",
     "microcode_amd_concat",
     "microcode_amd_fam19h_20241121"),
]
CUR_DIR = pathlib.Path(os.path.realpath(__file__)).parent
CACHE_DIR = CUR_DIR / "container_cache"
EXP_DIR = CUR_DIR / "container_exp"
AUI_PATH = os.getenv("AUI_PATH")


class IncorrectCheckSumError(Exception):
    def __init__(self, csum, exp):
        self.csum = csum
        self.exp = exp
        super().__init__("Incorrect checksum, got %s, expected %s" %
                         (csum, exp))


def file_csum(f):
    csum = hashlib.sha256()
    csum.update(f.read())

    return csum.hexdigest()


def check_csum(path, exp_csum):
    """
    Check if file is already exists iand has the expected checksum
    """
    try:
        c = open(path, mode="rb")
        csum = file_csum(c)
        if csum != exp_csum:
            warnings.warn(RuntimeWarning(("Checksum mismatch: %s expected, " +
                                          "got %s, trying to download") %
                                         (exp_csum, csum)))
            return False
    except OSError as e:
        if e.errno == errno.ENOENT:
            return False
        else:
            raise

    return True


@pytest.fixture(scope="module")
def container(tmp_path_factory):
    """
    container fixture is a factory that provides a function that verifies
    that the correct microcode container is in the cache, and tries
    to download it if it is not the case, returning a tuple of microcode name
    and the path ot it.
    """
    def get_container(name):
        exp_csum, urls, tar_path = CONTAINER_DATA[name]
        path = CACHE_DIR / ("%s.bin" % name)

        os.makedirs(CACHE_DIR, exist_ok=True)

        if not check_csum(path, exp_csum):
            # Download into a temporary directory and check its checksum,
            # copy to the cache on success
            if not isinstance(urls, tuple):
                urls = (urls,)
            dl = tmp_path_factory.mktemp("dl")

            csum_ok = False
            for url in urls:
                tmp = dl / \
                    ("%s.%s" % (name, "out" if tar_path is None else "tar"))
                r = requests.get(url, allow_redirects=True)
                if r.status_code != 200:
                    continue
                with open(tmp, mode="wb") as t:
                    t.write(r.content)

                # Some microcode blobs are inside tarballs, need to be extracted
                if tar_path is not None:
                    with tarfile.open(tmp, "r:*") as tar:
                        tmp = dl / ("%s.bin" % name)
                        ti = tar.getmember(tar_path)
                        ti.name = tmp.name
                        tar.extract(ti, path=tmp.parent, set_attrs=False)

                # Check the checksum before copying to the cache,
                # bail out on mismatch
                with open(tmp, mode="rb") as t:
                    tmp_csum = file_csum(t)

                    if tmp_csum == exp_csum:
                        csum_ok = True
                        break

            if not csum_ok:
                raise IncorrectCheckSumError(tmp_csum, exp_csum)

            shutil.move(tmp, path)

        rel_path = path.relative_to(CUR_DIR)

        return (name, rel_path)

    return get_container


@pytest.fixture(scope="module", params=CONTAINERS)
def released_container(request, container):
    return container(request.param)


@pytest.fixture(scope="module")
def concat_container(request, container, tmp_path_factory):
    def get_concat_container(name):
        containers, exp_csum = CONTAINER_SETS[name]
        path = CACHE_DIR / ("%s.bin" % name)

        os.makedirs(CACHE_DIR, exist_ok=True)

        if not check_csum(path, exp_csum):
            concat = tmp_path_factory.mktemp("concat")
            tmp = pathlib.Path(concat, "%s.bin" % name)

            with open(tmp, mode="wb") as t:
                for cname in containers:
                    _, cpath = container(cname)

                    with open(CUR_DIR / cpath, "rb") as c:
                        t.write(c.read())

            # Check the checksum before copying to the cache,
            # bail out on mismatch
            with open(tmp, mode="rb") as t:
                tmp_csum = file_csum(t)

                if tmp_csum != exp_csum:
                    raise IncorrectCheckSumError(tmp_csum, exp_csum)

            shutil.move(tmp, path)

        rel_path = path.relative_to(CUR_DIR)

        return (name, rel_path)

    return get_concat_container


@pytest.fixture(scope="module", params=CONTAINER_SETS)
def concat_released_container(request, concat_container):
    return concat_container(request.param)


@pytest.fixture(scope="module",
                params=MULTIPLE_CONTAINERS, ids=lambda x: "+".join(x))
def multiple_containers(request, container, concat_container):
    containers = request.param
    return [container(cname) if cname in CONTAINERS else
            concat_container(cname) for cname in containers]


def __test_container(capfd, container, exp, args):
    name, path = container
    exp_data = exp(name, "".join(args))
    subprocess.run([AUI_PATH, ] + args + [path, ], cwd=CUR_DIR)

    out, err = capfd.readouterr()
    assert err == ""
    assert out == exp_data


@pytest.mark.parametrize("args", [([]), (["-v"]), (["-v", "--verbose"])],
                         ids=lambda x: "".join(x))
def test_released_container(capfd, released_container, exp, args):
    __test_container(capfd, released_container, exp, args)


@pytest.mark.parametrize("args", [([]), (["--verbose"]), (["-vv"])],
                         ids=lambda x: "".join(x))
def test_concatenated_container(capfd, concat_released_container, exp, args):
    __test_container(capfd, concat_released_container, exp, args)


@pytest.mark.parametrize("args", [([]), (["-v"]), (["-v", "--verbose"])],
                         ids=lambda x: "".join(x))
def test_multiple_containers(capfd, multiple_containers, exp, args):
    cdata = multiple_containers
    exp_data = ""
    paths = []

    for name, path in cdata:
        exp_data += exp(name, "".join(args))
        paths.append(path)

    subprocess.run([AUI_PATH, ] + args + paths, cwd=CUR_DIR)

    out, err = capfd.readouterr()
    assert err == ""
    assert out == exp_data
