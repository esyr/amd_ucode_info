#!/usr/bin/python3

# Test various synthetic microcode container to trigger various amd_ucode_info
# parsing corner cases.
#
# SPDX-License-Identifier: MIT License
# Copyright (C) 2025 amd_ucode_info developers

import errno
import os
import pytest
import re
import struct
import subprocess

from collections import namedtuple

CUR_DIR = os.path.dirname(os.path.realpath(__file__))
AUI_PATH = os.getenv("AUI_PATH")


def u8(val):
    return struct.pack("<B", val)


def u16(val):
    return struct.pack("<H", val)


def u32(val):
    return struct.pack("<I", val)


def eqtbl_item(cpuid, eqid, errata_mask=0, errata_compare=0, res=0):
    return u32(cpuid) + u32(errata_mask) + u32(errata_compare) + \
           u16(eqid) + u16(res)


def patch_hdr(rev, eqid, date=0, checksum=0, data_id=0, data_len=0,
              init_flag=0, nb_dev_id=0, sb_dev_id=0,
              nb_rev_id=0, sb_rev_id=0, bios_api_rev=0,
              res=(0,)*3, match_reg=(0,)*8):
    return u32(date) + u32(rev) + \
           u16(data_id) + u8(data_len) + u8(init_flag) + \
           u32(checksum) + u32(nb_dev_id) + u32(sb_dev_id) + \
           u16(eqid) + u8(nb_rev_id) + u8(sb_rev_id) + \
           u8(bios_api_rev) + b''.join([u8(res[i]) for i in range(3)]) + \
           b''.join([u32(match_reg[i]) for i in range(8)])


MAGIC = u32(0x00414d44)
EQTBL_SECTION_ID = u32(0)
PATCH_SECTION_ID = u32(1)

ETD = namedtuple("ExtractTestData",
                 ("extract_xfail", "split_xfail", "reason", "warnings",
                  "data", "out"))

TEST_DATA = {
    # name: (data, retcode, has_exp, err)
    # data is a tuple of bytes, retcode is an integer,
    # has_exp is a boolean, err is a tuples of expected stdout/stderr strings,
    # None means the usage of *.out/*.err files in EXP_DIR
    "empty": ((), errno.EINVAL, False,
              ("container+0x0000: ERROR: File is too short to contain " +
               "container magic (0 bytes left, at least 4 bytes needed)", "")),
    "short_magic": ((u8(0x44), u8(0x4d), u8(0x41)), errno.EINVAL, False,
                    ("container+0x0000: ERROR: File is too short to contain " +
                     "container magic (3 bytes left, at least 4 bytes needed)",
                     "")),
    "wrong_magic1": ((u8(0x49), u8(0x4e), u8(0x54), u8(0x43)),
                     errno.EINVAL, False,
                     ("container+0x0000: ERROR: File is too short to contain" +
                      " patch header (4 bytes left, at least 64 bytes needed)",
                      "")),
    "wrong_magic2": ((u8(0x49), u8(0x4e), u8(0x54), u8(0x43), u32(0) * 64),
                     errno.EINVAL, False, None),
    "only_magic": ((MAGIC, ), errno.EINVAL, False,
                   ("container+0x0004: ERROR: File is too short to contain " +
                    "equivalence table section header (0 bytes left, " +
                    "at least 8 bytes needed)", "")),
    "short_eqtbl_hdr1": ((MAGIC, u8(0)), errno.EINVAL, False,
                         ("container+0x0004: ERROR: File is too short " +
                          "to contain equivalence table section header " +
                          "(1 byte left, at least 8 bytes needed)", "")),
    "short_eqtbl_hdr2": ((MAGIC, EQTBL_SECTION_ID), errno.EINVAL, False,
                         ("container+0x0004: ERROR: File is too short " +
                          "to contain equivalence table section header " +
                          "(4 bytes left, at least 8 bytes needed)", "")),
    "short_eqtbl_hdr3": ((MAGIC, EQTBL_SECTION_ID, u16(0)),
                         errno.EINVAL, False,
                         ("container+0x0004: ERROR: File is too short " +
                          "to contain equivalence table section header " +
                          "(6 bytes left, at least 8 bytes needed)", "")),
    "wrong_eqtbl_id1": ((MAGIC, u32(1), u32(0)), errno.EINVAL, False,
                        ("container+0x0004: ERROR: Invalid equivalence "
                         "table section identifier: 0x00000001", "")),
    "empty_eqtbl": ((MAGIC, EQTBL_SECTION_ID, u32(0)), 0, False,
                    ("container: WARNING: Equivalence table section size " +
                     "(0) is too small to contain a single record",
                     "container: WARNING: A guard equivalence table " +
                     "record with zero CPUID is missing", "")),
    "short_eqtbl1": ((MAGIC, EQTBL_SECTION_ID, u32(1)), errno.EINVAL, False,
                     ("container+0x000c: ERROR: File is too short " +
                      "to contain equivalence table (0 bytes left, " +
                      "at least 1 byte needed)", "")),
    "short_eqtbl2": ((MAGIC, EQTBL_SECTION_ID, u32(1), u8(1)), 0, False,
                     ("container: WARNING: Equivalence table section size " +
                      "(1) is too small to contain a single record",
                      "container: WARNING: A guard equivalence table " +
                      "record with zero CPUID is missing", "")),
    "min_eqtbl1": ((MAGIC, EQTBL_SECTION_ID, u32(16), u32(0) * 4), 0, True,
                   ("",)),
    "min_eqtbl2": ((MAGIC, EQTBL_SECTION_ID, u32(20), u32(0) * 5), 0, True,
                   ("container+0x001c: WARNING: The remainder " +
                    "of the equivalence table section (4 bytes) " +
                    "is not big enough to accommodate an equalence table " +
                    "entry, ignoring it", "")),
    "min_eqtbl3": ((MAGIC, EQTBL_SECTION_ID, u32(16), u32(0xdeadbeef),
                    u32(0xfeedcafe), u32(0xbadc0ded), u32(0xface1e55)),
                   0, True,
                   ("container: WARNING: A guard equivalence table record " +
                    "with zero CPUID is missing", "")),
    "eqtbl_dup1": ((MAGIC, EQTBL_SECTION_ID, u32(48),
                    u32(0xdeadbeef), u32(0xfeedcafe),
                    u32(0xbadc0ded), u32(0xface1e55),
                    u32(0xdeadbeef), u32(0xfeedcafe),
                    u32(0xbadc0ded), u32(0xface1e55), u32(0) * 4),
                   0, True,
                   ("container+0x001c: WARNING: Duplicate CPUID 0xdeadbeef " +
                    "(CPUID=0xdeadbeef) in the equivalence table " +
                    "for equiv_id 0x1e55", "")),
    "eqtbl_dup2": ((MAGIC, EQTBL_SECTION_ID, u32(48),
                    u32(0x0bad0fed), u32(0xfeedcafe),
                    u32(0xbadc0ded), u32(0xface1e55),
                    u32(0x0bad0fed), u32(0xfeedcafe),
                    u32(0xbadc0ded), u32(0xdeefaced), u32(0) * 4),
                   0, True,
                   ("container+0x001c: WARNING: Different equiv_id's " +
                    "(0xaced and 0x1e55) are present in the equivalence " +
                    "table for CPUID 0x0bad0fed (Family=0xc9 Model=0xde " +
                    "Stepping=0x0d)", "")),
    "eqtbl_dup3": ((MAGIC, EQTBL_SECTION_ID, u32(48),
                    u32(0xdeadbeef), u32(0xfeedcafe),
                    u32(0xbadc0ded), u32(0xface1e55), u32(0) * 8),
                   0, True, ("",)),
    "eqtbl_dup4": ((MAGIC, EQTBL_SECTION_ID, u32(48), u32(0) * 4,
                    u32(0xdeadbeef), u32(0xfeedcafe),
                    u32(0xbadc0ded), u32(0xface1e55), u32(0) * 4),
                   0, True,
                   ("container+0x001c: WARNING: An equivalence table record " +
                    "with non-zero CPUID 0xdeadbeef (CPUID=0xdeadbeef) " +
                    "follows a record with zero CPUID (at position 0xc), " +
                    "some loader implementations may ignore it", "")),
    # Same equiv_id, different CPUIDs, nothing to report about
    "eqtbl_dup5": ((MAGIC, EQTBL_SECTION_ID, u32(48),
                    u32(0xdeadbeef), u32(0xfeedcafe),
                    u32(0xbadc0ded), u32(0xface1e55),
                    u32(0xdeedbeef), u32(0xfeedcafe),
                    u32(0xbadc0ded), u32(0xface1e55), u32(0) * 4),
                   0, True, ("",)),
    # Similar to eqtbl_dup1, but one of the records has equiv_id of 0
    # and is ignored by amd_ucode_info, despite being a matching record
    # for virtually all publically available microcode loader impementations;
    # note that it also not considered a stop record by FreeBSD parser.
    "eqtbl_dup6": ((MAGIC, EQTBL_SECTION_ID, u32(48),
                    u32(0xdeadbeef), u32(0xfeedcafe),
                    u32(0xbadc0ded), u32(0xface0000),
                    u32(0xdeadbeef), u32(0xfeedcafe),
                    u32(0xbadc0ded), u32(0xface1e55), u32(0) * 4),
                   0, True,
                   ("container+0x001c: WARNING: Different equiv_id's " +
                    "(0x1e55 and 0x0000) are present in the equivalence " +
                    "table for CPUID 0xdeadbeef (CPUID=0xdeadbeef)", "")),
    "bad_patch1": ((MAGIC, EQTBL_SECTION_ID, u32(16), u32(0) * 4,
                    EQTBL_SECTION_ID),
                   errno.EINVAL, True,
                   ("container+0x001c: ERROR: File is too short to contain " +
                    "microcode patch section header (4 bytes left, at least " +
                    "8 bytes needed)", "")),
    "bad_patch2": ((MAGIC, EQTBL_SECTION_ID, u32(16), u32(0) * 4,
                    EQTBL_SECTION_ID, u32(0), PATCH_SECTION_ID, u32(0)),
                   errno.EINVAL, True,
                   ("container+0x001c: ERROR: Invalid patch identifier: " +
                    "0x00000000", "")),
    "bad_patch3": ((MAGIC, EQTBL_SECTION_ID, u32(16), u32(0) * 4,
                    PATCH_SECTION_ID, u32(0)),
                   0, True,
                   ("container+0x0020: ERROR: Patch is too short (at least " +
                    "64 bytes expected, got 0), skipping", "")),
    "bad_patch4": ((MAGIC, EQTBL_SECTION_ID, u32(16), u32(0) * 4,
                    PATCH_SECTION_ID, u32(0), PATCH_SECTION_ID, u32(0)),
                   0, True,
                   ("container+0x0020: ERROR: Patch is too short (at least " +
                    "64 bytes expected, got 0), skipping",
                    "container+0x0028: ERROR: Patch is too short (at least " +
                    "64 bytes expected, got 0), skipping", "")),
    "bad_patch5": ((MAGIC, EQTBL_SECTION_ID, u32(16), u32(0) * 4,
                    PATCH_SECTION_ID, u32(64),
                    u32(0xbadc0ded) * 15, u16(0xcafe), u8(42)),
                   errno.EINVAL, True,
                   ("container+0x0024: ERROR: File is too short to contain " +
                    "microcode patch section (63 bytes left, at least " +
                    "64 bytes needed)", "")),
    "no_eqid": ((MAGIC, EQTBL_SECTION_ID, u32(16), u32(0) * 4,
                 PATCH_SECTION_ID, u32(64), u32(0x1a2b3c4d) * 16),
                0, True,
                ("container+0x001c: WARNING: Reserved field (0xb) " +
                 "in the family 17h+ patch level (0x1a2b3c4d) is not zero",
                 "container+0x001c: WARNING: Patch equivalence id " +
                 "not present in equivalence table (0x3c4d)", "")),
    "zero_eqid": ((MAGIC, EQTBL_SECTION_ID, u32(32),
                   u32(0xdeadbeef), u32(0xfeedcafe),
                   u32(0xbadc0ded), u32(0xface0000), u32(0) * 4,
                   PATCH_SECTION_ID, u32(68),
                   u32(0x12345678), u32(0x89abcdef),
                   u16(0xcafe), u8(0x42), u8(42),
                   u32(0xbadc0ded), u32(0xbeef1022), u32(0xface1022), u16(0),
                   u8(0x23), u8(0x69), u8(0xae),
                   u8(0x55) * 3, u32(0x8091a2b3) * 8, u32(0xc0deda7a)),
                  0, True,
                  ("container+0x002c: WARNING: Reserved field (0xb) " +
                   "in the family 17h+ patch level (0x89abcdef) is not zero",
                   "")),
    "zero_cpuid": ((MAGIC, EQTBL_SECTION_ID, u32(32),
                    eqtbl_item(0x00000000, 0xdead), u32(0) * 4,
                    PATCH_SECTION_ID, u32(64),
                    patch_hdr(0xbadc0ded, 0xdead, 0x07192002)),
                   0, True,
                   ("container+0x002c: WARNING: Reserved field (0xc) " +
                    "in the family 17h+ patch level (0xbadc0ded) is not zero",
                    "container+0x002c: WARNING: Patch equivalence id" +
                    " not present in equivalence table (0xdead)",
                    "")),
    "miss_cpuid": ((MAGIC, EQTBL_SECTION_ID, u32(32),
                    eqtbl_item(0x00780fab, 0xdead), u32(0) * 4,
                    PATCH_SECTION_ID, u32(64),
                    patch_hdr(0x0ab0cdef, 0xdead, 0x04052063)),
                   0, True,
                   ("container+0x002c: WARNING: CPUID decoded " +
                    "from the microcode patch header (Family=0x19 " +
                    "Model=0xbc Stepping=0x0d) is not present " +
                    "in the equivalence table", "")),
    "bad_cpuid": ((MAGIC, EQTBL_SECTION_ID, u32(32),
                   eqtbl_item(0x1230456, 0xdead), u32(0) * 4,
                   PATCH_SECTION_ID, u32(64),
                   patch_hdr(0xfacefeed, 0xdead, 0x07192002)),
                  0, True,
                  ("container+0x002c: WARNING: Reserved field (0xe) " +
                   "in the family 17h+ patch level (0xfacefeed) is not zero",
                   "")),
    "min_concat": ((MAGIC, EQTBL_SECTION_ID, u32(16), u32(0) * 4,
                    MAGIC, EQTBL_SECTION_ID, u32(16), u32(0) * 4), 0, True,
                   ("",)),
    # Check that eqtable definitions don't leak in other containers
    "concat_eqid1": ((MAGIC, EQTBL_SECTION_ID, u32(32),
                      eqtbl_item(0xdeadbeef, 0xcafe), u32(0) * 4,
                      MAGIC, EQTBL_SECTION_ID, u32(16), u32(0) * 4,
                      PATCH_SECTION_ID, u32(64),
                      patch_hdr(0xbadc0ded, 0xcafe, 0x31415926,
                                match_reg=(0x5a5a5a5a,)*8)),
                     0, True,
                     ("container+0x0048: WARNING: Reserved field (0xc) " +
                      "in the family 17h+ patch level (0xbadc0ded) " +
                      "is not zero",
                      "container+0x0048: WARNING: Patch equivalence id " +
                      "not present in equivalence table (0xcafe)", "")),
    "concat_eqid2": ((MAGIC, EQTBL_SECTION_ID, u32(32),
                      eqtbl_item(0xbadc0ded, 0xcafe), u32(0) * 4,
                      MAGIC, EQTBL_SECTION_ID, u32(32),
                      eqtbl_item(0x1632, 0xcafe), u32(0) * 4,
                      PATCH_SECTION_ID, u32(64),
                      patch_hdr(0xface1e55, 0xcafe, 0x1011970)),
                     0, True,
                     ("container+0x0058: WARNING: Reserved field (0xe) " +
                      "in the family 17h+ patch level (0xface1e55) " +
                      "is not zero", "")),
}
TESTS = TEST_DATA.keys()

extract_e1 = eqtbl_item(0x01230f45, 0x1234, 0xfedcba98, 0x12345678, 0xbead)
extract_e2 = eqtbl_item(0x01350f79, 0x1357)
extract_e3 = eqtbl_item(0x01470fad, 0x1234)
extract_e4 = eqtbl_item(0x0abc0fde, 0x1357)
extract_p1 = patch_hdr(0x12304567, 0x1234, 0x20042084, 0x5a5a5a, 0xabcd, 0x42,
                       0x23, 0xdead1022, 0xbeef1022, 0x23, 0x57, 0xae,
                       (0xaa, 0xbb, 0xcc),
                       tuple(x * 314159265 for x in range(1, 9)))
extract_p2 = patch_hdr(0x135079bd, 0x1357, 0x01022003) + b'\xba\xdc\x0d\xed'
EXTRACT_TEST_DATA = {
    # name: ((eqtblitem,), (patch,), extract_xfail, split_xfail, (chunks),
    #        ((extract_name, split_name, (eqtblidx), patchidx)))
    # eqtblitem, patch are either bytes or tuples of bytes
    # extract_xfail, split_xfail are bool
    # chunks are either bytes directly, or special tuples:
    # ("magic",), ("eqtable", eqtblitm, ...), ("patches", patch, ...)
    # Magic a the beginning of the file is added automatically.
    "extract_no_eqtbl1":
        ETD(False, False, None,
            ("container+0x001c: WARNING: Patch equivalence id not present " +
             "in equivalence table (0x1234)", ""),
            (("eqtable",), ("patches", extract_p1)),
            (("mc_patch_012304567.bin",
              "mc_equivid_0x1234_patch_0x12304567.bin",
              (), extract_p1),)),
    "extract_no_eqtbl2":
        ETD(False, False, None,
            ("container+0x002c: WARNING: Patch equivalence id not present " +
             "in equivalence table (0x1234)",
             "container+0x00a0: WARNING: Patch equivalence id not present " +
             "in equivalence table (0x1357)", ""),
            (("eqtable", extract_e2), ("patches", extract_p1),
             ("magic",),
             ("eqtable", extract_e1), ("patches", extract_p2)),
            (("mc_patch_012304567.bin",
              "mc_equivid_0x1234_patch_0x12304567.bin",
              (), extract_p1),
             ("mc_patch_0135079bd.bin",
              "mc_equivid_0x1357_patch_0x135079bd.bin",
              (), extract_p2),
             )),
    "extract_eqtbl1":
        ETD(False, False, None, ("",),
            (("eqtable", extract_e1), ("patches", extract_p1)),
            (("mc_patch_012304567.bin",
              "mc_equivid_0x1234_cpuid_0x01230f45_patch_0x12304567.bin",
              (extract_e1,), extract_p1),)),
    "extract_eqtbl2":
        ETD(False, False, None, ("",),
            (("eqtable", extract_e3, extract_e2, extract_e1, extract_e4),
             ("patches", extract_p2, extract_p1)),
            (("mc_patch_012304567.bin",
              "mc_equivid_0x1234_cpuid_0x01470fad_cpuid_0x01230f45"
              "_patch_0x12304567.bin",
              (extract_e3, extract_e1), extract_p1),
             ("mc_patch_0135079bd.bin",
              "mc_equivid_0x1357_cpuid_0x01350f79_cpuid_0x0abc0fde"
              "_patch_0x135079bd.bin",
              (extract_e2, extract_e4), extract_p2),)),
}
EXTRACT_TESTS = EXTRACT_TEST_DATA.keys()


@pytest.fixture(scope="module", params=TESTS)
def gen_container(request, tmp_path_factory):
    data, retcode, exp_data, err_data = TEST_DATA[request.param]
    cdir = tmp_path_factory.mktemp("synthetic")
    cpath = cdir / "container"
    with open(cpath, mode="wb") as c:
        for i in data:
            c.write(i)

    return (request.param, cpath, retcode, exp_data, err_data)


@pytest.fixture(params=EXTRACT_TESTS)
def gen_extract_container(request, tmp_path):
    desc = EXTRACT_TEST_DATA[request.param]
    cpath = tmp_path / "container"

    with open(cpath, mode="wb") as c:
        c.write(MAGIC)
        for i in desc.data:
            if isinstance(i, bytes):
                c.write(i)
            elif i[0] == "magic":
                c.write(MAGIC)
            elif i[0] == "eqtable":
                eqtbl = b''.join(i[1:])
                sz = len(eqtbl) + 16
                c.write(u32(0))
                c.write(u32(sz))
                c.write(eqtbl)
                c.write(b'\0' * 16)
            elif i[0] == "patches":
                for p in i[1:]:
                    c.write(u32(1))
                    c.write(u32(len(p)))
                    c.write(p)
            else:
                raise ValueError("Unexpected extract data item: %r" % i)

    return (request.param, tmp_path, desc)


@pytest.fixture
def extract_split_container(request, gen_extract_container):
    """
    Processes the data from gen_extract_container and generates
    the expected output based on which feature is used.

    Param: feature name, either "extract", or "spolit".

    Returns: (name, wd_path, arg_option, {patch_name: patch_data})
      - name - test vector name
      - wd_path - working dir to run amd_ucode_info in
      - arg_option - argument to pass in the command line to invoke
                     the feature requested (fature name prefixed with "--")
      - patch_name - file name of an output patch
      - patch_data - bytes representing the expected data that constitutes
                     the patch
    """
    name, path, desc = gen_extract_container
    is_split = request.param == "split"
    out = {}

    xfail = desc.split_xfail if is_split else desc.extract_xfail
    if xfail:
        request.node.add_marker(pytest.mark.xfail(reason=desc.reason))

    for extract_name, split_name, eqtbl_items, patch in desc.out:
        key = split_name if is_split else extract_name
        if is_split:
            print("%r" % (eqtbl_items,), file=open("/tmp/out_", "w+"))
            eqtbl = b''.join(eqtbl_items)
            data = b''.join((MAGIC,
                             u32(0), u32(len(eqtbl) + 16), eqtbl, b'\0' * 16,
                             u32(1), u32(len(patch)) + patch))
        else:
            data = patch

        out[key] = data

    return (name, path, "--" + request.param, desc.warnings, out)


@pytest.mark.parametrize("args", [([]), (["-v"]), (["-v", "-v"]), (["-vvv"])],
                         ids=lambda x: "".join(x))
def test_synthetic_container(capfd, gen_container, exp, err, args):
    name, cpath, retcode, exp_data, err_data = gen_container
    if exp_data:
        exp_data = exp(name, "".join(args))
    else:
        exp_data = "Microcode patches in container:\n"
    if err_data is None:
        err_data = err(name, "".join(args))
    else:
        err_data = "\n".join(err_data)
    cdir = os.path.dirname(cpath)
    cmpl = subprocess.run([AUI_PATH, ] + args + ["container", ], cwd=cdir)

    out, err = capfd.readouterr()
    assert out == exp_data
    assert err == err_data
    assert cmpl.returncode == retcode


@pytest.mark.parametrize("extract_split_container", ["extract", "split"],
                         indirect=True)
@pytest.mark.parametrize("verbosity_args", [([]), (["-v"]),
                                            (["--verbose", "--verbose"])],
                         ids=lambda x: "".join(x))
def test_synthetic_extract_split(request, capfd, extract_split_container, exp,
                                 verbosity_args):
    out_dir = "out"
    extract_re = re.compile(r"^(    Patch extracted to )(?P<path>.*)$",
                            re.MULTILINE)

    name, cpath, arg, err_data, out_patches = extract_split_container
    args = verbosity_args + [arg, out_dir]

    # TODO: Rewrite to exp_data generation from the test data
    exp_data = exp(name, "".join(args))
    # Monkeypatching the output paths
    exp_data = extract_re.sub(r"\1%s/\g<path>" % cpath, exp_data)

    err_data = "\n".join(err_data)

    cmpl = subprocess.run([AUI_PATH, ] + args + ["container", ], cwd=cpath)
    out, err = capfd.readouterr()

    assert out == exp_data
    assert err == err_data
    assert cmpl.returncode == 0

    out_path = cpath / out_dir
    processed = set()
    for out_path in out_path.iterdir():
        patch_name = out_path.name
        with open(out_path, "rb") as f:
            patch = f.read()

        assert out_patches[patch_name] == patch
        processed.add(patch_name)

    assert processed == out_patches.keys()
