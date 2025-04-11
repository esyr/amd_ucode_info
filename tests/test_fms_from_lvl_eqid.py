#!/usr/bin/python3

# Test fms_from_lvl_eqid
#
# SPDX-License-Identifier: MIT License
# Copyright (C) 2025 amd_ucode_info developers

import os
import pytest
import sys

CUR_DIR = os.path.dirname(os.path.realpath(__file__))
AUI_PATH = os.getenv("AUI_PATH")
AUI_DIR = os.path.dirname(AUI_PATH)

# Avoid mangling sys.path if pytest is called with --aui-path=amd_ucode_info
# for testing the system version of the script.
if AUI_DIR:
    sys.path.insert(0, AUI_DIR)
from amd_ucode_info import cpuid2fms, fms_from_lvl_eqid

# Test data for testing fms_from_lvl_eqid function
FMS_FROM_LVL_EQID_TESTS = [
    # (lvl, eqid, cpuid, stderr)
    (0x01000084, 0x1022, 0x100f22, ""),
    (0x05000028, 0x5010, 0x500f10, ""),
    (0x06000624, 0x6012, 0x600f12, ""),
    (0x0700010f, 0x7001, 0x700f01, ""),
    (0x0a00107a, 0xa010, 0xa00f10, ""),
    (0x0a201210, 0xa212, 0xa20f12, ""),
    (0x0aa00116, 0xaa01, 0xaa0f01, ""),

    (0x00000000, 0x0000, None, ""),
    (0x00caffee, 0xdead, None, ""),
    (0x01234567, 0x0123, None,
     "WARNING: Discrepancy in the extended family value between the patch " +
     "level (0x01 in 0x01234567) and equivalence ID (0x0 in 0x0123)\n"),
    (0x01234567, 0x1234, 0x120f34, ""),
    (0x06adc0de, 0x7175, None,
     "WARNING: Discrepancy in the extended family value between the patch " +
     "level (0x06 in 0x06adc0de) and equivalence ID (0x7 in 0x7175)\n"),
    (0xbad0da7a, 0xface, 0xbad0fda, ""),
    (0xbadc0ded, 0x7e57, None,
     "WARNING: Reserved field (0xc) in the family 17h+ patch level " +
     "(0xbadc0ded) is not zero\n"),
]


@pytest.mark.parametrize("args", FMS_FROM_LVL_EQID_TESTS,
                         ids=lambda x: "lvl:%#010x-eqid:%#06x" % (x[0], x[1]))
def test_cpuid2str(args, capfd):
    lvl, eqid, exp_cpuid, exp_err = args
    exp_fms = cpuid2fms(exp_cpuid) if exp_cpuid is not None else None

    fms = fms_from_lvl_eqid(lvl, eqid, None, None)
    out, err = capfd.readouterr()

    assert fms == exp_fms
    assert err == exp_err
    assert out == ""
