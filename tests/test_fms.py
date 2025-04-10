#!/usr/bin/python3

# Test CPUID-related functions
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
from amd_ucode_info import FMS, cpuid2fms, fms2str, cpuid2str

# Test data for testing cpuid2fms, fms2str, and cpuid2str functions
FMS_TEST_DATA = [
    # (FMS, str)
    (FMS(0x000, 0x00, 0x0, False, 0x00000000, 0x00000000),
     "Family=0x00 Model=0x00 Stepping=0x00"),
    (FMS(0x006, 0x07, 0x8, False, 0x00000000, 0x00000678),
     "Family=0x06 Model=0x07 Stepping=0x08"),
    (FMS(0x00f, 0x0f, 0xf, False, 0x00000000, 0x00000fff),
     "Family=0x0f Model=0x0f Stepping=0x0f"),
    (FMS(0x01e, 0xf0, 0x1, False, 0x00000000, 0x00ff0f01),
     "Family=0x1e Model=0xf0 Stepping=0x01"),
    (FMS(0x10e, 0xff, 0xf, False, 0x00000000, 0x0fff0fff),
     "Family=0x10e Model=0xff Stepping=0x0f"),
    (FMS(0x00f, 0x0f, 0xf, True, 0x00000000, 0x00100eff), "CPUID=0x00100eff"),
    (FMS(0x006, 0x03, 0x2, False, 0x00001000, 0x00001632), "CPUID=0x00001632"),
    (FMS(0x010, 0x01, 0x2, False, 0x10000000, 0x10100f12), "CPUID=0x10100f12"),
    (FMS(0x0ba, 0xce, 0xd, True, 0xb0000000, 0xbadc0ded), "CPUID=0xbadc0ded"),
    (FMS(0x10e, 0xff, 0xf, False, 0xf000f000, 0xffffffff), "CPUID=0xffffffff"),
]

CPUID2FMS_TESTS = [(x[0].cpu_id, x[0]) for x in FMS_TEST_DATA]
FMS2STR_TESTS = [(x[0], x[1]) for x in FMS_TEST_DATA]
CPUID2STR_TESTS = [(x[0].cpu_id, x[1]) for x in FMS_TEST_DATA]


@pytest.mark.parametrize("args", CPUID2FMS_TESTS,
                         ids=lambda x: "%#010x" % x[0])
def test_cpuid2fms(args):
    cpuid, fms = args
    assert cpuid2fms(cpuid) == fms


@pytest.mark.parametrize("args", FMS2STR_TESTS,
                         ids=lambda x: "%#010x" % x[0].cpu_id)
def test_fms2str(args):
    fms, out = args
    assert fms2str(fms) == out


@pytest.mark.parametrize("args", CPUID2STR_TESTS,
                         ids=lambda x: "%#010x" % x[0])
def test_cpuid2str(args):
    cpuid, out = args
    assert cpuid2str(cpuid) == out
