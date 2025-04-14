#!/usr/bin/python3

# Test detect_raw_patch
#
# SPDX-License-Identifier: MIT License
# Copyright (C) 2025 amd_ucode_info developers

import io
import os
import pytest
import sys

from functools import reduce
from itertools import zip_longest

CUR_DIR = os.path.dirname(os.path.realpath(__file__))
AUI_PATH = os.getenv("AUI_PATH")
AUI_DIR = os.path.dirname(AUI_PATH)

# Avoid mangling sys.path if pytest is called with --aui-path=amd_ucode_info
# for testing the system version of the script.
if AUI_DIR:
    sys.path.insert(0, AUI_DIR)
from amd_ucode_info import PatchHeader, RawPatchIssue, detect_raw_patch

# Test data for testing detect_raw_patch function
DETECT_RAW_PATCH_TEST_DATA = {
    # name: (data, expected_hdr_args, expected_desc)
    "no_data": (b'', (0,),
                {RawPatchIssue.YEAR_OUT_OF_RANGE:
                    "year (0000) is out of 2000..2099 range",
                 RawPatchIssue.DAY_OUT_OF_RANGE:
                    "day (00) is out of 01..31 range",
                 RawPatchIssue.MONTH_OUT_OF_RANGE:
                    "month (00) is out of 01..13 range",
                 RawPatchIssue.UNEXPECTED_PATCH_DATA_ID:
                    "patch data format ID (0x0000) is out of the expected"
                    " 0x8000..0x80ff range",
                 }),
    "lo_bytes": (bytes(range(0, 256)),
                 (0x03020100, 0x07060504, 0x0908, 0x0a, 0x0b, 0x0f0e0d0c,
                  0x13121110, 0x17161514, 0x1918, 0x1a, 0x1b, 0x1c,
                  (0x1d, 0x1e, 0x1f),
                  tuple(range(0x23222120, 0x43424140, 0x04040404))),
                 {RawPatchIssue.YEAR_OUT_OF_RANGE:
                     "year (0100) is out of 2000..2099 range",
                  RawPatchIssue.UNEXPECTED_PATCH_DATA_ID:
                     "patch data format ID (0x0908) is out of the expected"
                     " 0x8000..0x80ff range",
                  RawPatchIssue.UNEXPECTED_NON_ZERO_CSUM:
                     "non-zero checksum field value (0x0f0e0d0c) for patch"
                     " data format 0x0908",
                  RawPatchIssue.UNEXPECTED_RESERVED_VALUE:
                     "unexpected reserved field value (b'\\x1d\\x1e\\x1f')"
                     " for data format ID 0x0908 (b'\\x00\\x00\\x00'"
                     " expected)",
                  }),
    "ascii_bytes": (bytes(range(64, 128)),
                    (0x43424140, 0x47464544, 0x4948, 0x4a, 0x4b, 0x4f4e4d4c,
                     0x53525150, 0x57565554, 0x5958, 0x5a, 0x5b, 0x5c,
                     (0x5d, 0x5e, 0x5f),
                     tuple(range(0x63626160, 0x83828180, 0x04040404))),
                    {RawPatchIssue.YEAR_OUT_OF_RANGE:
                        "year (4140) is out of 2000..2099 range",
                     RawPatchIssue.DAY_OUT_OF_RANGE:
                        "day (42) is out of 01..31 range",
                     RawPatchIssue.MONTH_OUT_OF_RANGE:
                        "month (43) is out of 01..13 range",
                     RawPatchIssue.UNEXPECTED_ZEN_PATCH_LVL:
                        "unexpected non-zero reserved field value (0x00060000)"
                        " in Zen+ patch level (0x47464544)",
                     RawPatchIssue.UNEXPECTED_PATCH_DATA_ID:
                        "patch data format ID (0x4948) is out of the expected"
                        " 0x8000..0x80ff range",
                     RawPatchIssue.UNEXPECTED_NON_ZERO_CSUM:
                        "non-zero checksum field value (0x4f4e4d4c) for patch"
                        " data format 0x4948",
                     RawPatchIssue.UNEXPECTED_RESERVED_VALUE:
                        "unexpected reserved field value (b']^_') for data"
                        " format ID 0x4948 (b'\\x00\\x00\\x00' expected)",
                     }),
    "hi_bytes": (bytes(range(160, 256)),
                 (0xa3a2a1a0, 0xa7a6a5a4, 0xa9a8, 0xaa, 0xab, 0xafaeadac,
                  0xb3b2b1b0, 0xb7b6b5b4, 0xb9b8, 0xba, 0xbb, 0xbc,
                  (0xbd, 0xbe, 0xbf),
                  tuple(range(0xc3c2c1c0, 0xe3e2e1e0, 0x04040404))),
                 {RawPatchIssue.NON_DEC_DATE_DIGIT:
                     "a non-decimal digit 0xa is present in the patch date"
                     " field (0xa3a2a1a0)",
                  RawPatchIssue.YEAR_OUT_OF_RANGE:
                     "year (a1a0) is out of 2000..2099 range",
                  RawPatchIssue.DAY_OUT_OF_RANGE:
                     "day (a2) is out of 01..31 range",
                  RawPatchIssue.MONTH_OUT_OF_RANGE:
                     "month (a3) is out of 01..13 range",
                  RawPatchIssue.UNEXPECTED_ZEN_PATCH_LVL:
                     "unexpected non-zero reserved field value (0x00060000)"
                     " in Zen+ patch level (0xa7a6a5a4)",
                  RawPatchIssue.UNEXPECTED_PATCH_DATA_ID:
                     "patch data format ID (0xa9a8) is out of the expected"
                     " 0x8000..0x80ff range",
                  RawPatchIssue.UNEXPECTED_NON_ZERO_CSUM:
                     "non-zero checksum field value (0xafaeadac) for patch"
                     " data format 0xa9a8",
                  RawPatchIssue.UNEXPECTED_RESERVED_VALUE:
                     "unexpected reserved field value (b'\\xbd\\xbe\\xbf')"
                     " for data format ID 0xa9a8 (b'\\x00\\x00\\x00'"
                     " expected)",
                  }),
    "year_1999": (None, (0x12311999, 0x00000000, 0x8080, 0x80, 0x80),
                  {RawPatchIssue.YEAR_OUT_OF_RANGE:
                      "year (1999) is out of 2000..2099 range",
                   }),
    # Also checks the checksum and the reserved field for format 0x8000
    "year_2100": (None,
                  (0x01012100, 0x010fffff, 0x8000, 0xff, 0x00, 0xfedcba98,
                   0, 0, 0x10aa, 0xab, 0xcd, 0xef, (0xaa,) * 3),
                  {RawPatchIssue.YEAR_OUT_OF_RANGE:
                      "year (2100) is out of 2000..2099 range",
                   }),
    "month_00": (None, (0x00302000, 0x08a0cdef, 0x8002),
                 {RawPatchIssue.MONTH_OUT_OF_RANGE:
                     "month (00) is out of 01..13 range",
                  }),
    # 0x03000027 microcode patch has the data_code value of 0x13092011
    "month_13": (None,
                 (0x13092011, 0x03000027, 0x8004, 0x00, 0x01, 0x00000000,
                  0x12001022, 0x12041022, 0x3010),
                 {}),
    "month_14": (None, (0x14012099, 0x03000027, 0x8006, 0x82, 0x03),
                 {RawPatchIssue.MONTH_OUT_OF_RANGE:
                     "month (14) is out of 01..13 range",
                  }),
    # Also checks the reserved field for format 0x8001
    "day_00": (None,
               (0x12002022, 0x08000000, 0x8001, 0x00, 0x00, 0x00000000,
                0x00000000, 0x00000000, 0x8000, 0x00, 0x00, 0x00,
                (0xaa,) * 3),
               {RawPatchIssue.DAY_OUT_OF_RANGE:
                   "day (00) is out of 01..31 range",
                }),
    # Also checks the checksum and the reserved field for format 0x8003
    "day_32": (None,
               (0x02322084, 0x80000000, 0x8003, 0x00, 0x00, 0x12345678,
                0x00000000, 0x00000000, 0x8000, 0x00, 0x00, 0x00,
                (0xaa,) * 3),
               {RawPatchIssue.DAY_OUT_OF_RANGE:
                   "day (32) is out of 01..31 range",
                }),
    # pre-Zen patch IDs mostly utilised the lower bits, and there are none seen
    # so far that use bits 0x00f00000 of the patch level.
    "pre_zen_lvl1": (None, (0x12232056, 0x00100000, 0x8005),
                     {RawPatchIssue.UNEXPECTED_PRE_ZEN_PATCH_LVL:
                         "unexpected pre-Zen patch level (0x00100000)",
                      }),
    "pre_zen_lvl2": (None, (0x01232045, 0x01800000, 0x8006),
                     {RawPatchIssue.UNEXPECTED_PRE_ZEN_PATCH_LVL:
                         "unexpected pre-Zen patch level (0x01800000)",
                      }),
    "pre_zen_lvl3": (None, (0x02202020, 0x07f00000, 0x8006),
                     {RawPatchIssue.UNEXPECTED_PRE_ZEN_PATCH_LVL:
                         "unexpected pre-Zen patch level (0x07f00000)",
                      }),
    "zen_lvl1": (None, (0x10182028, 0x08010000, 0x8006),
                 {RawPatchIssue.UNEXPECTED_ZEN_PATCH_LVL:
                     "unexpected non-zero reserved field value (0x00010000)"
                     " in Zen+ patch level (0x08010000)",
                  }),
    "zen_lvl2": (None, (0x02112029, 0x0b061234, 0x800a),
                 {RawPatchIssue.UNEXPECTED_ZEN_PATCH_LVL:
                     "unexpected non-zero reserved field value (0x00060000)"
                     " in Zen+ patch level (0x0b061234)",
                  }),
    "zen_lvl3": (None, (0x12162024, 0xfff8ffff, 0x800f),
                 {RawPatchIssue.UNEXPECTED_ZEN_PATCH_LVL:
                     "unexpected non-zero reserved field value (0x00080000)"
                     " in Zen+ patch level (0xfff8ffff)",
                  }),
    "data_id_7fff": (None, (0x12162024, 0x0890abcd, 0x7fff),
                     {RawPatchIssue.UNEXPECTED_PATCH_DATA_ID:
                         "patch data format ID (0x7fff) is out of the expected"
                         " 0x8000..0x80ff range",
                      }),
    "data_id_8100": (None,
                     (0x12162024, 0x01020304, 0x8100, 0x00, 0x00, 0x00000000,
                      0x10221022, 0x10221022, 0x1234),
                     {RawPatchIssue.UNEXPECTED_PATCH_DATA_ID:
                         "patch data format ID (0x8100) is out of the expected"
                         " 0x8000..0x80ff range",
                      }),
    "cksum_8001": (None,
                   (0x12232034, 0x80000000, 0x8001, 0x02, 0x01, 0x00000001,
                    0x00000000, 0x00000000, 0x8088, 0x01, 0x02, 0x03,
                    (0xaa,) * 3),
                   {RawPatchIssue.UNEXPECTED_NON_ZERO_CSUM:
                       "non-zero checksum field value (0x00000001) for patch"
                       " data format 0x8001",
                    }),
    "reserved0": (None,
                  (0x01022010, 0x0f000000, 0x8000),
                  {RawPatchIssue.UNEXPECTED_OLD_RESERVED_VALUE:
                      "unexpected reserved field value (b'\\x00\\x00\\x00')"
                      " for data format ID 0x8000 (b'\\xaa\\xaa\\xaa'"
                      " expected)",
                   }),
    "reserved1": (None,
                  (0x08102040, 0x10000000, 0x8001),
                  {RawPatchIssue.UNEXPECTED_OLD_RESERVED_VALUE:
                      "unexpected reserved field value (b'\\x00\\x00\\x00')"
                      " for data format ID 0x8001 (b'\\xaa\\xaa\\xaa'"
                      " expected)",
                   }),
    "reserved2": (None,
                  (0x05102040, 0x20000000, 0x8002, 0x00, 0x00, 0x00000000,
                   0x00000000, 0x00000000, 0x0000, 0x00, 0x00, 0x00,
                   (0x41, 0x4d, 0x44)),
                  {RawPatchIssue.UNEXPECTED_RESERVED_VALUE:
                      "unexpected reserved field value (b'AMD')"
                      " for data format ID 0x8002 (b'\\x00\\x00\\x00'"
                      " expected)",
                   }),
    "reserved3": (None,
                  (0x09142035, 0x40000000, 0x8003),
                  {RawPatchIssue.UNEXPECTED_OLD_RESERVED_VALUE:
                      "unexpected reserved field value (b'\\x00\\x00\\x00')"
                      " for data format ID 0x8003 (b'\\xaa\\xaa\\xaa'"
                      " expected)",
                   }),
    "reserved4": (None,
                  (0x05102040, 0x20000000, 0x8004, 0x00, 0x00, 0x00000000,
                   0x00000000, 0x00000000, 0x0000, 0x00, 0x00, 0x00,
                   (0x20, 0x22, 0x27)),
                  {RawPatchIssue.UNEXPECTED_RESERVED_VALUE:
                      "unexpected reserved field value (b' \"\\'')"
                      " for data format ID 0x8004 (b'\\x00\\x00\\x00'"
                      " expected)",
                   }),
}
DETECT_RAW_PATCH_TESTS = DETECT_RAW_PATCH_TEST_DATA.keys()


@pytest.mark.parametrize("name", DETECT_RAW_PATCH_TESTS)
def test_detect_raw_patch(name):
    def serialize(vals):
        def it(x, y):
            if isinstance(x, tuple):
                if not isinstance(y, tuple):
                    y = (y,) * len(x)
                for a, b in zip_longest(x, y, fillvalue=0):
                    yield from it(a, b)
            else:
                yield y.to_bytes(x, 'little')

        szs = (4, 4, 2, 1, 1, 4, 4, 4, 2, 1, 1, 1, (1,) * 3, (4,) * 8)

        return b''.join(tuple(it(szs, vals)))

    data, exp_hdr, exp_desc = DETECT_RAW_PATCH_TEST_DATA[name]
    if data is None:
        data = serialize(exp_hdr)
    exp_hdr = PatchHeader(*exp_hdr)
    exp_issues = reduce(lambda x, y: x | y, exp_desc.keys(),
                        RawPatchIssue.NONE)
    f = io.BytesIO(data)

    hdr, issues, desc = detect_raw_patch(f)

    assert hdr == exp_hdr
    assert desc == exp_desc
    assert issues == exp_issues
