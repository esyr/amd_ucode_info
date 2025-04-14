#!/usr/bin/python3
# SPDX-License-Identifier: MIT License
# Copyright (C) 2020 Advanced Micro Devices, Inc.

"""
Parse an amd-ucode container file and print the family, model, stepping number,
and patch level for each patch in the file. The --extract option will dump the
raw microcode patches to a provided directory.
"""

import argparse
import errno
import io
import os
import sys

from collections import namedtuple
from collections import OrderedDict
from enum import Flag, auto

MAGIC_SIZE = 4
SECTION_HDR_SIZE = 8
EQ_TABLE_ENTRY_SIZE = 16
EQ_TABLE_LEN_OFFSET = 8
EQ_TABLE_OFFSET = MAGIC_SIZE + SECTION_HDR_SIZE
EQ_TABLE_TYPE = 0
PATCH_TYPE = 1
PATCH_HEADER_SIZE = 64  # sizeof(struct microcode_header_amd)

VERBOSE_DEBUG = 2

FMS = namedtuple("FMS", ("family", "model", "stepping",
                         "family_invalid", "reserved", "cpu_id"))
EquivTableEntry = namedtuple("EquivTableEntry",
                             ("cpuid", "equiv_id", "data", "offset"))
PatchHeader = namedtuple("PatchHeader",
                         ("data_code", "ucode_level",
                          "mc_patch_data_id", "mc_patch_data_len", "init_flag",
                          "mc_patch_data_checksum", "nb_dev_id", "sb_dev_id",
                          "equiv_id", "nb_rev_id", "sb_rev_id", "bios_api_rev",
                          "reserved", "match_reg"),
                         defaults=(0, ) * 12 + ((0,) * 3, (0,) * 8))
PatchEntry = namedtuple("PatchEntry",
                        ("file", "offset", "size", "equiv_id", "level"))


# Issues with the patch header, as returned by detect_raw_patch()
class RawPatchIssue(Flag):
    NONE = 0
    NON_DEC_DATE_DIGIT = auto()
    YEAR_OUT_OF_RANGE = auto()
    DAY_OUT_OF_RANGE = auto()
    MONTH_OUT_OF_RANGE = auto()
    UNEXPECTED_PRE_ZEN_PATCH_LVL = auto()
    UNEXPECTED_ZEN_PATCH_LVL = auto()
    UNEXPECTED_PATCH_DATA_ID = auto()
    UNEXPECTED_NON_ZERO_CSUM = auto()
    # Reserved field is not b'\xaa\xaa\xaa' for patch format 0x800[013]
    UNEXPECTED_OLD_RESERVED_VALUE = auto()
    # Reserved field is not b'\x00\x00\x00'
    UNEXPECTED_RESERVED_VALUE = auto()


def diagmsg(prefix, msg, f=None, offs=None):
    print("%s%s%s%s: %s" %
          ("" if f is None else f.name if isinstance(f, io.IOBase) else f,
           "" if offs is None else "+%#06x" % offs,
           "" if f is None else ": ",
           prefix, msg),
          file=sys.stderr)


def err(msg, f=None, offs=None):
    diagmsg("ERROR", msg, f, offs)


def warn(msg, f=None, offs=None):
    diagmsg("WARNING", msg, f, offs)


def read_int32(ucode_file):
    """ Read four bytes of binary data and return as a 32 bit int """
    return int.from_bytes(ucode_file.read(4), 'little')


def read_int16(ucode_file):
    """ Read two bytes of binary data and return as a 16 bit int """
    return int.from_bytes(ucode_file.read(2), 'little')


def read_int8(ucode_file):
    """ Read one byte of binary data and return as a 8 bit int """
    return int.from_bytes(ucode_file.read(1), 'little')


def cpuid2fms(cpu_id):
    """
    Parses CPUID signature and converts it into FMS named tuple.

    CPUID signature (EAX=1) has the following definition:
     * bits 3..0:   Stepping
     * bits 7..4:   Model
     * bits 11..8:  Family
     * bits 13..12: Processor type (used by some old Intel CPU models
                    to indicate OverDrive or dual processor SKUs), not used
                    in AMD x86 CPUs
     * bits 15..14: Reserved
     * bits 19..16: Extended model
     * bits 27..20: Extended family
     * bits 31..28: Reserved

    The resulting family is calculated as the sum of extended family and family
    field;  family field is supposed to be 0xf if the extended family field
    value is non-zero.  Resulting model is calculated as concatenation
    of extended model and model fields.

    The function calculated the resulting family and model, along
    with the indication if the family field follows the aforementioned
    guideline and the contents of the reserved fields.
    """
    orig_family = (cpu_id >> 8) & 0xf
    ext_family = (cpu_id >> 20) & 0xff
    family = ext_family + orig_family
    family_invalid = ext_family and (orig_family != 0xf)

    model = (cpu_id >> 4) & 0xf
    model |= (cpu_id >> 12) & 0xf0

    stepping = cpu_id & 0xf

    reserved = cpu_id & 0xf000f000

    return FMS(family, model, stepping, family_invalid, reserved, cpu_id)


def fms2str(fms):
    if fms.family_invalid or fms.reserved:
        # If CPUID can't be uniquely reconstructed from family/model/stepping,
        # just print it raw
        return "CPUID=%#010x" % fms.cpu_id
    else:
        return "Family=%#04x Model=%#04x Stepping=%#04x" % \
               (fms.family, fms.model, fms.stepping)


def cpuid2str(cpu_id):
    return fms2str(cpuid2fms(cpu_id))


def fms_from_lvl_eqid(lvl, eqid, f, pos):
    """
    Try to reconstruct CPUID from the information present in microcode patch
    leveland equivalence ID fields.
    """
    ext_fam = (lvl >> 24) & 0xff

    if ext_fam >= 0x8:
        """
        For the family 17h (Zen) and higher we can rely solely
        on the information in the microcode patch level:  per Linux commit
        v6.12-rc1~228^2~1, the patch level there has the following schema:
        struct {
            u32 rev        : 8,
                stepping   : 4,
                model      : 4,
                __reserved : 4,
                ext_model  : 4,
                ext_fam    : 8;
        };
        """
        ext_model = (lvl >> 20) & 0xf
        reserved = (lvl >> 16) & 0xf
        model = (lvl >> 12) & 0xf
        stepping = (lvl >> 8) & 0xf

        if reserved:
            warn(("Reserved field (%#03x) in the family 17h+ patch level " +
                  "(%#010x) is not zero") % (reserved, lvl), f, pos)
            return None
    else:
        # For families 0Fh..16h we try to use equivalence ID,
        # but this may be imprecise;  all the publicly available microcode
        # containers seem to have at least the CPUID obtained
        # from reconstructing it from the equiv_id, however.
        eqid_ext_fam = (eqid >> 12) & 0xf
        ext_model = (eqid >> 8) & 0xf
        model = (eqid >> 4) & 0xf
        stepping = eqid & 0xf

        if ext_fam != eqid_ext_fam:
            warn(("Discrepancy in the extended family value between " +
                  "the patch level (%#04x in %#010x) and equivalence ID " +
                  "(%#03x in %#06x)") % (ext_fam, lvl, eqid_ext_fam, eqid),
                 f, pos)
            return None

    return FMS(ext_fam + 0xf, ext_model << 4 | model, stepping, False, 0,
               ext_fam << 20 | ext_model << 16 | 0xf00 | model << 4 | stepping)


def read_patch_hdr(f):
    """
    Reads PATCH_HEADER_SIZE from f and puts them into PatchHeader.

    The patch header is defined as follows:

    struct microcode_header_amd {
        u32 data_code;
        u32 patch_id;
        u16 mc_patch_data_id;
        u8  mc_patch_data_len;
        u8  init_flag;
        u32 mc_patch_data_checksum;
        u32 nb_dev_id;
        u32 sb_dev_id;
        u16 processor_rev_id;
        u8  nb_rev_id;
        u8  sb_rev_id;
        u8  bios_api_rev;
        u8  reserved1[3];
        u32 match_reg[8];
    } __packed;
    """
    return PatchHeader(read_int32(f),  # data_code
                       read_int32(f),  # ucode_level
                       read_int16(f),  # mc_patch_data_id
                       read_int8(f),   # mc_patch_data_len
                       read_int8(f),   # init_flag
                       read_int32(f),  # mc_patch_data_checksum
                       read_int32(f),  # nb_dev_id
                       read_int32(f),  # sb_dev_id
                       read_int16(f),  # equiv_id
                       read_int8(f),   # nb_rev_id
                       read_int8(f),   # sb_rev_id
                       read_int8(f),   # bios_api_rev
                       tuple(read_int8(f) for _ in range(3)),   # reserved
                       tuple(read_int32(f) for _ in range(8)))  # match_reg


def detect_raw_patch(f):
    """
    Checks if the next 64 bytes look like a patch header.

    Returns: (hdr, issues, desc)
      - hdr is a PatchHeader that has been read;
      - issues is a set of RawPatchIssue flags, or 0 if no issues
        have been found;
      - desc is a dict PatchHeader: str containing messages describing each
        of the issue, that can be presented to the user.
    """
    def issue(val, desc_str):
        nonlocal issues
        nonlocal desc

        issues |= val
        desc[val] = desc_str

    hdr = read_patch_hdr(f)
    issues = RawPatchIssue.NONE
    desc = {}

    # Check that the date consists of decimal digits
    for i in range(8):
        digit = (hdr.data_code >> (i * 4)) & 0xf
        if digit > 9:
            issue(RawPatchIssue.NON_DEC_DATE_DIGIT,
                  ("a non-decimal digit %#x is present in the patch date " +
                   "field (%#010x)") % (digit, hdr.data_code))
            break
    # We expect 20YY as a sane value, where Y is in 0..9 range
    if (hdr.data_code >> 8) & 0xff != 0x20:
        issue(RawPatchIssue.YEAR_OUT_OF_RANGE,
              "year (%04x) is out of 2000..2099 range"
              % (hdr.data_code & 0xffff))
    day = (hdr.data_code >> 16) & 0xff
    if not (0x1 <= day <= 0x31):
        issue(RawPatchIssue.DAY_OUT_OF_RANGE,
              "day (%02x) is out of 01..31 range" % day)
    # 0x13 because there was 0x03000027 microcode patch with the data_code
    # value of 0x13092011
    month = (hdr.data_code >> 24) & 0xff
    if not (0x1 <= month <= 0x13):
        issue(RawPatchIssue.MONTH_OUT_OF_RANGE,
              "month (%02x) is out of 01..13 range" % month)

    # For patch level, we can check that it is small enough for families
    # 0Fh..16h and that the reserved field is 0 for families 17h+.
    # We could also check that the extended family is not big enough,
    # but it is difficult to point out specific upper bound.
    ext_fam = hdr.ucode_level >> 24
    # if ext_fam < 1:
    #     issues |= 1 << 4
    if (ext_fam < 8) and (hdr.ucode_level & 0x00f00000):
        issue(RawPatchIssue.UNEXPECTED_PRE_ZEN_PATCH_LVL,
              "unexpected pre-Zen patch level (%#010x)" % hdr.ucode_level)
    lvl_reserved = hdr.ucode_level & 0x000f0000
    if (ext_fam >= 8) and (hdr.ucode_level & 0x000f0000):
        issue(RawPatchIssue.UNEXPECTED_ZEN_PATCH_LVL,
              ("unexpected non-zero reserved field value (%#010x) in Zen+ " +
               "patch level (%#010x)") % (lvl_reserved, hdr.ucode_level))

    # mc_patch_data_id seems to be 0x80XX so far
    if hdr.mc_patch_data_id < 0x8000 or hdr.mc_patch_data_id > 0x80ff:
        issue(RawPatchIssue.UNEXPECTED_PATCH_DATA_ID,
              ("patch data format ID (%#06x) is out of the expected" +
               " 0x8000..0x80ff range") % hdr.mc_patch_data_id)

    # For checksum, let's just check that it's zero when data_id is not 0x8000
    # or 0x8003, as checking the checksum requires reading of the whole patch
    if hdr.mc_patch_data_id not in (0x8000, 0x8003) \
       and hdr.mc_patch_data_checksum:
        issue(RawPatchIssue.UNEXPECTED_NON_ZERO_CSUM,
              ("non-zero checksum field value (%#010x) for patch data format" +
               " %#06x") % (hdr.mc_patch_data_checksum, hdr.mc_patch_data_id))

    # The "reserved" field seems to contain 0xaa bytes for data_id 0x800[013]
    # and zeroes otherwise
    if hdr.mc_patch_data_id in (0x8000, 0x8001, 0x8003):
        if hdr.reserved != (0xaa, 0xaa, 0xaa):
            issue(RawPatchIssue.UNEXPECTED_OLD_RESERVED_VALUE,
                  ("unexpected reserved field value (%r) for data format" +
                   " ID %#06x (b'\\xaa\\xaa\\xaa' expected)")
                  % (bytes(hdr.reserved), hdr.mc_patch_data_id))
    else:
        if hdr.reserved != (0x00, 0x00, 0x00):
            issue(RawPatchIssue.UNEXPECTED_RESERVED_VALUE,
                  ("unexpected reserved field value (%r) for data format" +
                   " ID %#06x (b'\\x00\\x00\\x00' expected)")
                  % (bytes(hdr.reserved), hdr.mc_patch_data_id))

    return (hdr, issues, desc)


def parse_patch_hdr(hdr, ucode_file, cursor, opts, ids, start, length, raw):
    if opts.verbose:
        add_info = (" Start=%u bytes Date=%04x-%02x-%02x" +
                    " Equiv_id=%#06x") % \
                   (start, hdr.data_code & 0xffff,
                    hdr.data_code >> 24, (hdr.data_code >> 16) & 0xff,
                    hdr.equiv_id)
    else:
        add_info = ""

    patch_fms = fms_from_lvl_eqid(hdr.ucode_level, hdr.equiv_id,
                                  ucode_file, cursor)

    if hdr.equiv_id not in ids:
        if not raw:
            warn(("Patch equivalence id not present in equivalence" +
                  " table (%#06x)") % hdr.equiv_id, ucode_file, cursor)
        if patch_fms is None:
            print(("  Family=???? Model=???? Stepping=????: " +
                   "Patch=%#010x Length=%u bytes%s")
                  % (hdr.ucode_level, length, add_info))
        else:
            print("  %s: Patch=%#010x Length=%u bytes%s"
                  % (fms2str(patch_fms), hdr.ucode_level, length, add_info))
    else:
        cpuid_match = patch_fms is None
        # The cpu_id is the equivalent to CPUID_Fn00000001_EAX
        for cpuid in ids[hdr.equiv_id]:
            if not cpuid_match and cpuid == patch_fms.cpu_id:
                cpuid_match = True
            print("  %s: Patch=%#010x Length=%u bytes%s"
                  % (cpuid2str(cpuid), hdr.ucode_level, length, add_info))
        if not cpuid_match and patch_fms.family >= 0x17:
            warn(("CPUID decoded from the microcode patch header " +
                  "(%s) is not present in the equivalence table")
                 % fms2str(patch_fms), ucode_file, cursor)

    if opts.verbose >= VERBOSE_DEBUG:
        print(("   [data_code=%#010x, mc_patch_data_id=%#06x, " +
               "mc_patch_data_len=%#04x, init_flag=%#04x, " +
               "mc_patch_data_checksum=%#010x]") %
              (hdr.data_code, hdr.mc_patch_data_id,
               hdr.mc_patch_data_len, hdr.init_flag,
               hdr.mc_patch_data_checksum))
        print(("   [nb_dev_id=%#010x, sb_dev_id=%#010x, " +
               "nb_rev_id=%#04x, sb_rev_id=%#04x, " +
               "bios_api_rev=%#04x, reserved=[%#04x, %#04x, %#04x]]") %
              (hdr.nb_dev_id, hdr.sb_dev_id, hdr.nb_rev_id,
               hdr.sb_rev_id, hdr.bios_api_rev,
               hdr.reserved[0], hdr.reserved[1], hdr.reserved[2]))
        print("   [match_reg=[%s]]" %
              ", ".join(["%#010x" % x for x in hdr.match_reg]))

    return PatchEntry(ucode_file.name, start, length,
                      hdr.equiv_id, hdr.ucode_level)


def parse_equiv_table(opts, ucode_file, start_offset, eq_table_len):
    """
    Read equivalence table and return a list of the equivalence ids contained
    """
    table = {}
    raw_table = []
    zero_cpuid_record = 0
    # For sanity check only
    cpuid_map = {}

    table_item = start_offset + EQ_TABLE_OFFSET
    table_stop = start_offset + EQ_TABLE_OFFSET + eq_table_len

    while table_item < table_stop:
        # Linux microcode loader ignores incomplete equivalence table entries,
        # and trying to parse them would yield garbage anyway
        rem = table_stop - table_item
        if rem < EQ_TABLE_ENTRY_SIZE:
            warn(("The remainder of the equivalence table section " +
                  "(%d byte%s) is not big enough to accommodate " +
                  "an equalence table entry, ignoring it") %
                 (rem, "" if rem == 1 else "s"), ucode_file, table_item)
            break

        ucode_file.seek(table_item, io.SEEK_SET)
        data = ucode_file.read(EQ_TABLE_ENTRY_SIZE)
        ucode_file.seek(table_item, io.SEEK_SET)

        """
        struct equiv_cpu_entry {
            u32 installed_cpu;
            u32 fixed_errata_mask;
            u32 fixed_errata_compare;
            u16 equiv_cpu;
            u16 res;
        } __packed;
        """
        cpu_id = read_int32(ucode_file)
        errata_mask = read_int32(ucode_file)
        errata_compare = read_int32(ucode_file)
        equiv_id = read_int16(ucode_file)
        res = read_int16(ucode_file)

        if equiv_id != 0:
            # FreeBSD container parser does not iterate over the whole section,
            # but instead scans until it encounters a record with zero CPUID.
            if zero_cpuid_record and cpu_id != 0:
                warn(("An equivalence table record with non-zero " +
                      "equiv_id (%#06x) and CPUID %#010x (%s) follows " +
                      "a record with zero CPUID (at position %#x), some " +
                      "loader implementations may ignore it") %
                     (equiv_id, cpu_id, cpuid2str(cpu_id),
                      zero_cpuid_record), ucode_file, table_item)

            if equiv_id not in table:
                table[equiv_id] = OrderedDict()

            if cpu_id in table[equiv_id]:
                warn(("Duplicate CPUID %#010x (%s) in the equivalence table " +
                      "for equiv_id %#06x") %
                     (cpu_id, cpuid2str(cpu_id), equiv_id),
                     ucode_file, table_item)

            if cpu_id in cpuid_map:
                if equiv_id != cpuid_map[cpu_id]:
                    warn(("Different equiv_id's (%#06x and %#06x) " +
                          "are present in the equivalence table for CPUID " +
                          "%#010x (%s)") %
                         (equiv_id, cpuid_map[cpu_id], cpu_id,
                          cpuid2str(cpu_id)), ucode_file, table_item)
            else:
                cpuid_map[cpu_id] = equiv_id

            entry = EquivTableEntry(cpu_id, equiv_id, data, table_item)
            table[equiv_id][cpu_id] = entry
            raw_table.append(entry)

        # FreeBSD parser does not respect section size at all and scans
        # the equivalence table until it encounters a record with zero CPUID
        # (see sys/x86/x86/ucode_subr.c:ucode_amd_find()), so check
        # for a presence of such guard record.
        if cpu_id == 0:
            zero_cpuid_record = table_item

        if opts.verbose >= VERBOSE_DEBUG:
            print((" [equiv entry@%#010x: cpuid %#010x, equiv id %#06x, " +
                   "errata mask %#010x, errata compare %#010x, res %#06x]") %
                  (table_item, cpu_id, equiv_id, errata_mask, errata_compare,
                   res))

        table_item += EQ_TABLE_ENTRY_SIZE

    return (table, raw_table, bool(zero_cpuid_record))


def extract_patch(opts, out_dir, ucode_file, patch, equiv_table=None):
    """
    Extract patch (along with the respective headers and equivalence table
    entries if equiv_table is provided) from ucode_file starting at patch.start
    to a file inside out_dir.  Directory will be created if it doesn't already
    exist.

    @param opts: options, as returned by ArgumentParser.parse_args()
    @type opts: argparse.Namespace
    @param out_dir: directory inside which the output file is stored
    @type out_dir: str
    @param ucode_file: file object to read the patch from
    @type ucode_file: io.BufferedIOBase
    @param patch: the patch to write out
    @type patch: PatchEntry
    @param equiv_table: if provided, a valid container file is created
                        that also includes entries relevant to the patch's
                        equiv_id
    @type equiv_table: dict
    """
    cwd = os.getcwd()

    if not os.path.exists(out_dir):
        os.makedirs(out_dir)

    os.chdir(out_dir)

    if equiv_table is None:
        # Raw patch
        out_file_name = "mc_patch_0%x.bin" % patch.level
    else:
        out_file_name = "mc_equivid_%#06x" % patch.equiv_id
        for cpuid in equiv_table[patch.equiv_id]:
            out_file_name += '_cpuid_%#010x' % cpuid
        out_file_name += "_patch_%#010x.bin" % patch.level

    out_path = "%s/%s" % (os.getcwd(), out_file_name)
    out_file = open(out_file_name, "wb")

    os.chdir(cwd)

    if equiv_table is not None:
        cpuids = equiv_table[patch.equiv_id].values() \
                    if patch.equiv_id in equiv_table else []
    else:
        cpuids = None

    write_mc(opts, out_file, [patch], ucode_file, cpuids)

    out_file.close()

    print("    Patch extracted to %s" % out_path)


def merge_mc(opts, out_path, table, patches):
    """
    Generate a merged container out of the provided table and patches and write
    it to out_path.

    @param opts: options, as returned by ArgumentParser.parse_args()
    @type opts: argparse.Namespace
    @param out_path: path to write out the generated container to
    @type out_path: str
    @param table: a list of equivalence table entries to accompany the patches
    @type table: list(EquivTableEntry)
    @param patches: a list of patches to write out
    @type patches: list(PatchEntry)
    """
    # Do some sanity checks, but only warn about the issues
    equivid_map = {}
    cpuid_map = {}

    for entry in table:
        if entry.equiv_id not in equivid_map:
            equivid_map[entry.equiv_id] = dict()

        if entry.cpuid in equivid_map[entry.equiv_id]:
            warn(("Duplicate CPUID %#010x (%s) in the equivalence table " +
                  "for equiv_id %#06x ") %
                 (entry.cpuid, cpuid2str(entry.cpuid), entry.equiv_id))
        else:
            equivid_map[entry.equiv_id][entry.cpuid] = entry

        if entry.cpuid in cpuid_map:
            if entry.equiv_id != cpuid_map[entry.cpuid]:
                warn(("Different equiv_id's (%#06x and %#06x) are present " +
                      "in the equivalence table for CPUID %#010x (%s)") %
                     (entry.equiv_id, cpuid_map[entry.cpuid], entry.cpuid,
                      cpuid2str(entry.cpuid)))
            else:
                cpuid_map[entry.cpuid] = entry.equiv_id

    with open(out_path, "wb") as out_file:
        write_mc(opts, out_file, patches, equiv_table=table)

        print("Microcode written to %s" % out_path)


def write_mc(opts, out_file, patches, ucode_file=None, equiv_table=None):
    """
    Writes microcode data from patches to out_file.  If equiv_table
    is provided, a valid container file is generated, that also includes
    a container header, the equivalence table, and patch headers.

    @param opts: options, as returned by ArgumentParser.parse_args()
    @type opts: argparse.Namespace
    @param out_file: file object to write the data to
    @type out_file: io.BufferedIOBase
    @param patches: an array of patches to write out
    @type patches: list(PatchEntry)
    @param ucode_file: file object to read the patch from;
                       if None is provided, a file with path specified
                       in PatchEntry.file is opened instead  (default: None)
    @type ucode_file: io.BufferedIOBase
    @param equiv_table: if provided, a valid container file is created
                        that also includes all the necessary headers
                        and entries provided in equiv_table (default: None)
    @type equiv_table: list(EquivTableEntry)
    """
    if equiv_table is not None:
        # Container header
        out_file.write(b'DMA\x00')

        # Equivalence table header
        out_file.write(EQ_TABLE_TYPE.to_bytes(4, 'little'))
        table_size = EQ_TABLE_ENTRY_SIZE * (len(equiv_table) + 1)
        out_file.write(table_size.to_bytes(4, 'little'))

        # Equivalence table
        for cpuid in equiv_table:
            out_file.write(cpuid.data)

        out_file.write(b'\0' * EQ_TABLE_ENTRY_SIZE)

    for patch in patches:
        # Patch header
        if equiv_table is not None:
            out_file.write(PATCH_TYPE.to_bytes(4, 'little'))
            out_file.write(patch.size.to_bytes(4, 'little'))

        if ucode_file is None:
            in_file = open(patch.file, "rb")
        else:
            in_file = ucode_file

        in_file.seek(patch.offset, io.SEEK_SET)
        out_file.write(in_file.read(patch.size))

        if ucode_file is None:
            in_file.close()


def parse_ucode_file(opts, path, start_offset):
    """
    Scan through microcode container file printing the microcode patch level
    for each model contained in the file.
    """
    def check_bytes_left(f, sz, desc):
        """
        An auxiliary function for checking if the remaining part of file
        (from current position to the previously cached "end_of_file" position)
        is big enough to contain some expected structure and printing an error
        if it is not the case.

        @param f    File object
        @param sz   Minimum expected size, in bytes
        @param desc Description of the structure/entity that is expected to be
                    at least sz bytes big.
        @returns    True the remaining part of the file is big enough,
                    False if file is too short.
        """
        bytes_left = end_of_file - f.tell()
        if bytes_left >= sz:
            return True

        err(("File is too short to contain %s (%d byte%s left, " +
             "at least %d byte%s needed)") %
            (desc, bytes_left, "" if bytes_left == 1 else "s",
            sz, "" if sz == 1 else "s"), f, f.tell())

        return False

    def process_patch(patch, ids):
        patches.append(patch)

        if opts.extract:
            extract_patch(opts, opts.extract, ucode_file, patch)

        if opts.split:
            extract_patch(opts, opts.split, ucode_file, patch, ids)

    table = None
    patches = []

    with open(path, "rb") as ucode_file:
        print("Microcode patches in %s%s:" %
              (path, "+%#x" % start_offset if start_offset else ""))

        # Seek to end of file to determine file size
        ucode_file.seek(0, io.SEEK_END)
        end_of_file = ucode_file.tell()
        container_str = ""

        # Check magic number
        ucode_file.seek(start_offset, io.SEEK_SET)
        if not check_bytes_left(ucode_file, MAGIC_SIZE, "container magic"):
            return (None, None, None, errno.EINVAL)
        file_magic = ucode_file.read(MAGIC_SIZE)
        if file_magic != b'DMA\x00':
            if start_offset != 0:
                err("Missing magic number at beginning of container",
                    ucode_file, start_offset)
                return (None, None, None, errno.EINVAL)
            else:
                # A string that is used for the error message that file
                # is neither a container nor a raw patch
                container_str = "a container%s or " \
                    % (" (got magic %r, expected b'DMA\\x00')" % file_magic
                       if opts.verbose >= VERBOSE_DEBUG else "")

            ucode_file.seek(0, io.SEEK_SET)
            if not check_bytes_left(ucode_file, PATCH_HEADER_SIZE,
                                    "patch header"):
                return (None, None, None, errno.EINVAL)

            hdr, issues, issues_desc = detect_raw_patch(ucode_file)
            if issues == RawPatchIssue.NONE:
                patch = parse_patch_hdr(hdr, ucode_file, 0, opts, {},
                                        0, end_of_file, True)

                process_patch(patch, {})

                return (None, [], patches, 0)
            else:
                err("File does not appear to be %sa raw patch%s" %
                    (container_str, " (%s)" % ", ".join(issues_desc.values())
                                    if opts.verbose >= VERBOSE_DEBUG else ""),
                    ucode_file)
                return (None, None, None, errno.EINVAL)

        # Check the equivalence table type
        if not check_bytes_left(ucode_file, SECTION_HDR_SIZE,
                                "equivalence table section header"):
            return (None, None, None, errno.EINVAL)
        eq_table_type = read_int32(ucode_file)
        if eq_table_type != EQ_TABLE_TYPE:
            err("Invalid equivalence table section identifier: %#010x" %
                eq_table_type, ucode_file, start_offset + MAGIC_SIZE)
            return (None, None, None, errno.EINVAL)

        # Read the equivalence table length
        eq_table_len = read_int32(ucode_file)
        if not check_bytes_left(ucode_file, eq_table_len, "equivalence table"):
            return (None, None, None, errno.EINVAL)
        # Both Linux and FreeBSD container parsers currently bail out
        # if the section is too small to contain at least one entry;
        if eq_table_len < EQ_TABLE_ENTRY_SIZE:
            warn(("Equivalence table section size (%d) is too small " +
                  "to contain a single record") % eq_table_len, ucode_file)
            ids, table, zero_cpuid = ({}, [], False)
        else:
            ids, table, zero_cpuid = \
                parse_equiv_table(opts, ucode_file, start_offset, eq_table_len)

        if not zero_cpuid:
            warn("A guard equivalence table record with zero CPUID is missing",
                 ucode_file)

        cursor = start_offset + EQ_TABLE_OFFSET + eq_table_len
        while cursor < end_of_file:
            # Seek to the start of the patch information
            ucode_file.seek(cursor, io.SEEK_SET)
            if not check_bytes_left(ucode_file, SECTION_HDR_SIZE,
                                    "microcode patch section header"):
                return (None, table, patches, errno.EINVAL)

            patch_start = cursor + SECTION_HDR_SIZE

            patch_type_bytes = ucode_file.read(4)
            # Beginning of a new container
            if patch_type_bytes == b'DMA\x00':
                return (cursor, table, patches, 0)
            patch_type = int.from_bytes(patch_type_bytes, 'little')
            if patch_type != PATCH_TYPE:
                err("Invalid patch identifier: %#010x" % (patch_type),
                    ucode_file, cursor)
                return (None, table, patches, errno.EINVAL)

            patch_length = read_int32(ucode_file)
            if not check_bytes_left(ucode_file, patch_length,
                                    "microcode patch section"):
                return (None, table, patches, errno.EINVAL)
            if patch_length < PATCH_HEADER_SIZE:
                err(("Patch is too short (at least %d bytes expected, " +
                     "got %d), skipping") % (PATCH_HEADER_SIZE, patch_length),
                    ucode_file, cursor + 4)

                cursor = cursor + SECTION_HDR_SIZE + patch_length
                continue

            hdr = read_patch_hdr(ucode_file)

            patch = parse_patch_hdr(hdr, ucode_file, cursor, opts, ids,
                                    patch_start, patch_length, False)

            process_patch(patch, ids)

            cursor = cursor + SECTION_HDR_SIZE + patch_length

    return (None, table, patches, 0)


def parse_ucode_files(opts):
    all_tables = []
    all_patches = []
    status = 0

    for f in opts.container_file:
        offset = 0
        while offset is not None:
            offset, table, patches, error = parse_ucode_file(opts, f, offset)

            # We update status with the first error occurred during
            # the processing, then preserve it
            if status == 0:
                status = error

            if opts.merge:
                if table is not None:
                    all_tables += table
                if patches is not None:
                    all_patches += patches

    if opts.merge:
        merge_mc(opts, opts.merge, all_tables, all_patches)

    return status


def parse_options():
    """ Parse options """
    parser = argparse.ArgumentParser(description="Print information about" +
                                                 " an amd-ucode container")
    parser.add_argument("container_file", nargs='+')
    parser.add_argument("-e", "--extract",
                        help="Dump each patch in container to the specified" +
                             " directory")
    parser.add_argument("-s", "--split",
                        help="Split out each patch in a separate container " +
                             "to the specified directory")
    parser.add_argument("-m", "--merge",
                        help="Write a merged container to the specified file")
    parser.add_argument("-v", "--verbose", action="count", default=0,
                        help="Increase output verbosity level: provide once " +
                             "to see additional information about patches, " +
                             "twice to see all the information available")
    opts = parser.parse_args()

    for f in opts.container_file:
        if not os.path.isfile(f):
            parser.print_help(file=sys.stderr)
            print(file=sys.stderr)
            err("Container file \"%s\" does not exist" % f)
            sys.exit(errno.ENOENT)

    return opts


def main():
    """ main """
    opts = parse_options()

    sys.exit(parse_ucode_files(opts))


if __name__ == "__main__":
    main()
