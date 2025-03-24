#!/usr/bin/python3

# General configuration and fixtures for amd_ucode_info tests
#
# SPDX-License-Identifier: MIT License
# Copyright (C) 2025 amd_ucode_info developers

import os
import pathlib
import pytest

# Defaults/constants
CUR_DIR = os.path.dirname(os.path.realpath(__file__))
EXP_DIR = pathlib.Path(CUR_DIR, "container_exp")
AUI_NAME = "amd_ucode_info.py"
AUI_DIR = os.path.dirname(CUR_DIR)
AUI_PATH = pathlib.Path(AUI_DIR, AUI_NAME)


# Configuration

def pytest_addoption(parser):
    parser.addoption("--aui-path", action="store", default=AUI_PATH,
                     help="Path to the amd_ucode_info script, default is %s" %
                          AUI_PATH)


def pytest_configure(config):
    os.environ["AUI_PATH"] = str(config.getoption("aui_path"))


# Fixtures

def get_exp(name, sfx, ext="out"):
    exp_path = pathlib.Path(EXP_DIR, "%s%s.%s" % (name, sfx, ext))

    with open(exp_path, mode="r") as f:
        exp = f.read()

    return exp


@pytest.fixture
def exp():
    def get(name, sfx):
        return get_exp(name, sfx)

    return get


@pytest.fixture
def err():
    def get(name, sfx):
        return get_exp(name, sfx, "err")

    return get
