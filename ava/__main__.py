#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import sys
from ava import scanner


if __name__ == "__main__":
    # pass system args
    args = sys.argv[1:]
    status = scanner.main(args)

    # exit
    sys.exit(status)
