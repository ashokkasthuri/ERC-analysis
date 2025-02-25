'''
Author: ashokkasthuri ashokk@smu.edu.sg
Date: 2025-02-18 09:50:50
LastEditors: ashokkasthuri ashokk@smu.edu.sg
LastEditTime: 2025-02-22 19:57:37
FilePath: /ERC-analysis-master/ERCmain/erc_main.py
Description: 这是默认设置,请设置`customMade`, 打开koroFileHeader查看配置 进行设置: https://github.com/OBKoro1/koro1FileHeader/wiki/%E9%85%8D%E7%BD%AE
'''
#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import json
import logging
import os
import subprocess
import sys
import tempfile
from typing import Sequence

import rattle
import re
import pandas as pd
import csv

import src.dataflow as dataflow
import src.function as function
import src.settings as settings
import src.tac_cfg as tac_cfg

import matplotlib.pyplot as plt
import networkx as nx


# This might not be true, but I have a habit of running the wrong python version and this is to save me frustration
assert (sys.version_info.major >= 3 and sys.version_info.minor >= 6)

logger = logging.getLogger(__name__)
'''
Author: ashokkasthuri ashokk@smu.edu.sg
Date: 2025-02-18 09:50:50
LastEditors: ashokkasthuri ashokk@smu.edu.sg
LastEditTime: 2025-02-18 09:53:35
FilePath: /ERC-analysis-master/ERC-main/erc_main.py
Description: 这是默认设置,请设置`customMade`, 打开koroFileHeader查看配置 进行设置: https://github.com/OBKoro1/koro1FileHeader/wiki/%E9%85%8D%E7%BD%AE
'''



def main(argv: Sequence[str] = tuple(sys.argv)) -> None:
    
    sys.setrecursionlimit(20000)
    parser = argparse.ArgumentParser(
        description='Rattle Ethereum EVM binary analysis from CSV file'
    )
    
    # parser.add_argument('--input', '-i', type=argparse.FileType('rb'), help='input evm file')
    parser.add_argument('--input', '-i', type=argparse.FileType('r'), help='input evm file')
    
    # parser.add_argument('--input', '-i', type=argparse.FileType('r'),
    #                     help='Input CSV file with a "bytecode" column')
    parser.add_argument('--optimize', '-O', action='store_true',
                        help='Optimize resulting SSA form')
    parser.add_argument('--no-split-functions', '-nsf', action='store_false',
                        help='Do not split functions')
    parser.add_argument('--log', type=argparse.FileType('w'), default=sys.stdout,
                        help='Log output file (default stdout)')
    parser.add_argument('--verbosity', '-v', type=str, default="None",
                        help='Log output verbosity (None, Critical, Error, Warning, Info, Debug)')
    parser.add_argument('--supplemental_cfg_file', type=argparse.FileType('r'), default=None,
                        help='Optional supplemental CFG file')
    parser.add_argument('--stdout_to', type=argparse.FileType('wt'), default=None,
                        help='Redirect stdout to file')
    args = parser.parse_args(argv[1:])

    if args.input is None:
        parser.print_usage()
        sys.exit(1)

    if args.stdout_to:
        sys.stdout = args.stdout_to

    edges = []
    if args.supplemental_cfg_file:
        edges = json.loads(args.supplemental_cfg_file.read())

    try:
        loglevel = getattr(logging, args.verbosity.upper())
    except AttributeError:
        loglevel = None
    logging.basicConfig(stream=args.log, level=loglevel)
    
    # ssa = rattle.Recover(args.input.read(), edges=edges, optimize=args.optimize,
    #                      split_functions=args.no_split_functions)
    
    # PermitMain(ssa)
    
    settings.import_config()
    cfg = tac_cfg.TACGraph.from_bytecode(args.input.read().splitlines())
    
    g = cfg.nx_graph()
    # g.graph
    
    # # Draw the graph (you can customize the layout and appearance)
    # pos = nx.spring_layout(g)  # positions for all nodes
    # nx.draw(g, pos, with_labels=True, node_color='lightblue', edge_color='gray', node_size=500, font_size=8)

    # # Display the graph interactively
    # plt.show()

    # # Alternatively, save the graph as a PNG
    # plt.savefig("cfg_graph.png")
    
    
    dataflow.analyse_graph(cfg)
    fun_extractor = function.FunctionExtractor(cfg)
    f = fun_extractor.extract()
    
    
    # print(f"fun_extractor : {fun_extractor}")