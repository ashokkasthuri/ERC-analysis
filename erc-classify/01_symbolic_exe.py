'''
Author: ashokkasthuri ashokraj.kasthuri@gmail.com
Date: 2026-04-01 14:59:45
LastEditors: ashokkasthuri ashokraj.kasthuri@gmail.com
LastEditTime: 2026-04-01 15:01:40
FilePath: /ERC-analysis-master/erc-classify/01_symbolic_exe.py
Description: 这是默认设置,请设置`customMade`, 打开koroFileHeader查看配置 进行设置: https://github.com/OBKoro1/koro1FileHeader/wiki/%E9%85%8D%E7%BD%AE
'''
from greed import Project

p = Project(target_dir="/Users/ashokk/Documents/ERC-analysis-master/erc-classify/erc-classify/erc_source_code_ground_truth/ERC20/ERC20_bin_0x3D9D4068653E2528d388f7E31Fa2BE8a83bef5aD.hex")

entry_state = p.factory.entry_state(xid=0)
simgr = p.factory.simgr(entry_state=entry_state)
simgr.run()