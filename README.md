# Merkle Tree Commitment

应用密码学作业一：先用一个短摘要固定一组消息，之后开封全部消息或其中一个位置，让别人核对内容与原承诺一致。实现使用手写 SHA3-256 和每叶子独立随机值，包含绑定性、隐藏性分析及性能评估。

## 先运行一个例子

需要 Python 3.9 或更新版本，无第三方运行时依赖。在仓库根目录执行 `PYTHONPATH=src python3 -B -m examples.demo`。

演示使用方案文档中的三个消息“6”“9”“0”，开封位置 2。你会看到承诺摘要、107 B 的证明，以及三个结果：有效开封为 True、篡改消息为 False、完整开封为 True。每次运行都会生成新的随机值，所以承诺摘要通常不同。

## 阅读与人工审查

- 先读 [方案设计](docs/方案设计.md)：从三个消息的小树理解承诺、认证路径、安全分析和 SHA3。
- 再读实现：`protocol.py` 定义字段和编码，`tree.py` 实现建树与开封，`sha3.py` 实现哈希。
- 对照 `tests/` 中的独立递归规格、multiproof 分布测试和官方哈希答案，核对实现是否符合定义。
- 最后读 [性能报告](results/性能与验证结果.md)，了解实测结果和计时范围；[作业要求](docs/作业要求.md) 保留课程原文。

`commit(messages)` 返回公开承诺和承诺方的树状态；`state.open(index)` 返回单条消息与证明；`verify()` 检查该位置。需要开封多个位置时，`state.open_many(indices)` 返回按升序排列的消息和合并证明，`verify_many()` 只重算共享路径上的唯一父节点。完整开封使用 `state.open_all()` 与 `verify_all()`。协议细节和安全假设集中在方案设计中。

```python
messages, proof = state.open_many([1, 4, 5])
valid = verify_many(public, messages, proof)
```

## 测试与实验

以下命令都在仓库根目录执行：

- 正确性与安全回归：`PYTHONPATH=src python3 -B -m unittest discover -s tests -v`。
- 低熵猜测演示：`PYTHONPATH=src python3 -B -m examples.privacy_experiment`。
- 五组性能测量：`PYTHONPATH=src python3 -B -m benchmarks.benchmark --repetitions 5 --output-dir results-new`。

先执行测试，再测性能。基准核对测量样本的有效开封和哈希次数，输出目录保存原始样本及报告。使用 `results-new` 可保留已有记录，`-B` 防止生成 Python 缓存。现有 `results/` 是提交 `2ff13ad` 的历史基线。

需要在其他程序中导入时，可在自己的虚拟环境运行 `python3 -m pip install -e .` 做可编辑安装。上面的源码运行命令不需要安装；打包工具可能需要获取 setuptools。

## 项目结构

| 路径 | 职责 |
| --- | --- |
| src/merkle_commitment/protocol.py | 承诺与开封的数据类型、字段校验及编解码 |
| src/merkle_commitment/tree.py | 建树、开封和验证 |
| src/merkle_commitment/sha3.py | SHA3-256 算法 |
| tests/ | 承诺流程回归、multiproof 分布正确性、独立规格及 140 条 NIST 向量 |
| examples/ | 基础演示和猜测实验 |
| benchmarks/ | 性能采样与报告生成 |
| docs/ | 方案设计、示意图和作业要求 |
| results/ | 原始样本、执行日志和性能表格 |

实现代码构成 `merkle_commitment` 包，位于 `src/`；测试和辅助脚本单独组织。组员信息暂留空，提交前填写。合作修改使用独立分支和 Pull Request，协议或安全假设有变化时同步更新文档与测试。
