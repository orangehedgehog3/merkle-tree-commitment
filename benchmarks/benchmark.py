#!/usr/bin/env python3
"""性能采样与报告生成；测试和攻击演示使用各自入口。"""
import argparse
from datetime import datetime
import json
from pathlib import Path
import platform
import random
import statistics
import subprocess
import sys
import time
import tracemalloc
from unittest.mock import patch

from merkle_commitment import tree as m
from merkle_commitment.sha3 import sha3_256_digest


def environment():
    def sysctl(key):
        try:
            return subprocess.check_output(['sysctl', '-n', key], text=True,
                                           stderr=subprocess.DEVNULL).strip()
        except (OSError, subprocess.CalledProcessError):
            return 'unavailable'
    cpu = sysctl('machdep.cpu.brand_string')
    return {'python': sys.version, 'system': platform.system(),
            'os_release': platform.release(), 'machine': platform.machine(),
            'processor': cpu if cpu != 'unavailable' else (platform.processor() or 'unavailable'),
            'logical_cpus': sysctl('hw.logicalcpu'), 'memory_bytes': sysctl('hw.memsize'),
            'executable': sys.executable, 'timestamp': datetime.now().astimezone().isoformat()}


def measured(fn, repetitions, batch=1):
    fn()  # 一次预热，不进入样本。
    samples = []
    for _ in range(repetitions):
        started = time.perf_counter_ns()
        for _ in range(batch):
            fn()
        samples.append((time.perf_counter_ns() - started) / batch / 1e9)
    return {'samples_seconds': samples, 'mean_seconds': statistics.mean(samples),
            'median_seconds': statistics.median(samples),
            'stdev_seconds': statistics.stdev(samples) if repetitions > 1 else 0.0,
            'min_seconds': min(samples), 'max_seconds': max(samples), 'batch': batch}


def count_hash_calls(values):
    """只在独立的一次构建中计数，离开作用域即恢复原函数。"""
    original, calls = m.H, 0

    def counted(data):
        nonlocal calls
        calls += 1
        return original(data)

    with patch.object(m, 'H', counted):
        m.commit(values)
    return calls


def count_verification_hashes(operation):
    """计数一次验证操作的哈希调用，不混入计时样本。"""
    original, calls = m.H, 0

    def counted(data):
        nonlocal calls
        calls += 1
        return original(data)

    with patch.object(m, 'H', counted):
        if not operation():
            raise RuntimeError('verification fixture failed')
    return calls


def peak_allocation(values):
    """单独测 Python 分配峰值，异常时也关闭追踪。"""
    tracemalloc.start()
    try:
        state = m.commit(values)
        peak = tracemalloc.get_traced_memory()[1]
        del state
        return peak
    finally:
        tracemalloc.stop()


def benchmark(repetitions):
    output = {'environment': environment(), 'repetitions': repetitions,
              'method': '一次预热；perf_counter_ns；计时不含tracemalloc；单独测建树峰值Python分配',
              'tree': [], 'hash': [], 'message_length': []}
    for length in (0, 32, 135, 136, 137, 273, 4096):
        value = bytes([0x61]) * length
        output['hash'].append({'message_bytes': length,
                               'permutations': length // 136 + 1,
                               'hash': measured(lambda: sha3_256_digest(value), repetitions, batch=10)})
    for n in (1, 3, 8, 32, 128, 256, 1024):
        values = [i.to_bytes(8, 'big') + b'x' * 24 for i in range(n)]
        depth, capacity = (n - 1).bit_length(), 1 << (n - 1).bit_length()
        build = measured(lambda: m.commit(values), repetitions)
        public, state = m.commit(values)
        index = n // 2
        value, proof = state.open(index)
        wire, public_wire = proof.to_bytes(), public.to_bytes()
        opening = state.open_all()
        if not m.verify(public_wire, index, value, wire) or not m.verify_all(public, opening):
            raise RuntimeError('benchmark fixture failed verification')
        generate = measured(lambda: state.prove(index), repetitions, batch=200)
        verify = measured(lambda: m.verify(public_wire, index, value, wire), repetitions, batch=10)
        full_verify = measured(lambda: m.verify_all(public, opening), repetitions)
        serialize = measured(proof.to_bytes, repetitions, batch=200)
        # 计数和分配追踪均不进入延迟样本。
        hash_calls = count_hash_calls(values)
        if hash_calls != 2 * capacity:
            raise RuntimeError('unexpected tree hash count')
        peak = peak_allocation(values)
        output['tree'].append({'leaf_count': n, 'message_bytes': 32, 'depth': depth,
            'padded_leaf_count': capacity, 'hash_calls_observed': hash_calls,
            'commitment_bytes': len(public_wire), 'proof_bytes': len(wire),
            'full_opening_bytes': len(opening.to_bytes()), 'python_peak_bytes': peak,
            'build': build, 'prove': generate, 'verify_wire': verify,
            'verify_full': full_verify, 'proof_serialization': serialize,
            'leaves_per_second': n / build['mean_seconds']})
        print('measured n=%d build=%.3f ms proof=%d B' %
              (n, build['mean_seconds'] * 1e3, len(wire)), flush=True)
    for length in (0, 32, 256, 4096):
        values = [b'x' * length] * 32
        output['message_length'].append({'leaf_count': 32, 'message_bytes': length,
            'build': measured(lambda: m.commit(values), repetitions)})

    leaf_count, opening_count = 1024, 64
    values = [index.to_bytes(8, 'big') + b'x' * 24 for index in range(leaf_count)]
    public, state = m.commit(values)
    distributions = {
        '相邻': tuple(range(480, 480 + opening_count)),
        '随机': tuple(sorted(random.Random(2026).sample(range(leaf_count), opening_count))),
        '分散': tuple(index * leaf_count // opening_count for index in range(opening_count)),
    }
    output['multiproof'] = []
    for label, indices in distributions.items():
        messages, proof = state.open_many(indices)
        individual = tuple(state.prove(index) for index in indices)
        if not m.verify_many(public, messages, proof):
            raise RuntimeError('multiproof fixture failed verification')
        individual_pairs = tuple(zip(indices, messages, individual))
        individual_hashes = count_verification_hashes(
            lambda: all(m.verify(public, index, message, item_proof)
                        for index, message, item_proof in individual_pairs))
        multiproof_hashes = count_verification_hashes(
            lambda: m.verify_many(public, messages, proof))
        individual_verify_time = measured(
            lambda: all(m.verify(public, index, message, item_proof)
                        for index, message, item_proof in individual_pairs),
            repetitions)
        multiproof_verify_time = measured(
            lambda: m.verify_many(public, messages, proof), repetitions)
        output['multiproof'].append({
            'distribution': label, 'leaf_count': leaf_count,
            'opening_count': opening_count, 'frontier_hashes': len(proof.siblings),
            'multiproof_bytes': len(proof.to_bytes()),
            'individual_proof_bytes': sum(len(item.to_bytes()) for item in individual),
            'multiproof_verification_hashes': multiproof_hashes,
            'individual_verification_hashes': individual_hashes,
            'multiproof_verify': multiproof_verify_time,
            'individual_verify': individual_verify_time,
        })
    return output


def render_report(data):
    """从原始样本生成便于比较的表格，先给结果再说明测量范围。"""
    env = data['environment']
    rows = data['tree']
    largest = max(rows, key=lambda row: row['leaf_count'])
    repetitions = data['repetitions']

    def timing(metric, scale):
        return '%.3f ± %.3f' % (metric['mean_seconds'] * scale,
                               metric['stdev_seconds'] * scale)

    lines = ['# 性能与验证结果', '',
        '每叶消息为 %d B 时，%d 个叶子的建树均值为 %.3f s，单项验证均值为 %.3f ms，证明编码为 %d B。'
        % (largest['message_bytes'], largest['leaf_count'], largest['build']['mean_seconds'],
           largest['verify_wire']['mean_seconds'] * 1e3, largest['proof_bytes']), '',
        '建树工作量随补齐叶数增长；证明大小随树深度增长。长消息会增加单次哈希的吸收块数，进一步增加建树成本。', '']
    if 'source_commit' in data:
        lines += ['> 本报告保留提交 `%s` 的重构前实测基线。当前版本的测量入口见 [README](../README.md)；本次整理仅改变报告表达。'
                  % data['source_commit'], '']

    timestamp = datetime.fromisoformat(env['timestamp']).strftime('%Y-%m-%d %H:%M:%S %z')
    lines += ['## 测量条件', '',
        '采样时间：%s。设备为 %s，%s 个逻辑 CPU；Python %s，%s %s（%s）。'
        % (timestamp, env['processor'], env['logical_cpus'], env['python'].split()[0],
           env['system'], env['os_release'], env['machine']), '',
        '- 规模实验每叶消息固定为 %d B，验证位置为 n//2，即列表中间的位置。' % largest['message_bytes'],
        '- 每项先预热一次，再取 %d 组样本。表格的“均值 ± 标准差”反映这 %d 组的计时与波动；批量调用按每次耗时折算，次数见原始 JSON 的 batch 字段。' % (repetitions, repetitions),
        '- 建树计时包含消息转换、随机值生成、哈希和树分配。单项验证输入编码字节，包含解析及根比较；完整验证输入已解析对象，包含重建和比较，不包含开封解析。',
        '- Python 分配峰值用 tracemalloc 单独测量，单位为 KiB（1024 B）；它不是进程总内存，追踪开销也未混入延迟样本。', '',
        '## 建树成本', '',
        'n 是真实叶子数，N 是补齐后的叶子数。哈希次数由单独的一次构建计数得到。', '',
        '| n | N | 哈希调用次数 | 建树 ms | 吞吐 leaves/s |',
        '| --- | --- | --- | --- | --- |']
    for row in rows:
        lines.append('| %d | %d | %d | %s | %.0f |' %
            (row['leaf_count'], row['padded_leaf_count'], row['hash_calls_observed'],
             timing(row['build'], 1e3), row['leaves_per_second']))
    lines += ['', '建树共调用哈希 2N 次：N 个叶子、N−1 个内部节点和一次最终承诺。'
              'n≤N<2n，因此固定消息长度下为 O(n)。跨越二次幂边界会增加占位叶；例如 n=3 要补到 N=4。', '',
              '## 单项证明的时间与大小', '',
              'h 是树深度。生成证明只收集兄弟摘要；验证还要执行 h+2 次哈希。', '',
              '| n | h | 生成 μs | 验证 ms（含解析） | 证明 B |',
              '| --- | --- | --- | --- | --- |']
    for row in rows:
        lines.append('| %d | %d | %s | %s | %d |' %
            (row['leaf_count'], row['depth'], timing(row['prove'], 1e6),
             timing(row['verify_wire'], 1e3), row['proof_bytes']))
    serial = [row['proof_serialization']['mean_seconds'] * 1e6 for row in rows]
    lines += ['', '所有承诺编码均为 %d B。证明实际编码为 43+32h B，消息本身不计入这个大小。'
              '每多一层路径，证明增加 32 B。' % largest['commitment_bytes'], '',
              '证明序列化另行计时，各规模的均值为 %.2f–%.2f μs；完整样本见原始 JSON。'
              % (min(serial), max(serial)), '',
              '## 完整开封与内存', '',
              '本表仍使用每叶 %d B 消息。完整开封包含全部消息和随机值，验证需要重建整棵树。'
              % largest['message_bytes'], '',
              '| n | 完整开封 B | 完整验证 ms（不含解析） | Python 峰值 KiB |',
              '| --- | --- | --- | --- |']
    for row in rows:
        lines.append('| %d | %d | %s | %.1f |' %
            (row['leaf_count'], row['full_opening_bytes'], timing(row['verify_full'], 1e3),
             row['python_peak_bytes'] / 1024))
    lines += ['', '## 手写 SHA3-256 的块边界', '',
              '一次哈希可包含多次状态置换。135 B 输入与后缀合成一个块；136 B 输入要增加填充块，置换次数由 1 变为 2，耗时也随之增加。', '',
              '| 输入 B | 置换次数 | 哈希 ms |', '| --- | --- | --- |']
    for row in data['hash']:
        lines.append('| %d | %d | %s |' %
                     (row['message_bytes'], row['permutations'], timing(row['hash'], 1e3)))
    lines += ['', '## 消息长度对建树的影响', '',
              '固定 32 个位置，每个位置放相同内容、相同长度的消息；每个叶子仍独立生成随机值。', '',
              '| n | 每叶消息 B | 建树 ms |', '| --- | --- | --- |']
    for row in data['message_length']:
        lines.append('| %d | %d | %s |' %
                     (row['leaf_count'], row['message_bytes'], timing(row['build'], 1e3)))
    lines += ['', '本实现的真实叶子哈希输入有 57 B 固定开销。消息为 256 B 或 4096 B 时，需要吸收更多块，因此相同叶子数量也会花更多时间。', '',
              '## 批量证明分布对比', '',
              '固定 1024 个叶子、同时开封 64 个位置。证明字节数不包含消息本身；逐项证明大小为 64 个单项证明编码之和。验证哈希次数通过拦截实际哈希函数计数，multiproof 只重算被选叶子和唯一父节点。', '',
              '验证耗时为一次批量验证与 64 次顺序单项验证的总耗时；每项先预热，再按测量条件重复采样。', '',
              '| 分布 | frontier 摘要数 | Multiproof B | 逐项证明 B | Multiproof 哈希数 | 逐项哈希数 | Multiproof 验证 ms | 逐项验证总 ms |',
              '| --- | --- | --- | --- | --- | --- | --- | --- |']
    for row in data['multiproof']:
        lines.append('| %s | %d | %d | %d | %d | %d | %s | %s |' %
            (row['distribution'], row['frontier_hashes'], row['multiproof_bytes'],
             row['individual_proof_bytes'], row['multiproof_verification_hashes'],
             row['individual_verification_hashes'], timing(row['multiproof_verify'], 1e3),
             timing(row['individual_verify'], 1e3)))
    lines += ['', '相邻位置共享的路径最多，证明通常最短；随机和分散位置的共享较少。具体节省量取决于选中位置在树中的分布。', '',
              '## 原始记录与复现', '',
              '全部样本和环境字段保存在 [results.json](results.json)，当时的执行输出见 [run.log](run.log)。'
              '这些数据用于判断该设备上的纯 Python 实现；微秒级操作还会受计时和系统调度影响。', '']
    if 'source_command' in data:
        lines += ['当时的采集命令为 `%s`，对应前述历史提交。' % data['source_command'], '']
    if 'hardware_source' in env:
        lines += ['> ' + env['hardware_source'], '']
    return '\n'.join(lines)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--repetitions', type=int, default=5)
    parser.add_argument('--output-dir', type=Path, default=Path(__file__).resolve().parents[1] / 'results')
    args = parser.parse_args()
    if args.repetitions < 2:
        parser.error('--repetitions must be >= 2')
    data = benchmark(args.repetitions)
    args.output_dir.mkdir(parents=True, exist_ok=True)
    (args.output_dir / 'results.json').write_text(json.dumps(data, ensure_ascii=False, indent=2) + '\n')
    (args.output_dir / '性能与验证结果.md').write_text(render_report(data))
    print('Saved:', args.output_dir)


if __name__ == '__main__':
    main()
