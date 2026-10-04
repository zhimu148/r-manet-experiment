# 计算机网络中新型往返时间测量系统的设计与开发

## 基于Dart的内联实时RTT测量系统 · C++实现

> 中国科学技术大学 软件学院 · 工程实践项目 · 2026  
> **开发语言**：C++17 | **平台**：Linux | **构建**：CMake

---

## 项目简介

本项目基于SIGCOMM 2022论文《Continuous In-Network Round-Trip Time Monitoring》提出的Dart原型系统，使用**C/C++在Linux环境下**重新实现了完整的RTT（往返时间）测量系统。核心算法包括：

- **测量范围(MR)**：追踪每个TCP流的未确认字节区间，持续计算RTT
- **多级Cuckoo哈希表**：在严格内存约束下高效管理流/包状态
- **自适应PT管理**：根据负载动态调节采样率
- **RTT异常检测**：基于滑动窗口统计的在线异常检测

## 技术栈

| 层次 | 技术 | 用途 |
|------|------|------|
| 核心引擎 | C++17 (模板、STL) | RTT测量核心逻辑 |
| 包捕获 | libpcap / DPDK | 离线pcap读取 / 在线高速抓包 |
| 构建系统 | CMake 3.15+ / GCC 9+ | 编译与测试 |
| 数据分析 | C++ (自定义统计模块) | RTT统计聚合与异常检测 |
| 参考实现 | P4 (Tofino) | Dart原始数据平面设计 |

## 文档导航

| 文档 | 内容 | 谁看 |
|------|------|------|
| [README.md](./README.md) | 快速概览（本文件） | 所有人 |
| [项目文档.md](./项目文档.md) | 完整设计文档（C++版） | 写报告的 |
| [项目文档.docx](./项目文档.docx) | Word版，可直接打印交老师 | 交作业 |
| [API文档.md](./API文档.md) | C++ API参考（头文件接口） | 写代码的 |
| [部署测试指南.md](./部署测试指南.md) | 编译、运行、测试步骤 | 搭环境的 |
| [答辩PPT大纲.md](./答辩PPT大纲.md) | PPT框架建议 | 做PPT的 |

## 快速开始

```bash
# 1. 安装依赖
sudo apt-get install -y build-essential cmake g++ libpcap-dev zlib1g-dev

# 2. 编译
cd rtt_measurement && mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
make -j$(nproc)

# 3. 运行（离线pcap模式）
./rtt_measure -i ../data/smallFlows.pcap -o ./output

# 4. 查看结果
cat output/summary.txt
head -20 output/rtt_samples.csv

# 5. 运行测试
ctest --output-on-failure
```

## 项目结构

```
rtt_measurement/
├── CMakeLists.txt
├── include/
│   ├── rtt_core/       # RTTEngine, FlowTable, PacketTable, CuckooHash
│   ├── capture/        # PcapReader, DpdkCapture
│   ├── analysis/       # RttCollector, AnomalyDetector, StatsWriter
│   └── adaptive/       # AdaptivePTManager
├── src/                # 对应 .cpp 实现文件
├── tests/              # 单元测试
└── data/               # 测试用pcap文件
```

## 核心概念速览

- **MR (Measurement Range)**：`[left_edge, right_edge)`，追踪未确认字节区间
- **Flow Table**：维护每流MR，`CuckooHashTable<FlowKey, FlowRecord, 4>`
- **Packet Table**：存储飞行中包的时间戳，ACK到达时计算RTT = t_ack − t_send
- **Cuckoo Hashing**：表满时"踢出"旧记录，被踢记录尝试下一级，多级失败触发再循环
- **防止长RTT偏差**：表满时保留旧记录，丢弃新记录（反之则会系统性遗漏长RTT）

---

*项目开始日期：2026年6月*
