# 新型RTT测量系统 C++ API 参考文档

> **语言**：C++17 | **构建**：CMake 3.15+ | **平台**：Linux (Ubuntu 20.04 LTS)  
> **依赖**：libpcap / DPDK 20.11+, zlib, ONNX Runtime (可选，用于ML检测)

---

## 目录

1. [项目结构与编译](#1-项目结构与编译)
2. [核心数据结构](#2-核心数据结构)
3. [CuckooHashTable 模板类](#3-cuckoohashtable-模板类)
4. [FlowTable 流表](#4-flowtable-流表)
5. [PacketTable 包表](#5-packettable-包表)
6. [ApproxFlowTable 近似流表](#6-approxflowtable-近似流表)
7. [RTTEngine 测量引擎](#7-rttengine-测量引擎)
8. [包捕获模块](#8-包捕获模块)
9. [RTT分析模块](#9-rtt分析模块)
10. [自适应PT管理器](#10-自适应pt管理器)
11. [数据格式规范](#11-数据格式规范)

---

## 1. 项目结构与编译

### 1.1 目录结构

```
rtt_measurement/
├── include/                    # 头文件
│   ├── rtt_core/
│   │   ├── common.h            # 公共类型定义
│   │   ├── cuckoo_hash.h       # 多级Cuckoo哈希表模板
│   │   ├── flow_table.h        # 流表
│   │   ├── packet_table.h      # 包表
│   │   ├── approx_flow_table.h # 近似流表
│   │   ├── rtt_engine.h        # RTT测量引擎
│   │   └── accountant.h        # 统计计数器
│   ├── capture/
│   │   ├── pcap_reader.h       # 离线pcap读取
│   │   └── dpdk_capture.h      # 在线DPDK抓包
│   ├── analysis/
│   │   ├── rtt_collector.h     # RTT样本收集
│   │   ├── anomaly_detector.h  # 异常检测
│   │   └── stats_writer.h      # 统计输出
│   └── adaptive/
│       └── pt_manager.h        # 自适应PT管理器
├── src/                        # 实现文件
│   ├── rtt_core/               # 对应include/rtt_core/*.cpp
│   ├── capture/                # 对应include/capture/*.cpp
│   ├── analysis/               # 对应include/analysis/*.cpp
│   ├── adaptive/pt_manager.cpp
│   └── main.cpp                # 程序入口
├── tests/                      # 单元测试
│   ├── test_cuckoo_hash.cpp
│   ├── test_flow_table.cpp
│   ├── test_packet_table.cpp
│   └── test_rtt_engine.cpp
├── CMakeLists.txt
└── Makefile
```

### 1.2 CMake构建配置

```cmake
# CMakeLists.txt
cmake_minimum_required(VERSION 3.15)
project(rtt_measurement VERSION 1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# 查找依赖
find_package(PkgConfig REQUIRED)
pkg_check_modules(PCAP REQUIRED libpcap)
find_library(ZLIB_LIB z)
find_library(PTHREAD_LIB pthread)

option(USE_DPDK "Enable DPDK live capture" OFF)
option(USE_ONNX  "Enable ONNX Runtime ML detection" OFF)

if(USE_DPDK)
    find_package(DPDK REQUIRED)
endif()

# 核心库
add_library(rtt_core STATIC
    src/rtt_core/cuckoo_hash.cpp
    src/rtt_core/flow_table.cpp
    src/rtt_core/packet_table.cpp
    src/rtt_core/approx_flow_table.cpp
    src/rtt_core/rtt_engine.cpp
    src/rtt_core/accountant.cpp
)
target_include_directories(rtt_core PUBLIC include)
target_link_libraries(rtt_core PUBLIC ${ZLIB_LIB} ${PTHREAD_LIB})

# 可执行文件
add_executable(rtt_measure src/main.cpp)
target_link_libraries(rtt_measure rtt_core ${PCAP_LIBRARIES})
```

### 1.3 编译与运行

```bash
# 编译
mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
make -j$(nproc)

# 运行（离线模式：pcap文件输入）
./rtt_measure --input trace.pcap --output rtt_samples.csv

# 运行（在线模式：DPDK实时抓包，需root权限）
sudo ./rtt_measure --dpdk --interface eth0 --output rtt_samples.csv

# 运行单元测试
cd build && ctest --output-on-failure
```

---

## 2. 核心数据结构

### 2.1 `common.h` —— 公共类型定义

```cpp
// include/rtt_core/common.h
#pragma once

#include <cstdint>
#include <cstring>
#include <string>
#include <array>
#include <chrono>
#include <vector>

namespace rtt {

// ============ 基本类型 ============
using u8  = uint8_t;
using u16 = uint16_t;
using u32 = uint32_t;
using u64 = uint64_t;

// ============ TCP相关类型 ============
struct Ipv4Addr {
    u8 octets[4];

    Ipv4Addr() : octets{0,0,0,0} {}
    Ipv4Addr(u8 a, u8 b, u8 c, u8 d) : octets{a,b,c,d} {}
    explicit Ipv4Addr(u32 addr) {
        octets[0] = (addr >> 24) & 0xFF;
        octets[1] = (addr >> 16) & 0xFF;
        octets[2] = (addr >> 8)  & 0xFF;
        octets[3] =  addr        & 0xFF;
    }

    u32 to_u32() const {
        return (static_cast<u32>(octets[0]) << 24) |
               (static_cast<u32>(octets[1]) << 16) |
               (static_cast<u32>(octets[2]) << 8)  |
               (static_cast<u32>(octets[3]));
    }

    bool operator==(const Ipv4Addr& other) const {
        return std::memcmp(octets, other.octets, 4) == 0;
    }

    std::string to_string() const;
};

// 流键：TCP五元组
struct FlowKey {
    Ipv4Addr src_ip;
    Ipv4Addr dst_ip;
    u16      src_port;
    u16      dst_port;

    bool operator==(const FlowKey& other) const {
        return src_ip == other.src_ip &&
               dst_ip == other.dst_ip &&
               src_port == other.src_port &&
               dst_port == other.dst_port;
    }

    // 用于CRC32哈希
    std::string to_hash_string() const;
};

// 包键：流键 + 期望确认号
struct PacketKey {
    FlowKey flow_key;
    u32     exp_ack;

    bool operator==(const PacketKey& other) const {
        return flow_key == other.flow_key &&
               exp_ack == other.exp_ack;
    }
};

// ============ 测量范围 (MR) ============
struct MeasurementRange {
    u32 left_edge;   // 最小未确认字节序号
    u32 right_edge;  // 最大期望确认序号

    bool is_collapsed() const { return left_edge == right_edge; }
    bool contains(u32 seq_no) const { return left_edge <= seq_no && seq_no < right_edge; }
};

// ============ 时间戳 ============
using Timestamp = std::chrono::steady_clock::time_point;
using TimestampUs = std::chrono::microseconds;

inline TimestampUs to_us(const Timestamp& t1, const Timestamp& t2) {
    return std::chrono::duration_cast<TimestampUs>(t1 - t2);
}

inline double to_ms_double(const Timestamp& t1, const Timestamp& t2) {
    auto us = to_us(t1, t2);
    return static_cast<double>(us.count()) / 1000.0;
}

// ============ TCP标志 ============
enum class TcpFlags : u8 {
    NONE = 0x00,
    FIN  = 0x01,
    SYN  = 0x02,
    RST  = 0x04,
    PSH  = 0x08,
    ACK  = 0x10,
    URG  = 0x20,
};

inline bool has_flag(u8 flags, TcpFlags f) { return (flags & static_cast<u8>(f)) != 0; }
inline u8 operator|(TcpFlags a, TcpFlags b) { return static_cast<u8>(a) | static_cast<u8>(b); }

// ============ 流签名（CRC32哈希） ============
using FlowSignature = u32;

FlowSignature compute_seq_flow_sign(const FlowKey& key);
FlowSignature compute_ack_flow_sign(const FlowKey& key);

// ============ Flow Table记录 ============
struct FlowRecord {
    FlowKey          key;
    FlowSignature    flow_sign;      // 32-bit CRC32哈希
    MeasurementRange mr;             // 测量范围
    Timestamp        entry_time;     // 记录创建时间
    Timestamp        update_time;    // 最后更新时间
    u8               entry_flags;    // 创建时的TCP标志
    u8               update_flags;   // 更新时的TCP标志
};

// ============ Packet Table记录 ============
struct PacketRecord {
    PacketKey  key;
    Timestamp  send_time;            // 数据包发送时间戳
    u32        sequence_number;      // 原始TCP SEQ号
};

// ============ RTT样本 ============
struct RttSample {
    FlowKey   flow_key;
    u32       sequence_number;
    double    rtt_ms;                // RTT值（毫秒）
    Timestamp timestamp;            // 采样时间
};

// ============ 枚举类型 ============
enum class PacketType : u8 {
    TCP_SEQ    = 1,   // TCP SEQ方向数据包
    TCP_ACK    = 2,   // TCP ACK方向确认包
    TCP_BOTH   = 3,   // 同时匹配两个方向
    INVALID    = 0,   // 无效/丢弃
};

enum class SynAction : u8 {
    IGNORE   = 0,     // 忽略SYN包
    TIMEOUT  = 1,     // SYN短超时
    STAGING  = 2,     // SYN暂存表
};

enum class EvictionStage : u8 {
    START     = 0,    // 流水线开始时检查
    IMMEDIATE = 1,    // 每级都检查
    END       = 2,    // 流水线末尾检查
};

enum class EvictionCode : u8 {
    SUCCESS         = 0,  // 正常插入
    TIMEOUT         = 1,  // 超时淘汰
    AFT_CHECK_FAIL  = 2,  // AFT检查失败
    FT_NOT_FOUND    = 3,  // 流表记录不存在
    FT_CHECK_FAIL   = 4,  // 流表检查失败
    INSERT_FAILED   = 5,  // 插入失败
};

} // namespace rtt
```

---

## 3. CuckooHashTable 模板类

### 3.1 头文件

```cpp
// include/rtt_core/cuckoo_hash.h
#pragma once

#include "rtt_core/common.h"
#include "rtt_core/accountant.h"
#include <vector>
#include <functional>
#include <memory>
#include <cstdint>
#include <zlib.h>

namespace rtt {

/**
 * 多级Cuckoo哈希表模板类
 * 
 * 这是FlowTable和PacketTable的基类，实现了：
 * - 多级CRC32哈希索引
 * - Cuckoo式的记录驱逐/再插入
 * - 可配置的再循环次数
 * - 超时淘汰机制
 * 
 * @tparam KeyType   键类型（需支持 operator== 和 to_hash_string()）
 * @tparam ValueType 值类型
 * @tparam NumStages 流水线级数（编译期常量，典型值4）
 */
template <typename KeyType, typename ValueType, size_t NumStages = 4>
class CuckooHashTable {
public:
    // ============ 配置参数 ============
    struct Config {
        size_t    max_size = 262144;           // 最大条目数
        u32       recirculations = 3;          // 允许的再循环次数 (0-7)
        bool      prefer_new = true;           // true: 优先保留新记录
        EvictionStage eviction_stage = EvictionStage::START;
        u32       entry_timeout_ms = 10000;    // 条目超时（毫秒），0=不超时
        double    sampling_rate = 1.0;         // 采样率 (0.0 ~ 1.0]
        u32       log_interval_ms = 60000;     // 日志快照间隔
    };

    // ============ 构造与析构 ============
    explicit CuckooHashTable(const Config& config);
    ~CuckooHashTable() = default;

    // 禁止拷贝（资源管理类）
    CuckooHashTable(const CuckooHashTable&) = delete;
    CuckooHashTable& operator=(const CuckooHashTable&) = delete;

    // 允许移动
    CuckooHashTable(CuckooHashTable&&) = default;
    CuckooHashTable& operator=(CuckooHashTable&&) = default;

    // ============ 核心操作 ============

    /**
     * 查找记录
     * @param key  查找键
     * @return     找到返回记录指针，未找到返回 nullptr
     *             指针有效期至下次 insert/delete/update 调用
     */
    const ValueType* lookup(const KeyType& key) const;

    /**
     * 插入记录
     * @param record    待插入记录
     * @param now       当前时间戳
     * @param touched   输出：再循环过程中被淘汰的记录列表
     * @return          true=插入成功, false=插入失败（表满且无法淘汰）
     */
    bool insert(const ValueType& record, Timestamp now,
                std::vector<ValueType>* touched = nullptr);

    /**
     * 删除记录
     * @param key  要删除的键
     * @param now  当前时间戳
     * @return     true=删除成功, false=未找到
     */
    bool remove(const KeyType& key, Timestamp now);

    /**
     * 更新记录（记录必须已存在）
     * @param key       查找键
     * @param new_record 新记录值
     * @param now       当前时间戳
     * @return          true=更新成功, false=未找到
     */
    bool update(const KeyType& key, const ValueType& new_record, Timestamp now);

    /**
     * 遍历查找（仅调试用，性能低）
     * @param key  查找键
     * @return     找到返回记录指针，未找到返回 nullptr
     */
    const ValueType* exhaustive_lookup(const KeyType& key) const;

    // ============ 状态查询 ============

    size_t num_records() const { return num_records_; }
    size_t capacity() const { return stage_size_ * NumStages; }
    double utilization() const {
        return static_cast<double>(num_records_) / capacity();
    }
    const Accountant& accountant() const { return accountant_; }

private:
    // 每级哈希索引计算
    u32 compute_stage_index(const KeyType& key, size_t stage) const;

    // 超时淘汰检查
    bool should_evict(const ValueType& record, Timestamp now) const;

    // 执行单级插入/替换
    ValueType* insert_at_stage(size_t stage, u32 index, const ValueType& record);

    // 子类可覆写的虚函数
    virtual bool check_eviction_condition(
        const ValueType& record, Timestamp now, void* context) const;
    virtual void on_eviction(const ValueType& evicted, Timestamp now);

    // 数据成员
    Config  config_;
    size_t  stage_size_;    // 每级槽位数 = max_size / NumStages
    size_t  num_records_;
    std::array<std::vector<std::unique_ptr<ValueType>>, NumStages> hash_arrays_;
    Accountant accountant_;
};

} // namespace rtt
```

### 3.2 关键方法说明

| 方法 | 复杂度 | 说明 |
|------|--------|------|
| `lookup()` | O(NumStages) | 遍历所有级查找匹配键，命中即返回 |
| `insert()` | O((recirc+1) × NumStages) | Cuckoo插入，可能驱逐现有记录并触发再循环 |
| `remove()` | O(NumStages) | 遍历查找并置空，减少记录计数 |
| `update()` | O(NumStages) | 查找并原地替换记录值 |

---

## 4. FlowTable 流表

### 4.1 头文件

```cpp
// include/rtt_core/flow_table.h
#pragma once

#include "rtt_core/common.h"
#include "rtt_core/cuckoo_hash.h"
#include <optional>

namespace rtt {

/**
 * 流表：维护每个活跃TCP流的测量范围(MR)
 * 
 * 继承自 CuckooHashTable，增加了：
 * - SYN包处理策略 (ignore/timeout/staging)
 * - MR操作 (扩展/收缩/折叠)
 * - 流记录的特定淘汰条件
 */
class FlowTable : public CuckooHashTable<FlowKey, FlowRecord, 4> {
public:
    struct FlowConfig : public Config {
        SynAction syn_action = SynAction::IGNORE;
        u32       syn_timeout_ms = 100;       // SYN超时模式
        // SYN暂存表参数（syn_action == STAGING 时生效）
        size_t    syn_staging_num_stages = 4;
        size_t    syn_staging_max_size = 4096;
        u32       syn_staging_recirculations = 2;
        u32       syn_staging_timeout_ms = 500;
    };

    explicit FlowTable(const FlowConfig& config);

    /**
     * 处理SEQ方向数据包
     * 
     * 根据MR状态和SEQ号决定操作：
     * - SEQ扩展MR → 更新right_edge，标记需插入PT
     * - SEQ重置MR → 新建MR区间，标记需插入PT
     * - SEQ违规   → 折叠/删除流记录
     * 
     * @param flow_key  五元组流键
     * @param seq_no    TCP序列号
     * @param payload_size TCP载荷大小
     * @param flags     TCP标志位
     * @param now       当前时间戳
     * @param need_pt_insert 输出：是否需要向PT插入记录
     * @return          MR操作后的状态
     */
    enum class SeqResult {
        EXTEND,           // MR扩展，正常
        RESTART,          // MR重置（检测到空洞）
        COLLAPSE,         // MR折叠（重传/违规）
        DROP,             // 包被丢弃（SYN忽略等）
        NEW_FLOW,         // 新流创建
    };

    SeqResult process_seq(const FlowKey& flow_key,
                          u32 seq_no, u32 payload_size,
                          u8 flags, Timestamp now,
                          bool* need_pt_insert);

    /**
     * 处理ACK方向确认包
     * 
     * @param flow_key  五元组流键（注意：方向取反）
     * @param ack_no    TCP确认号
     * @param flags     TCP标志位
     * @param now       当前时间戳
     * @param need_pt_lookup 输出：是否需要查找PT
     * @param match_eack     输出：PT匹配用的期望ACK号
     * @return          ACK处理后的状态
     */
    enum class AckResult {
        PROCEED,          // ACK在MR内，需匹配PT计算RTT
        COLLAPSE,         // ACK到达MR边界，折叠流记录
        DUPLICATE,        // 重复ACK，删除流记录
        DROP,             // 包被丢弃
        NOT_FOUND,        // 流记录不存在
    };

    AckResult process_ack(const FlowKey& flow_key,
                          u32 ack_no, u8 flags, Timestamp now,
                          bool* need_pt_lookup, u32* match_eack);

private:
    FlowConfig flow_config_;
    // SYN暂存表（仅在 STAGING 模式下分配）
    std::unique_ptr<CuckooHashTable<FlowKey, FlowRecord, 4>> syn_table_;

    bool is_syn_packet(u8 flags) const;
    bool is_rst_packet(u8 flags) const;
    bool is_pure_ack(u8 flags, u32 payload_size) const;
    bool has_syn_timeout_expired(const FlowRecord& rec, Timestamp now) const;
};

} // namespace rtt
```

---

## 5. PacketTable 包表

### 5.1 头文件

```cpp
// include/rtt_core/packet_table.h
#pragma once

#include "rtt_core/common.h"
#include "rtt_core/cuckoo_hash.h"

namespace rtt {

// 前置声明
class FlowTable;
class ApproxFlowTable;

/**
 * 包表：存储"飞行中"数据包的时间戳
 * 
 * 当SEQ方向包被确认"需要PT插入"后，其时间戳存入PT。
 * 当ACK到达并匹配时，取出时间戳计算RTT = t_ack - t_send。
 */
class PacketTable : public CuckooHashTable<PacketKey, PacketRecord, 4> {
public:
    explicit PacketTable(const Config& config);

    /**
     * 插入包记录
     * 
     * 插入前会检查是否应淘汰旧记录：
     * 1. 超时 → 淘汰
     * 2. AFT检查 → 对应流ACK已确认 → 淘汰
     * 3. FT检查 → 流不存在或ACK已被确认 → 淘汰
     * 
     * @param record        待插入包记录
     * @param now           当前时间戳
     * @param flow_table    关联的流表（用于淘汰检查）
     * @param aft           关联的近似流表（可选，加速淘汰）
     * @return              淘汰码
     */
    EvictionCode insert_with_check(const PacketRecord& record,
                                   Timestamp now,
                                   const FlowTable* flow_table,
                                   const ApproxFlowTable* aft = nullptr);

    /**
     * 匹配包记录并计算RTT
     * 
     * @param match_key  匹配键（flow_key + eACK = ACK#）
     * @param now        当前时间戳（ACK到达时间）
     * @param rtt_out    输出：计算出的RTT值（毫秒）
     * @return           true=匹配成功并已删除记录, false=未匹配
     */
    bool match_and_compute_rtt(const PacketKey& match_key,
                               Timestamp now,
                               double* rtt_out);

private:
    EvictionCode check_eviction(const PacketRecord& record,
                                Timestamp now,
                                const FlowTable* flow_table,
                                const ApproxFlowTable* aft) const;
};

} // namespace rtt
```

---

## 6. ApproxFlowTable 近似流表

### 6.1 头文件

```cpp
// include/rtt_core/approx_flow_table.h
#pragma once

#include "rtt_core/common.h"
#include "rtt_core/cuckoo_hash.h"

namespace rtt {

/**
 * 近似流表 (AFT)：简化的流表副本
 * 
 * 目的：加速Packet Table的过期淘汰判断。
 * AFT存储近似的MR信息，PT淘汰时可先查询AFT快速判断
 * 某个包的ACK是否已被确认，避免每次都查FT。
 * 
 * 与FT的区别：
 * - 不触发再循环（单次遍历）
 * - 键匹配时原地更新
 * - 宽松的插入语义（失败直接丢弃，不影响正确性）
 */
class ApproxFlowTable : public CuckooHashTable<FlowKey, FlowRecord, 4> {
public:
    explicit ApproxFlowTable(const Config& config);

    /**
     * 插入或更新记录（不触发再循环）
     * 
     * 遍历各级流水线，遇到空位插入，遇到同键替换，
     * 遇到不同键则Cuckoo驱逐一次。
     * 
     * @param record  待插入/更新的记录
     * @param now     当前时间戳
     * @return        true=成功, false=失败（可安全忽略）
     */
    bool insert_or_update(const FlowRecord& record, Timestamp now);
};

} // namespace rtt
```

---

## 7. RTTEngine 测量引擎

### 7.1 头文件

```cpp
// include/rtt_core/rtt_engine.h
#pragma once

#include "rtt_core/common.h"
#include "rtt_core/flow_table.h"
#include "rtt_core/packet_table.h"
#include "rtt_core/approx_flow_table.h"
#include <vector>
#include <functional>

namespace rtt {

/**
 * RTT测量引擎：整合所有组件的主控制器
 * 
 * 用法：
 *   RTTEngine::Config cfg;
 *   cfg.flow.max_size = 262144;
 *   cfg.packet.max_size = 262144;
 *   cfg.enable_aft = false;
 * 
 *   RTTEngine engine(cfg);
 *   engine.set_rtt_callback([](const RttSample& s) {
 *       std::cout << "RTT: " << s.rtt_ms << " ms\n";
 *   });
 * 
 *   // 对每个捕获的TCP包调用
 *   engine.process_packet(pkt_info, now);
 */
class RTTEngine {
public:
    // ============ 配置 ============
    struct Config {
        FlowTable::FlowConfig  flow;
        PacketTable::Config    packet;
        ApproxFlowTable::Config aft;
        bool enable_aft = false;            // 是否启用AFT
        bool enable_adaptive_pt = false;    // 是否启用自适应PT
        std::string home_subnet_file;       // 本地子网配置文件路径
    };

    // ============ 回调类型 ============
    using RttCallback = std::function<void(const RttSample&)>;

    // ============ 构造 ============
    explicit RTTEngine(const Config& config);
    ~RTTEngine();

    // ============ 核心接口 ============

    /**
     * 处理单个TCP数据包
     * 
     * 自动判断方向（SEQ/ACK），协调FT/PT/AFT操作，
     * 当检测到RTT时触发回调。
     * 
     * @param src_ip       源IP
     * @param dst_ip       目的IP
     * @param src_port     TCP源端口
     * @param dst_port     TCP目的端口
     * @param seq_no       TCP序列号
     * @param ack_no       TCP确认号
     * @param flags        TCP标志位
     * @param payload_size TCP载荷大小（字节）
     * @param timestamp    包到达时间戳
     */
    void process_packet(Ipv4Addr src_ip, Ipv4Addr dst_ip,
                        u16 src_port, u16 dst_port,
                        u32 seq_no, u32 ack_no,
                        u8 flags, u32 payload_size,
                        Timestamp timestamp);

    // ============ 查询接口 ============

    /** 获取RTT样本总数 */
    size_t total_rtt_samples() const { return rtt_sample_count_; }

    /** 获取所有RTT样本（用于离线分析） */
    const std::vector<RttSample>& rtt_samples() const { return rtt_samples_; }

    /** 获取流表 */
    const FlowTable& flow_table() const { return flow_table_; }

    /** 获取包表 */
    const PacketTable& packet_table() const { return packet_table_; }

    /** 注册RTT回调（每检测到一个RTT触发一次） */
    void set_rtt_callback(RttCallback cb) { rtt_callback_ = std::move(cb); }

    /** 触发快照记录 */
    void take_snapshot(Timestamp now);

    /** 保存统计数据到文件 */
    void save_statistics(const std::string& output_dir) const;

private:
    PacketType classify_packet(Ipv4Addr src_ip, Ipv4Addr dst_ip,
                               u8 flags, u32 payload_size) const;

    bool is_home_network(Ipv4Addr ip) const;

    void handle_seq_direction(const FlowKey& key, u32 seq_no,
                              u32 payload_size, u8 flags, Timestamp ts);

    void handle_ack_direction(const FlowKey& key, u32 ack_no,
                              u8 flags, Timestamp ts);

    // 配置与组件
    Config config_;
    FlowTable      flow_table_;
    PacketTable    packet_table_;
    std::unique_ptr<ApproxFlowTable> aft_;    // 可选
    std::vector<Ipv4Addr> home_subnets_;      // 本地子网列表

    // 运行时状态
    size_t rtt_sample_count_ = 0;
    std::vector<RttSample> rtt_samples_;      // 全量RTT样本
    RttCallback rtt_callback_;                // 实时RTT回调

    // 当前正在处理的包信息（用于ACK方向匹配）
    struct PendingPacket {
        FlowKey flow_key;
        u32     exp_ack;
        Timestamp send_time;
    };
};

} // namespace rtt
```

### 7.2 使用示例

```cpp
#include "rtt_core/rtt_engine.h"
#include <iostream>

int main() {
    // 1. 配置引擎
    rtt::RTTEngine::Config cfg;
    cfg.flow.max_size = 256 * 1024;    // 256K 流表条目
    cfg.flow.recirculations = 3;
    cfg.flow.syn_action = rtt::SynAction::IGNORE;
    cfg.packet.max_size = 256 * 1024;  // 256K 包表条目
    cfg.packet.recirculations = 3;
    cfg.enable_aft = false;

    // 2. 创建引擎
    rtt::RTTEngine engine(cfg);

    // 3. 注册实时回调（可选）
    engine.set_rtt_callback([](const rtt::RttSample& s) {
        printf("RTT: flow=%s:%u -> %s:%u, seq=%u, rtt=%.3f ms\n",
               s.flow_key.src_ip.to_string().c_str(), s.flow_key.src_port,
               s.flow_key.dst_ip.to_string().c_str(), s.flow_key.dst_port,
               s.sequence_number, s.rtt_ms);
    });

    // 4. 逐包处理（包从 pcap_reader 或 dpdk_capture 获取）
    // for each captured TCP packet:
    engine.process_packet(src_ip, dst_ip, src_port, dst_port,
                          seq_no, ack_no, flags, payload_size, timestamp);

    // 5. 保存结果
    engine.save_statistics("./output");
    printf("Total RTT samples: %zu\n", engine.total_rtt_samples());

    return 0;
}
```

---

## 8. 包捕获模块

### 8.1 PcapReader —— 离线pcap文件读取

```cpp
// include/capture/pcap_reader.h
#pragma once

#include "rtt_core/common.h"
#include <pcap.h>
#include <string>
#include <functional>
#include <memory>

namespace rtt {

/**
 * 离线pcap文件读取器
 * 
 * 解析pcap文件中的TCP包，逐包回调给RTTEngine处理。
 * 
 * 用法：
 *   PcapReader reader("trace.pcap");
 *   reader.set_callback([](const ParsedPacket& pkt) {
 *       engine.process_packet(...);
 *   });
 *   reader.process_all();
 */
class PcapReader {
public:
    struct ParsedPacket {
        Ipv4Addr  src_ip;
        Ipv4Addr  dst_ip;
        u16       src_port;
        u16       dst_port;
        u32       seq_no;
        u32       ack_no;
        u8        tcp_flags;
        u32       payload_size;
        Timestamp timestamp;      // 从pcap时间戳转换
    };

    using PacketCallback = std::function<void(const ParsedPacket&)>;

    explicit PcapReader(const std::string& pcap_path);
    ~PcapReader();

    /** 注册逐包回调 */
    void set_callback(PacketCallback cb) { callback_ = std::move(cb); }

    /** 处理pcap中的所有包 */
    size_t process_all();

    /** 处理指定数量的包 */
    size_t process_n(size_t count);

    /** 获取pcap中的总包数（需完整扫描一次） */
    size_t total_packets() const { return total_packets_; }

private:
    static void pcap_handler(u_char* user, const struct pcap_pkthdr* hdr,
                             const u_char* bytes);

    pcap_t*         handle_ = nullptr;
    PacketCallback  callback_;
    size_t          total_packets_ = 0;
    size_t          processed_count_ = 0;
};

} // namespace rtt
```

### 8.2 DpdkCapture —— 在线DPDK实时抓包（可选）

```cpp
// include/capture/dpdk_capture.h
#pragma once

#ifdef USE_DPDK

#include "rtt_core/common.h"
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>
#include <string>
#include <functional>
#include <vector>

namespace rtt {

/**
 * DPDK在线抓包模块
 * 
 * 绕过Linux内核协议栈，通过DPDK直接从网卡抓包，
 * 实现高性能、低延迟的在线RTT测量。
 * 
 * 用法：
 *   DpdkCapture capture("eth0");
 *   capture.set_callback([](const ParsedPacket& pkt) {
 *       engine.process_packet(...);
 *   });
 *   capture.start();  // 阻塞运行，直到 Ctrl+C
 */
class DpdkCapture {
public:
    struct Config {
        std::string interface;               // 网卡名称
        u16         rx_ring_size = 1024;     // 接收环形缓冲区大小
        u16         tx_ring_size = 1024;
        u16         nb_queues = 1;           // 队列数
        u32         burst_size = 32;         // 每次批量处理包数
        std::string eal_args = "";           // 额外EAL参数
    };

    using ParsedPacket = PcapReader::ParsedPacket;  // 复用相同结构
    using PacketCallback = std::function<void(const ParsedPacket&)>;

    explicit DpdkCapture(const Config& config);
    ~DpdkCapture();

    /** 注册逐包回调 */
    void set_callback(PacketCallback cb) { callback_ = std::move(cb); }

    /** 初始化DPDK端口 */
    bool init();

    /** 开始抓包循环（阻塞） */
    void start();

    /** 停止抓包 */
    void stop();

    /** 获取统计信息 */
    struct Stats {
        uint64_t rx_packets;
        uint64_t rx_bytes;
        uint64_t tx_packets;
    };
    Stats get_stats() const;

private:
    void parse_packet(struct rte_mbuf* mbuf);

    Config          config_;
    PacketCallback  callback_;
    u16             port_id_ = 0;
    volatile bool   running_ = false;
    Stats           stats_ = {};
};

} // namespace rtt

#endif // USE_DPDK
```

---

## 9. RTT分析模块

### 9.1 RttCollector —— RTT样本收集器

```cpp
// include/analysis/rtt_collector.h
#pragma once

#include "rtt_core/common.h"
#include <vector>
#include <map>
#include <mutex>
#include <string>

namespace rtt {

/**
 * RTT样本收集器（线程安全）
 * 
 * 收集RTT样本并提供聚合查询：
 * - 按流分组
 * - 按时间窗口统计
 * - 导出CSV/JSON
 */
class RttCollector {
public:
    RttCollector() = default;

    /** 添加RTT样本（线程安全） */
    void add_sample(const RttSample& sample);

    /** 按流获取所有样本 */
    std::map<FlowKey, std::vector<double>>
    samples_by_flow() const;

    /** 获取全局RTT统计 */
    struct RttStats {
        size_t count;
        double min_ms, max_ms;
        double mean_ms, median_ms;
        double p50_ms, p95_ms, p99_ms;
        double stddev_ms;
    };
    RttStats compute_stats() const;

    /** 获取滑动窗口内的RTT统计 */
    RttStats compute_window_stats(Timestamp from, Timestamp to) const;

    /** 导出为CSV */
    void export_csv(const std::string& path) const;

    /** 导出为JSON */
    void export_json(const std::string& path) const;

    /** 获取样本总数 */
    size_t total_count() const { return samples_.size(); }

private:
    mutable std::mutex mutex_;
    std::vector<RttSample> samples_;
};

} // namespace rtt
```

### 9.2 AnomalyDetector —— 异常检测器

```cpp
// include/analysis/anomaly_detector.h
#pragma once

#include "rtt_core/common.h"
#include <vector>
#include <deque>
#include <string>
#include <functional>

namespace rtt {

/**
 * 基于滑动窗口统计的RTT异常检测器
 * 
 * 使用轻量级统计方法（不依赖ML框架），也可通过ONNX Runtime
 * 加载预训练的Isolation Forest模型。
 * 
 * 异常类型：
 * - SPIKE:   单点RTT突增 > 阈值×基线
 * - DRIFT:   RTT持续漂移（30s窗口均值趋势）
 * - JITTER:  RTT方差突然增大
 */
class AnomalyDetector {
public:
    enum class AnomalyType {
        SPIKE,        // RTT尖峰
        DRIFT_UP,     // RTT持续上升
        DRIFT_DOWN,   // RTT持续下降
        JITTER,       // 抖动增大
    };

    struct Anomaly {
        AnomalyType type;
        Timestamp   detected_time;
        FlowKey     flow_key;
        double      current_rtt_ms;
        double      baseline_rtt_ms;
        double      deviation;
        std::string description;
    };

    struct Config {
        size_t short_window_size = 50;    // 短窗口样本数
        size_t long_window_size  = 500;   // 长窗口样本数（基线）
        double spike_threshold   = 3.0;   // 尖峰阈值（倍数于基线）
        double jitter_threshold  = 5.0;   // 抖动阈值（标准差倍数）
        bool   use_ml_model      = false;
        std::string ml_model_path;        // ONNX模型路径（如启用ML）
    };

    using AlertCallback = std::function<void(const Anomaly&)>;

    explicit AnomalyDetector(const Config& config);
    ~AnomalyDetector();

    /** 处理新RTT样本，如有异常触发回调 */
    void process_sample(const RttSample& sample);

    /** 注册异常告警回调 */
    void set_alert_callback(AlertCallback cb) { alert_cb_ = std::move(cb); }

    /** 获取指定流的当前基线RTT */
    double get_baseline(const FlowKey& key) const;

private:
    Config  config_;
    AlertCallback alert_cb_;

    // 每个流维护独立的滑动窗口
    struct FlowWindow {
        std::deque<double> short_window;  // 短窗口（检测尖峰）
        std::deque<double> long_window;   // 长窗口（计算基线）
        double baseline = 0.0;
        double variance = 0.0;
    };
    std::map<FlowKey, FlowWindow> flow_windows_;

#ifdef USE_ONNX
    // ML模型推理上下文
    void* ort_session_ = nullptr;  // Ort::Session*
#endif

    void update_baseline(const FlowKey& key, FlowWindow& w);
    void check_spike(const FlowKey& key, FlowWindow& w, double rtt_ms, Timestamp ts);
    void check_jitter(const FlowKey& key, FlowWindow& w, Timestamp ts);
};

} // namespace rtt
```

### 9.3 StatsWriter —— 统计输出

```cpp
// include/analysis/stats_writer.h
#pragma once

#include "rtt_core/common.h"
#include <string>
#include <fstream>

namespace rtt {

/**
 * 统计结果输出器
 * 
 * 将RTT测量统计数据写入文件：
 * - 每流RTT样本列表
 * - 全局RTT统计摘要
 * - 按时间窗口的RTT分布
 */
class StatsWriter {
public:
    explicit StatsWriter(const std::string& output_dir);
    ~StatsWriter();

    /** 写入RTT样本列表 */
    void write_samples(const std::vector<RttSample>& samples,
                       const std::string& filename = "rtt_samples.csv");

    /** 写入流级别统计 */
    void write_flow_stats(
        const std::map<FlowKey, std::vector<double>>& flow_samples,
        const std::string& filename = "flow_stats.csv");

    /** 写入全局摘要 */
    void write_summary(const RttCollector::RttStats& stats,
                       const std::string& filename = "summary.txt");

private:
    std::string output_dir_;
};

} // namespace rtt
```

---

## 10. 自适应PT管理器

### 10.1 头文件

```cpp
// include/adaptive/pt_manager.h
#pragma once

#include "rtt_core/common.h"
#include <atomic>

namespace rtt {

/**
 * 自适应Packet Table管理器
 * 
 * 实时监控PT利用率，动态调整采样率：
 * - PT利用率 > 80% → 采样率 × 0.8（减少新记录插入）
 * - PT利用率 < 30% → 采样率 × 1.2（提高测量覆盖）
 * - 使用EWMA平滑利用率估计（α=0.2）
 * 
 * 线程安全：所有方法可在多线程环境调用。
 */
class AdaptivePTManager {
public:
    struct Config {
        double alpha = 0.2;           // EWMA平滑因子
        double low_threshold = 0.3;   // 低水位（提高采样率）
        double high_threshold = 0.8;  // 高水位（降低采样率）
        double min_sampling_rate = 0.1;   // 最小采样率
        double max_sampling_rate = 1.0;   // 最大采样率
        double rate_adjust_factor = 0.8;  // 采样率调节因子
        u32    adjust_interval_ms = 1000; // 调节间隔（毫秒）
    };

    explicit AdaptivePTManager(const Config& config);

    /** 更新PT占用率观察值（每次插入/删除时调用） */
    void update_utilization(size_t num_records, size_t capacity);

    /** 获取当前采样率 */
    double sampling_rate() const {
        return sampling_rate_.load(std::memory_order_relaxed);
    }

    /** 判断是否应该采样当前包 */
    bool should_sample();

    /** 获取当前EWMA利用率 */
    double ewma_utilization() const {
        return ewma_utilization_.load(std::memory_order_relaxed);
    }

    /** 强制设置采样率（用于手动覆盖） */
    void force_sampling_rate(double rate);

private:
    void adjust_sampling_rate();

    Config config_;
    std::atomic<double> ewma_utilization_{0.0};
    std::atomic<double> sampling_rate_{1.0};
    Timestamp last_adjust_time_;
};

} // namespace rtt
```

### 10.2 使用示例

```cpp
#include "adaptive/pt_manager.h"

// 初始化
rtt::AdaptivePTManager::Config pt_cfg;
pt_cfg.alpha = 0.2;
pt_cfg.low_threshold = 0.3;
pt_cfg.high_threshold = 0.8;
rtt::AdaptivePTManager pt_mgr(pt_cfg);

// 每次向PT插入记录后更新利用率
pt_mgr.update_utilization(packet_table.num_records(),
                          packet_table.capacity());

// 每次需要向PT插入新记录前判断是否采样
if (pt_mgr.should_sample()) {
    // 继续向PT插入记录
    packet_table.insert_with_check(record, now, &flow_table);
} else {
    // 跳过此包的PT插入（节省资源）
}
```

---

## 11. 数据格式规范

### 11.1 输入格式：pcap文件

标准的pcap/pcapng格式，通过libpcap库解析。支持的协议栈：Ethernet / IPv4 / TCP。

### 11.2 输出格式：RTT样本CSV

```csv
# rtt_samples.csv
timestamp,src_ip,dst_ip,src_port,dst_port,seq_no,rtt_ms
1719590400.123456,192.168.1.100,10.0.0.50,54321,80,1048576,15.234
1719590400.234567,192.168.1.100,10.0.0.50,54321,80,1052672,18.567
1719590400.345678,192.168.1.101,10.0.0.51,54322,443,2097152,22.891
```

### 11.3 输出格式：流统计CSV

```csv
# flow_stats.csv
src_ip,dst_ip,src_port,dst_port,samples,min_ms,max_ms,mean_ms,median_ms,p95_ms
192.168.1.100,10.0.0.50,54321,80,1523,12.3,45.6,18.2,17.1,32.5
192.168.1.101,10.0.0.51,54322,443,891,15.1,38.2,20.5,19.3,28.7
```

### 11.4 输出格式：异常日志

```json
{
  "anomalies": [
    {
      "type": "SPIKE",
      "time": "2026-06-24T12:00:00.123456Z",
      "flow": "192.168.1.100:54321->10.0.0.50:80",
      "current_rtt_ms": 145.3,
      "baseline_rtt_ms": 18.2,
      "deviation": 7.98,
      "description": "RTT spike: 145.3ms (baseline 18.2ms, 7.98x deviation)"
    }
  ]
}
```

---

*API文档版本：v2.0 | 语言：C++17 | 更新日期：2026年6月*
