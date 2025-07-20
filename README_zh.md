# PyPing - 高级Python网络测试工具

![Python 版本](https://img.shields.io/badge/python-3.7+-blue.svg)
![许可证](https://img.shields.io/badge/license-MIT-green.svg)

## 功能特性
- 多协议支持 (ICMP/TCP/UDP)
- IPv4 & IPv6 双协议栈
- 详细连接统计
- 可定制测试参数

## 安装方法

从源码安装
git clone https://github.com/PuqiAR/pyping
cd pyping

## 使用说明

### 基础命令
| 命令                        | 说明          | 示例                          |
| --------------------------- | ------------- | ----------------------------- |
| pyping <主机>               | 基本ICMP ping | pyping example.com            |
| pyping <主机> -p <协议>     | 选择协议      | pyping example.com -p tcp     |
| pyping <主机> --port <端口> | 指定端口      | pyping example.com --port 443 |

### 高级选项
| 选项           | 说明                    | 默认值 |
| -------------- | ----------------------- | ------ |
| -p, --protocol | 协议类型 (icmp/tcp/udp) | icmp   |
| --port         | 目标端口号              | 无     |
| -f, --family   | IP版本 (4/6)            | 4      |
| -n, --count    | 发包数量                | 4      |
| -t             | 持续ping模式            | 关闭   |
| -i, --interval | Ping间隔(秒)            | 0.5    |

## 使用示例
- 基本ICMP ping测试
  ```bash
    pyping 192.168.1.1
  ```

- IPv6 TCP端口测试
  ```bash
    pyping example.com -p tcp --port 80 -f 6
  ```

- 持续UDP测试
  ```bash
    pyping example.com -p udp --port 53 -t -i 0.5
  ```

## 环境要求
详见requirements.txt文件

## 许可证
MIT 许可证 © 2023 PuqiAR
