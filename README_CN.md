# 迷你 TLS 服务器/客户端

> [English version](README.md)

> [Russian version](README_RU.md)

## 项目简介

一个自包含的迷你 TLS 服务器与 TLS 客户端项目，使用纯 C/C++ 编写，基于 **crypery** 库（TLS 1.2/1.3）构建。

- **服务器**监听 TCP 端口，启动时生成 RSA-2048 密钥和自签名 X.509 证书，与每个连接的客户端完成 TLS 握手（自动协商 TLS 1.2 或 1.3 版本），并回显（echo）所有接收到的数据。
- **客户端**连接到服务器，完成握手，打印协商后的会话参数，并以交互或非交互模式与服务器交换消息。

无任何外部依赖：所有加密算法均在 crypery 库内部从零实现。

## 项目特点

- **TLS 1.2 和 TLS 1.3**，自动协商版本（服务器同时支持两者）。
- **加密算法**：`TLS_AES_128_GCM_SHA256`（TLS 1.3）、`ECDHE-RSA-AES128-GCM-SHA256`（TLS 1.2）。
- **密钥交换**：X25519（TLS 1.3）、P-256 曲线上的 ECDHE（TLS 1.2）。
- **自签名证书**由服务器在启动时生成--无需提供证书和密钥文件。
- **纯 C 实现，不依赖外部加密库**：AES-128-GCM、SHA-256、HMAC-SHA256、HKDF、RSA-2048、ECDH、X.509--全部从零实现。
- **可移植性**：Windows（MinGW、Winsock）和类 Unix 系统（BSD 套接字）。
- **两种客户端模式**：交互模式（与服务器对话）和非交互模式（从 stdin 读取行）。
- **回显服务器**：返回所有接收到的数据--便于测试 TLS 通道。
- 握手完成后，客户端打印协商的 TLS 版本、密码套件和密钥交换方法。

## 使用的模块（crypery 库）

示例直接使用 `tls` 模块；编译时会编译库的所有模块：

- **tls** - 基础加密层：TLS 1.2/1.3 握手（客户端/服务器）、AES-128-GCM、SHA-256、HMAC-SHA256、RSA-2048、ECDH（P-256、X25519）、X.509 证书生成与解析。
- **ssl** - 内置 TLS 之上的 OpenSSL 兼容封装（SSL_CTX/SSL API、超时、对端证书校验）。
- **http** - 基于 TCP/TLS 的 HTTP/1.1 服务器（路由、静态文件、WebSocket、SSE）。
- **url** - HTTP/HTTPS 客户端（类 curl API、重定向、chunked 编码）。

## 编译

### Windows

需要 GCC（MinGW-w64）在 PATH 中。

运行构建脚本：

```bat
build_tls.bat
```

脚本会连同示例一起编译整个 crypery 库：

| 目标文件 | 源文件 |
|---|---|
| `tls_client.exe` | `crypery/*.c` + `tls_client.c` |
| `tls_server.exe` | `crypery/*.c` + `tls_server.c` |

编译参数：`-O2`（优化）、`-I./crypery`（库头文件）、`-DHTTP_NO_GZIP`（禁用 gzip 及对 zlib 的依赖）、`-lws2_32`（Winsock）。

### Linux

需要 GCC（例如 Debian/Ubuntu 上 `apt-get install gcc`）。

运行构建脚本：

```sh
chmod +x build_tls.sh
./build_tls.sh
```

脚本会连同示例一起编译整个 crypery 库：

| 目标文件 | 源文件 |
|---|---|
| `tls_client` | `crypery/*.c` + `tls_client.c` |
| `tls_server` | `crypery/*.c` + `tls_server.c` |

编译参数：`-O2`（优化）、`-I./crypery`（库头文件）、`-DHTTP_NO_GZIP`（禁用 gzip 及对 zlib 的依赖）、`-lpthread`（POSIX 线程）。

## 使用方法

### 1. 启动服务器

```bat
tls_server.exe:: 默认端口 - 2000
tls_server.exe 8443:: 自定义端口
```

服务器生成密钥和证书后，等待连接。

### 2. 启动客户端（在另一个终端中）

```bat
tls_client.exe:: localhost:2000
tls_client.exe 127.0.0.1 8443:: 自定义主机和端口
```

### 3. 交互模式

握手完成后，客户端打印会话参数和来自服务器的信息。输入消息并按 Enter--服务器会将其回显：

```
Client: hello
Server: hello
```

退出：输入 `exit` 命令或按 Esc 键。

### 4. 非交互模式

如果 stdin 不是终端，客户端将从 stdin 读取行，并通过 TLS 逐行发送：

```bat
echo "test" | tls_client.exe
```

### 会话示例

```
Connected to localhost:2000
Client TLS: 1.3
Server TLS: 1.2/1.3 (1.3)
Cipher Suite: TLS_AES_128_GCM_SHA256
Key Exchange: X25519
Interactive:  yes
Enter message ('exit' or esc to quit):
Client: hello
Server: hello
Exiting...
Disconnected from localhost:2000
```

## 许可证

GNU AGPL v3（Affero GPL）
