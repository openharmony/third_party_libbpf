# libbpf

仓库包含三方开源软件libbpf，libbpf是eBPF技术的一种实现，开发人员可以基于libbpf开发eBPF程序，可用于网络过滤、程序跟踪、性能分析以及调试等场景。

‍

# 目录结构

```
docs/          文档
fuzz/          fuzz测试
include/       头文件
scripts/       脚本
src/           源文件
LICENSE        证书文件
README.md      英文说明
README_zh.md   中文说明
```

# OpenHarmony如何集成libbpf

## 1.头文件引入

```
#include "libbpf.h"
#include "bpf.h"
```

## 2.BUILD.gn添加引用

```
deps += ["//third_party/libbpf:libbpf"]
```

# libbpf相关知识文档

bpf参考指南[https://nakryiko.com/posts/bpf-core-reference-guide/](https://nakryiko.com/posts/bpf-core-reference-guide/)

libbpf开发教程[https://nakryiko.com/posts/bcc-to-libbpf-howto-guide/](https://nakryiko.com/posts/bcc-to-libbpf-howto-guide/)

# License

`SPDX-License-Identifier: BSD-2-Clause OR LGPL-2.1`

‍
