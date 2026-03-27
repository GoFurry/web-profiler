# web-profiler

[![Last Version](https://img.shields.io/github/release/GoFurry/web-profiler/all.svg?logo=github&color=brightgreen)](https://github.com/GoFurry/web-profiler/releases)
[![License](https://img.shields.io/github/license/GoFurry/coraza-fiber-lite)](LICENSE)
[![Go Version](https://img.shields.io/badge/go-%3E%3D1.26-blue)](go.mod)

**中文文档 | [English](README.md)**

`web-profiler` 是一个面向 `net/http` 的轻量级请求分析中间件。
它会在受控开销下分析进入的请求，并把结构化结果写入 `context.Context`，同时保证下游 handler 依然可以继续读取原始请求体。

它的定位是“请求分析基础设施”，不是“安全决策引擎”。

## 🐲 项目特点

- 原生 `net/http` 中间件接口，方便接入 Gin、Chi、Echo 等基于 `net/http` 的框架
- 请求体只做一次受限采样，多个分析模块共享结果
- 通过 `FromContext` 读取统一的结构化分析结果
- 记录每次请求的分析耗时，并保留纳秒级精度
- 发生超限或解析异常时以 `Warnings` 降级，不中断请求
- 内置熵值、请求指纹、结构复杂度、字符集分布四类分析能力

## 安装

```bash
go get github.com/GoFurry/web-profiler
```

## 🚀 快速开始

```go
package main

import (
	"log"
	"net/http"

	webprofiler "github.com/GoFurry/web-profiler"
)

func main() {
	cfg := webprofiler.DefaultConfig()

	handler := webprofiler.Middleware(cfg)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		profile, ok := webprofiler.FromContext(r.Context())
		if ok && profile != nil {
			if profile.Entropy != nil {
				log.Printf("entropy=%.4f", profile.Entropy.Value)
			}
			if profile.Fingerprint != nil {
				log.Printf("fingerprint=%s", profile.Fingerprint.Hash)
			}
		}

		// 这里仍然可以继续读取请求体。
		w.WriteHeader(http.StatusOK)
	}))

	log.Fatal(http.ListenAndServe(":8080", handler))
}
```

如果你更喜欢直接包裹现有 handler，也可以使用：

```go
handler := webprofiler.Wrap(mux, webprofiler.DefaultConfig())
```

一个可直接运行的原生 `net/http` 示例放在 [`example/main.go`](example/main.go)。

## 在 handler 里读取分析结果

你可以在任何下游 handler 里通过 `FromContext` 取回 `Profile`，然后读取元数据、分析结果和 warning：

```go
func inspectHandler(w http.ResponseWriter, r *http.Request) {
	profile, ok := webprofiler.FromContext(r.Context())
	if !ok || profile == nil {
		http.Error(w, "profile not found", http.StatusInternalServerError)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	log.Printf("path=%s content_type=%s", profile.Meta.Path, profile.Meta.ContentType)
	log.Printf("analysis_duration=%s", profile.Meta.AnalysisDuration)
	log.Printf("body=%s", string(body))

	if profile.Entropy != nil {
		log.Printf("entropy=%.4f sample_bytes=%d", profile.Entropy.Value, profile.Entropy.SampledBytes)
	}
	if profile.Fingerprint != nil {
		log.Printf("fingerprint=%s fields=%v", profile.Fingerprint.Hash, profile.Fingerprint.Fields)
	}
	if profile.Complexity != nil {
		log.Printf("complexity_score=%d depth=%d fields=%d", profile.Complexity.Score, profile.Complexity.Depth, profile.Complexity.FieldCount)
	}
	if profile.Charset != nil {
		log.Printf("non_ascii_ratio=%.2f suspicious=%v", profile.Charset.NonASCIIRatio, profile.Charset.SuspiciousFlags)
	}
	if len(profile.Warnings) > 0 {
		log.Printf("warnings=%v", profile.Warnings)
	}

	w.WriteHeader(http.StatusOK)
}
```

## Gin 框架示例

Gin 底层就是 `net/http`，可以直接把 engine 包进中间件：

```go
package main

import (
	"log"
	"net/http"

	"github.com/gin-gonic/gin"
	webprofiler "github.com/GoFurry/web-profiler"
)

func main() {
	cfg := webprofiler.DefaultConfig()
	engine := gin.New()

	engine.POST("/inspect", func(c *gin.Context) {
		profile, ok := webprofiler.FromContext(c.Request.Context())
		if !ok || profile == nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "profile not found"})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"path":         profile.Meta.Path,
			"content_type": profile.Meta.ContentType,
			"analysis_ns":  profile.Meta.AnalysisDuration.Nanoseconds(),
			"entropy":      profile.Entropy,
			"fingerprint":  profile.Fingerprint,
			"complexity":   profile.Complexity,
			"charset":      profile.Charset,
			"warnings":     profile.Warnings,
		})
	})

	handler := webprofiler.Middleware(cfg)(engine)
	log.Fatal(http.ListenAndServe(":8080", handler))
}
```

## 对外 API

```go
func Middleware(cfg Config) func(http.Handler) http.Handler
func Wrap(next http.Handler, cfg Config) http.Handler
func DefaultConfig() Config
func FromContext(ctx context.Context) (*Profile, bool)
```

## 分析结果包含什么

### `Entropy`

- 基于请求体采样字节计算 Shannon 熵
- 返回采样字节数与实际观测字节数
- 保留采样策略信息

### `Fingerprint`

- 归一化后的请求头字段
- 可选的客户端 IP 与 TLS 元信息
- 带版本号的稳定哈希指纹

### `Complexity`

- JSON 深度与字段数量统计
- 对象数、数组数、最大数组长度
- URL-encoded 表单统计
- 可解释的评分因子

### `Charset`

- ASCII 字母、数字、空白、符号、控制字符、非 ASCII 占比
- 可选的可疑标记，例如非法 UTF-8、零宽字符、混合脚本

## 🧭 配置说明

`DefaultConfig()` 会返回一份可以直接使用、且带上限保护的默认配置：

- `BodyConfig` 控制读取上限、采样大小、方法过滤和内容类型过滤
- `FingerprintConfig` 控制头字段白名单、代理信任、TLS 元数据和哈希版本
- `ComplexityConfig` 控制 JSON 深度、字段数量和支持的内容类型
- `CharsetConfig` 控制文本分析字节数与可疑模式检测

常见自定义方式：

```go
cfg := webprofiler.DefaultConfig()
cfg.Body.MaxReadBytes = 64 << 10
cfg.Body.SampleBytes = 8 << 10
cfg.Fingerprint.IncludeIP = true
cfg.Fingerprint.TrustProxy = true
cfg.Complexity.MaxJSONDepth = 16
```

## 性能说明

- `MetaInfo.AnalysisDuration` 会记录这次中间件分析本身的耗时，类型是 `time.Duration`
- 示例返回同时暴露 `analysis_duration` 和 `analysis_duration_ns`，既方便人看，也方便做指标聚合
- 指纹阶段的 `SHA-256` 只是对少量归一化后的 header、TLS/IP 字段做哈希，通常不是主要开销
- 大多数场景下，更主要的成本来自请求体读取、JSON 解析和字符扫描，而不是最后那次 `SHA-256`
- 如果你在超高 QPS 场景对极致开销很敏感，可以基于真实流量压测，并按需关闭 `EnableFingerprint`、`IncludeIP` 或 `IncludeTLS`

## 示例返回字段对照表

[`example/main.go`](example/main.go) 返回的 JSON 里，每个字段大致表示如下：

| 字段 | 含义 |
| --- | --- |
| `path` | 中间件和 handler 看到的请求路径。 |
| `body` | handler 再次读取到的请求体，用来证明中间件分析后已经恢复了 `r.Body`。 |
| `entropy.Value` | 请求体采样字节的 Shannon 熵，通常越高代表字节分布越分散。 |
| `entropy.SampledBytes` | 参与熵值计算的字节数。 |
| `entropy.TotalObservedBytes` | 中间件实际观测到的请求体字节数。 |
| `entropy.SampleStrategy` | 当前使用的采样策略。 |
| `fingerprint.Fields` | 参与请求指纹计算的归一化字段。 |
| `fingerprint.Hash` | 归一化字段计算出的稳定 SHA-256 摘要。 |
| `fingerprint.HashAlgorithm` | 当前使用的指纹哈希算法。 |
| `fingerprint.HashVersion` | 指纹结构或算法版本号。 |
| `complexity.ContentType` | 用于复杂度分析的内容类型。 |
| `complexity.Depth` | 解析后请求体的结构深度。 |
| `complexity.FieldCount` | 解析得到的字段或值总数。 |
| `complexity.ObjectCount` | JSON 对象数量。 |
| `complexity.ArrayCount` | 数组数量。 |
| `complexity.MaxArrayLength` | 请求体里出现的最大数组长度。 |
| `complexity.Score` | 聚合后的复杂度分数。 |
| `complexity.ScoreFactors` | 复杂度分数的拆解因子。 |
| `charset.TotalChars` | 参与字符分析的总字符数。 |
| `charset.ASCIIAlphaRatio` | ASCII 字母占比。 |
| `charset.DigitRatio` | 数字占比。 |
| `charset.WhitespaceRatio` | 空白字符占比。 |
| `charset.SymbolRatio` | 标点和符号占比。 |
| `charset.ControlCharRatio` | 控制字符或非法字节序列占比。 |
| `charset.NonASCIIRatio` | 非 ASCII 字符占比。 |
| `charset.SuspiciousFlags` | 可疑标记，例如非法 UTF-8、零宽字符、混合脚本。 |
| `content_type` | 规范化后的请求 `Content-Type`。 |
| `content_length` | 请求里声明的 body 长度。 |
| `sampled` | 是否只分析了请求体的一部分样本。 |
| `sample_bytes` | 实际参与 body 分析的样本字节数。 |
| `body_truncated` | 是否因为 `MaxReadBytes` 到上限而截断。 |
| `analysis_duration` | 人类可读的分析耗时，例如 `187.4µs`。 |
| `analysis_duration_ns` | 纳秒级精确耗时，适合做监控聚合。 |

## 🌟 设计边界

这个中间件：

- 只分析请求，不处理响应
- 不负责持久化或上报分析结果
- 不会因为分析失败而阻断主链路
- 不保证对所有内容类型都做深度解析
- 不直接输出业务风险结论

## 结果模型

每个请求都会生成一个 `Profile`：

```go
type Profile struct {
	Meta        MetaInfo
	Entropy     *EntropyResult
	Fingerprint *FingerprintResult
	Complexity  *ComplexityResult
	Charset     *CharsetResult
	Warnings    []Warning
}
```

各分析模块使用可选指针字段，便于业务区分“未启用”“被跳过”和“已有结果”。

## 测试

```bash
go test ./...
```

当前测试覆盖了中间件注入、请求体重放、配置归一化、分析结果以及 warning 降级路径。

## 🐺 License

本项目基于 [MIT License](LICENSE) 开源, 允许商业使用、修改、分发, 无需保留原作者版权声明。