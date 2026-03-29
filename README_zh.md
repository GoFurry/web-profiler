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
- 补充了观测字节数、header 统计和分模块耗时等元数据
- 支持 `head`、`tail`、`head_tail` 三种受限采样策略
- 可选支持压缩请求体分析、可信代理 CIDR 校验和多种指纹哈希算法
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

	log.Printf("path=%s content_type=%s observed_bytes=%d", profile.Meta.Path, profile.Meta.ContentType, profile.Meta.ObservedBytes)
	log.Printf("headers=%d header_bytes=%d", profile.Meta.HeaderCount, profile.Meta.HeaderBytes)
	log.Printf("analysis_duration=%s", profile.Meta.AnalysisDuration)
	log.Printf("body=%s", string(body))

	if profile.Entropy != nil {
		log.Printf("entropy=%.4f sample_bytes=%d", profile.Entropy.Value, profile.Entropy.SampledBytes)
	}
	if profile.Fingerprint != nil {
		log.Printf("fingerprint=%s fields=%v", profile.Fingerprint.Hash, profile.Fingerprint.Fields)
	}
	if profile.Complexity != nil {
		log.Printf("complexity_score=%d depth=%d fields=%d scalars=%d", profile.Complexity.Score, profile.Complexity.Depth, profile.Complexity.FieldCount, profile.Complexity.ScalarCount)
	}
	if profile.Charset != nil {
		log.Printf("non_ascii_ratio=%.2f scripts=%v suspicious=%v", profile.Charset.NonASCIIRatio, profile.Charset.UnicodeScriptCounts, profile.Charset.SuspiciousFlags)
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
			"observed":     profile.Meta.ObservedBytes,
			"headers":      profile.Meta.HeaderCount,
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

### `Meta`

- 请求方法、路径、规范化内容类型、请求长度
- 实际观测字节数、采样字节数、是否截断、header 数量与字节量
- 总分析耗时和分模块耗时
- 当 body 分析被跳过或降级时，对应的 warning 信息

### `Entropy`

- 基于请求体采样字节计算 Shannon 熵
- 补充归一化熵、唯一字节数、重复率和近似可压缩性
- 返回采样字节数与实际观测字节数
- 保留采样策略信息

### `Fingerprint`

- 归一化后的请求头字段
- 可选的客户端 IP 与 TLS 元信息
- 带来源标记、弱/强哈希和版本号的稳定指纹
- 如果不希望返回原始归一化字段，可启用只返回 hash 的模式
- 支持可信代理 CIDR 策略，以及 `sha1`、`sha256`、`sha512`、`fnv1a64` 等哈希算法

### `Complexity`

- JSON 深度、字段数、标量/null/字符串统计和 key 长度摘要
- 对象数、数组数、最大数组长度、最大对象宽度
- URL-encoded 表单统计以及 key/value 长度摘要
- 可选的 multipart 文件元信息，例如文件数、扩展名和内容类型分布
- 可解释的评分因子

### `Charset`

- ASCII 字母、数字、空白、符号、控制字符、非 ASCII 占比
- Emoji 占比和不可见字符密度
- 启用后可输出 Unicode 脚本分布计数
- 可选的同形异义字符检测，以及面向 JSON、XML、表单的格式化文本指标
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
cfg.Body.SampleStrategy = webprofiler.SampleStrategyHeadTail
cfg.Body.EnableCompressedAnalysis = true
cfg.Fingerprint.IncludeIP = true
cfg.Fingerprint.TrustProxy = true
cfg.Fingerprint.TrustedProxyCIDRs = []string{"10.0.0.0/8", "192.168.0.0/16"}
cfg.Fingerprint.HashAlgorithm = "sha512"
cfg.Fingerprint.ExposeFields = false
cfg.Complexity.MaxJSONDepth = 16
cfg.Complexity.EnableMultipartMeta = true
cfg.Charset.EnableConfusableDetection = true
cfg.Charset.EnableFormatSpecificMetrics = true
```

## 性能说明

- `MetaInfo.AnalysisDuration` 会记录这次中间件分析本身的耗时，类型是 `time.Duration`
- `MetaInfo` 现在还会记录分模块耗时，便于你判断时间主要花在指纹、采样、复杂度还是字符分析上
- 示例返回同时暴露 `analysis_duration` 和 `analysis_duration_ns`，既方便人看，也方便做指标聚合
- 指纹阶段的 `SHA-256` 只是对少量归一化后的 header、TLS/IP 字段做哈希，通常不是主要开销
- 现在也支持其他指纹哈希算法，但从兼容性和稳定性看，`sha256` 仍然是最合适的默认值
- 压缩请求体分析是可选能力，因为它会增加解压成本；当你的流量里确实存在较多编码请求体时再开启更合适
- 如果你想进一步降低指纹结果的暴露和处理成本，可以设置 `Fingerprint.ExposeFields = false`，只保留 hash 和来源信息
- 大多数场景下，更主要的成本来自请求体读取、JSON 解析和字符扫描，而不是最后那次 `SHA-256`
- 如果你在超高 QPS 场景对极致开销很敏感，可以基于真实流量压测，并按需关闭 `EnableFingerprint`、`IncludeIP` 或 `IncludeTLS`

## 示例返回字段对照表

[`example/main.go`](example/main.go) 返回的 JSON 里，每个字段大致表示如下：

| 字段 | 含义 |
| --- | --- |
| `path` | 中间件和 handler 看到的请求路径。 |
| `body` | handler 再次读取到的请求体，用来证明中间件分析后已经恢复了 `r.Body`。 |
| `observed_bytes` | 中间件在采样前实际观测到的 body 字节数。 |
| `header_count` | 中间件统计到的 header 条目数，包含 `Host`。 |
| `header_bytes` | 中间件统计到的 header key/value 总字节量近似值。 |
| `entropy.Value` | 请求体采样字节的 Shannon 熵，通常越高代表字节分布越分散。 |
| `entropy.NormalizedValue` | 将熵值按 `8 bits/byte` 近似归一化后的结果，可粗略看作 `0..1` 区间。 |
| `entropy.SampledBytes` | 参与熵值计算的字节数。 |
| `entropy.TotalObservedBytes` | 中间件实际观测到的请求体字节数。 |
| `entropy.UniqueByteCount` | 采样结果里出现过的不同字节值数量。 |
| `entropy.RepetitionRatio` | 采样字节中，除首次出现外的重复字节占比。 |
| `entropy.CompressionRatio` | 近似 gzip 压缩后大小与采样大小的比值，越低通常说明内容越重复。 |
| `entropy.ApproxCompressibility` | 从压缩比推导出的便捷指标，越高通常代表越容易压缩。 |
| `entropy.SampleStrategy` | 当前使用的采样策略。 |
| `fingerprint.Fields` | 参与请求指纹计算的归一化字段。 |
| `fingerprint.SourceFlags` | 这次指纹实际用了哪些来源，例如 `headers`、`tls`、`ip`。 |
| `fingerprint.Hash` | 归一化字段计算出的稳定 SHA-256 摘要。 |
| `fingerprint.WeakHash` | 排除更易波动输入后得到的指纹 hash，例如不包含客户端 IP。 |
| `fingerprint.StrongHash` | 基于完整配置输入集合得到的指纹 hash。 |
| `fingerprint.HashAlgorithm` | 当前使用的指纹哈希算法。 |
| `fingerprint.HashVersion` | 指纹结构或算法版本号。 |
| `complexity.ContentType` | 用于复杂度分析的内容类型。 |
| `complexity.Depth` | 解析后请求体的结构深度。当前深度按递归遍历层级计算，标量叶子节点也会增加最终深度。 |
| `complexity.FieldCount` | 解析得到的字段或值总数。 |
| `complexity.ObjectCount` | JSON 对象数量。 |
| `complexity.ArrayCount` | 数组数量。 |
| `complexity.ScalarCount` | 非容器值数量，例如字符串、数字、布尔值和 `null`。 |
| `complexity.NullCount` | JSON 中 `null` 的数量。 |
| `complexity.StringCount` | JSON 中字符串值的数量。 |
| `complexity.UniqueKeyCount` | 解析过程中遇到的 key 数量。 |
| `complexity.MaxArrayLength` | 请求体里出现的最大数组长度。 |
| `complexity.MaxObjectFields` | 单个对象或表单 key 集合中的最大字段数。 |
| `complexity.MaxKeyLength` | 复杂度分析过程中出现的最大 key 长度。 |
| `complexity.MaxStringLength` | JSON 字符串值的最大长度。 |
| `complexity.MaxValueLength` | 表单 value 的最大长度。 |
| `complexity.AverageKeyLength` | 表单 key 的平均长度。 |
| `complexity.AverageValueLength` | 表单 value 的平均长度。 |
| `complexity.MultipartFileCount` | 在 multipart 元信息模式下识别到的上传文件数量。 |
| `complexity.MultipartFieldCount` | 在 multipart 元信息模式下识别到的非文件字段数量。 |
| `complexity.MultipartFileExtensions` | multipart 上传里各文件扩展名的计数。 |
| `complexity.MultipartFileContentTypes` | multipart 上传里各文件内容类型的计数。 |
| `complexity.MultipartMaxFileNameLength` | 本次请求中 multipart 文件名的最大长度。 |
| `complexity.Score` | 聚合后的复杂度分数。 |
| `complexity.ScoreFactors` | 复杂度分数的拆解因子。 |
| `charset.TotalChars` | 参与字符分析的总字符数。 |
| `charset.ASCIIAlphaRatio` | ASCII 字母占比。 |
| `charset.DigitRatio` | 数字占比。 |
| `charset.WhitespaceRatio` | 空白字符占比。 |
| `charset.SymbolRatio` | 标点和符号占比。 |
| `charset.ControlCharRatio` | 控制字符或非法字节序列占比。 |
| `charset.NonASCIIRatio` | 非 ASCII 字符占比。 |
| `charset.EmojiRatio` | 采样文本中 emoji 类字符的大致占比。 |
| `charset.InvisibleCharRatio` | 不可见字符占比，例如零宽字符和格式控制字符。 |
| `charset.ConfusableCount` | 命中内置同形异义字符集合的字符数量。 |
| `charset.UnicodeScriptCounts` | 启用脚本识别后，各 Unicode 脚本的字符计数。 |
| `charset.FormatMetrics` | 可选的格式感知文本指标，适用于 JSON、XML 和表单，例如 token 数、重复 key 等。 |
| `charset.SuspiciousFlags` | 可疑标记，例如非法 UTF-8、零宽字符、混合脚本。 |
| `content_type` | 规范化后的请求 `Content-Type`。 |
| `content_length` | 请求里声明的 body 长度。 |
| `sampled` | 是否只分析了请求体的一部分样本。 |
| `sample_bytes` | 实际参与 body 分析的样本字节数。 |
| `body_truncated` | 是否因为 `MaxReadBytes` 到上限而截断。 |
| `fingerprint_duration_ns` | 生成请求指纹花费的时间。 |
| `body_capture_duration_ns` | 读取和恢复请求体花费的时间。 |
| `entropy_duration_ns` | 计算熵值花费的时间。 |
| `complexity_duration_ns` | 计算复杂度指标花费的时间。 |
| `charset_duration_ns` | 计算字符集指标花费的时间。 |
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

如果你想看更完整的内部结构和后续演进方向，可以继续阅读 [Architecture_zh.md](Architecture_zh.md)。

## 测试

```bash
go test ./...
```

当前测试覆盖了中间件注入、请求体重放、配置归一化、分析结果以及 warning 降级路径。

## 🐺 License

本项目基于 [MIT License](LICENSE) 开源, 允许商业使用、修改、分发, 无需保留原作者版权声明。
