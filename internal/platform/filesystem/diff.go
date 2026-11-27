package filesystem

import (
	"fmt"
	"strings"
)

type diffOpKind int

const (
	opEqual diffOpKind = iota
	opDelete
	opInsert
)

type diffLine struct {
	kind diffOpKind
	text string
	oldN int
	newN int
}

// GenerateUnifiedDiff 为两份文本生成标准 Unified Diff（带 3 行上下文），供人工审批界面预览。
func GenerateUnifiedDiff(relPath, oldContent, newContent string) string {
	if oldContent == newContent {
		return ""
	}
	oldLines := splitLines(oldContent)
	newLines := splitLines(newContent)

	ops := computeLineDiff(oldLines, newLines)
	if len(ops) == 0 {
		return ""
	}

	const contextLines = 3
	type hunkRange struct {
		start int
		end   int
	}
	var ranges []hunkRange
	for i, op := range ops {
		if op.kind == opEqual {
			continue
		}
		s := max(0, i-contextLines)
		e := min(len(ops), i+contextLines+1)
		if len(ranges) > 0 && s <= ranges[len(ranges)-1].end {
			ranges[len(ranges)-1].end = max(ranges[len(ranges)-1].end, e)
		} else {
			ranges = append(ranges, hunkRange{start: s, end: e})
		}
	}
	if len(ranges) == 0 {
		return ""
	}

	var b strings.Builder
	fmt.Fprintf(&b, "--- a/%s\n", relPath)
	fmt.Fprintf(&b, "+++ b/%s\n", relPath)

	for _, r := range ranges {
		slice := ops[r.start:r.end]
		oldStart, oldCount := 0, 0
		newStart, newCount := 0, 0
		for _, op := range slice {
			switch op.kind {
			case opEqual:
				if oldStart == 0 {
					oldStart = op.oldN
				}
				if newStart == 0 {
					newStart = op.newN
				}
				oldCount++
				newCount++
			case opDelete:
				if oldStart == 0 {
					oldStart = op.oldN
				}
				oldCount++
			case opInsert:
				if newStart == 0 {
					newStart = op.newN
				}
				newCount++
			}
		}
		if oldStart == 0 && oldCount == 0 {
			oldStart = 0
		}
		if newStart == 0 && newCount == 0 {
			newStart = 0
		}
		fmt.Fprintf(&b, "@@ -%d,%d +%d,%d @@\n", oldStart, oldCount, newStart, newCount)
		for _, op := range slice {
			switch op.kind {
			case opEqual:
				b.WriteString(" " + op.text + "\n")
			case opDelete:
				b.WriteString("-" + op.text + "\n")
			case opInsert:
				b.WriteString("+" + op.text + "\n")
			}
		}
	}
	return b.String()
}

func splitLines(s string) []string {
	if s == "" {
		return nil
	}
	norm := strings.ReplaceAll(s, "\r\n", "\n")
	lines := strings.Split(norm, "\n")
	if len(lines) > 0 && lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}
	return lines
}

// computeLineDiff 对中小文件使用精确 LCS，对超大差异回退到首尾共同前后缀以防 O(N*M) 内存膨胀。
func computeLineDiff(a, b []string) []diffLine {
	// 去除共同前缀与后缀，大幅减小 DP 矩阵规模
	prefix := 0
	for prefix < len(a) && prefix < len(b) && a[prefix] == b[prefix] {
		prefix++
	}
	suffix := 0
	for suffix < len(a)-prefix && suffix < len(b)-prefix && a[len(a)-1-suffix] == b[len(b)-1-suffix] {
		suffix++
	}

	var ops []diffLine
	for i := 0; i < prefix; i++ {
		ops = append(ops, diffLine{kind: opEqual, text: a[i], oldN: i + 1, newN: i + 1})
	}

	midA := a[prefix : len(a)-suffix]
	midB := b[prefix : len(b)-suffix]

	if len(midA)*len(midB) > 250000 {
		// 超大变更块直接按整块删+增呈现，保证 O(N) 性能
		for i, line := range midA {
			ops = append(ops, diffLine{kind: opDelete, text: line, oldN: prefix + i + 1})
		}
		for j, line := range midB {
			ops = append(ops, diffLine{kind: opInsert, text: line, newN: prefix + j + 1})
		}
	} else {
		m, n := len(midA), len(midB)
		dp := make([][]int, m+1)
		for i := range dp {
			dp[i] = make([]int, n+1)
		}
		for i := m - 1; i >= 0; i-- {
			for j := n - 1; j >= 0; j-- {
				if midA[i] == midB[j] {
					dp[i][j] = dp[i+1][j+1] + 1
				} else if dp[i+1][j] >= dp[i][j+1] {
					dp[i][j] = dp[i+1][j]
				} else {
					dp[i][j] = dp[i][j+1]
				}
			}
		}
		i, j := 0, 0
		for i < m && j < n {
			if midA[i] == midB[j] {
				ops = append(ops, diffLine{kind: opEqual, text: midA[i], oldN: prefix + i + 1, newN: prefix + j + 1})
				i++
				j++
			} else if dp[i+1][j] >= dp[i][j+1] {
				ops = append(ops, diffLine{kind: opDelete, text: midA[i], oldN: prefix + i + 1})
				i++
			} else {
				ops = append(ops, diffLine{kind: opInsert, text: midB[j], newN: prefix + j + 1})
				j++
			}
		}
		for ; i < m; i++ {
			ops = append(ops, diffLine{kind: opDelete, text: midA[i], oldN: prefix + i + 1})
		}
		for ; j < n; j++ {
			ops = append(ops, diffLine{kind: opInsert, text: midB[j], newN: prefix + j + 1})
		}
	}

	for k := 0; k < suffix; k++ {
		ai := len(a) - suffix + k
		bi := len(b) - suffix + k
		ops = append(ops, diffLine{kind: opEqual, text: a[ai], oldN: ai + 1, newN: bi + 1})
	}
	return ops
}
