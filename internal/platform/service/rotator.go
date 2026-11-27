package service

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
)

// RotatingLogWriter 实现线程安全的按单文件大小自动轮转的守护进程日志写入器。
type RotatingLogWriter struct {
	path       string
	maxBytes   int64
	maxBackups int

	mu   sync.Mutex
	file *os.File
	size int64
}

// NewRotatingLogWriter 创建或追加打开带轮转能力的守护进程日志文件。
func NewRotatingLogWriter(path string, maxSizeMB, maxBackups int) (*RotatingLogWriter, error) {
	if maxSizeMB <= 0 {
		maxSizeMB = 10
	}
	if maxBackups <= 0 {
		maxBackups = 5
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("创建守护日志目录失败: %w", err)
	}
	w := &RotatingLogWriter{
		path:       path,
		maxBytes:   int64(maxSizeMB) * 1024 * 1024,
		maxBackups: maxBackups,
	}
	if err := w.openLocked(); err != nil {
		return nil, err
	}
	return w, nil
}

func (w *RotatingLogWriter) openLocked() error {
	f, err := os.OpenFile(w.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("打开守护日志文件失败: %w", err)
	}
	var curSize int64
	if st, err := f.Stat(); err == nil {
		curSize = st.Size()
	}
	w.file = f
	w.size = curSize
	return nil
}

// Write 将日志字节写入文件，并在超出上限时触发轮转。
func (w *RotatingLogWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.file == nil {
		if err := w.openLocked(); err != nil {
			return 0, err
		}
	}
	if w.size+int64(len(p)) > w.maxBytes && w.size > 0 {
		if err := w.rotateLocked(); err != nil {
			return 0, err
		}
	}
	n, err := w.file.Write(p)
	w.size += int64(n)
	return n, err
}

func (w *RotatingLogWriter) rotateLocked() error {
	if w.file != nil {
		_ = w.file.Close()
		w.file = nil
	}
	for i := w.maxBackups; i >= 1; i-- {
		src := w.path
		if i > 1 {
			src = fmt.Sprintf("%s.%d", w.path, i-1)
		}
		dst := fmt.Sprintf("%s.%d", w.path, i)
		if _, err := os.Stat(src); err == nil {
			_ = os.Remove(dst)
			_ = os.Rename(src, dst)
		}
	}
	return w.openLocked()
}

// Close 关闭底层日志文件句柄。
func (w *RotatingLogWriter) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.file == nil {
		return nil
	}
	err := w.file.Close()
	w.file = nil
	return err
}

// TailFile 读取指定文本文件的最后 N 行，供 `nodebridge service logs` 使用。
func TailFile(path string, maxLines int) ([]string, error) {
	if maxLines <= 0 {
		maxLines = 100
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	// 大日志文件只从尾部窗口读取（默认最多回看 2MB），避免内存暴涨
	const maxReadWindow = 2 * 1024 * 1024
	if st, err := f.Stat(); err == nil && st.Size() > maxReadWindow {
		if _, err := f.Seek(st.Size()-maxReadWindow, io.SeekStart); err == nil {
			// 丢弃可能被截断的第一行残片
			br := bufio.NewReader(f)
			_, _ = br.ReadString('\n')
			return scanTailLines(br, maxLines)
		}
	}
	return scanTailLines(f, maxLines)
}

func scanTailLines(r io.Reader, maxLines int) ([]string, error) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 16*1024), 512*1024)
	ring := make([]string, 0, maxLines)
	for sc.Scan() {
		if len(ring) < maxLines {
			ring = append(ring, sc.Text())
		} else {
			copy(ring, ring[1:])
			ring[maxLines-1] = sc.Text()
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return ring, nil
}
