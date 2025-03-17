package filesystem

import (
	"path/filepath"
	"strings"
)

// isTextFile 判断一个文件是否为文本文件（基于文件扩展名）
func isTextFile(filename string) bool {
	// 常见文本文件扩展名
	textExtensions := map[string]bool{
		".txt":  true,
		".log":  true,
		".csv":  true,
		".xml":  true,
		".json": true,
		".html": true,
		".htm":  true,
		".css":  true,
		".js":   true,
		".md":   true,
		".ini":  true,
		".cfg":  true,
		".conf": true,
		".py":   true,
		".go":   true,
		".java": true,
		".c":    true,
		".cpp":  true,
		".h":    true,
		".sh":   true,
		".bat":  true,
	}

	ext := strings.ToLower(filepath.Ext(filename))
	return textExtensions[ext]
}

// isBinaryFile 判断一个文件是否为二进制文件（基于文件扩展名）
func isBinaryFile(filename string) bool {
	// 常见二进制文件扩展名
	binaryExtensions := map[string]bool{
		".exe":   true,
		".dll":   true,
		".so":    true,
		".dylib": true,
		".bin":   true,
		".img":   true,
		".iso":   true,
		".zip":   true,
		".rar":   true,
		".7z":    true,
		".tar":   true,
		".gz":    true,
		".bz2":   true,
		".xz":    true,
		".pdf":   true,
		".doc":   true,
		".docx":  true,
		".xls":   true,
		".xlsx":  true,
		".ppt":   true,
		".pptx":  true,
		".jpg":   true,
		".jpeg":  true,
		".png":   true,
		".gif":   true,
		".bmp":   true,
		".mp3":   true,
		".mp4":   true,
		".avi":   true,
		".mkv":   true,
		".mov":   true,
		".wav":   true,
		".flac":  true,
	}

	ext := strings.ToLower(filepath.Ext(filename))
	return binaryExtensions[ext]
}
