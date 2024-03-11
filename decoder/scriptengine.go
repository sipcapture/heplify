package decoder

import (
	"bufio"
	"bytes"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"strings"
	"unicode"

	"github.com/sipcapture/heplify/config"
)

// ScriptEngine interface
type ScriptEngine interface {
	Run(pkt *Packet) error
	Close()
}

// NewScriptEngine returns a script interface
func NewScriptEngine() (ScriptEngine, error) {
	return NewLuaEngine()
}

func scanCode() (string, *bytes.Buffer, error) {
	buf := bytes.NewBuffer(nil)

	file := config.Cfg.ScriptFile

	if file != "" {
		f, err := os.Open(file)
		if err != nil {
			return file, nil, err
		}
		_, err = io.Copy(buf, f)
		if err != nil {
			return file, nil, err
		}
		err = f.Close()
		if err != nil {
			return file, nil, err
		}
	}

	return file, buf, nil
}

func extractFunc(r io.Reader) []string {
	var funcs []string
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := cutSpace(scanner.Text())
		if strings.HasPrefix(line, "--") {
			continue
		}
		if strings.HasPrefix(line, "function") {
			if b, e := strings.Index(line, "("), strings.Index(line, ")"); b > -1 && e > -1 && b < e {
				funcs = append(funcs, line[len("function"):e+1])
			}
		}
	}
	return funcs
}

func cutSpace(str string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsSpace(r) {
			return -1
		}
		return r
	}, str)
}

// HashString returns md5, sha1 or sha256 sum
func HashString(algo, s string) string {
	switch algo {
	case "md5":
		return fmt.Sprintf("%x", md5.Sum([]byte(s)))
	case "sha1":
		return fmt.Sprintf("%x", sha1.Sum([]byte(s)))
	case "sha256":
		return fmt.Sprintf("%x", sha256.Sum256([]byte(s)))
	}
	return s
}

// HashTable is a simple kv store
func HashTable(op, key, val string) string {
	switch op {
	case "get":
		if res := scriptCache.Get(nil, stb(key)); res != nil {
			return string(res)
		}
	case "set":
		scriptCache.Set(stb(key), stb(val))
	case "del":
		scriptCache.Del(stb(key))
	}
	return ""
}
