package decoder

import (
	"bufio"
	"bytes"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
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

func scanCode() ([]string, *bytes.Buffer, error) {
	var files []string
	buf := bytes.NewBuffer(nil)

	path := config.Cfg.ScriptFolder

	if path != "" {
		dir, err := ioutil.ReadDir(path)
		if err != nil {
			return nil, nil, err
		}

		for _, file := range dir {
			if !file.IsDir() {
				n := file.Name()
				p := filepath.Join(path, n)
				if strings.HasSuffix(n, ".lua") {
					f, err := os.Open(p)
					if err != nil {
						return nil, nil, err
					}
					_, err = io.Copy(buf, f)
					if err != nil {
						return nil, nil, err
					}
					err = f.Close()
					if err != nil {
						return nil, nil, err
					}
				} else if strings.HasSuffix(n, ".expr") {
					s, err := ioutil.ReadFile(p)
					if err != nil {
						return nil, nil, err
					}
					if len(s) > 4 {
						files = append(files, string(s))
					}
				}
			}
		}
	}

	return files, buf, nil
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
