package publish

import (
	"github.com/negbie/logp"
)

type FileOutputer struct {
}

func (fo *FileOutputer) Output(msg []byte) {
	h, err := DecodeHEP(msg)
	if err == nil {
		logp.Info("%s\n", h.String())
	} else {
		logp.Warn("%s", err)
	}
}

func NewFileOutputer() (*FileOutputer, error) {
	fo := &FileOutputer{}
	return fo, nil
}
