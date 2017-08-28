package outputs

import (
	"github.com/negbie/heplify/logp"
)

type FileOutputer struct {
}

func (fo *FileOutputer) Output(msg []byte) {
	logp.Info("fileOutputer %s", msg)
}

func NewFileOutputer() (*FileOutputer, error) {
	fo := &FileOutputer{}
	return fo, nil
}
