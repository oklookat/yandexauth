package yandexauth

import (
	"fmt"
	"strconv"
	"time"
)

func wrapErrStr(err string) error {
	return fmt.Errorf(_errPrefix+"%s", err)
}

func generateDeviceID() string {
	return strconv.FormatInt(time.Now().UnixMilli(), 10)
}
