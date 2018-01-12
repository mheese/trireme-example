package versions

import (
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// Fields returns a ready to dump zap.Fields containing all the versions used.
func Fields() []zapcore.Field {
	return []zapcore.Field{
		zap.String("Version", VERSION),
		zap.String("Revision", REVISION),
	}
}
