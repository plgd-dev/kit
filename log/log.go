package log

import (
	"go.uber.org/zap"
)

var logger zap.Logger
var log *zap.SugaredLogger

func init() {
	config := zap.NewDevelopmentConfig()
	logger, err := config.Build()
	if err != nil {
		panic("Unable to create logger")
	}
	log = logger.Sugar()
}

// Debug uses fmt.Sprint to construct and log a message.
func Debug(args ...interface{}) {
	log.Debug(args...)
}

// Info uses fmt.Sprint to construct and log a message.
func Info(args ...interface{}) {
	log.Info(args...)
}

// Warn uses fmt.Sprint to construct and log a message.
func Warn(args ...interface{}) {
	log.Warn(args...)
}

// Error uses fmt.Sprint to construct and log a message.
func Error(args ...interface{}) {
	log.Error(args...)
}

// DPanic uses fmt.Sprint to construct and log a message. In development, the
// logger then panics. (See DPanicLevel for details.)
func DPanic(args ...interface{}) {
	log.DPanic(args...)
}

// Panic uses fmt.Sprint to construct and log a message, then panics.
func Panic(args ...interface{}) {
	log.Panic(args...)
}

// Fatal uses fmt.Sprint to construct and log a message, then calls os.Exit.
func Fatal(args ...interface{}) {
	log.Fatal(args...)
}

// Debugf uses fmt.Sprintf to log a templated message.
func Debugf(template string, args ...interface{}) {
	log.Debugf(template, args...)
}

// Infof uses fmt.Sprintf to log a templated message.
func Infof(template string, args ...interface{}) {
	log.Infof(template, args...)
}

// Warnf uses fmt.Sprintf to log a templated message.
func Warnf(template string, args ...interface{}) {
	log.Warnf(template, args...)
}

// Errorf uses fmt.Sprintf to log a templated message.
func Errorf(template string, args ...interface{}) {
	log.Errorf(template, args...)
}

// DPanicf uses fmt.Sprintf to log a templated message. In development, the
// logger then panics. (See DPanicLevel for details.)
func DPanicf(template string, args ...interface{}) {
	log.DPanicf(template, args...)
}

// Panicf uses fmt.Sprintf to log a templated message, then panics.
func Panicf(template string, args ...interface{}) {
	log.Panicf(template, args...)
}

// Fatalf uses fmt.Sprintf to log a templated message, then calls os.Exit.
func Fatalf(template string, args ...interface{}) {
	log.Fatalf(template, args...)
}
