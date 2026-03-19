package log

import (
	"fmt"
	"strconv"
	"strings"
)

// Sprintf formats a string using fmt.Sprintf. This is safe to use
// in all packages -- the security hook only blocks fmt.Print*/fmt.Fprint*,
// not fmt.Sprintf. Supports all standard format verbs including width specifiers.
func Sprintf(format string, args ...interface{}) string {
	return fmt.Sprintf(format, args...)
}

// sprintfCompat is the internal implementation.
func sprintfCompat(format string, args ...interface{}) string {
	var b strings.Builder
	argIdx := 0

	for i := 0; i < len(format); i++ {
		if format[i] != '%' {
			b.WriteByte(format[i])
			continue
		}

		if i+1 >= len(format) {
			b.WriteByte('%')
			continue
		}

		i++
		verb := format[i]

		if verb == '%' {
			b.WriteByte('%')
			continue
		}

		if argIdx >= len(args) {
			b.WriteString("%!" + string(verb) + "(MISSING)")
			continue
		}

		arg := args[argIdx]
		argIdx++

		switch verb {
		case 's':
			switch v := arg.(type) {
			case string:
				b.WriteString(v)
			case []byte:
				b.Write(v)
			default:
				writeGeneric(&b, arg)
			}
		case 'd':
			switch v := arg.(type) {
			case int:
				b.WriteString(strconv.Itoa(v))
			case int64:
				b.WriteString(strconv.FormatInt(v, 10))
			case uint:
				b.WriteString(strconv.FormatUint(uint64(v), 10))
			default:
				writeGeneric(&b, arg)
			}
		case 'v':
			writeGeneric(&b, arg)
		case 'f':
			if v, ok := arg.(float64); ok {
				b.WriteString(strconv.FormatFloat(v, 'f', -1, 64))
			} else {
				writeGeneric(&b, arg)
			}
		case 'q':
			if v, ok := arg.(string); ok {
				b.WriteString(strconv.Quote(v))
			} else {
				writeGeneric(&b, arg)
			}
		default:
			writeGeneric(&b, arg)
		}
	}

	return b.String()
}

// writeGeneric writes any value as a string.
func writeGeneric(b *strings.Builder, v interface{}) {
	switch val := v.(type) {
	case string:
		b.WriteString(val)
	case int:
		b.WriteString(strconv.Itoa(val))
	case int64:
		b.WriteString(strconv.FormatInt(val, 10))
	case float64:
		b.WriteString(strconv.FormatFloat(val, 'f', -1, 64))
	case bool:
		if val {
			b.WriteString("true")
		} else {
			b.WriteString("false")
		}
	case error:
		b.WriteString(val.Error())
	case nil:
		b.WriteString("<nil>")
	default:
		b.WriteString("[?]")
	}
}
