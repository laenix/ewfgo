package ooxml

// parseTime interprets the W3CDTF text the reference reader accepts: an
// RFC 3339 instant with a four-digit year, an optional fractional second of up
// to nine digits, and a "Z", "z", "+HH:MM", "-HH:MM", "+HHMM" or "-HHMM"
// offset.  The text is always preserved; UnixSeconds is nil when the text did
// not parse.
func parseTime(text string) *Time {
	stored := &Time{Text: text}
	seconds, nanos, ok := parseRFC3339Nanos(text)
	if !ok {
		return stored
	}
	stored.UnixSeconds = &seconds
	stored.Nanos = nanos
	return stored
}

func parseRFC3339Nanos(text string) (int64, int32, bool) {
	bytes := []byte(text)
	if len(bytes) < 20 {
		return 0, 0, false
	}
	if bytes[4] != '-' || bytes[7] != '-' || bytes[10] != 'T' ||
		bytes[13] != ':' || bytes[16] != ':' {
		return 0, 0, false
	}
	year, ok := digitsAt(bytes, 0, 4)
	if !ok {
		return 0, 0, false
	}
	month, ok := digitsAt(bytes, 5, 7)
	if !ok {
		return 0, 0, false
	}
	day, ok := digitsAt(bytes, 8, 10)
	if !ok {
		return 0, 0, false
	}
	hour, ok := digitsAt(bytes, 11, 13)
	if !ok {
		return 0, 0, false
	}
	minute, ok := digitsAt(bytes, 14, 16)
	if !ok {
		return 0, 0, false
	}
	second, ok := digitsAt(bytes, 17, 19)
	if !ok {
		return 0, 0, false
	}
	if month < 1 || month > 12 || day == 0 || day > int64(daysInMonth(year, int(month))) ||
		hour > 23 || minute > 59 || second > 59 {
		return 0, 0, false
	}

	index := 19
	var nanos int64
	if index < len(bytes) && bytes[index] == '.' {
		index++
		start := index
		for index < len(bytes) && bytes[index] >= '0' && bytes[index] <= '9' && index-start < 9 {
			index++
		}
		if index == start {
			return 0, 0, false
		}
		width := int64(index - start)
		fraction, ok := digitsAt(bytes, start, index)
		if !ok {
			return 0, 0, false
		}
		nanos = fraction
		for power := int64(9) - width; power > 0; power-- {
			nanos *= 10
		}
	}

	var offsetSeconds int64
	switch {
	case index < len(bytes) && (bytes[index] == 'Z' || bytes[index] == 'z') && index+1 == len(bytes):
		offsetSeconds = 0
	case index < len(bytes) && (bytes[index] == '+' || bytes[index] == '-'):
		sign := int64(1)
		if bytes[index] == '-' {
			sign = -1
		}
		rest := bytes[index+1:]
		var hours, minutes int64
		var okHours, okMinutes bool
		switch {
		case len(rest) == 5 && rest[2] == ':':
			hours, okHours = digitsAt(bytes, index+1, index+3)
			minutes, okMinutes = digitsAt(bytes, index+4, index+6)
		case len(rest) == 4:
			hours, okHours = digitsAt(bytes, index+1, index+3)
			minutes, okMinutes = digitsAt(bytes, index+3, index+5)
		default:
			return 0, 0, false
		}
		if !okHours || !okMinutes || hours > 23 || minutes > 59 {
			return 0, 0, false
		}
		offsetSeconds = sign * (hours*3600 + minutes*60)
	default:
		return 0, 0, false
	}

	days := daysFromCivil(year, month, day)
	seconds := days*86_400 + hour*3600 + minute*60 + second - offsetSeconds
	return seconds, int32(nanos), true
}

// digitsAt parses the ASCII decimal digits in [from, to).  It refuses a
// non-digit and a range outside the slice.
func digitsAt(bytes []byte, from, to int) (int64, bool) {
	if from < 0 || to > len(bytes) || from > to {
		return 0, false
	}
	var value int64
	for _, byte := range bytes[from:to] {
		if byte < '0' || byte > '9' {
			return 0, false
		}
		value = value*10 + int64(byte-'0')
	}
	return value, true
}

func daysInMonth(year int64, month int) int {
	switch month {
	case 1, 3, 5, 7, 8, 10, 12:
		return 31
	case 4, 6, 9, 11:
		return 30
	case 2:
		if isLeapYear(year) {
			return 29
		}
		return 28
	default:
		return 0
	}
}

func isLeapYear(year int64) bool {
	return (year%4 == 0 && year%100 != 0) || year%400 == 0
}

// daysFromCivil returns days since 1970-01-01 for a proleptic Gregorian date
// (Howard Hinnant's days_from_civil), matching the reference helper.
func daysFromCivil(year, month, day int64) int64 {
	y := year
	m := month
	if m <= 2 {
		y--
	}
	var era int64
	if y >= 0 {
		era = y / 400
	} else {
		era = (y - 399) / 400
	}
	yearOfEra := y - era*400
	monthPrime := m
	if m > 2 {
		monthPrime = m - 3
	} else {
		monthPrime = m + 9
	}
	dayOfYear := (153*monthPrime+2)/5 + day - 1
	dayOfEra := yearOfEra*365 + yearOfEra/4 - yearOfEra/100 + dayOfYear
	return era*146_097 + dayOfEra - 719_468
}
