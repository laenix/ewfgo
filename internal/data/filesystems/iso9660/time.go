package iso9660

// IsoTime is a timestamp recorded by ISO 9660, in Unix nanoseconds. The zero
// value is "not recorded".
type IsoTime struct {
	unixNanos int64
}

// UnixNanos returns the timestamp in nanoseconds since the Unix epoch.
func (t IsoTime) UnixNanos() int64 { return t.unixNanos }

func newIsoTime(unixNanos int64) IsoTime { return IsoTime{unixNanos: unixNanos} }

// isoTimeFromRecording decodes a seven-byte directory-record timestamp,
// applying its 15-minute zone offset.
func isoTimeFromRecording(bytes []byte) (IsoTime, bool) {
	if len(bytes) < 7 {
		return IsoTime{}, false
	}
	allZero := true
	for _, b := range bytes[:6] {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		return IsoTime{}, false
	}
	year := int64(1900) + int64(bytes[0])
	local, ok := unixSecondsFromCivil(year, uint32(bytes[1]), uint32(bytes[2]),
		uint32(bytes[3]), uint32(bytes[4]), uint32(bytes[5]))
	if !ok {
		return IsoTime{}, false
	}
	offsetMinutes := int64(int8(bytes[6])) * 15
	return newIsoTime((local - offsetMinutes*60) * 1_000_000_000), true
}

// isoTimeFromASCII decodes a seventeen-byte descriptor timestamp:
// YYYYMMDDHHMMSScc followed by the zone byte.
func isoTimeFromASCII(bytes []byte) (IsoTime, bool) {
	if len(bytes) < 17 {
		return IsoTime{}, false
	}
	digits := bytes[:16]
	allZero := true
	for _, b := range digits {
		if b != '0' && b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		return IsoTime{}, false
	}
	for _, b := range digits {
		if b < '0' || b > '9' {
			return IsoTime{}, false
		}
	}
	number := func(from, to int) int64 {
		var value int64
		for _, b := range digits[from:to] {
			value = value*10 + int64(b-'0')
		}
		return value
	}
	year := number(0, 4)
	month := uint32(number(4, 6))
	day := uint32(number(6, 8))
	hour := uint32(number(8, 10))
	minute := uint32(number(10, 12))
	second := uint32(number(12, 14))
	hundredths := number(14, 16)
	local, ok := unixSecondsFromCivil(year, month, day, hour, minute, second)
	if !ok {
		return IsoTime{}, false
	}
	offsetMinutes := int64(int8(bytes[16])) * 15
	return newIsoTime((local-offsetMinutes*60)*1_000_000_000 + hundredths*10_000_000), true
}

func unixSecondsFromCivil(year int64, month, day, hour, minute, second uint32) (int64, bool) {
	if month < 1 || month > 12 || day < 1 || hour > 23 || minute > 59 || second > 59 {
		return 0, false
	}
	if day > daysInMonth(year, month) {
		return 0, false
	}
	days := daysFromCivil(year, month, day)
	return days*86400 + int64(hour)*3600 + int64(minute)*60 + int64(second), true
}

func daysInMonth(year int64, month uint32) uint32 {
	switch month {
	case 1, 3, 5, 7, 8, 10, 12:
		return 31
	case 4, 6, 9, 11:
		return 30
	case 2:
		if year%4 == 0 && (year%100 != 0 || year%400 == 0) {
			return 29
		}
		return 28
	default:
		return 0
	}
}

// daysFromCivil converts a proleptic Gregorian date to days since 1970-01-01,
// using Howard Hinnant's civil-from-days algorithm.
func daysFromCivil(year int64, month, day uint32) int64 {
	y := year
	m := int64(month)
	if m <= 2 {
		y--
		m += 12
	}
	doy := (153*(m-3)+2)/5 + int64(day) - 1
	era := y / 400
	if y < 0 && y%400 != 0 {
		era--
	}
	yoe := y - era*400
	doe := yoe*365 + yoe/4 - yoe/100 + doy
	return era*146097 + doe - 719468
}
