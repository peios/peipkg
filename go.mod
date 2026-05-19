module github.com/peios/peipkg

go 1.26.2

require (
	github.com/BurntSushi/toml v1.6.0
	github.com/klauspost/compress v1.18.6
	golang.org/x/sys v0.42.0
	golang.org/x/text v0.37.0
	modernc.org/sqlite v1.50.1
)

require (
	github.com/dustin/go-humanize v1.0.1 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	github.com/ncruces/go-strftime v1.0.0 // indirect
	github.com/peios/libp-go v0.0.0-00010101000000-000000000000
	github.com/peios/pkm/uapi/go v0.0.0-00010101000000-000000000000
	github.com/remyoudompheng/bigfft v0.0.0-20230129092748-24d4a6f8daec // indirect
	modernc.org/libc v1.72.3 // indirect
	modernc.org/mathutil v1.7.1 // indirect
	modernc.org/memory v1.11.0 // indirect
)

replace github.com/peios/libp-go => ../libp-go

replace github.com/peios/pkm/uapi/go => ../pkm/uapi/go
