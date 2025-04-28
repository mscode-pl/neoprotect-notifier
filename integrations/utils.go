package integrations

import (
	"fmt"
	"time"
)

func formatBPS(bps int64) string {
	if bps < 1000 {
		return fmt.Sprintf("%d bps", bps)
	} else if bps < 1000000 {
		return fmt.Sprintf("%.2f Kbps", float64(bps)/1000)
	} else if bps < 1000000000 {
		return fmt.Sprintf("%.2f Mbps", float64(bps)/1000000)
	} else if bps < 1000000000000 {
		return fmt.Sprintf("%.2f Gbps", float64(bps)/1000000000)
	} else {
		return fmt.Sprintf("%.2f Tbps", float64(bps)/1000000000000)
	}
}

func formatPPS(pps int64) string {
	if pps < 1000 {
		return fmt.Sprintf("%d pps", pps)
	} else if pps < 1000000 {
		return fmt.Sprintf("%.2f Kpps", float64(pps)/1000)
	} else if pps < 1000000000 {
		return fmt.Sprintf("%.2f Mpps", float64(pps)/1000000)
	} else {
		return fmt.Sprintf("%.2f Gpps", float64(pps)/1000000000)
	}
}

func calculatePercentageChange(old, new int64) int {
	if old == 0 {
		return 100
	}
	return int((float64(new-old) / float64(old)) * 100)
}

func formatDuration(d time.Duration) string {
	if d < time.Minute {
		return fmt.Sprintf("%d seconds", int(d.Seconds()))
	} else if d < time.Hour {
		minutes := int(d.Minutes())
		seconds := int(d.Seconds()) % 60
		return fmt.Sprintf("%d minutes, %d seconds", minutes, seconds)
	} else if d < 24*time.Hour {
		hours := int(d.Hours())
		minutes := int(d.Minutes()) % 60
		return fmt.Sprintf("%d hours, %d minutes", hours, minutes)
	} else {
		days := int(d.Hours()) / 24
		hours := int(d.Hours()) % 24
		return fmt.Sprintf("%d days, %d hours", days, hours)
	}
}
