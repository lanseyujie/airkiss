package airkiss

import (
	"math"
)

type State int

const (
	CheckingGuideCode State = iota
	CheckingMagicCode
	CheckingPrefixCode
	CheckingSeqData
	Done
)

const (
	windowSizeDefault = 4
	windowSizeSeqData = 6
)

type AirKiss struct {
	SSID       string
	SSIDCRC8   int
	Password   string
	RandomByte byte

	baseLength  int
	totalLength int // LENGTH(PASSWORD)+LENGTH(RANDOM_BYTE)+LENGTH(SSID)
	pwdLength   int

	state        State
	done         chan struct{}
	seqNo        uint16
	ignoreSeqCnt uint16
	window       []int

	seqDataCnt int
	seqData    map[int][windowSizeSeqData]byte // index => data
}

func New() *AirKiss {
	return &AirKiss{
		window:     make([]int, 0, 6),
		baseLength: -1,
		done:       make(chan struct{}),
	}
}

func crc8(buf []byte) (crc byte) {
	for i := 0; i < len(buf); i++ {
		crc ^= buf[i]
		for j := 8; j > 0; j-- {
			if crc&0x01 > 0 {
				crc = (crc >> 1) ^ 0x8c
			} else {
				crc = crc >> 1
			}
		}
	}

	return
}

// 判断窗口中的数字是否连续递增
func isIncreasing(window []int) bool {
	for i := 1; i < len(window); i++ {
		if window[i-1]+1 != window[i] {
			return false
		}
	}

	return true
}

func (ak *AirKiss) Put(frameLen int, seqNo uint16) {
	// frameLen max 512 = 0x0200 = 0b1000000000 = 9bits
	prev := ak.seqNo
	ak.seqNo = seqNo
	if (prev != 0 && prev+1 != ak.seqNo) || ak.ignoreSeqCnt > 0 {
		// seqNo 与之前序列断开，则重置，然后从此重新开始
		ak.window = ak.window[:0]
		if ak.ignoreSeqCnt > 0 {
			ak.ignoreSeqCnt--
			return
		}
	}

	var windowSize int
	switch ak.state {
	case CheckingSeqData:
		windowSize = windowSizeSeqData
	default:
		windowSize = windowSizeDefault
	}

	// 向序列增加元素
	if ak.baseLength >= 0 {
		frameLen -= ak.baseLength
	}

	if len(ak.window) < windowSize {
		ak.window = append(ak.window, frameLen)
		if len(ak.window) < windowSize {
			return
		}
	} else {
		ak.window[len(ak.window)-1] = frameLen
	}

	ak.parseFrame()

	// 向前移位，方便下一次数据直接拼接到末尾，形成一个新序列
	for i := 1; i < len(ak.window); i++ {
		ak.window[i-1] = ak.window[i]
	}
}

func (ak *AirKiss) Done() <-chan struct{} {
	return ak.done
}

func (ak *AirKiss) parseFrame() {
	switch ak.state {
	case CheckingMagicCode:
		totalLength, ssidCrc8, done := ak.getLengthAndCRC8(0)
		if !done {
			return
		}

		ak.totalLength, ak.SSIDCRC8 = totalLength, ssidCrc8

		ak.setState(CheckingPrefixCode, 20)
	case CheckingPrefixCode:
		pwdLength, pwdLengthCrc8, done := ak.getLengthAndCRC8(4)
		if !done || crc8([]byte{byte(pwdLength)}) != byte(pwdLengthCrc8) {
			return
		}

		{
			ak.pwdLength = pwdLength
			ak.seqDataCnt = int(math.Ceil(float64(ak.totalLength) / 4.00))
			ak.seqData = make(map[int][windowSizeSeqData]byte, ak.seqDataCnt)
		}

		ak.setState(CheckingSeqData, 20)
	case CheckingSeqData:
		if done := ak.getSeqAndData(); !done {
			return
		}

		{
			data := make([]byte, 0, ak.seqDataCnt*4)
			for i := 0; i < ak.seqDataCnt; i++ {
				dat := ak.seqData[i]
				data = append(data, dat[2:]...)
			}

			ak.Password = string(data[:ak.pwdLength])
			ak.RandomByte = data[ak.pwdLength]
			ak.SSID = string(data[ak.pwdLength+1:])
		}

		ak.setState(Done, 0)
		close(ak.done)
	default:
		if ak.baseLength < 0 {
			baseLength, ok := ak.findOrderNumbers()
			if !ok {
				return
			}

			ak.baseLength = baseLength
			ak.setState(CheckingMagicCode, 10)
		}
	}
}

func (ak *AirKiss) setState(state State, ignoreCnt uint16) {
	ak.ignoreSeqCnt = ignoreCnt
	ak.state = state
	ak.window = ak.window[:0]
}

func (ak *AirKiss) findOrderNumbers() (baseLen int, ok bool) {
	if isIncreasing(ak.window) {
		return ak.window[0] - 1, true
	}

	return
}

func (ak *AirKiss) getLengthAndCRC8(base int) (length, crc8 int, ok bool) {
	for i, v := range ak.window {
		if v&0x01f0 != (i+base)<<4 {
			return
		}
	}

	length = ((ak.window[0] & 0x000F) << 4) + (ak.window[1] & 0x000F)
	crc8 = ((ak.window[2] & 0x000F) << 4) + (ak.window[3] & 0x000F)
	ok = true

	ak.window = ak.window[:0]

	return
}

func (ak *AirKiss) getSeqAndData() (ok bool) {
	tempBuffer := [windowSizeSeqData]byte{}
	for i, v := range ak.window {
		switch i {
		case 0:
			// FLAG 检查
			// [bit8] 0 [bit7] 1
			// 0 1... ....
			if v&0x0180 != 0x0080 {
				return
			}

			// 取参数值 seqNo crc low 7bits
			tempBuffer[i] = byte(v & 0x7F)
		case 1:
			// [bit8] 0 [bit7] 1
			// 0 1... ....
			if v&0x0180 != 0x0080 {
				return
			}

			// seqNo data index
			tempBuffer[i] = byte(v & 0x7F)
			if _, exist := ak.seqData[int(tempBuffer[1])]; exist || int(tempBuffer[1]) > ak.seqDataCnt {
				return
			}
		default:
			// 最后一组数据时，无需校验超出 totalLength 的数据位
			if int(tempBuffer[1]) == ak.seqDataCnt-1 && (i-2) > (ak.totalLength%4)-1 {
				break
			}

			// [bit8] 1
			// 1 .... ....
			if v&0x0100 != 0x0100 {
				return
			}

			// data
			tempBuffer[i] = byte(v & 0xFF)
		}
	}

	// 本协议中的 CRC8 只有低位的 7 bits，故需要将计算结果 & 0x7F 再比对
	end := len(tempBuffer)
	if int(tempBuffer[1]) == ak.seqDataCnt-1 {
		end = 2 + ak.totalLength%4
	}

	if tempBuffer[0] != crc8(tempBuffer[1:end])&0x7F {
		// CRC8 校验失败 或 index 超出 则 丢弃本组
		ak.window = ak.window[:0]

		return
	}

	ak.seqData[int(tempBuffer[1])] = tempBuffer
	ak.window = ak.window[:0]

	for i := 0; i < ak.seqDataCnt; i++ {
		if _, exist := ak.seqData[i]; !exist {
			return
		}
	}

	return true
}
