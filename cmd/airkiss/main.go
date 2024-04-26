package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/lanseyujie/airkiss"
)

func loadIface(iface string) (*pcap.Handle, error) {
	handle, err := pcap.OpenLive(iface, 1600, true, pcap.BlockForever)

	return handle, err
}

func loadCap(filename string) (*pcap.Handle, error) {
	f, err := os.Open(filename)
	if err != nil {
		return nil, err
	}

	handle, err := pcap.OpenOfflineFile(f)
	if err != nil {
		return nil, err
	}

	return handle, nil
}

func main() {
	var iface string
	flag.StringVar(&iface, "if", "", "wireless interface")
	flag.Parse()

	handle, err := loadIface(iface)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	// https://www.tcpdump.org/manpages/pcap-filter.7.html
	err = handle.SetBPFFilter("type data")
	if err != nil {
		log.Fatal(err)
	}

	// SA:BSSID
	m := map[string]*airkiss.AirKiss{}
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	t := time.After(time.Second * 60)

FLAG:
	for packet := range packetSource.Packets() {
		if packet == nil {
			continue
		}

		dot11Packet, ok := packet.Layer(layers.LayerTypeDot11).(*layers.Dot11)
		if !ok {
			continue
		}

		if dot11Packet.Flags.ToDS() == dot11Packet.Flags.FromDS() {
			continue
		}

		var bssid, sa, da net.HardwareAddr
		var key string
		if dot11Packet.Flags.ToDS() {
			// To AP
			// A1     A2  A3
			// BSSID  SA  DA
			bssid, sa, da = dot11Packet.Address1, dot11Packet.Address2, dot11Packet.Address3
			key = sa.String() + bssid.String()
		} else {
			// From AP
			// A1    A2    A3
			// DA   BSSID  SA
			bssid, sa, da = dot11Packet.Address2, dot11Packet.Address3, dot11Packet.Address1
			key = bssid.String() + sa.String()
		}

		ak, ok := m[key]
		if !ok {
			ak = airkiss.New()
			m[key] = ak
		}

		{
			fmt.Println("====================================================")
			fmt.Println(" Sequence NO:", dot11Packet.SequenceNumber)
			fmt.Println("   Flag ToDS:", dot11Packet.Flags.ToDS())
			fmt.Println(" Destination:", da)
			fmt.Println("       BSSID:", bssid)
			fmt.Println("      Source:", sa)
			fmt.Println("Frame Length:", len(packet.Data()))
		}

		ak.Put(len(packet.Data()), dot11Packet.SequenceNumber)
		select {
		case <-ak.Done():
			log.Printf("SSID: %s SSIDCRC8: 0x%X RandomByte: 0x%X Password: %s\n", ak.SSID, ak.SSIDCRC8, ak.RandomByte, ak.Password)

			break FLAG
		case <-t:
			log.Println("TIMEOUT")

			break FLAG
		default:
		}
	}
}
