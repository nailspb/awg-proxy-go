// Авто-определение сетевых параметров контейнера: его собственный IP на veth
// и default-gateway (= адрес роутера со стороны контейнера). Фронт использует
// это, чтобы предзаполнить пустые поля Settings/Router без ручного ввода.
package api

import (
	"encoding/hex"
	"net"
	"net/http"
	"os"
	"strings"
)

type netAutoResp struct {
	ContainerAddr string `json:"container_addr"` // первый non-loopback IPv4 контейнера
	Gateway       string `json:"gateway"`        // default route (роутер)
}

func (s *Server) netAuto(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, netAutoResp{
		ContainerAddr: detectContainerAddr(),
		Gateway:       detectGateway(),
	})
}

// detectContainerAddr — первый non-loopback IPv4 поднятого интерфейса. Этого
// достаточно для типового сценария с одним veth-каналом до роутера.
func detectContainerAddr() string {
	ifs, err := net.Interfaces()
	if err != nil {
		return ""
	}
	for _, ifc := range ifs {
		if ifc.Flags&net.FlagLoopback != 0 || ifc.Flags&net.FlagUp == 0 {
			continue
		}
		addrs, _ := ifc.Addrs()
		for _, a := range addrs {
			ipnet, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			if ip4 := ipnet.IP.To4(); ip4 != nil && !ip4.IsLoopback() {
				return ip4.String()
			}
		}
	}
	return ""
}

// detectGateway — default route из /proc/net/route. Шлюз хранится hex
// little-endian (формат procfs ядра linux), напр. "0111A8C0" → 192.168.17.1.
func detectGateway() string {
	data, err := os.ReadFile("/proc/net/route")
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(data), "\n")[1:] {
		f := strings.Fields(line)
		// Колонки: Iface Destination Gateway Flags ...
		if len(f) < 3 || f[1] != "00000000" {
			continue
		}
		raw, err := hex.DecodeString(f[2])
		if err != nil || len(raw) != 4 {
			continue
		}
		return net.IPv4(raw[3], raw[2], raw[1], raw[0]).String()
	}
	return ""
}
