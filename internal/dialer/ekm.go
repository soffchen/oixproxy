package dialer

import (
	"fmt"
	"net"
	"reflect"
	"unsafe"

	utls "github.com/metacubex/utls"

	"github.com/soffchen/oixproxy/internal/identity"
)

func exportFromConn(conn net.Conn, n Node) ([]byte, error) {
	if n.identityVersion() == 1 {
		return nil, nil
	}
	var c *utls.Conn
	switch t := conn.(type) {
	case *utls.UConn:
		c = t.Conn
	case *utls.Conn:
		c = t
	default:
		return nil, fmt.Errorf("snell ech-tls exporter unavailable")
	}
	if c == nil {
		return nil, fmt.Errorf("snell ech-tls exporter unavailable")
	}
	// Chrome parrots leave Config.Renegotiation set, which makes
	// ConnectionState.ExportKeyingMaterial always fail. TLS 1.3 still
	// has a working exporter on Conn.ekm (same as the official helper).
	ekm, err := connEKM(c)
	if err != nil {
		return nil, err
	}
	out, err := ekm(identity.ExporterLabel, nil, identity.ExporterSize)
	if err != nil {
		return nil, fmt.Errorf("snell ech-tls exporter: %w", err)
	}
	if len(out) != identity.ExporterSize {
		return nil, fmt.Errorf("snell ech-tls exporter length %d", len(out))
	}
	return out, nil
}

func connEKM(c *utls.Conn) (func(string, []byte, int) ([]byte, error), error) {
	v := reflect.ValueOf(c).Elem().FieldByName("ekm")
	if !v.IsValid() || v.Kind() != reflect.Func || v.IsNil() {
		return nil, fmt.Errorf("snell ech-tls exporter unavailable")
	}
	fn := reflect.NewAt(v.Type(), unsafe.Pointer(v.UnsafeAddr())).Elem().Interface()
	ekm, ok := fn.(func(string, []byte, int) ([]byte, error))
	if !ok || ekm == nil {
		return nil, fmt.Errorf("snell ech-tls exporter unavailable")
	}
	return ekm, nil
}
