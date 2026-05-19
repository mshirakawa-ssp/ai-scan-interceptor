// icap-debug: listens on an ICAP port and dumps raw bytes to stdout.
// Use this to inspect what Squid actually sends over the ICAP connection.
package main

import (
	"fmt"
	"io"
	"log"
	"net"
	"os"
)

func main() {
	addr := ":1344"
	if len(os.Args) > 1 {
		addr = os.Args[1]
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("debug ICAP server listening on %s", addr)
	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Fatal(err)
		}
		go handle(conn)
	}
}

func handle(conn net.Conn) {
	defer conn.Close()
	buf := make([]byte, 8192)
	n, err := conn.Read(buf)
	if n > 0 {
		fmt.Printf("\n══════════ RAW from %s (%d bytes) ══════════\n%q\n", conn.RemoteAddr(), n, buf[:n])
	}
	if err != nil && err != io.EOF {
		log.Printf("read: %v", err)
	}
	// Reply with a valid ICAP 204 so Squid doesn't retry endlessly
	conn.Write([]byte("ICAP/1.0 204 No Modifications Needed\r\nISTag: \"debug\"\r\n\r\n"))
}
