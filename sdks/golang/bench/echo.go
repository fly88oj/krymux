// Echo throughput benchmark for the Go Krymux SDK.
//
// Measures the mux + stream data path (writer batching, framing, flow control,
// optional deflate) over a loopback TCP socket pair — both sessions in this
// one process, no TLS (TLS is crypto/tls-internal and identical before/after
// any SDK-level optimization).
//
// Per combination of payload size (1 MiB, 16 MiB) and compression (none,
// deflate): open a stream, push the payload in 64-KiB chunks, half-close, read
// the echo back, verify sha256. 3 runs, median one-way payload MiB/s.
//
//	go run ./bench
//
// Output lines: `RESULT go <size>MiB <comp> <median MiB/s>`
package main

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
	"net"
	"os"
	"sort"
	"time"

	"github.com/fly88oj/krymux-go/pkg/mux"
)

const (
	chunk = 64 * 1024
	runs  = 3
)

var sizes = []int{1, 16} // MiB
var comps = []string{"none", "deflate"}

// makePayload mirrors the example clients: half random, half compressible.
func makePayload(size int) []byte {
	buf := make([]byte, size)
	if _, err := rand.Read(buf[:size/2]); err != nil {
		panic(err)
	}
	unit := []byte("compressible-payload ")
	for i := size / 2; i < size; i++ {
		buf[i] = unit[i%len(unit)]
	}
	return buf
}

func serve(conn net.Conn) {
	handler := func(st *mux.Stream, _ mux.Target) {
		st.Accept("echo")
		go func() {
			io.Copy(st, st) // echo until the peer FINs
			st.CloseWrite()
		}()
	}
	if _, err := mux.NewServerSession(conn, mux.SessionOptions{}, handler); err != nil {
		conn.Close()
	}
}

func runOnce(addr string, payload []byte, comp string, expectHash [32]byte) float64 {
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		panic(err)
	}
	sess, err := mux.NewClientSession(conn, mux.SessionOptions{})
	if err != nil {
		panic(err)
	}
	t0 := time.Now()
	st, err := sess.OpenStream(mux.Target{Hint: "raw"}, comp)
	if err != nil {
		panic(err)
	}
	writeErr := make(chan error, 1)
	go func() {
		for off := 0; off < len(payload); off += chunk {
			end := off + chunk
			if end > len(payload) {
				end = len(payload)
			}
			if _, err := st.Write(payload[off:end]); err != nil {
				writeErr <- err
				return
			}
		}
		st.CloseWrite()
		writeErr <- nil
	}()
	hasher := sha256.New()
	got, err := io.Copy(hasher, st)
	if err != nil {
		panic(err)
	}
	if err := <-writeErr; err != nil {
		panic(err)
	}
	dt := time.Since(t0).Seconds()
	if int(got) != len(payload) || string(hasher.Sum(nil)) != string(expectHash[:]) {
		panic("echo mismatch (size or sha256)")
	}
	sess.Close("done")
	return float64(len(payload)) / 1048576 / dt
}

func main() {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		panic(err)
	}
	addr := listener.Addr().String()
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go serve(conn)
		}
	}()

	fmt.Printf("bench go chunk=%d runs=%d\n", chunk, runs)
	for _, sizeMiB := range sizes {
		payload := makePayload(sizeMiB * 1048576)
		expect := sha256.Sum256(payload)
		for _, comp := range comps {
			var mbs []float64
			for i := 0; i < runs; i++ {
				mbs = append(mbs, runOnce(addr, payload, comp, expect))
			}
			sort.Float64s(mbs)
			median := mbs[len(mbs)/2]
			fmt.Printf("RESULT go %dMiB %s %.1f  (runs: %.1f, %.1f, %.1f)\n",
				sizeMiB, comp, median, mbs[0], mbs[1], mbs[2])
		}
	}
	os.Exit(0)
}
