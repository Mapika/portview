// Demo service: an ingest endpoint on :7000 with a genuine connection leak.
//
// allowHalfOpen matters here. With Node's default (false), the server socket is
// closed automatically when the client sends FIN, and nothing accumulates. With
// it enabled the server keeps its half open after the client disconnects, which
// is precisely the CLOSE_WAIT leak portview doctor is meant to flag — a real
// condition, not staged output.
//
// Doubles as a regression fixture: doctor does NOT currently detect this,
// because get_port_infos deduplicates by (port, protocol, pid) and collapses all
// 16 leaked sockets into a single row. Once that is fixed, running this service
// must make `portview doctor` report a connection leak on :7000.
const net = require('net');

const held = [];
const server = net.createServer({ allowHalfOpen: true }, (socket) => {
  held.push(socket); // deliberately never closed
});

server.listen(7000, '127.0.0.1', () => {
  // Cross doctor's threshold of >10 CLOSE_WAIT sockets on one port.
  for (let i = 0; i < 16; i++) {
    const c = net.createConnection(7000, '127.0.0.1', () => c.end());
  }
});

setInterval(() => {}, 1 << 30);
