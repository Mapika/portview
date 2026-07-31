// Demo service: an in-memory cache on :6380 that really does hold ~1.2 GB.
//
// Not staged output — this genuinely crosses portview doctor's 1 GB
// resident-memory threshold, so the "excessive memory" finding in the
// recording is a real detection of a real condition.
const http = require('http');

const store = Buffer.alloc(1_200_000_000);
store.fill(1); // touch the pages so they count toward RSS, not just virtual size

http
  .createServer((_, res) => res.end(String(store.length)))
  .listen(6380, '127.0.0.1');
setInterval(() => {}, 1 << 30);
