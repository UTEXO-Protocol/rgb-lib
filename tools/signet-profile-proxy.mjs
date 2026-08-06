import http from 'node:http';

const listenPort = Number.parseInt(process.env.LISTEN_PORT ?? '3012', 10);
const upstream = new URL(process.env.UPSTREAM_URL ?? 'http://127.0.0.1:3003');
const latencyMs = Number.parseInt(process.env.LATENCY_MS ?? '650', 10);
const failAfter = Number.parseInt(process.env.FAIL_AFTER ?? '130', 10);
let requestCount = 0;

const server = http.createServer(async (request, response) => {
  requestCount += 1;
  const currentRequest = requestCount;
  await new Promise((resolve) => setTimeout(resolve, latencyMs));

  if (currentRequest > failAfter) {
    response.writeHead(503, { 'content-type': 'text/plain' });
    response.end('controlled indexer outage');
    return;
  }

  try {
    const target = new URL(request.url ?? '/', upstream);
    const upstreamResponse = await fetch(target, { method: request.method });
    const body = Buffer.from(await upstreamResponse.arrayBuffer());
    response.writeHead(upstreamResponse.status, {
      'content-type': upstreamResponse.headers.get('content-type') ?? 'application/octet-stream',
      'x-benchmark-request-count': String(currentRequest),
    });
    response.end(body);
  } catch (error) {
    response.writeHead(502, { 'content-type': 'text/plain' });
    response.end(error instanceof Error ? error.message : String(error));
  }
});

server.listen(listenPort, '127.0.0.1', () => {
  process.stdout.write(
    `signet-profile-proxy listen=${listenPort} latency_ms=${latencyMs} fail_after=${failAfter}\n`,
  );
});
