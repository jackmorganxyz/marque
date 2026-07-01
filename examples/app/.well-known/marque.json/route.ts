// app/.well-known/marque.json/route.ts
//
// Publishes THIS agent's identity: the wallet ADDRESS (never the private key).
// The whole trust model rests on this file being served over TLS from the
// agent's own origin. Rotation = add the new address to keys, then remove the
// old; revocation = remove the entry (lag = verifier cache TTL). Short max-age
// bounds revocation latency. Serve from a route not subject to shared/edge
// cache-key confusion.
//
// MARQUE_ADDRESS holds one or more comma-separated addresses so you can run the
// add-new-then-remove-old overlap during rotation. Read per request (not
// force-static) so an env change takes effect without a rebuild.
export const dynamic = 'force-dynamic';

export function GET() {
  const keys = (process.env.MARQUE_ADDRESS ?? '').split(',').map(s => s.trim()).filter(Boolean);
  return Response.json(
    { v: 1, keys },                                  // the address(es), NOT the private key
    { headers: { 'cache-control': 'public, max-age=300' } },
  );
}
