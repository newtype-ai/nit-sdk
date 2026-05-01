import assert from 'node:assert/strict';
import test from 'node:test';

const agentId = '3b4852c2-8d61-55f1-ad5a-0f4f188155f0';
const signature = Buffer.alloc(64, 1).toString('base64');
const publicKey = `ed25519:${Buffer.alloc(32, 2).toString('base64')}`;
const readToken = 'eyJzdWIiOiJhZ2VudCJ9.wm5_g4uXdyQItLkONFLvJmUCbN3Y7sPx';

const card = {
  protocolVersion: '0.3.0',
  name: 'agent',
  description: 'test agent',
  version: '1.0.0',
  url: `https://agent-${agentId}.newtype-ai.org`,
  defaultInputModes: ['text/plain'],
  defaultOutputModes: ['text/plain'],
  publicKey,
  skills: [{ id: 'test-skill' }],
};

async function sdk() {
  return import('../dist/index.js');
}

test('verifyAgent validates payloads before sending requests', async () => {
  const { verifyAgent } = await sdk();
  let called = false;
  const oldFetch = globalThis.fetch;
  globalThis.fetch = async () => {
    called = true;
    return new Response('{}');
  };

  try {
    await assert.rejects(
      () => verifyAgent({
        agent_id: '550e8400-e29b-41d4-a716-446655440000',
        domain: 'faam.io',
        timestamp: 1,
        signature,
      }),
      /UUIDv5/,
    );
    await assert.rejects(
      () => verifyAgent({
        agent_id: agentId,
        domain: 'bad/domain',
        timestamp: 1,
        signature,
      }),
      /unsafe/,
    );
    await assert.rejects(
      () => verifyAgent({
        agent_id: agentId,
        domain: 'faam.io',
        timestamp: 1,
        signature: signature.replace(/=$/, ''),
      }),
      /64-byte/,
    );
    assert.equal(called, false);
  } finally {
    globalThis.fetch = oldFetch;
  }
});

test('verifyAgent bounds and validates server responses', async () => {
  const { verifyAgent } = await sdk();
  const oldFetch = globalThis.fetch;

  globalThis.fetch = async () => new Response('x', {
    status: 200,
    headers: { 'content-length': String(300 * 1024) },
  });
  let result = await verifyAgent({
    agent_id: agentId,
    domain: 'faam.io',
    timestamp: 1,
    signature,
  });
  assert.equal(result.verified, false);
  assert.match(result.error, /exceeds/);

  globalThis.fetch = async () => new Response(JSON.stringify({
    verified: true,
    admitted: true,
    agent_id: '550e8400-e29b-41d4-a716-446655440000',
    domain: 'faam.io',
    branch: 'faam.io',
    card,
    readToken,
  }));
  result = await verifyAgent({
    agent_id: agentId,
    domain: 'faam.io',
    timestamp: 1,
    signature,
  });
  assert.equal(result.verified, false);
  assert.match(result.error, /UUIDv5/);

  globalThis.fetch = async () => new Response(JSON.stringify({
    verified: true,
    admitted: true,
    agent_id: agentId,
    domain: 'faam.io',
    branch: 'faam.io',
    card,
    readToken,
  }));
  result = await verifyAgent({
    agent_id: agentId,
    domain: 'faam.io',
    timestamp: 1,
    signature,
    public_key: publicKey,
  });
  assert.equal(result.verified, true);
  assert.equal(result.card.name, 'agent');

  globalThis.fetch = oldFetch;
});

test('fetchAgentCard validates inputs and bounded card responses', async () => {
  const { fetchAgentCard, NitSdkError } = await sdk();
  const oldFetch = globalThis.fetch;

  await assert.rejects(
    () => fetchAgentCard(agentId, 'bad/domain', readToken),
    /unsafe/,
  );
  await assert.rejects(
    () => fetchAgentCard(agentId, 'faam.io', 'not-a-token'),
    /two-part/,
  );

  globalThis.fetch = async () => new Response('missing', { status: 404 });
  assert.equal(await fetchAgentCard(agentId, 'faam.io', readToken), null);

  globalThis.fetch = async () => new Response('x', {
    status: 200,
    headers: { 'content-length': String(200 * 1024) },
  });
  await assert.rejects(
    () => fetchAgentCard(agentId, 'faam.io', readToken),
    (err) => err instanceof NitSdkError && /exceeds/.test(err.message),
  );

  globalThis.fetch = async () => new Response(JSON.stringify(card));
  const fetched = await fetchAgentCard(agentId, 'faam.io', readToken);
  assert.equal(fetched.name, 'agent');

  globalThis.fetch = oldFetch;
});
