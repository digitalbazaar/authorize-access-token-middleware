export async function hashClientSecret({clientSecret}) {
    assert.string(clientSecret, 'clientSecret');
    const digest = crypto.createHash('sha256').update(clientSecret).digest();
    // format as multihash digest
    // sha2-256: 0x12, length: 32 (0x20), digest value
    const mh = Buffer.alloc(34);
    mh[0] = 0x12;
    mh[1] = 0x20;
    mh.set(digest, 2);
    return mh;
}
