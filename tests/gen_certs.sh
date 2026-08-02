#!/usr/bin/env bash
# =============================================================================
#  gen_certs.sh — 生成 TLS 测试证书 (tests/certs/)
#
#  产物:
#    ca.pem/ca.key         — 测试根 CA (自签)
#    server.pem/server.key — 服务器证书 (SAN: DNS:localhost, IP:127.0.0.1)
#    client.pem/client.key — 客户端证书 (mTLS 用例)
#  幂等: 已存在则跳过 (如需重新生成, 先删 tests/certs/)
#  =============================================================================

set -euo pipefail

OUT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/certs"
mkdir -p "$OUT"

if [ -f "$OUT/ca.pem" ] && [ -f "$OUT/server.pem" ] && [ -f "$OUT/client.pem" ]; then
    echo "==> 证书已存在: $OUT (跳过, 如需重新生成先删除)"
    exit 0
fi

echo "==> 生成测试证书到 $OUT ..."

# 根 CA (自签, RSA 2048)
openssl req -x509 -newkey rsa:2048 -nodes -keyout "$OUT/ca.key" -out "$OUT/ca.pem" \
    -days 3650 -subj "/CN=libsevent test CA" >/dev/null 2>&1

# 服务器证书 (SAN: DNS:localhost + IP:127.0.0.1 — hostname 校验正反用例共用)
openssl req -newkey rsa:2048 -nodes -keyout "$OUT/server.key" -out "$OUT/server.csr" \
    -subj "/CN=localhost" >/dev/null 2>&1
openssl x509 -req -in "$OUT/server.csr" -CA "$OUT/ca.pem" -CAkey "$OUT/ca.key" \
    -CAcreateserial -out "$OUT/server.pem" -days 3650 \
    -extfile <(printf "subjectAltName=DNS:localhost,IP:127.0.0.1") >/dev/null 2>&1

# 客户端证书 (mTLS: 服务端 verify_peer=true 验证用)
openssl req -newkey rsa:2048 -nodes -keyout "$OUT/client.key" -out "$OUT/client.csr" \
    -subj "/CN=test-client" >/dev/null 2>&1
openssl x509 -req -in "$OUT/client.csr" -CA "$OUT/ca.pem" -CAkey "$OUT/ca.key" \
    -CAcreateserial -out "$OUT/client.pem" -days 3650 >/dev/null 2>&1

rm -f "$OUT"/*.csr "$OUT"/ca.srl
echo "==> 完成: ca / server (SAN: localhost,127.0.0.1) / client"
