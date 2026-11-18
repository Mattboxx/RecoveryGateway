"""Check the TLS deny-list against public certificates on the host.

Also the private trust anchors of the tailnet's own connections (Headscale
over HTTPS with a private CA or a self-signed certificate): accepted only by
ml_tls_tailnet_attach() (control and DERP), never by ml_tls_bundle_attach()
(updates, MQTT, notifications); the certificate name is still checked;
invalid, oversized, too many or distrusted certificates are refused.

Calls the actual verification callback with a listed public certificate and
checks it sets the distrust flag even when the bundle callback clears flags.
Checks the normal path with an independently generated test-only chain.
The full TLS integration here uses Mbed TLS 3.6.5 for backward compatibility.
"""
import datetime
import hashlib
import os
from pathlib import Path
import re
import subprocess
import tempfile
import warnings

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

ROOT = Path(__file__).resolve().parents[1]
ML = ROOT / 'external/microlink/components/microlink'
MBED = Path(os.environ.get('TLS_TEST_MBEDTLS_DIR', str(Path.home() / '.platformio/packages/framework-espidf@3.50503.0/components/mbedtls/mbedtls')))
# The pinned SDK's certificate bundle (CI: sparse ESP-IDF checkout, CRT_BUNDLE).
BUNDLE = Path(os.environ.get('TLS_TEST_CA_BUNDLE', str(MBED.parent / 'esp_crt_bundle/cacrt_all.pem')))
FIXTURE = ROOT / 'tools/fixtures/emudhra-compromised-intermediates.crt'
ISRG_X1_SHA256 = '96BCEC06264976F37460779ACF28C5A7CFE8A3C0AAE11A8FFCEE05C0BDDF08C6'

# Every bundle user goes through the wrapper.
sources = list((ROOT / 'main').glob('*.c')) + list((ML / 'src').glob('*.c'))
for path in sources:
    text = path.read_text(encoding='utf-8', errors='replace')
    if path.name != 'ml_tls_distrust.c':
        assert not re.search(r'\besp_crt_bundle_attach\b(?!\.h)', text.replace('esp_crt_bundle.h', '')), path.name
users = [p.name for p in sources if re.search(r'ml_tls_(bundle|tailnet)_attach', p.read_text(encoding='utf-8', errors='replace'))]
tailnet_users = sorted(p.name for p in sources if 'ml_tls_tailnet_attach(' in p.read_text(encoding='utf-8', errors='replace')
                       or 'crt_bundle_attach = ml_tls_tailnet_attach' in p.read_text(encoding='utf-8', errors='replace'))
assert tailnet_users == ['ml_coord.c', 'ml_derp.c', 'ml_tls_distrust.c'], tailnet_users   # nothing else trusts private anchors
assert {'ml_coord.c', 'ml_derp.c', 'ota_remote.c', 'mqtt_integration.c', 'ntfy_integration.c', 'notify_channels.c',
        'ddns.c', 'layout_migration.c', 'throughput.c'} <= set(users), users
assert '"src/ml_tls_distrust.c"' in (ML / 'CMakeLists.txt').read_text(encoding='utf-8')
assert 'cJSON_AddNumberToObject(td, "refused_chains", ml_tls_distrust_refusals());' in (ROOT / 'main/web_ui.c').read_text(encoding='utf-8')


def pems(text):
    return [m.group(0) for m in re.finditer(r'-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----', text, re.S)]


def by_sha(certs, sha):
    for c in certs:
        if hashlib.sha256(c.public_bytes(serialization.Encoding.DER)).hexdigest().upper() == sha:
            return c
    raise AssertionError('certificate not found: ' + sha)


compromised = [x509.load_pem_x509_certificate(p.encode()) for p in pems(FIXTURE.read_text(encoding='utf-8'))]
assert len(compromised) == 16
warnings.filterwarnings('ignore', message='Parsed a serial number')   # one legacy bundle root
bundle = [x509.load_pem_x509_certificate(p.encode()) for p in pems(BUNDLE.read_text(encoding='utf-8'))]
isrg = by_sha(bundle, ISRG_X1_SHA256)
now = datetime.datetime.now(datetime.timezone.utc)


def leaf(issuer_name, issuer_key, name):
    key = ec.generate_private_key(ec.SECP256R1())
    cert = (x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)]))
            .issuer_name(issuer_name).public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1)).not_valid_after(now + datetime.timedelta(days=30))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(name)]), critical=False)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .sign(issuer_key, hashes.SHA384()))
    return cert


good_key = ec.generate_private_key(ec.SECP256R1())
good_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'Test Root')])
good_root = (x509.CertificateBuilder().subject_name(good_name).issuer_name(good_name).public_key(good_key.public_key())
             .serial_number(1).not_valid_before(now - datetime.timedelta(days=1))
             .not_valid_after(now + datetime.timedelta(days=60))
             .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
             .add_extension(x509.KeyUsage(False, False, False, False, False, True, True, False, False), critical=True)
             .sign(good_key, hashes.SHA256()))
good_leaf = leaf(good_name, good_key, 'gateway.example.test')
# A private CA (as a homelab Headscale would use) and a self-signed server certificate.
priv_key = ec.generate_private_key(ec.SECP256R1())
priv_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'Private Root')])
priv_root = (x509.CertificateBuilder().subject_name(priv_name).issuer_name(priv_name).public_key(priv_key.public_key())
             .serial_number(7).not_valid_before(now - datetime.timedelta(days=1))
             .not_valid_after(now + datetime.timedelta(days=60))
             .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
             .add_extension(x509.KeyUsage(False, False, False, False, False, True, True, False, False), critical=True)
             .sign(priv_key, hashes.SHA256()))
priv_leaf = leaf(priv_name, priv_key, 'gateway.example.test')
self_key = ec.generate_private_key(ec.SECP256R1())
self_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'gateway.example.test')])
self_signed = (x509.CertificateBuilder().subject_name(self_name).issuer_name(self_name).public_key(self_key.public_key())
               .serial_number(9).not_valid_before(now - datetime.timedelta(days=1))
               .not_valid_after(now + datetime.timedelta(days=60))
               .add_extension(x509.SubjectAlternativeName([x509.DNSName('gateway.example.test')]), critical=False)
               .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
               .sign(self_key, hashes.SHA256()))
PRIV_FP = hashlib.sha256(priv_root.public_bytes(serialization.Encoding.DER)).hexdigest()

PROGRAM = r'''
#define _POSIX_C_SOURCE 200809L   /* strnlen with -std=c11 on glibc */
#define ML_TLS_HOST_TEST 1
#include "ml_tls_distrust.c"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static int attach_rc, bundle_calls, clear_flags, set_callback = 1;
static int bundle_cb(void *ctx, mbedtls_x509_crt *crt, int depth, uint32_t *flags)
{
    (void)crt; (void)depth;
    assert(ctx == (void *)&bundle_calls);
    bundle_calls++;
    if (clear_flags) *flags = 0;
    return 0;
}
esp_err_t esp_crt_bundle_attach(void *conf)
{
    if (attach_rc) return attach_rc;
    if (conf && set_callback) mbedtls_ssl_conf_verify(conf, bundle_cb, &bundle_calls);
    return ESP_OK;
}
static char *slurp(const char *path)
{
    FILE *f = fopen(path, "rb"); assert(f);
    static char buf[200000]; size_t n = fread(buf, 1, sizeof buf - 1, f); fclose(f); buf[n] = 0;
    char *copy = malloc(n + 1); memcpy(copy, buf, n + 1); return copy;
}
static mbedtls_x509_crt load(const char *path)
{
    mbedtls_x509_crt c; mbedtls_x509_crt_init(&c);
    assert(mbedtls_x509_crt_parse_file(&c, path) == 0);
    return c;
}
static int verify(mbedtls_x509_crt *chain, mbedtls_x509_crt *ca, mbedtls_ssl_config *conf, uint32_t *flags)
{
    return mbedtls_x509_crt_verify(chain, ca, NULL, "gateway.example.test", flags,
                                   conf ? conf->f_vrfy : NULL, conf ? conf->p_vrfy : NULL);
}
int main(int argc, char **argv)
{
    (void)argc;
    mbedtls_x509_crt good = load(argv[1]), good_root = load(argv[2]);
    mbedtls_x509_crt compromised = load(argv[3]), roots = load(argv[4]);
    uint32_t flags = 99;
    assert(verify(&good, &good_root, NULL, &flags) == 0 && flags == 0);
    mbedtls_ssl_config conf; mbedtls_ssl_config_init(&conf);
    assert(ml_tls_bundle_attach(&conf) == ESP_OK && conf.f_vrfy == distrust_verify && conf.p_vrfy == &bundle_calls);
    flags = 0;
    assert(conf.f_vrfy(conf.p_vrfy, &compromised, 1, &flags) == 0);
    assert(flags & MBEDTLS_X509_BADCERT_NOT_TRUSTED);
    assert(bundle_calls > 0 && ml_tls_distrust_refusals() == 1);
    clear_flags = 1; flags = 0;   /* a bundle callback that clears its anchor's flags cannot undo it */
    assert(conf.f_vrfy(conf.p_vrfy, &compromised, 1, &flags) == 0);
    assert(flags & MBEDTLS_X509_BADCERT_NOT_TRUSTED);
    clear_flags = 0; flags = 99;
    assert(verify(&good, &good_root, &conf, &flags) == 0 && flags == 0);   /* normal chains unaffected */
    assert(ml_tls_distrust_refusals() == 2);
    /* All 16 published certificates match; the roots and an unrelated root do not. */
    unsigned n = 0;
    for (mbedtls_x509_crt *c = &compromised; c && c->raw.len; c = c->next, n++)
        assert(ml_tls_spki_distrusted(c->pk_raw.p, c->pk_raw.len));
    assert(n == 16);
    unsigned r = 0;
    for (mbedtls_x509_crt *c = &roots; c && c->raw.len; c = c->next, r++)
        assert(!ml_tls_spki_distrusted(c->pk_raw.p, c->pk_raw.len));
    assert(r == 2);
    assert(!ml_tls_spki_distrusted(NULL, 10) && !ml_tls_spki_distrusted(compromised.pk_raw.p, 0));
    uint8_t changed[200]; assert(compromised.pk_raw.len <= sizeof changed);
    memcpy(changed, compromised.pk_raw.p, compromised.pk_raw.len); changed[compromised.pk_raw.len - 1] ^= 1;
    assert(!ml_tls_spki_distrusted(changed, compromised.pk_raw.len));
    /* Attach paths. */
    assert(ml_tls_bundle_attach(NULL) == ESP_OK);
    assert(ml_tls_bundle_attach(&conf) == ESP_OK && conf.f_vrfy == distrust_verify);   /* again: no recursion */
    flags = 0; bundle_calls = 0;
    assert(conf.f_vrfy(conf.p_vrfy, &compromised, 1, &flags) == 0);
    assert((flags & MBEDTLS_X509_BADCERT_NOT_TRUSTED) && bundle_calls == 1);
    mbedtls_ssl_config other; mbedtls_ssl_config_init(&other);
    attach_rc = ESP_FAIL; assert(ml_tls_bundle_attach(&other) == ESP_FAIL && other.f_vrfy == NULL);
    attach_rc = 0; set_callback = 0; assert(ml_tls_bundle_attach(&other) == ESP_FAIL && other.f_vrfy == NULL);
    /* Everything parsed is released (LeakSanitizer runs on the Linux CI). */
    mbedtls_ssl_config_free(&other);
    mbedtls_ssl_config_free(&conf);
    /* Private tailnet anchors. */
    set_callback = 1;
    mbedtls_x509_crt priv_leaf = load(argv[6]), self_signed = load(argv[7]);
    char *priv_root_pem = slurp(argv[5]), *self_pem = slurp(argv[7]), *too_many = slurp(argv[8]), *one_bad = slurp(argv[9]);
    mbedtls_ssl_config tc; mbedtls_ssl_config_init(&tc);
    assert(!ml_tls_tailnet_ca_set());
    assert(ml_tls_tailnet_attach(&tc) == ESP_OK && tc.ca_chain == NULL);         /* nothing set: bundle only */
    flags = 0; assert(mbedtls_x509_crt_verify(&priv_leaf, tc.ca_chain, NULL, "gateway.example.test", &flags, tc.f_vrfy, tc.p_vrfy) != 0);
    char fp[65], subject[128];
    assert(ml_tls_check_tailnet_ca(priv_root_pem, fp, subject, sizeof subject) == 1);
    assert(!strcmp(fp, argv[10]) && strstr(subject, "CN=Private Root"));
    assert(ml_tls_set_tailnet_ca(priv_root_pem) == ESP_OK && ml_tls_tailnet_ca_set());
    mbedtls_ssl_config tc2; mbedtls_ssl_config_init(&tc2);
    assert(ml_tls_tailnet_attach(&tc2) == ESP_OK && tc2.ca_chain && tc2.f_vrfy == distrust_verify);
    flags = 99; assert(mbedtls_x509_crt_verify(&priv_leaf, tc2.ca_chain, NULL, "gateway.example.test", &flags, tc2.f_vrfy, tc2.p_vrfy) == 0 && flags == 0);
    flags = 0; assert(mbedtls_x509_crt_verify(&priv_leaf, tc2.ca_chain, NULL, "other.example.test", &flags, tc2.f_vrfy, tc2.p_vrfy) != 0
                      && (flags & MBEDTLS_X509_BADCERT_CN_MISMATCH));               /* the name still counts */
    flags = 0; assert(mbedtls_x509_crt_verify(&good, tc2.ca_chain, NULL, "gateway.example.test", &flags, tc2.f_vrfy, tc2.p_vrfy) != 0);   /* other roots: not via the anchor */
    mbedtls_ssl_config other_service; mbedtls_ssl_config_init(&other_service);
    assert(ml_tls_bundle_attach(&other_service) == ESP_OK && other_service.ca_chain == NULL);   /* updates/MQTT: never */
    /* A self-signed server certificate as its own anchor. */
    assert(ml_tls_set_tailnet_ca(self_pem) == ESP_OK);
    mbedtls_ssl_config tc3; mbedtls_ssl_config_init(&tc3); assert(ml_tls_tailnet_attach(&tc3) == ESP_OK);
    flags = 99; assert(mbedtls_x509_crt_verify(&self_signed, tc3.ca_chain, NULL, "gateway.example.test", &flags, tc3.f_vrfy, tc3.p_vrfy) == 0);
    /* Refused input keeps nothing. */
    const char *bad[] = {"", "garbage", "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n", too_many, one_bad};
    for (unsigned i = 1; i < sizeof bad / sizeof bad[0]; i++) {
        assert(ml_tls_set_tailnet_ca(bad[i]) == ESP_FAIL && !ml_tls_tailnet_ca_set());
        assert(ml_tls_check_tailnet_ca(bad[i], fp, subject, sizeof subject) == 0 && !fp[0]);
    }
    char *big = malloc(ML_TLS_TAILNET_CA_MAX + 100); memset(big, 'A', ML_TLS_TAILNET_CA_MAX + 99); big[ML_TLS_TAILNET_CA_MAX + 99] = 0;
    memcpy(big, "-----BEGIN CERTIFICATE-----", 27);
    assert(ml_tls_set_tailnet_ca(big) == ESP_FAIL && !ml_tls_tailnet_ca_set());
    assert(ml_tls_set_tailnet_ca(priv_root_pem) == ESP_OK && ml_tls_set_tailnet_ca("") == ESP_OK && !ml_tls_tailnet_ca_set());
    assert(ml_tls_set_tailnet_ca(NULL) == ESP_OK);
    mbedtls_ssl_config_free(&tc); mbedtls_ssl_config_free(&tc2); mbedtls_ssl_config_free(&tc3); mbedtls_ssl_config_free(&other_service);
    mbedtls_x509_crt_free(&priv_leaf); mbedtls_x509_crt_free(&self_signed);
    free(priv_root_pem); free(self_pem); free(too_many); free(one_bad); free(big);
    puts("PASS: private tailnet anchors: private CA and self-signed accepted for control/DERP only, name still checked, other services unaffected, bad input refused");
    mbedtls_x509_crt *all[] = {&good, &good_root, &compromised, &roots};
    for (unsigned i = 0; i < sizeof all / sizeof all[0]; i++) mbedtls_x509_crt_free(all[i]);
    puts("PASS: TLS distrust callback, published fingerprints, normal test chain and attach failures (Mbed TLS 3 host)");
    return 0;
}
'''


def main():
    with tempfile.TemporaryDirectory(prefix='tls-distrust-') as folder:
        path = Path(folder)
        pem = lambda *certs: ''.join(c.public_bytes(serialization.Encoding.PEM).decode() for c in certs)
        (path / 'good.pem').write_text(pem(good_leaf))
        (path / 'good_root.pem').write_text(pem(good_root))
        (path / 'compromised.pem').write_text(pem(*compromised))
        (path / 'roots.pem').write_text(pem(isrg, good_root))
        (path / 'priv_root.pem').write_text(pem(priv_root))
        (path / 'priv_leaf.pem').write_text(pem(priv_leaf))
        (path / 'self.pem').write_text(pem(self_signed))
        (path / 'too_many.pem').write_text(pem(priv_root, good_root, self_signed, priv_leaf, good_leaf))
        (path / 'one_bad.pem').write_text(pem(compromised[0]))
        (path / 'esp_err.h').write_text('#pragma once\ntypedef int esp_err_t;\n#define ESP_OK 0\n#define ESP_FAIL -1\n')
        (path / 'test.c').write_text(PROGRAM, encoding='utf-8')
        exe = path / ('test.exe' if os.name == 'nt' else 'test')
        library = sorted(str(p) for p in (MBED / 'library').glob('*.c'))
        flags = ['-std=c11', '-O1', '-w', '-I', str(path), '-I', str(ML / 'include'), '-I', str(ML / 'src'),
                 '-I', str(MBED / 'include'), '-I', str(MBED / 'library')]
        if os.environ.get('HOTLOOP_SANITIZE') == '1':
            flags += ['-fsanitize=address,undefined', '-fno-omit-frame-pointer']
        libs = ['-lws2_32', '-lbcrypt'] if os.name == 'nt' else []
        subprocess.run([os.environ.get('CC', 'gcc'), *flags, str(path / 'test.c'), *library, '-o', str(exe), *libs],
                       check=True)
        run = subprocess.run([str(exe)] + [str(path / n) for n in ('good.pem', 'good_root.pem', 'compromised.pem', 'roots.pem',
                                                                   'priv_root.pem', 'priv_leaf.pem', 'self.pem', 'too_many.pem', 'one_bad.pem')] + [PRIV_FP],
                             capture_output=True, text=True, timeout=60)
        print(run.stdout, end='')
        assert run.returncode == 0, (run.returncode, run.stdout[-2000:], run.stderr[-4000:])


if __name__ == '__main__':
    main()
