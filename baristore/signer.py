#!/usr/bin/env python3
# =============================================================================
#  BariStore — Pure-Python Mach-O & IPA Code Signer (MIT)
#
#  Signs iOS IPAs on-device in a-Shell using stdlib + `cryptography`:
#    * LC_CODE_SIGNATURE + SuperBlob (CodeDirectory v0x20400, SHA-256, 16 KB pages)
#    * Designated RequirementSet + XML & DER Entitlements
#    * CMS SignedData with Apple attributes 1.2.840.113635.100.9.1 & .2
#    * CodeResources (v1 SHA-1 + v2 SHA-256)
#    * Bundle ID rewriting, App Group stamping/stripping, custom display name,
#      selective or full app-extension (.appex) removal, and self-verification
# =============================================================================

import base64
import binascii
import datetime
import hashlib
import os
import plistlib
import shutil
import struct
import tempfile
import time
import zipfile

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.x509.oid import NameOID

from . import storage

PAGE_SIZE = 16384
PAGE_SHIFT = 14

MH_MAGIC = 0xFEEDFACE
MH_MAGIC_64 = 0xFEEDFACF
MH_CIGAM = 0xCEFAEDFE
MH_CIGAM_64 = 0xCFFAEDFE
FAT_MAGIC = 0xCAFEBABE
FAT_MAGIC_64 = 0xCAFEBABF
LC_SEGMENT = 0x1
LC_SEGMENT_64 = 0x19
LC_CODE_SIGNATURE = 0x1D
LC_UUID = 0x1B
MH_EXECUTE = 0x2

CSMAGIC_REQUIREMENTS = 0xFADE0C01
CSMAGIC_REQUIREMENT = 0xFADE0C00
CSMAGIC_CODEDIRECTORY = 0xFADE0C02
CSMAGIC_EMBEDDED_SIGNATURE = 0xFADE0CC0
CSMAGIC_EMBEDDED_ENTITLEMENTS = 0xFADE7171
CSMAGIC_EMBEDDED_DER_ENTITLEMENTS = 0xFADE7172
CSMAGIC_BLOBWRAPPER = 0xFADE0B01

CSSLOT_CODEDIRECTORY = 0
CSSLOT_INFOSLOT = 1
CSSLOT_REQUIREMENTS = 2
CSSLOT_RESOURCEDIR = 3
CSSLOT_ENTITLEMENTS = 5
CSSLOT_DER_ENTITLEMENTS = 7
CSSLOT_SIGNATURESLOT = 0x10000

CS_EXECSEG_MAIN_BINARY = 0x1
CS_EXECSEG_CAN_LOAD_CDHASH = 0x100
CS_EXECSEG_CAN_EXEC_CDHASH = 0x200

OID_SIGNED_DATA = "1.2.840.113549.1.7.2"
OID_DATA = "1.2.840.113549.1.7.1"
OID_CONTENT_TYPE = "1.2.840.113549.1.9.3"
OID_MESSAGE_DIGEST = "1.2.840.113549.1.9.4"
OID_SIGNING_TIME = "1.2.840.113549.1.9.5"
OID_SHA256 = "2.16.840.1.101.3.4.2.1"
OID_RSA = "1.2.840.113549.1.1.1"
OID_CDHASHES_PLIST = "1.2.840.113635.100.9.1"
OID_CDHASHES = "1.2.840.113635.100.9.2"

APPLE_CA_DER = [
    (
        "AppleWWDRCAG2",
        "MIIC9zCCAnygAwIBAgIIb+/Y9emjp+4wCgYIKoZIzj0EAwIwZzEbMBkGA1UEAwwSQXBwbGUg"
        "Um9vdCBDQSAtIEczMSYwJAYDVQQLDB1BcHBsZSBDZXJ0aWZpY2F0aW9uIEF1dGhvcml0eTET"
        "MBEGA1UECgwKQXBwbGUgSW5jLjELMAkGA1UEBhMCVVMwHhcNMTQwNTA2MjM0MzI0WhcNMjkw"
        "NTA2MjM0MzI0WjCBgDE0MDIGA1UEAwwrQXBwbGUgV29ybGR3aWRlIERldmVsb3BlciBSZWxh"
        "dGlvbnMgQ0EgLSBHMjEmMCQGA1UECwwdQXBwbGUgQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkx"
        "EzARBgNVBAoMCkFwcGxlIEluYy4xCzAJBgNVBAYTAlVTMFkwEwYHKoZIzj0CAQYIKoZIzj0D"
        "AQcDQgAE3fC3BkvP3XMEE8RDiQOTgPte9nStQmFSWAImUxnIYyIHCVJhysTZV+9tJmiLdJGM"
        "xPmAaCj8CWjwENrp0C7JGqOB9zCB9DBGBggrBgEFBQcBAQQ6MDgwNgYIKwYBBQUHMAGGKmh0"
        "dHA6Ly9vY3NwLmFwcGxlLmNvbS9vY3NwMDQtYXBwbGVyb290Y2FnMzAdBgNVHQ4EFgQUhLaE"
        "zDqGYnIWWZToGqO9SN863wswDwYDVR0TAQH/BAUwAwEB/zAfBgNVHSMEGDAWgBS7sN6hWDOI"
        "mqSKmd6+veuv2sskqzA3BgNVHR8EMDAuMCygKqAohiZodHRwOi8vY3JsLmFwcGxlLmNvbS9h"
        "cHBsZXJvb3RjYWczLmNybDAOBgNVHQ8BAf8EBAMCAQYwEAYKKoZIhvdjZAYCDwQCBQAwCgYI"
        "KoZIzj0EAwIDaQAwZgIxANmxxzHGI/ZPTdDZR8V9GGkRh3En02it4Jtlmr5s3z9GppAJvm6h"
        "OyywUYlBPIfSvwIxAPxkUolLPF2/axzCiZgvcq61m6oaCyNUd1ToFUOixRLal1BzfF7QbrJc"
        "YlDXUfE6Wg==",
    ),
    (
        "AppleWWDRCAG3",
        "MIIEUTCCAzmgAwIBAgIQfK9pCiW3Of57m0R6wXjF7jANBgkqhkiG9w0BAQsFADBiMQswCQYD"
        "VQQGEwJVUzETMBEGA1UEChMKQXBwbGUgSW5jLjEmMCQGA1UECxMdQXBwbGUgQ2VydGlmaWNh"
        "dGlvbiBBdXRob3JpdHkxFjAUBgNVBAMTDUFwcGxlIFJvb3QgQ0EwHhcNMjAwMjE5MTgxMzQ3"
        "WhcNMzAwMjIwMDAwMDAwWjB1MUQwQgYDVQQDDDtBcHBsZSBXb3JsZHdpZGUgRGV2ZWxvcGVy"
        "IFJlbGF0aW9ucyBDZXJ0aWZpY2F0aW9uIEF1dGhvcml0eTELMAkGA1UECwwCRzMxEzARBgNV"
        "BAoMCkFwcGxlIEluYy4xCzAJBgNVBAYTAlVTMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIB"
        "CgKCAQEA2PWJ/KhZC4fHTJEuLVaQ03gdpDDppUjvC0O/LYT7JF1FG+XrWTYSXFRknmxiLbTG"
        "l8rMPPbWBpH85QKmHGq0edVny6zpPwcR4YS8Rx1mjjmi6LRJ7TrS4RBgeo6TjMrA2gzAg9Dj"
        "+ZHWp4zIwXPirkbRYp2SqJBgN31ols2N4Pyb+ni743uvLRfdW/6AWSN1F7gSwe0b5TTO/iK1"
        "nkmw5VW/j4SiPKi6xYaVFuQAyZ8D0MyzOhZ71gVcnetHrg21LYwOaU1A0EtMOwSejSGxrC5D"
        "VDDOwYqGlJhL32oNP/77HK6XF8J4CjDgXx9UO0m3JQAaN4LSVpelUkl8YDib7wIDAQABo4Hv"
        "MIHsMBIGA1UdEwEB/wQIMAYBAf8CAQAwHwYDVR0jBBgwFoAUK9BpR5R2Cf70a40uQKb3R01/"
        "CF4wRAYIKwYBBQUHAQEEODA2MDQGCCsGAQUFBzABhihodHRwOi8vb2NzcC5hcHBsZS5jb20v"
        "b2NzcDAzLWFwcGxlcm9vdGNhMC4GA1UdHwQnMCUwI6AhoB+GHWh0dHA6Ly9jcmwuYXBwbGUu"
        "Y29tL3Jvb3QuY3JsMB0GA1UdDgQWBBQJ/sAVkPmvZAqSErkmKGMMl+ynsjAOBgNVHQ8BAf8E"
        "BAMCAQYwEAYKKoZIhvdjZAYCAQQCBQAwDQYJKoZIhvcNAQELBQADggEBAK1lE+j24IF3RAJH"
        "Qr5fpTkg6mKp/cWQyXMT1Z6b0KoPjY3L7QHPbChAW8dVJEH4/M/BtSPp3Ozxb8qAHXfCxGFJ"
        "JWevD8o5Ja3T43rMMygNDi6hV0Bz+uZcrgZRKe3jhQxPYdwyFot30ETKXXIDMUacrptAGvr0"
        "4NM++i+MZp+XxFRZ79JI9AeZSWBZGcfdlNHAwWx/eCHvDOs7bJmCS1JgOLU5gm3sUjFTvg+R"
        "TElJdI+mUcuER04ddSduvfnSXPN/wmwLCTbiZOTCNwMUGdXqapSqqdv+9poIZ4vvK7iqF0mD"
        "r8/LvOnP6pVxsLRFoszlh6oKw0E6eVzaUDSdlTs=",
    ),
    (
        "AppleWWDRCAG4",
        "MIIEVTCCAz2gAwIBAgIUE9x3lVJx5T3GMujM/+Uh88zFztIwDQYJKoZIhvcNAQELBQAwYjEL"
        "MAkGA1UEBhMCVVMxEzARBgNVBAoTCkFwcGxlIEluYy4xJjAkBgNVBAsTHUFwcGxlIENlcnRp"
        "ZmljYXRpb24gQXV0aG9yaXR5MRYwFAYDVQQDEw1BcHBsZSBSb290IENBMB4XDTIwMTIxNjE5"
        "MzYwNFoXDTMwMTIxMDAwMDAwMFowdTFEMEIGA1UEAww7QXBwbGUgV29ybGR3aWRlIERldmVs"
        "b3BlciBSZWxhdGlvbnMgQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkxCzAJBgNVBAsMAkc0MRMw"
        "EQYDVQQKDApBcHBsZSBJbmMuMQswCQYDVQQGEwJVUzCCASIwDQYJKoZIhvcNAQEBBQADggEP"
        "ADCCAQoCggEBANAfeKp6JzKwRl/nF3bYoJ0OKY6tPTKlxGs3yeRBkWq3eXFdDDQEYHX3rkOP"
        "R8SGHgjov9Y5Ui8eZ/xx8YJtPH4GUnadLLzVQ+mxtLxAOnhRXVGhJeG+bJGdayFZGEHVD41t"
        "QSo5SiHgkJ9OE0/QjJoyuNdqkh4laqQyziIZhQVg3AJK8lrrd3kCfcCXVGySjnYB5kaP5eYq"
        "+6KwrRitbTOFOCOL6oqW7Z+uZk+jDEAnbZXQYojZQykn/e2kv1MukBVlPNkuYmQzHWxq3Y4h"
        "qqRfFcYw7V/mjDaSlLfcOQIA+2SM1AyB8j/VNJeHdSbCb64DYyEMe9QbsWLFApy9/a8CAwEA"
        "AaOB7zCB7DASBgNVHRMBAf8ECDAGAQH/AgEAMB8GA1UdIwQYMBaAFCvQaUeUdgn+9GuNLkCm"
        "90dNfwheMEQGCCsGAQUFBwEBBDgwNjA0BggrBgEFBQcwAYYoaHR0cDovL29jc3AuYXBwbGUu"
        "Y29tL29jc3AwMy1hcHBsZXJvb3RjYTAuBgNVHR8EJzAlMCOgIaAfhh1odHRwOi8vY3JsLmFw"
        "cGxlLmNvbS9yb290LmNybDAdBgNVHQ4EFgQUW9n6HeeaGgujmXYiUIY+kchbd6gwDgYDVR0P"
        "AQH/BAQDAgEGMBAGCiqGSIb3Y2QGAgEEAgUAMA0GCSqGSIb3DQEBCwUAA4IBAQA/Vj2e5bbD"
        "eeZFIGi9v3OLLBKeAuOugCKMBB7DUshwgKj7zqew1UJEggOCTwb8O0kU+9h0UoWvp50h5wES"
        "A5/NQFjQAde/MoMrU1goPO6cn1R2PWQnxn6NHThNLa6B5rmluJyJlPefx4elUWY0GzlxOSTj"
        "h2fvpbFoe4zuPfeutnvi0v/fYcZqdUmVIkSoBPyUuAsuORFJEtHlgepZAE9bPFo22noicwkJ"
        "ac3AfOriJP6YRLj477JxPxpd1F1+M02cHSS+APCQA1iZQT0xWmJArzmoUUOSqwSonMJNsUvS"
        "q3xKX+udO7xPiEAGE/+QF4oIRynoYpgppU8RBWk6z/Kf",
    ),
    (
        "AppleWWDRCAG5",
        "MIIEVTCCAz2gAwIBAgIUO36ACu7TAqHm7NuX2cqsKJzxaZQwDQYJKoZIhvcNAQELBQAwYjEL"
        "MAkGA1UEBhMCVVMxEzARBgNVBAoTCkFwcGxlIEluYy4xJjAkBgNVBAsTHUFwcGxlIENlcnRp"
        "ZmljYXRpb24gQXV0aG9yaXR5MRYwFAYDVQQDEw1BcHBsZSBSb290IENBMB4XDTIwMTIxNjE5"
        "Mzg1NloXDTMwMTIxMDAwMDAwMFowdTFEMEIGA1UEAww7QXBwbGUgV29ybGR3aWRlIERldmVs"
        "b3BlciBSZWxhdGlvbnMgQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkxCzAJBgNVBAsMAkc1MRMw"
        "EQYDVQQKDApBcHBsZSBJbmMuMQswCQYDVQQGEwJVUzCCASIwDQYJKoZIhvcNAQEBBQADggEP"
        "ADCCAQoCggEBAJ9d2h/7+rzQSyI8x9Ym+hf39J8ePmQRZprvXr6rNL2qLCFu1h6UIYUsdMEO"
        "EGGqPGNKfkrjyHXWz8KcCEh7arkpsclm/ciKFtGyBDyCuoBs4v8Kcuus/jtvSL6eixFNlX2y"
        "e5AvAhxO/Em+12+1T754xtress3J2WYRO1rpCUVziVDUTuJoBX7adZxLAa7a489tdE3eU9DV"
        "GjiCOtCd410pe7GB6iknC/tgfIYS+/BiTwbnTNEf2W2e7XPaeCENnXDZRleQX2eEwXN3Cqhi"
        "YraucIa7dSOJrXn25qTU/YMmMgo7JJJbIKGc0S+AGJvdPAvntf3sgFcPF54/K4cnu/cCAwEA"
        "AaOB7zCB7DASBgNVHRMBAf8ECDAGAQH/AgEAMB8GA1UdIwQYMBaAFCvQaUeUdgn+9GuNLkCm"
        "90dNfwheMEQGCCsGAQUFBwEBBDgwNjA0BggrBgEFBQcwAYYoaHR0cDovL29jc3AuYXBwbGUu"
        "Y29tL29jc3AwMy1hcHBsZXJvb3RjYTAuBgNVHR8EJzAlMCOgIaAfhh1odHRwOi8vY3JsLmFw"
        "cGxlLmNvbS9yb290LmNybDAdBgNVHQ4EFgQUGYuXjUpbYXhX9KVcNRKKOQjjsHUwDgYDVR0P"
        "AQH/BAQDAgEGMBAGCiqGSIb3Y2QGAgEEAgUAMA0GCSqGSIb3DQEBCwUAA4IBAQBaxDWi2eYK"
        "nlKiAIIid81yL5D5Iq8UJcyqCkJgksK9dR3rTMoV5X5rQBBe+1tFdA3wen2Ikc7eY4tCidIY"
        "30GzWJ4GCIdI3UCvI9Xt6yxg5eukfxzpnIPWlF9MYjmKTq4TjX1DuNxerL4YQPLmDyxdE5Px"
        "e2WowmhI3v+0lpsM+zI2np4NlV84CouW0hJst4sLjtc+7G8Bqs5NRWDbhHFmYuUZZTDNiv9F"
        "U/tu+4h3Q8NIY/n3UbNyXnniVs+8u4S5OFp4rhFIUrsNNYuU3sx0mmj1SWCUrPKosxWGkNDM"
        "MEOG0+VwAlG0gcCol9Tq6rCMCUDvOJOyzSID62dDZchF",
    ),
    (
        "AppleWWDRCAG6",
        "MIIDFjCCApygAwIBAgIUIsGhRwp0c2nvU4YSycafPTjzbNcwCgYIKoZIzj0EAwMwZzEbMBkG"
        "A1UEAwwSQXBwbGUgUm9vdCBDQSAtIEczMSYwJAYDVQQLDB1BcHBsZSBDZXJ0aWZpY2F0aW9u"
        "IEF1dGhvcml0eTETMBEGA1UECgwKQXBwbGUgSW5jLjELMAkGA1UEBhMCVVMwHhcNMjEwMzE3"
        "MjAzNzEwWhcNMzYwMzE5MDAwMDAwWjB1MUQwQgYDVQQDDDtBcHBsZSBXb3JsZHdpZGUgRGV2"
        "ZWxvcGVyIFJlbGF0aW9ucyBDZXJ0aWZpY2F0aW9uIEF1dGhvcml0eTELMAkGA1UECwwCRzYx"
        "EzARBgNVBAoMCkFwcGxlIEluYy4xCzAJBgNVBAYTAlVTMHYwEAYHKoZIzj0CAQYFK4EEACID"
        "YgAEbsQKC94PrlWmZXnXgtxzdVJL8T0SGYngDRGpngn3N6PT8JMEb7FDi4bBmPhCnZ3/sq6P"
        "F/cGcKXWsL5vOteRhyJ45x3ASP7cOB+aao90fcpxSv/EZFbniAbNgZGhIhpIo4H6MIH3MBIG"
        "A1UdEwEB/wQIMAYBAf8CAQAwHwYDVR0jBBgwFoAUu7DeoVgziJqkipnevr3rr9rLJKswRgYI"
        "KwYBBQUHAQEEOjA4MDYGCCsGAQUFBzABhipodHRwOi8vb2NzcC5hcHBsZS5jb20vb2NzcDAz"
        "LWFwcGxlcm9vdGNhZzMwNwYDVR0fBDAwLjAsoCqgKIYmaHR0cDovL2NybC5hcHBsZS5jb20v"
        "YXBwbGVyb290Y2FnMy5jcmwwHQYDVR0OBBYEFD8vlCNR01DJmig97bB85c+lkGKZMA4GA1Ud"
        "DwEB/wQEAwIBBjAQBgoqhkiG92NkBgIBBAIFADAKBggqhkjOPQQDAwNoADBlAjBAXhSq5IyK"
        "ogMCPtw490BaB677CaEGJXufQB/EqZGd6CSjiCtOnuMTbXVXmxxcxfkCMQDTSPxarZXvNrkx"
        "U3TkUMI33yzvFVVRT4wxWJC994OsdcZ4+RGNsYDyR5gmdr0nDGg=",
    ),
    (
        "AppleRootCA",
        "MIIEuzCCA6OgAwIBAgIBAjANBgkqhkiG9w0BAQUFADBiMQswCQYDVQQGEwJVUzETMBEGA1UE"
        "ChMKQXBwbGUgSW5jLjEmMCQGA1UECxMdQXBwbGUgQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkx"
        "FjAUBgNVBAMTDUFwcGxlIFJvb3QgQ0EwHhcNMDYwNDI1MjE0MDM2WhcNMzUwMjA5MjE0MDM2"
        "WjBiMQswCQYDVQQGEwJVUzETMBEGA1UEChMKQXBwbGUgSW5jLjEmMCQGA1UECxMdQXBwbGUg"
        "Q2VydGlmaWNhdGlvbiBBdXRob3JpdHkxFjAUBgNVBAMTDUFwcGxlIFJvb3QgQ0EwggEiMA0G"
        "CSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDkkakJH5HbHkdQ6wXtXnmELes2oldMVeyLGYne"
        "+Uts9QerIjAC6Bg++FAJ039BqJj50cpmnCRrEdCju+QbKsMflZ56DKRHi1vUFjczy8QPTc4U"
        "adHJGXL1XQ7Vf1+b8iUDulWPTV0N8WQ1IxVLFVkds5T39pyez1C6wVhQZ48ItCD3y6wsIG9w"
        "tj8BMIy3Q88PnT3zK0koGsj+zrW5DtleHNbLPbU6rfQPDgCSC7EhFi501TwN22IWq6NxkkdT"
        "VcGvL0Gz+PvjcM3mo0xFfh9Ma1CWQYnEdGILEINBhzOKgbEwWOxaBDKMaLOPHd5lc/9nXmW8"
        "Sdh2nzMUZaF3lMktAgMBAAGjggF6MIIBdjAOBgNVHQ8BAf8EBAMCAQYwDwYDVR0TAQH/BAUw"
        "AwEB/zAdBgNVHQ4EFgQUK9BpR5R2Cf70a40uQKb3R01/CF4wHwYDVR0jBBgwFoAUK9BpR5R2"
        "Cf70a40uQKb3R01/CF4wggERBgNVHSAEggEIMIIBBDCCAQAGCSqGSIb3Y2QFATCB8jAqBggr"
        "BgEFBQcCARYeaHR0cHM6Ly93d3cuYXBwbGUuY29tL2FwcGxlY2EvMIHDBggrBgEFBQcCAjCB"
        "thqBs1JlbGlhbmNlIG9uIHRoaXMgY2VydGlmaWNhdGUgYnkgYW55IHBhcnR5IGFzc3VtZXMg"
        "YWNjZXB0YW5jZSBvZiB0aGUgdGhlbiBhcHBsaWNhYmxlIHN0YW5kYXJkIHRlcm1zIGFuZCBj"
        "b25kaXRpb25zIG9mIHVzZSwgY2VydGlmaWNhdGUgcG9saWN5IGFuZCBjZXJ0aWZpY2F0aW9u"
        "IHByYWN0aWNlIHN0YXRlbWVudHMuMA0GCSqGSIb3DQEBBQUAA4IBAQBcNplMLXi37Yyb3PN3"
        "m/J20ncwT8EfhYOFG5k9RzfyqZtAjizUsZAS2L70c5vu0mQPy3lPNNiiPvl4/2vIB+x9OYOL"
        "UyDTOMSxv5pPCmv/K/xZpwUJfBdAVhEedNO3iyM7R6PVbyTi69G3cN8PReEnyvFteO3ntRcX"
        "qNx+IjXKJdXZD9Zr1KIkIxH3oayPc4FgxhtbCS+SsvhESPBgOJ4V9T0mZyCKM2r3DYLP3uuj"
        "L/lTaltkwGMzd/c6ByxW69oPIQ7aunMZT7XZNn/Bh1XZp5m5MkL72NVxnn6hUrcbvZNCJBIq"
        "xw8dtk2cXmPIS4AXUKqK1drk/NAJBzewdXUh",
    ),
    (
        "AppleRootCAG3",
        "MIICQzCCAcmgAwIBAgIILcX8iNLFS5UwCgYIKoZIzj0EAwMwZzEbMBkGA1UEAwwSQXBwbGUg"
        "Um9vdCBDQSAtIEczMSYwJAYDVQQLDB1BcHBsZSBDZXJ0aWZpY2F0aW9uIEF1dGhvcml0eTET"
        "MBEGA1UECgwKQXBwbGUgSW5jLjELMAkGA1UEBhMCVVMwHhcNMTQwNDMwMTgxOTA2WhcNMzkw"
        "NDMwMTgxOTA2WjBnMRswGQYDVQQDDBJBcHBsZSBSb290IENBIC0gRzMxJjAkBgNVBAsMHUFw"
        "cGxlIENlcnRpZmljYXRpb24gQXV0aG9yaXR5MRMwEQYDVQQKDApBcHBsZSBJbmMuMQswCQYD"
        "VQQGEwJVUzB2MBAGByqGSM49AgEGBSuBBAAiA2IABJjpLz1AcqTtkyJygRMc3RCV8cWjTnHc"
        "FBbZDuWmBSp3ZHtfTjjTuxxEtX/1H7YyYl3J6YRbTzBPEVoA/VhYDKX1DyxNB0cTddqXl5dv"
        "MVztK517IDvYuVTZXpmkOlEKMaNCMEAwHQYDVR0OBBYEFLuw3qFYM4iapIqZ3r6966/ayySr"
        "MA8GA1UdEwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQDAgEGMAoGCCqGSM49BAMDA2gAMGUCMQCD"
        "6cHEFl4aXTQY2e3v9GwOAEZLuN+yRhHFD/3meoyhpmvOwgPUnPWTxnS4at+qIxUCMG1mihDK"
        "1A3UT82NQz60imOlM27jbdoXt2QfyFMm+YhidDkLF1vLUagM6BgD56KyKA==",
    ),
]

_CA_CACHE = None

RULES_V1 = {
    "^.*": True,
    "^.*\\.lproj/": {"optional": True, "weight": 1000.0},
    "^.*\\.lproj/locversion.plist$": {"omit": True, "weight": 1100.0},
    "^Base\\.lproj/": {"weight": 1010.0},
    "^version.plist$": True,
}

RULES_V2 = {
    ".*\\.dSYM($|/)": {"weight": 11.0},
    "^(.*/)?\\.DS_Store$": {"omit": True, "weight": 2000.0},
    "^.*": True,
    "^.*\\.lproj/": {"optional": True, "weight": 1000.0},
    "^.*\\.lproj/locversion.plist$": {"omit": True, "weight": 1100.0},
    "^Base\\.lproj/": {"weight": 1010.0},
    "^Info\\.plist$": {"omit": True, "weight": 20.0},
    "^PkgInfo$": {"omit": True, "weight": 20.0},
    "^embedded\\.provisionprofile$": {"weight": 20.0},
    "^version\\.plist$": {"weight": 20.0},
}


class SigningError(Exception):
    pass


# --- IPA Inspection (Extensions, Bundle ID, Display Name) -------------------

def inspect_ipa(ipa_path):
    """Inspect an IPA without extracting it to disk.

    Returns a dict with:
      - name, bundle_id, version, build, icon_name
      - extensions: list of {folder, name, bundle_id}
      - has_extensions: bool
    """
    try:
        with zipfile.ZipFile(ipa_path) as archive:
            names = archive.namelist()
            main_infos = [
                n
                for n in names
                if n.startswith("Payload/")
                and n.endswith(".app/Info.plist")
                and n.count("/") == 2
            ]
            if not main_infos:
                raise SigningError("No Payload/*.app/Info.plist found in IPA.")
            main_info_path = main_infos[0]
            app_prefix = main_info_path[:-len("Info.plist")]
            info = plistlib.loads(archive.read(main_info_path))
            bundle_id = info.get("CFBundleIdentifier") or ""
            app_name = (
                info.get("CFBundleDisplayName")
                or info.get("CFBundleName")
                or bundle_id.rsplit(".", 1)[-1]
            )
            version = (
                info.get("CFBundleShortVersionString")
                or info.get("CFBundleVersion")
                or "1.0"
            )
            build = info.get("CFBundleVersion") or version

            extensions = []
            for entry in sorted(names):
                if (
                    entry.startswith(app_prefix)
                    and entry.endswith(".appex/Info.plist")
                ):
                    try:
                        ext_info = plistlib.loads(archive.read(entry))
                        ext_folder = os.path.basename(os.path.dirname(entry))
                        ext_bid = ext_info.get("CFBundleIdentifier") or ""
                        ext_name = (
                            ext_info.get("CFBundleDisplayName")
                            or ext_info.get("CFBundleName")
                            or ext_folder[:-6]
                        )
                        extensions.append(
                            {
                                "folder": ext_folder,
                                "name": ext_name,
                                "bundle_id": ext_bid,
                            }
                        )
                    except Exception:
                        continue

            return {
                "name": app_name,
                "bundle_id": bundle_id,
                "version": version,
                "build": build,
                "extensions": extensions,
                "has_extensions": len(extensions) > 0,
            }
    except SigningError:
        raise
    except Exception as exc:
        raise SigningError("Could not inspect IPA: %s" % exc)


# --- DER Helpers ------------------------------------------------------------

def der_length(size):
    if size < 0x80:
        return bytes([size])
    raw = size.to_bytes((size.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(raw)]) + raw


def der(tag, content):
    return bytes([tag]) + der_length(len(content)) + content


def der_integer(value, minimal=True):
    if value < 0:
        raise SigningError("negative integers are not used here")
    if value == 0:
        raw = b"\x00"
    else:
        raw = value.to_bytes((value.bit_length() + 7) // 8, "big")
        if minimal and raw[0] & 0x80:
            raw = b"\x00" + raw
    return der(0x02, raw)


def der_oid(dotted):
    parts = [int(part) for part in dotted.split(".")]
    if len(parts) < 2:
        raise SigningError("bad OID %r" % dotted)
    body = bytearray([parts[0] * 40 + parts[1]])
    for part in parts[2:]:
        chunks = []
        while True:
            chunks.insert(0, part & 0x7F)
            part >>= 7
            if not part:
                break
        for index in range(len(chunks) - 1):
            chunks[index] |= 0x80
        body.extend(chunks)
    return der(0x06, bytes(body))


def der_read(data, offset=0, depth=0):
    if depth > 16:
        raise SigningError("DER nested too deeply")
    if offset >= len(data):
        raise SigningError("truncated DER")
    tag = data[offset]
    offset += 1
    if offset >= len(data):
        raise SigningError("truncated DER length")
    first = data[offset]
    offset += 1
    if first == 0x80:
        start = offset
        position = offset
        while True:
            if position + 2 > len(data):
                raise SigningError("unterminated indefinite-length value")
            if data[position] == 0x00 and data[position + 1] == 0x00:
                return tag, data[start:position], position + 2
            _tag, _value, position = der_read(data, position, depth + 1)
    if first & 0x80:
        count = first & 0x7F
        if count > 4 or offset + count > len(data):
            raise SigningError("truncated DER length")
        size = int.from_bytes(data[offset:offset + count], "big")
        offset += count
    else:
        size = first
    end = offset + size
    if end > len(data):
        raise SigningError("truncated DER value")
    return tag, data[offset:end], end


def der_children(content):
    items = []
    offset = 0
    while offset < len(content):
        tag, value, offset = der_read(content, offset)
        items.append((tag, value))
    return items


def der_encode(tag, content):
    return der(tag, content)


# --- Plists, Profiles, Certificates -----------------------------------------

def read_plist(path):
    try:
        with open(path, "rb") as handle:
            raw = handle.read()
    except OSError as exc:
        raise SigningError("cannot read %s: %s" % (path, exc))
    try:
        return plistlib.loads(raw), raw
    except Exception as exc:
        raise SigningError("not a property list: %s (%s)" % (path, str(exc)[:80]))


def write_plist(path, value, prefer_binary):
    fmt = plistlib.FMT_BINARY if prefer_binary else plistlib.FMT_XML
    data = plistlib.dumps(value, fmt=fmt, sort_keys=True)
    with open(path, "wb") as handle:
        handle.write(data)
    return data


def parse_mobileprovision_blob(blob):
    for marker in (b"<?xml", b"<!DOCTYPE plist", b"<plist"):
        text = blob.find(marker)
        if text >= 0:
            end = blob.find(b"</plist>", text)
            if end >= 0:
                try:
                    return plistlib.loads(blob[text:end + len(b"</plist>")])
                except Exception as exc:
                    raise SigningError("the profile's plist is unreadable: %s" % (exc,))
            break
    binary = blob.find(b"bplist00")
    if binary >= 0:
        try:
            return plistlib.loads(blob[binary:])
        except Exception as exc:
            raise SigningError("the profile's plist is unreadable: %s" % (exc,))
    try:
        return plistlib.loads(blob)
    except Exception:
        raise SigningError("this is not a provisioning profile")


def _profile_datetime(value):
    if not isinstance(value, datetime.datetime):
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=datetime.timezone.utc)
    return value


def install_preflight(profile, udid=""):
    problems = []
    now = datetime.datetime.now(datetime.timezone.utc)
    expires = _profile_datetime(profile.get("ExpirationDate"))
    if expires is None:
        problems.append("the profile has no ExpirationDate")
    elif expires < now:
        problems.append("the provisioning profile expired on %s" % expires.date())
    devices = profile.get("ProvisionedDevices") or []
    if devices and udid:
        normal = lambda value: "".join(
            ch for ch in (value or "").lower() if ch in "0123456789abcdef"
        )
        if not any(normal(device) == normal(udid) for device in devices):
            problems.append("this profile does not include this device (%s)" % udid)
    certs = profile.get("DeveloperCertificates") or []
    seen_valid = False
    latest = None
    for item in certs:
        try:
            cert = x509.load_der_x509_certificate(bytes(item))
        except Exception:
            continue
        try:
            not_after = cert.not_valid_after_utc
        except AttributeError:
            not_after = cert.not_valid_after
            if not_after.tzinfo is None:
                not_after = not_after.replace(tzinfo=datetime.timezone.utc)
        if latest is None or not_after > latest:
            latest = not_after
        if not_after >= now:
            seen_valid = True
    if certs and not seen_valid:
        problems.append(
            "the profile's certificate expired on %s" % (latest.date() if latest else "?")
        )
    return problems


def read_mobileprovision(path):
    try:
        with open(path, "rb") as handle:
            blob = handle.read()
    except OSError as exc:
        raise SigningError("cannot read the profile %s: %s" % (path, exc))
    try:
        return parse_mobileprovision_blob(blob)
    except SigningError as exc:
        raise SigningError("%s: %s" % (path, exc))


def load_certificate(path):
    try:
        with open(path, "rb") as handle:
            raw = handle.read()
    except OSError as exc:
        raise SigningError("cannot read the certificate %s: %s" % (path, exc))
    try:
        if raw.lstrip().startswith(b"-----BEGIN"):
            return x509.load_pem_x509_certificate(raw)
        return x509.load_der_x509_certificate(raw)
    except Exception as exc:
        raise SigningError("not an X.509 certificate: %s (%s)" % (path, str(exc)[:80]))


def load_private_key(path):
    try:
        with open(path, "rb") as handle:
            raw = handle.read()
    except OSError as exc:
        raise SigningError("cannot read the key %s: %s" % (path, exc))
    try:
        return serialization.load_pem_private_key(raw, password=None)
    except Exception as exc:
        raise SigningError("not a usable private key: %s (%s)" % (path, str(exc)[:80]))


def apple_cas():
    global _CA_CACHE
    if _CA_CACHE is None:
        result = []
        for name, encoded in APPLE_CA_DER:
            der_bytes = base64.b64decode(encoded)
            result.append((name, x509.load_der_x509_certificate(der_bytes)))
        _CA_CACHE = result
    return _CA_CACHE


def _verify_with(key, signature, data, digest):
    if isinstance(key, rsa.RSAPublicKey):
        key.verify(signature, data, padding.PKCS1v15(), digest)
    elif isinstance(key, ec.EllipticCurvePublicKey):
        key.verify(signature, data, ec.ECDSA(digest))
    else:
        raise SigningError("unsupported certificate key type: %r" % (key,))


def certificate_chain(leaf):
    chain = [leaf]
    current = leaf
    for _ in range(2):
        issuer_name = current.issuer
        found = None
        for _name, candidate in apple_cas():
            if candidate.subject != issuer_name:
                continue
            try:
                _verify_with(
                    candidate.public_key(),
                    current.signature,
                    current.tbs_certificate_bytes,
                    current.signature_hash_algorithm,
                )
            except Exception:
                continue
            found = candidate
            break
        if found is None:
            if current.subject == current.issuer:
                break
            names = issuer_name.rfc4514_string()
            raise SigningError(
                'This certificate was issued by "%s", which is not one of the Apple CAs built into BariStore.'
                % names[:90]
            )
        chain.append(found)
        if found.subject == found.issuer:
            break
        current = found
    return chain


# --- CMS SignedData & Entitlements ------------------------------------------

def _attribute(oid, values):
    return der(0x30, der_oid(oid) + der(0x31, b"".join(values)))


def _algorithm(oid):
    return der(0x30, der_oid(oid) + b"\x05\x00")


def _cdhash_plist(digest):
    value = {"cdhashes": [digest[:20]]}
    return plistlib.dumps(value, fmt=plistlib.FMT_XML, sort_keys=True)


def build_cms(code_directory, leaf, chain, key):
    digest = hashlib.sha256(code_directory).digest()
    _tag, cert_body, _end = der_read(leaf.public_bytes(serialization.Encoding.DER), 0)
    _tbs_tag, tbs_body, _ = der_read(cert_body, 0)
    items = der_children(tbs_body)
    index = 1 if items[0][0] == 0xA0 else 0
    serial_tag, serial_value = items[index]
    issuer_tag, issuer_value = items[index + 2]
    issuer_and_serial = der(
        0x30, der_encode(issuer_tag, issuer_value) + der(serial_tag, serial_value)
    )

    attributes = [
        _attribute(OID_CONTENT_TYPE, [der_oid(OID_DATA)]),
        _attribute(
            OID_SIGNING_TIME,
            [der(0x17, time.strftime("%y%m%d%H%M%SZ", time.gmtime()).encode())],
        ),
        _attribute(OID_MESSAGE_DIGEST, [der(0x04, digest)]),
        _attribute(OID_CDHASHES, [der(0x30, der_oid(OID_SHA256) + der(0x04, digest))]),
        _attribute(OID_CDHASHES_PLIST, [der(0x04, _cdhash_plist(digest))]),
    ]
    attributes.sort()
    signed_attrs = der(0x31, b"".join(attributes))
    signature = key.sign(signed_attrs, padding.PKCS1v15(), hashes.SHA256())

    signer_info = der(
        0x30,
        der_integer(1)
        + issuer_and_serial
        + _algorithm(OID_SHA256)
        + der(0xA0, b"".join(attributes))
        + _algorithm(OID_RSA)
        + der(0x04, signature),
    )
    certificates = sorted(
        cert.public_bytes(serialization.Encoding.DER) for cert in chain
    )
    signed_data = der(
        0x30,
        der_integer(1)
        + der(0x31, _algorithm(OID_SHA256))
        + der(0x30, der_oid(OID_DATA))
        + der(0xA0, b"".join(certificates))
        + der(0x31, signer_info),
    )
    return der(0x30, der_oid(OID_SIGNED_DATA) + der(0xA0, signed_data))


def der_plist_value(value):
    if isinstance(value, bool):
        return der(0x01, b"\xff" if value else b"\x00")
    if isinstance(value, str):
        return der(0x0C, value.encode("utf-8"))
    if isinstance(value, int):
        return der_integer(value)
    if isinstance(value, (bytes, bytearray)):
        return der(0x04, bytes(value))
    if isinstance(value, list):
        return der(0x30, b"".join(der_plist_value(item) for item in value))
    if isinstance(value, dict):
        return der(0xB0, _der_plist_entries(value))
    raise SigningError("this entitlement value cannot be encoded: %r" % (value,))


def _der_plist_entries(mapping):
    entries = []
    for name in sorted(mapping):
        entries.append(
            der(0x30, der(0x0C, name.encode("utf-8")) + der_plist_value(mapping[name]))
        )
    return b"".join(entries)


def der_entitlements(value):
    return der(0x70, der_integer(1) + der(0xB0, _der_plist_entries(value)))


def entitlements_xml(value):
    return plistlib.dumps(value, fmt=plistlib.FMT_XML, sort_keys=True)


# --- CodeDirectory, Requirements, SuperBlob ---------------------------------

def _blob(magic, payload):
    return struct.pack(">II", magic, len(payload) + 8) + payload


def _padded_bytes(raw):
    padding_bytes = (4 - len(raw) % 4) % 4
    return struct.pack(">I", len(raw)) + raw + b"\x00" * padding_bytes


def _padded_string(text):
    return _padded_bytes(text.encode("utf-8"))


def build_requirements(identifier, common_name):
    wwdr = bytes([0x2A, 0x86, 0x48, 0x86, 0xF7, 0x63, 0x64, 0x06, 0x02, 0x01])
    expression = struct.pack(">I", 1)
    expression += struct.pack(">I", 6) + struct.pack(">I", 2) + _padded_string(identifier)
    expression += struct.pack(">I", 6) + struct.pack(">I", 15)
    expression += struct.pack(">I", 6) + struct.pack(">I", 11) + struct.pack(">I", 0)
    expression += _padded_string("subject.CN") + struct.pack(">I", 1) + _padded_string(common_name)
    expression += struct.pack(">I", 14) + struct.pack(">I", 1) + _padded_bytes(wwdr)
    expression += struct.pack(">I", 0)

    inner = _blob(CSMAGIC_REQUIREMENT, expression)
    body = struct.pack(">III", CSMAGIC_REQUIREMENTS, 20 + len(inner), 1)
    body += struct.pack(">II", 3, 20)
    return body + inner


def build_code_directory(
    identifier, team, code_limit, specials, page_hashes, exec_base, exec_limit, exec_flags
):
    ident = identifier.encode("utf-8") + b"\x00"
    team_bytes = team.encode("utf-8") + b"\x00" if team else b""
    highest = max(specials) if specials else 0

    header_size = 0x58
    ident_offset = header_size
    team_offset = header_size + len(ident) if team else 0
    digest_offset = header_size + len(ident) + len(team_bytes) + highest * 32
    total_size = digest_offset + len(page_hashes) * 32

    data = bytearray()
    data += struct.pack(
        ">IIIIIIIII",
        CSMAGIC_CODEDIRECTORY,
        total_size,
        0x20400,
        0,
        digest_offset,
        ident_offset,
        highest,
        len(page_hashes),
        code_limit,
    )
    data += struct.pack(">BBBB", 32, 2, 0, PAGE_SHIFT)
    data += struct.pack(">IIII", 0, 0, team_offset, 0)
    data += struct.pack(">QQQ", 0, exec_base, exec_limit)
    data += struct.pack(">Q", exec_flags)

    data += ident
    data += team_bytes
    for slot in range(highest, 0, -1):
        data += specials.get(slot, b"\x00" * 32)
    for digest in page_hashes:
        data += digest
    return bytes(data)


def build_superblob(blobs):
    blobs = sorted(blobs, key=lambda item: item[0])
    index_size = 12 + 8 * len(blobs)
    index = b""
    body = b""
    for slot, payload in blobs:
        index += struct.pack(">II", slot, index_size + len(body))
        body += payload
    total = index_size + len(body)
    return struct.pack(">III", CSMAGIC_EMBEDDED_SIGNATURE, total, len(blobs)) + index + body


# --- Mach-O Rewriting -------------------------------------------------------

def is_macho(data):
    if len(data) < 8:
        return False
    magic = data[:4]
    return magic in (
        b"\xcf\xfa\xed\xfe",
        b"\xfe\xed\xfa\xcf",
        b"\xce\xfa\xed\xfe",
        b"\xfe\xed\xfa\xce",
        b"\xca\xfe\xba\xbe",
        b"\xbe\xba\xfe\xca",
        b"\xca\xfe\xba\xbf",
        b"\xbf\xba\xfe\xca",
    )


def looks_like_macho_file(path):
    try:
        with open(path, "rb") as handle:
            return is_macho(handle.read(8))
    except OSError:
        return False


def _u32(data, offset, little):
    return struct.unpack_from("<I" if little else ">I", data, offset)[0]


def _u64(data, offset, little):
    return struct.unpack_from("<Q" if little else ">Q", data, offset)[0]


class ThinMachO:
    def __init__(self, data):
        self.data = data
        if len(data) < 32:
            raise SigningError("a Mach-O file is truncated")
        raw = data[:4]
        if raw == b"\xcf\xfa\xed\xfe":
            self.little, self.bits = True, 64
        elif raw == b"\xfe\xed\xfa\xcf":
            self.little, self.bits = False, 64
        elif raw in (b"\xce\xfa\xed\xfe", b"\xfe\xed\xfa\xce"):
            raise SigningError("this IPA contains a 32-bit binary; iOS 27 cannot run it")
        else:
            raise SigningError("not a Mach-O file")

        self.filetype = _u32(data, 12, self.little)
        self.ncmds = _u32(data, 16, self.little)
        self.sizeofcmds = _u32(data, 20, self.little)
        self.header_size = 32
        self.commands = []
        self.segments = {}
        self.section_offsets = []
        self.code_signature = None
        self.uuid = None

        offset = self.header_size
        end = self.header_size + self.sizeofcmds
        if end > len(data):
            raise SigningError("a Mach-O load-command table runs past the file")
        for _ in range(self.ncmds):
            if offset + 8 > end:
                raise SigningError("a Mach-O load command is truncated")
            command = _u32(data, offset, self.little)
            size = _u32(data, offset + 4, self.little)
            if size < 8 or offset + size > end:
                raise SigningError("a Mach-O load command has a bad size")
            self.commands.append((command, size, offset))
            if command == LC_SEGMENT_64:
                name = data[offset + 8:offset + 24].rstrip(b"\x00").decode("latin-1")
                vmaddr = _u64(data, offset + 24, self.little)
                vmsize = _u64(data, offset + 32, self.little)
                fileoff = _u64(data, offset + 40, self.little)
                filesize = _u64(data, offset + 48, self.little)
                count = _u32(data, offset + 64, self.little)
                self.segments[name] = {
                    "vmaddr": vmaddr,
                    "vmsize": vmsize,
                    "fileoff": fileoff,
                    "filesize": filesize,
                    "offset": offset,
                    "nsects": count,
                }
                for index in range(count):
                    section = offset + 72 + index * 80
                    if section + 80 > offset + size:
                        break
                    section_offset = _u32(data, section + 48, self.little)
                    if section_offset:
                        self.section_offsets.append(section_offset)
            elif command == LC_CODE_SIGNATURE:
                if size < 16:
                    raise SigningError("LC_CODE_SIGNATURE is malformed")
                dataoff = _u32(data, offset + 8, self.little)
                datasize = _u32(data, offset + 12, self.little)
                self.code_signature = {
                    "dataoff": dataoff,
                    "datasize": datasize,
                    "offset": offset,
                }
            elif command == LC_UUID and size >= 24:
                self.uuid = data[offset + 8:offset + 24].hex().upper()
            offset += size

    def segment(self, name):
        try:
            return self.segments[name]
        except KeyError:
            raise SigningError("this Mach-O has no %s segment" % name)

    def executable_bounds(self):
        text = self.segment("__TEXT")
        return text["fileoff"], text["fileoff"] + text["filesize"]

    def signature_start(self):
        linkedit = self.segment("__LINKEDIT")
        last = max(self.segments.values(), key=lambda seg: seg["fileoff"])
        if last is not linkedit:
            raise SigningError("__LINKEDIT is not the last segment")
        if self.code_signature:
            dataoff = self.code_signature["dataoff"]
            datasize = self.code_signature["datasize"]
            if dataoff + datasize != len(self.data):
                raise SigningError("existing signature is not at the end of the binary")
            if dataoff < linkedit["fileoff"]:
                raise SigningError("existing signature is outside __LINKEDIT")
            if linkedit["fileoff"] + linkedit["filesize"] != len(self.data):
                raise SigningError("__LINKEDIT does not end at the end of the file")
            return dataoff
        if linkedit["fileoff"] + linkedit["filesize"] != len(self.data):
            raise SigningError("binary has data after __LINKEDIT")
        return len(self.data)

    def can_add_command(self):
        first = min(self.section_offsets) if self.section_offsets else None
        if first is None:
            raise SigningError("binary has no sections")
        return first - (self.header_size + self.sizeofcmds) >= 16


def page_digests(data, code_limit):
    return [
        hashlib.sha256(data[start:start + PAGE_SIZE]).digest()
        for start in range(0, code_limit, PAGE_SIZE)
    ]


def patch_macho(mach, dataoff, datasize, add_command):
    data = bytearray(mach.data)
    linkedit = mach.segment("__LINKEDIT")

    if add_command:
        if not mach.can_add_command():
            raise SigningError("this Mach-O has no room for a signature load command")
        position = mach.header_size + mach.sizeofcmds
        struct.pack_into("<I" if mach.little else ">I", data, 16, mach.ncmds + 1)
        struct.pack_into("<I" if mach.little else ">I", data, 20, mach.sizeofcmds + 16)
        fmt = "<IIII" if mach.little else ">IIII"
        struct.pack_into(fmt, data, position, LC_CODE_SIGNATURE, 16, dataoff, datasize)
    else:
        command = mach.code_signature
        fmt = "<II" if mach.little else ">II"
        struct.pack_into(fmt, data, command["offset"] + 8, dataoff, datasize)

    new_size = (dataoff - linkedit["fileoff"]) + datasize
    rounded = (new_size + 16383) & ~16383
    vmsize = max(linkedit["vmsize"], rounded)
    u64 = "<Q" if mach.little else ">Q"
    struct.pack_into(u64, data, linkedit["offset"] + 32, vmsize)
    struct.pack_into(u64, data, linkedit["offset"] + 48, new_size)
    return data


def _sign_thin(
    data, identifier, team, entitlements, code_resources, info_plist, leaf, chain, key
):
    mach = ThinMachO(data)
    if team is None:
        team = ""

    code_end = mach.signature_start()
    dataoff = (code_end + 15) & ~15
    add_command = mach.code_signature is None

    info_blob = hashlib.sha256(info_plist).digest() if info_plist is not None else None
    resource_blob = (
        hashlib.sha256(code_resources).digest() if code_resources is not None else None
    )
    entitle_blob = None
    der_blob = None
    if entitlements is not None:
        entitle_blob = _blob(CSMAGIC_EMBEDDED_ENTITLEMENTS, entitlements_xml(entitlements))
        der_blob = _blob(CSMAGIC_EMBEDDED_DER_ENTITLEMENTS, der_entitlements(entitlements))

    common_name = ""
    for attribute in leaf.subject.get_attributes_for_oid(NameOID.COMMON_NAME):
        common_name = attribute.value
        break
    requirements = build_requirements(identifier, common_name)

    exec_base, exec_limit = mach.executable_bounds()
    exec_flags = 0
    if mach.filetype == MH_EXECUTE:
        exec_flags = CS_EXECSEG_MAIN_BINARY
        if entitlements:
            if entitlements.get("com.apple.private.amfi.can-load-cdhash"):
                exec_flags |= CS_EXECSEG_CAN_LOAD_CDHASH
            if entitlements.get("com.apple.private.amfi.can-execute-cdhash"):
                exec_flags |= CS_EXECSEG_CAN_EXEC_CDHASH

    specials = {CSSLOT_REQUIREMENTS: hashlib.sha256(requirements).digest()}
    if info_blob is not None:
        specials[CSSLOT_INFOSLOT] = info_blob
    if resource_blob is not None:
        specials[CSSLOT_RESOURCEDIR] = resource_blob
    if entitle_blob is not None:
        specials[CSSLOT_ENTITLEMENTS] = hashlib.sha256(entitle_blob).digest()
        specials[CSSLOT_DER_ENTITLEMENTS] = hashlib.sha256(der_blob).digest()

    predicted = 0
    superblob = b""
    for _attempt in range(4):
        patched = patch_macho(mach, dataoff, predicted, add_command)
        body = bytes(patched[:code_end]) + b"\x00" * (dataoff - code_end)
        hashes_list = page_digests(body, dataoff)
        code_directory = build_code_directory(
            identifier,
            team,
            dataoff,
            specials,
            hashes_list,
            exec_base,
            exec_limit,
            exec_flags,
        )
        blobs = [
            (CSSLOT_CODEDIRECTORY, code_directory),
            (CSSLOT_REQUIREMENTS, requirements),
        ]
        if entitle_blob is not None:
            blobs.append((CSSLOT_ENTITLEMENTS, entitle_blob))
            blobs.append((CSSLOT_DER_ENTITLEMENTS, der_blob))
        blobs.append(
            (
                CSSLOT_SIGNATURESLOT,
                _blob(CSMAGIC_BLOBWRAPPER, build_cms(code_directory, leaf, chain, key)),
            )
        )
        superblob = build_superblob(blobs)
        superblob += b"\x00" * ((16 - len(superblob) % 16) % 16)
        if len(superblob) == predicted:
            break
        predicted = len(superblob)
    else:
        raise SigningError("signature size did not settle for %s" % identifier)

    patched = patch_macho(mach, dataoff, len(superblob), add_command)
    return bytes(patched[:code_end]) + b"\x00" * (dataoff - code_end) + superblob


def _split_fat(data):
    magic = struct.unpack_from(">I", data, 0)[0]
    if magic not in (FAT_MAGIC, FAT_MAGIC_64):
        return None
    if magic == FAT_MAGIC_64:
        raise SigningError("this IPA contains a 64-bit fat binary")
    count = struct.unpack_from(">I", data, 4)[0]
    if count > 16:
        raise SigningError("implausible fat slice count")
    slices = []
    for index in range(count):
        base = 8 + index * 20
        cpu, subtype, offset, size, align = struct.unpack_from(">IIIII", data, base)
        if offset + size > len(data):
            raise SigningError("fat binary slice runs past the file")
        slices.append(
            {
                "cpu": cpu,
                "subtype": subtype,
                "offset": offset,
                "size": size,
                "align": align,
                "data": data[offset:offset + size],
            }
        )
    return slices


def _join_fat(slices):
    count = len(slices)
    header_size = 8 + count * 20
    for item in slices:
        item["align"] = max(item["align"], 4)
    position = header_size
    placements = []
    for item in slices:
        boundary = 1 << item["align"]
        position = (position + boundary - 1) & ~(boundary - 1)
        placements.append((position, item))
        position += len(item["data"])
    out = bytearray(struct.pack(">II", FAT_MAGIC, count))
    for position, item in placements:
        out += struct.pack(
            ">IIIII",
            item["cpu"],
            item["subtype"],
            position,
            len(item["data"]),
            item["align"],
        )
    for position, item in placements:
        if len(out) < position:
            out += b"\x00" * (position - len(out))
        out += item["data"]
    return bytes(out)


def sign_macho_bytes(
    data, identifier, team, entitlements, code_resources, info_plist, leaf, chain, key
):
    slices = _split_fat(data)
    if slices is None:
        return _sign_thin(
            data,
            identifier,
            team,
            entitlements,
            code_resources,
            info_plist,
            leaf,
            chain,
            key,
        )
    signed = []
    for item in slices:
        item = dict(item)
        item["data"] = _sign_thin(
            item["data"],
            identifier,
            team,
            entitlements,
            code_resources,
            info_plist,
            leaf,
            chain,
            key,
        )
        signed.append(item)
    return _join_fat(signed)


# --- CodeResources & Bundles ------------------------------------------------

def _is_omitted(relative):
    name = relative.rsplit("/", 1)[-1]
    if name == ".DS_Store" or relative.endswith(".lproj/locversion.plist"):
        return "both"
    if relative in ("Info.plist", "PkgInfo"):
        return "v2"
    return ""


def build_code_resources(bundle_dir, main_executable):
    files = {}
    files2 = {}
    root = os.path.abspath(bundle_dir)
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames.sort()
        relative_dir = os.path.relpath(dirpath, root)
        if relative_dir == ".":
            relative_dir = ""
        relative_dir = relative_dir.replace(os.sep, "/")
        if relative_dir.split("/")[0] == "_CodeSignature":
            dirnames[:] = []
            continue
        for name in sorted(filenames):
            relative = (relative_dir + "/" + name) if relative_dir else name
            absolute = os.path.join(dirpath, name)
            if relative == main_executable:
                continue
            omit = _is_omitted(relative)
            if os.path.islink(absolute):
                if omit != "v2":
                    files2[relative] = {
                        "symlink": os.readlink(absolute).replace(os.sep, "/")
                    }
                continue
            with open(absolute, "rb") as handle:
                payload = handle.read()
            if omit != "both":
                files[relative] = hashlib.sha1(payload).digest()
            if omit != "v2":
                files2[relative] = {"hash2": hashlib.sha256(payload).digest()}
    resources = {
        "files": files,
        "files2": files2,
        "rules": dict(RULES_V1),
        "rules2": dict(RULES_V2),
    }
    return plistlib.dumps(resources, fmt=plistlib.FMT_XML, sort_keys=True)


BUNDLE_SUFFIXES = (".app", ".appex", ".framework")


def _bundle_info(bundle_dir):
    info_path = os.path.join(bundle_dir, "Info.plist")
    if not os.path.isfile(info_path):
        return None
    try:
        info, raw = read_plist(info_path)
    except SigningError:
        return None
    executable = info.get("CFBundleExecutable")
    if not executable:
        return None
    executable_path = os.path.join(bundle_dir, executable)
    if not os.path.isfile(executable_path):
        raise SigningError(
            "%s says CFBundleExecutable=%s, but that file is missing"
            % (os.path.basename(bundle_dir), executable)
        )
    return info, raw, executable_path, executable


def _nested_bundles(bundle_dir):
    found = []
    for dirpath, dirnames, _filenames in os.walk(bundle_dir):
        dirnames.sort()
        keep = []
        for name in dirnames:
            full = os.path.join(dirpath, name)
            if name.endswith(BUNDLE_SUFFIXES) and _bundle_info(full) is not None:
                found.append(full)
            else:
                keep.append(name)
        dirnames[:] = keep
    return found


def _all_bundles(bundle_dir):
    found = []
    for child in _nested_bundles(bundle_dir):
        found.append(child)
        found.extend(_all_bundles(child))
    return found


def _inside_nested(path, nested):
    for parent in nested:
        if path == parent or path.startswith(parent + os.sep):
            return True
    return False


def _sign_loose_binaries(bundle_dir, nested, main_executable, config):
    for dirpath, dirnames, filenames in os.walk(bundle_dir):
        dirnames.sort()
        dirnames[:] = [
            name
            for name in dirnames
            if not _inside_nested(os.path.join(dirpath, name), nested)
        ]
        for name in sorted(filenames):
            absolute = os.path.join(dirpath, name)
            relative = os.path.relpath(absolute, bundle_dir).replace(os.sep, "/")
            if relative == main_executable or os.path.islink(absolute):
                continue
            if not looks_like_macho_file(absolute):
                continue
            with open(absolute, "rb") as handle:
                data = handle.read()
            uuid_str = (
                ThinMachO(data).uuid
                if data[:4] in (b"\xcf\xfa\xed\xfe", b"\xfe\xed\xfa\xcf")
                else None
            )
            identifier = name + ("-" + uuid_str if uuid_str else "")
            signed = sign_macho_bytes(
                data,
                identifier,
                config["team"],
                None,
                None,
                None,
                config["leaf"],
                config["chain"],
                config["key"],
            )
            with open(absolute, "wb") as handle:
                handle.write(signed)
            config["binaries"] += 1


def prepare_bundle_ids(app_dir, new_app_id, config, custom_display_name=None):
    info, _raw, _exe, _name = _bundle_info(app_dir)
    old_app_id = info.get("CFBundleIdentifier")
    if not old_app_id:
        raise SigningError("the app's Info.plist has no CFBundleIdentifier")

    def rewrite(bundle_dir, target, previous, display_name=None):
        loaded, raw_bytes, _executable_path, _executable = _bundle_info(bundle_dir)
        if not loaded:
            return
        loaded["CFBundleIdentifier"] = target
        if display_name:
            loaded["CFBundleDisplayName"] = display_name
            loaded["CFBundleName"] = display_name
        tasks = loaded.get("BGTaskSchedulerPermittedIdentifiers")
        if isinstance(tasks, list):
            loaded["BGTaskSchedulerPermittedIdentifiers"] = [
                task.replace(previous, target, 1) if isinstance(task, str) else task
                for task in tasks
            ]
        write_plist(
            os.path.join(bundle_dir, "Info.plist"),
            loaded,
            raw_bytes[:8] == b"bplist00",
        )

    rewrite(app_dir, new_app_id, old_app_id, display_name=custom_display_name)
    for nested in _all_bundles(app_dir):
        name = os.path.basename(nested)
        if not name.endswith((".appex", ".app")):
            continue
        loaded, _raw, _exe, _name = _bundle_info(nested)
        current = loaded.get("CFBundleIdentifier", "")
        if current.startswith(old_app_id + "."):
            target = new_app_id + current[len(old_app_id):]
        else:
            target = new_app_id + "." + current.rsplit(".", 1)[-1]
        rewrite(nested, target, current)
    return new_app_id


KNOWN_GROUP_FAMILIES = (
    "com.SideStore.SideStore",
    "com.kdt.livecontainer",
    "com.rileytestut.AltStore",
)


def _family_of(bundle_id):
    base = (bundle_id or "").split(".Beta")[0]
    for prefix in KNOWN_GROUP_FAMILIES:
        if base == prefix or base.startswith(prefix + "."):
            return True
    return False


def strip_ungranted_app_groups(app_dir, config, bundle_id=""):
    granted = sorted(
        set(config["entitlements"].get("com.apple.security.application-groups") or [])
    )
    for bundle_dir in [app_dir] + _all_bundles(app_dir):
        info = _bundle_info(bundle_dir)
        if not info:
            continue
        loaded, raw_bytes, _executable_path, _executable = info
        groups = loaded.get("ALTAppGroups")
        if granted and _family_of(bundle_id or loaded.get("CFBundleIdentifier", "")):
            if groups != granted:
                loaded["ALTAppGroups"] = list(granted)
                write_plist(
                    os.path.join(bundle_dir, "Info.plist"),
                    loaded,
                    raw_bytes[:8] == b"bplist00",
                )
            continue
        if not isinstance(groups, list):
            continue
        kept = [
            group
            for group in groups
            if isinstance(group, str) and group in granted
        ]
        if kept == groups:
            continue
        if kept:
            loaded["ALTAppGroups"] = kept
        else:
            loaded.pop("ALTAppGroups", None)
        write_plist(
            os.path.join(bundle_dir, "Info.plist"),
            loaded,
            raw_bytes[:8] == b"bplist00",
        )


def sign_bundle(bundle_dir, config, is_top=False, progress=None):
    name = os.path.basename(bundle_dir)
    if name.endswith(".app"):
        kind = "app"
    elif name.endswith(".appex"):
        kind = "appex"
    else:
        kind = "framework"

    info, raw_info, executable_path, executable_name = _bundle_info(bundle_dir)
    if info is None:
        raise SigningError("%s is not a code bundle (no usable Info.plist)" % name)

    for dirpath, dirnames, _filenames in os.walk(bundle_dir):
        for dname in dirnames:
            if os.path.islink(os.path.join(dirpath, dname)):
                raise SigningError(
                    "%s contains a directory symlink (%s)" % (name, os.path.join(dirpath, dname))
                )

    nested = _nested_bundles(bundle_dir)
    for child in nested:
        sign_bundle(child, config, False, progress=progress)

    _sign_loose_binaries(bundle_dir, nested, executable_name, config)

    if kind in ("app", "appex"):
        profile_path = os.path.join(bundle_dir, "embedded.mobileprovision")
        with open(profile_path, "wb") as handle:
            handle.write(config["profile_bytes"])
        os.chmod(profile_path, 0o644)

    if progress is not None:
        progress(name)
    resources = build_code_resources(bundle_dir, executable_name)
    signature_dir = os.path.join(bundle_dir, "_CodeSignature")
    os.makedirs(signature_dir, exist_ok=True)
    resources_path = os.path.join(signature_dir, "CodeResources")
    with open(resources_path, "wb") as handle:
        handle.write(resources)
    os.chmod(resources_path, 0o644)

    entitlements = config["entitlements"] if kind in ("app", "appex") else None
    identifier = info.get("CFBundleIdentifier") or name.rsplit(".", 1)[0]
    with open(executable_path, "rb") as handle:
        data = handle.read()
    if not is_macho(data):
        raise SigningError("%s is not a Mach-O executable" % executable_path)

    signed = sign_macho_bytes(
        data,
        identifier,
        config["team"],
        entitlements,
        resources,
        raw_info,
        config["leaf"],
        config["chain"],
        config["key"],
    )
    mode = os.stat(executable_path).st_mode
    with open(executable_path, "wb") as handle:
        handle.write(signed)
    os.chmod(executable_path, mode & 0o7777)
    config["binaries"] += 1


# --- Extracting, Packing, and Verifying IPAs --------------------------------

def _safe_path(root, name):
    target = os.path.abspath(os.path.join(root, name))
    if not (
        target == os.path.abspath(root)
        or target.startswith(os.path.abspath(root) + os.sep)
    ):
        raise SigningError("the IPA contains an unsafe path: %r" % name[:80])
    return target


def extract_ipa(ipa_path, work_dir, progress=None):
    try:
        archive = zipfile.ZipFile(ipa_path)
    except (OSError, zipfile.BadZipFile) as exc:
        raise SigningError("cannot open the IPA: %s" % (exc,))
    with archive:
        count = 0
        for item in archive.infolist():
            name = item.filename
            if not name or name.endswith("/"):
                target = (
                    _safe_path(work_dir, name.rstrip("/")) if name.strip("/") else None
                )
                if target:
                    os.makedirs(target, exist_ok=True)
                continue
            target = _safe_path(work_dir, name)
            parent = os.path.dirname(target)
            if parent:
                os.makedirs(parent, exist_ok=True)
            mode = (item.external_attr >> 16) & 0xFFFF
            payload = archive.read(item)
            if mode and (mode & 0o170000) == 0o120000:
                link = payload.decode("utf-8", "replace")
                try:
                    os.symlink(link, target)
                except (OSError, NotImplementedError):
                    source = _safe_path(
                        work_dir,
                        os.path.normpath(os.path.join(os.path.dirname(name), link)),
                    )
                    if os.path.isfile(source):
                        shutil.copyfile(source, target)
                    else:
                        with open(target, "wb") as handle:
                            handle.write(payload)
                continue
            with open(target, "wb") as handle:
                handle.write(payload)
            if mode:
                try:
                    os.chmod(target, mode & 0o7777)
                except OSError:
                    pass
            count += 1
            if progress is not None and count % 400 == 0:
                progress("Extracting IPA package (%d files)…" % count)


def find_payload_app(work_dir):
    payload = os.path.join(work_dir, "Payload")
    if not os.path.isdir(payload):
        raise SigningError("the IPA has no Payload folder")
    apps = sorted(
        name
        for name in os.listdir(payload)
        if name.endswith(".app") and os.path.isdir(os.path.join(payload, name))
    )
    if not apps:
        raise SigningError("the IPA's Payload folder holds no .app")
    if len(apps) > 1:
        raise SigningError("this IPA has %d apps in Payload" % len(apps))
    return os.path.join(payload, apps[0])


def write_ipa(work_dir, output_path, progress=None):
    temporary = output_path + ".part"
    try:
        with zipfile.ZipFile(
            temporary, "w", zipfile.ZIP_DEFLATED, allowZip64=True
        ) as archive:
            packed = 0
            for dirpath, dirnames, filenames in os.walk(work_dir):
                dirnames.sort()
                relative_dir = os.path.relpath(dirpath, work_dir).replace(os.sep, "/")
                if relative_dir == ".":
                    relative_dir = ""
                if relative_dir:
                    info = zipfile.ZipInfo(relative_dir + "/", time.localtime()[:6])
                    info.external_attr = ((0o40755 & 0xFFFF) << 16) | 0x10
                    info.compress_type = zipfile.ZIP_STORED
                    archive.writestr(info, b"")
                for name in sorted(filenames):
                    absolute = os.path.join(dirpath, name)
                    relative = (relative_dir + "/" + name) if relative_dir else name
                    stat = os.lstat(absolute)
                    if os.path.islink(absolute):
                        target = os.readlink(absolute).encode("utf-8")
                        info = zipfile.ZipInfo(
                            relative, time.localtime(stat.st_mtime)[:6]
                        )
                        info.external_attr = (0o120777 & 0xFFFF) << 16
                        info.compress_type = zipfile.ZIP_STORED
                        archive.writestr(info, target)
                        continue
                    mode = stat.st_mode & 0o7777
                    info = zipfile.ZipInfo(relative, time.localtime(stat.st_mtime)[:6])
                    info.external_attr = ((0o100000 | mode) & 0xFFFF) << 16
                    info.compress_type = zipfile.ZIP_DEFLATED
                    with open(absolute, "rb") as handle:
                        archive.writestr(info, handle.read())
                    packed += 1
                    if progress is not None and packed % 100 == 0:
                        progress("Packing signed IPA (%d files)…" % packed)
        os.replace(temporary, output_path)
    except BaseException:
        try:
            os.remove(temporary)
        except OSError:
            pass
        raise


def _prepare_config(profile_path, key_path, cert_path, udid=None):
    profile = read_mobileprovision(profile_path)
    with open(profile_path, "rb") as handle:
        profile_bytes = handle.read()

    entitlements = profile.get("Entitlements")
    if not isinstance(entitlements, dict):
        raise SigningError("the profile has no Entitlements dictionary")
    teams = profile.get("TeamIdentifier") or []
    if not teams:
        raise SigningError("the profile names no team")
    team = teams[0]

    application_id = entitlements.get("application-identifier")
    if not application_id:
        raise SigningError("the profile has no application-identifier")
    if application_id == team + ".*":
        app_id = "*"
    elif application_id.startswith(team + "."):
        app_id = application_id[len(team) + 1:]
    else:
        raise SigningError(
            "this profile's application-identifier (%s) does not belong to team %s"
            % (str(application_id)[:60], team)
        )

    problems = install_preflight(profile, udid or "")
    if problems:
        raise SigningError("; ".join(problems))

    leaf = load_certificate(cert_path)
    key = load_private_key(key_path)
    chain = certificate_chain(leaf)

    entitlements = dict(entitlements)
    entitlements["com.apple.developer.team-identifier"] = team
    if app_id == "*":
        app_id = None
    return {
        "team": team,
        "app_id": app_id,
        "entitlements": entitlements,
        "profile_bytes": profile_bytes,
        "profile": profile,
        "leaf": leaf,
        "chain": chain,
        "key": key,
        "binaries": 0,
    }


def sign_ipa(
    ipa_path,
    profile_path,
    key_path,
    cert_path,
    output_ipa=None,
    udid=None,
    progress=None,
    drop_extensions=False,
    drop_extension_folders=None,
    custom_display_name=None,
):
    """Sign an IPA file and return metadata about the signed output."""
    progress = progress or (lambda _step: None)
    for label, path in (
        ("IPA", ipa_path),
        ("profile", profile_path),
        ("key", key_path),
        ("certificate", cert_path),
    ):
        if not path or not os.path.isfile(path):
            raise SigningError("%s not found: %s" % (label, path or "(no path)"))

    ipa_path = os.path.abspath(ipa_path)
    base = ipa_path[:-4] if ipa_path.lower().endswith(".ipa") else ipa_path
    output_ipa = os.path.abspath(output_ipa or (base + "-signed.ipa"))

    progress("Reading provisioning profile & certificate…")
    config = _prepare_config(profile_path, key_path, cert_path, udid)

    parent = os.path.dirname(os.path.abspath(output_ipa)) or "."
    os.makedirs(parent, exist_ok=True)
    if os.path.abspath(output_ipa) == ipa_path:
        raise SigningError("output path would overwrite the source IPA")

    work_dir = tempfile.mkdtemp(prefix=".baristore-sign-", dir=parent)
    config["work_dir"] = work_dir
    try:
        progress("Extracting IPA package…")
        extract_ipa(
            ipa_path,
            work_dir,
            progress=lambda msg: progress(msg),
        )
        app_dir = find_payload_app(work_dir)

        plugins_dir = os.path.join(app_dir, "PlugIns")
        if drop_extensions and os.path.isdir(plugins_dir):
            shutil.rmtree(plugins_dir)
        elif drop_extension_folders and os.path.isdir(plugins_dir):
            drop_set = set(drop_extension_folders)
            for child in os.listdir(plugins_dir):
                if child in drop_set:
                    shutil.rmtree(os.path.join(plugins_dir, child), ignore_errors=True)

        app_info, _raw, _exe, _name = _bundle_info(app_dir)
        if app_info is None:
            raise SigningError("the app has no usable Info.plist")
        original_id = app_info.get("CFBundleIdentifier") or ""
        target_id = config["app_id"] or original_id
        if not target_id:
            raise SigningError("the app has no CFBundleIdentifier")

        progress("Preparing bundle identifiers & entitlements…")
        if config["app_id"] or custom_display_name:
            prepare_bundle_ids(
                app_dir, target_id, config, custom_display_name=custom_display_name
            )
        strip_ungranted_app_groups(app_dir, config, bundle_id=target_id)
        config["entitlements"]["application-identifier"] = (
            config["team"] + "." + target_id
        )
        config["bundle_id"] = target_id

        progress("Signing Mach-O binaries & frameworks…")
        sign_bundle(
            app_dir,
            config,
            True,
            progress=lambda name: progress("Signing %s…" % name),
        )

        progress("Packing signed IPA…")
        write_ipa(
            work_dir,
            output_ipa,
            progress=lambda msg: progress(msg),
        )

        progress("Signing complete.")
        return {
            "ipa": output_ipa,
            "bundle_id": target_id,
            "original_bundle_id": original_id,
            "team": config["team"],
            "binaries": config["binaries"],
            "size": os.path.getsize(output_ipa),
            "expires_at": int(
                _profile_datetime(config["profile"].get("ExpirationDate")).timestamp()
            )
            if _profile_datetime(config["profile"].get("ExpirationDate"))
            else int(time.time() + 7 * 86400),
        }
    finally:
        if os.path.isdir(work_dir):
            shutil.rmtree(work_dir, ignore_errors=True)
