import sys
import gzip
import zlib
import base64

def encode_gzip(data):
    if sys.version_info.major == 2:
        import StringIO as io
        out = io.StringIO()
        with gzip.GzipFile(fileobj=out, mode="w") as f:
            f.write(data)
        return out.getvalue()
    else:
        data = bytes(data, 'utf-8')
        return gzip.compress(data)

def encode_deflate(data):
    return zlib.compress(data)

def encode_plain(data):
    if sys.version_info.major == 2:
        return data
    else:
        return data.encode('utf-8')

def decode_base64(decode_input):
    # decode_input might be str or bytes depending on caller
    if isinstance(decode_input, str):
        decode_input = decode_input.encode("utf-8")

    return base64.b64decode(decode_input).decode("utf-8", errors="replace")
def decode_plain(data):
    if sys.version_info.major == 2:
        return data
    else:
        return data.decode('utf-8')
