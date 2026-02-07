from mcp.server.fastmcp import FastMCP
import base64
import binascii
import gzip
import zlib
import urllib.parse
import html
import quopri
import codecs
import json
import string

def _calculate_score(data: bytes) -> float:
    """Calculate a 'readability' score for bytes (0.0 to 1.0)."""
    if not data:
        return 0.0
    try:
        text = data.decode('utf-8')
        printable = set(string.printable)
        count = sum(1 for c in text if c in printable)
        return count / len(text)
    except UnicodeDecodeError:
        # If not utf-8, check if it's mostly ASCII printable bytes
        printable_bytes = set(string.printable.encode('ascii'))
        count = sum(1 for b in data if b in printable_bytes)
        return (count / len(data)) * 0.5 # Penalty for non-utf8

def _try_decode(data: str, encoding: str):
    """Try to decode data with specific encoding, returning (success, result_bytes, error)."""
    try:
        if encoding == "base64":
            # Handle standard and url-safe base64, and padding
            missing_padding = len(data) % 4
            if missing_padding:
                data += '=' * (4 - missing_padding)
            return True, base64.b64decode(data, validate=True), None
            
        elif encoding == "hex":
            # Remove spaces/colons/0x
            clean_data = data.replace(" ", "").replace(":", "").replace("0x", "")
            return True, binascii.unhexlify(clean_data), None
            
        elif encoding == "url":
            return True, urllib.parse.unquote_to_bytes(data), None
            
        elif encoding == "rot13":
            return True, codecs.decode(data, 'rot_13').encode('utf-8'), None
            
        elif encoding == "gzip":
            # Latin-1 allows 1:1 mapping of bytes to chars
            b = data.encode('latin-1') 
            return True, gzip.decompress(b), None

        elif encoding == "deflate":
            b = data.encode('latin-1')
            # -15 for raw deflate (no header), standard zlib has header
            try: 
                return True, zlib.decompress(b), None
            except:
                return True, zlib.decompress(b, -15), None

        elif encoding == "quopri":
            return True, quopri.decodestring(data.encode('utf-8')), None
            
        elif encoding == "html":
            return True, html.unescape(data).encode('utf-8'), None
            
        elif encoding == "unicode":
            # "Hello\u0020World" -> bytes
            return True, data.encode('utf-8').decode('unicode_escape').encode('utf-8'), None
        
        elif encoding == "ascii85":
            # Adobe Ascii85 usually delimited by <~ ~>
            d = data.strip()
            if d.startswith("<~"): d = d[2:]
            if d.endswith("~>"): d = d[:-2]
            return True, base64.a85decode(d), None

    except Exception as e:
        return False, None, str(e)
    
    return False, None, "Unknown encoding"

def register_decode_tools(mcp: FastMCP):

    @mcp.tool()
    def wireshark_decode_payload(data: str, encoding: str = "auto") -> str:
        """
        [Utils] Decode common encodings (Base64, Hex, URL, Gzip, etc.).
        
        Args:
            data: The string to decode.
            encoding: Target encoding. Supported:
                'base64', 'hex', 'url', 'rot13', 'gzip', 'deflate', 
                'html', 'unicode', 'quopri', 'ascii85'.
                Use 'auto' to try all and sort by readability.
                
        Returns:
            Decoded string (or JSON in 'auto' mode).
        """
        encodings = ["base64", "hex", "url", "rot13", "html", "unicode", "quopri", "ascii85"]
        # Exclude gzip/deflate from simple auto list, handled in chaining
        
        if encoding == "auto":
            results = []
            
            # 1. Try single-step decodes
            for enc in encodings:
                success, res_bytes, _ = _try_decode(data, enc)
                if success:
                    try:
                        text = res_bytes.decode('utf-8')
                        score = _calculate_score(res_bytes)
                        # Filter out trivial results
                        if text == data and enc in ["url", "html", "unicode", "rot13"]:
                             continue
                        if enc == "hex" and score < 0.1: 
                             continue
                             
                        results.append({
                            "encoding": enc,
                            "result": text[:200] + "..." if len(text) > 200 else text,
                            "score": round(score, 2),
                            "is_text": True
                        })
                    except:
                        # Binary result
                        results.append({
                            "encoding": enc,
                            "result": "<binary_data>",
                            "hex_preview": binascii.hexlify(res_bytes[:20]).decode('ascii'),
                            "score": 0.0,
                            "is_text": False
                        })
            
            # 2. Try Chained (e.g., Base64 -> Gzip)
            success, b64_bytes, _ = _try_decode(data, "base64")
            if success:
                try:
                    gzip_bytes = gzip.decompress(b64_bytes)
                    results.append({
                        "encoding": "base64+gzip",
                        "result": gzip_bytes.decode('utf-8', errors='replace')[:200],
                        "score": _calculate_score(gzip_bytes),
                        "is_text": True
                    })
                except: pass
                
                try:
                    zlib_bytes = zlib.decompress(b64_bytes)
                    results.append({
                        "encoding": "base64+zlib",
                        "result": zlib_bytes.decode('utf-8', errors='replace')[:200],
                        "score": _calculate_score(zlib_bytes),
                        "is_text": True
                    })
                except: pass

            # Sort by score desc
            results.sort(key=lambda x: x["score"], reverse=True)
            
            return json.dumps({
                "success": True, 
                "candidates": results[:5] # Return top 5
            }, indent=2)

        else:
            success, res_bytes, err = _try_decode(data, encoding)
            if not success:
               return json.dumps({"success": False, "error": err})
            
            try:
                return res_bytes.decode('utf-8')
            except UnicodeDecodeError:
                return f"[Binary Data] Hex: {binascii.hexlify(res_bytes).decode('ascii')}"
