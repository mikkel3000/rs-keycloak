"""Reads a QR code from a PNG, so a reference page and this server's page
compare by what the code says rather than by image bytes.

Only the Python standard library is used. The PNG is decoded (any bit
depth and color type, no interlacing), its dark pixels give the code's
modules, and the code is read as ISO/IEC 18004 describes it: format bits,
unmasked codewords in zigzag order, de-interleaved blocks whose
Reed-Solomon check bytes are verified, then byte, numeric, alphanumeric
and ECI segments. The image must be an unrotated, noise-free rendering,
as a server draws it.
"""
import struct
import zlib

ECC_LEVELS = {1: 'L', 0: 'M', 3: 'Q', 2: 'H'}
# Per error correction level, by version (index 0 unused), as in the
# standard's tables 9.
ECC_PER_BLOCK = {
    'L': [-1, 7, 10, 15, 20, 26, 18, 20, 24, 30, 18, 20, 24, 26, 30, 22, 24, 28, 30, 28, 28, 28, 28, 30, 30, 26, 28, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30],
    'M': [-1, 10, 16, 26, 18, 24, 16, 18, 22, 22, 26, 30, 22, 22, 24, 24, 28, 28, 26, 26, 26, 26, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28],
    'Q': [-1, 13, 22, 18, 26, 18, 24, 18, 22, 20, 24, 28, 26, 24, 20, 30, 24, 28, 28, 26, 30, 28, 30, 30, 30, 30, 28, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30],
    'H': [-1, 17, 28, 22, 16, 22, 28, 26, 26, 24, 28, 24, 28, 22, 24, 24, 30, 28, 28, 26, 28, 30, 24, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30],
}
BLOCKS = {
    'L': [-1, 1, 1, 1, 1, 1, 2, 2, 2, 2, 4, 4, 4, 4, 4, 6, 6, 6, 6, 7, 8, 8, 9, 9, 10, 12, 12, 12, 13, 14, 15, 16, 17, 18, 19, 19, 20, 21, 22, 24, 25],
    'M': [-1, 1, 1, 1, 2, 2, 4, 4, 4, 5, 5, 5, 8, 9, 9, 10, 10, 11, 13, 14, 16, 17, 17, 18, 20, 21, 23, 25, 26, 28, 29, 31, 33, 35, 37, 38, 40, 43, 45, 47, 49],
    'Q': [-1, 1, 1, 2, 2, 4, 4, 6, 6, 8, 8, 8, 10, 12, 16, 12, 17, 16, 18, 21, 20, 23, 23, 25, 27, 29, 34, 34, 35, 38, 40, 43, 45, 48, 51, 53, 56, 59, 62, 65, 68],
    'H': [-1, 1, 1, 2, 4, 4, 4, 5, 6, 8, 8, 11, 11, 16, 16, 18, 16, 19, 21, 25, 25, 25, 34, 30, 32, 35, 37, 40, 42, 45, 48, 51, 54, 57, 60, 63, 66, 70, 74, 77, 81],
}
ALPHANUMERIC = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:'
MASKS = [
    lambda i, j: (i + j) % 2 == 0,
    lambda i, j: i % 2 == 0,
    lambda i, j: j % 3 == 0,
    lambda i, j: (i + j) % 3 == 0,
    lambda i, j: (i // 2 + j // 3) % 2 == 0,
    lambda i, j: (i * j) % 2 + (i * j) % 3 == 0,
    lambda i, j: ((i * j) % 2 + (i * j) % 3) % 2 == 0,
    lambda i, j: ((i + j) % 2 + (i * j) % 3) % 2 == 0,
]


def png_pixels(data):
    """The PNG's width, height and rows of booleans, true where dark."""
    assert data[:8] == b'\x89PNG\r\n\x1a\n', 'not a PNG'
    position, idat, palette = 8, b'', None
    while position < len(data):
        length, kind = struct.unpack('>I4s', data[position:position + 8])
        chunk = data[position + 8:position + 8 + length]
        position += 12 + length
        if kind == b'IHDR':
            width, height, depth, color, _, _, interlace = struct.unpack('>IIBBBBB', chunk)
            assert interlace == 0, 'interlaced PNG'
        elif kind == b'PLTE':
            palette = [tuple(chunk[i:i + 3]) for i in range(0, len(chunk), 3)]
        elif kind == b'IDAT':
            idat += chunk
        elif kind == b'IEND':
            break
    channels = {0: 1, 2: 3, 3: 1, 4: 2, 6: 4}[color]
    bits = depth * channels
    stride, step = (width * bits + 7) // 8, max(1, bits // 8)
    raw, rows, previous = zlib.decompress(idat), [], bytearray(stride)
    for y in range(height):
        start = y * (stride + 1)
        kind, line = raw[start], bytearray(raw[start + 1:start + 1 + stride])
        for x in range(stride):
            left = line[x - step] if x >= step else 0
            up, corner = previous[x], previous[x - step] if x >= step else 0
            if kind == 1:
                line[x] = (line[x] + left) & 0xFF
            elif kind == 2:
                line[x] = (line[x] + up) & 0xFF
            elif kind == 3:
                line[x] = (line[x] + (left + up) // 2) & 0xFF
            elif kind == 4:
                estimate = left + up - corner
                pa, pb, pc = abs(estimate - left), abs(estimate - up), abs(estimate - corner)
                line[x] = (line[x] + (left if pa <= pb and pa <= pc else up if pb <= pc else corner)) & 0xFF
        previous = line
        row = []
        for x in range(width):
            if depth < 8:
                byte = line[x * bits // 8]
                sample = (byte >> (8 - depth - (x * bits) % 8)) & ((1 << depth) - 1)
                levels = [sample]
            else:
                width_bytes = depth // 8
                offset = x * channels * width_bytes
                levels = [line[offset + c * width_bytes] for c in range(channels)]
            if color == 3:
                red, green, blue = palette[levels[0]]
            elif color in (0, 4):
                red = green = blue = levels[0] * 255 // ((1 << depth) - 1) if depth < 8 else levels[0]
            else:
                red, green, blue = levels[:3]
            row.append(red * 299 + green * 587 + blue * 114 < 128000)
        rows.append(row)
    return width, height, rows


def _function_modules(size, version):
    used = [[False] * size for _ in range(size)]

    def area(top, left, height, width):
        for i in range(max(top, 0), min(top + height, size)):
            for j in range(max(left, 0), min(left + width, size)):
                used[i][j] = True

    area(0, 0, 9, 9)
    area(0, size - 8, 9, 8)
    area(size - 8, 0, 8, 9)
    area(6, 0, 1, size)
    area(0, 6, size, 1)
    if version >= 2:
        count = version // 7 + 2
        step = (version * 8 + count * 3 + 5) // (count * 4 - 4) * 2
        centers = [6] + [size - 7 - k * step for k in range(count - 1)][::-1]
        for a, row in enumerate(centers):
            for b, column in enumerate(centers):
                if (a, b) not in ((0, 0), (0, count - 1), (count - 1, 0)):
                    area(row - 2, column - 2, 5, 5)
    if version >= 7:
        area(0, size - 11, 6, 3)
        area(size - 11, 0, 3, 6)
    return used


def _gf_multiply(x, y):
    product = 0
    for i in range(7, -1, -1):
        product = ((product << 1) ^ ((product >> 7) * 0x11D)) & 0xFF
        product ^= ((y >> i) & 1) * x
    return product


def _check_bytes(data, degree):
    divisor = [0] * (degree - 1) + [1]
    root = 1
    for _ in range(degree):
        for j in range(degree):
            divisor[j] = _gf_multiply(divisor[j], root)
            if j + 1 < degree:
                divisor[j] ^= divisor[j + 1]
        root = _gf_multiply(root, 0x02)
    result = [0] * degree
    for byte in data:
        factor = byte ^ result.pop(0)
        result.append(0)
        for i in range(degree):
            result[i] ^= _gf_multiply(divisor[i], factor)
    return result


def read(png):
    """What a QR code PNG holds: its pixel size, module size and quiet zone
    in pixels, version, error correction level, segment modes and text."""
    width, height, rows = png_pixels(png)
    dark = [(y, x) for y in range(height) for x in range(width) if rows[y][x]]
    assert dark, 'blank image'
    top, left = dark[0]
    bottom, right = max(y for y, _ in dark), max(x for _, x in dark)
    run = 0
    while rows[top][left + run]:
        run += 1
    assert run % 7 == 0, 'no finder pattern'
    module = run // 7
    size = (right - left + 1) // module
    assert (bottom - top + 1) // module == size and (size - 17) % 4 == 0, 'not a square QR code'
    version = (size - 17) // 4

    def bit(i, j):
        return rows[top + i * module + module // 2][left + j * module + module // 2]

    format_bits = 0
    positions = [(row, 8) for row in range(6)] + [(7, 8), (8, 8), (8, 7)] + [(8, 14 - n) for n in range(9, 15)]
    for k, (i, j) in enumerate(positions):
        format_bits |= bit(i, j) << k
    format_bits ^= 0x5412
    level, mask = ECC_LEVELS[format_bits >> 13], (format_bits >> 10) & 7
    remainder = format_bits >> 10
    for _ in range(10):
        remainder = (remainder << 1) ^ ((remainder >> 9) * 0x537)
    assert ((format_bits >> 10) << 10 | remainder) == format_bits, 'format bits fail their check'

    used = _function_modules(size, version)
    stream = []
    right_column = size - 1
    while right_column >= 1:
        if right_column == 6:
            right_column = 5
        for vertical in range(size):
            for k in range(2):
                j = right_column - k
                upward = ((right_column + 1) & 2) == 0
                i = size - 1 - vertical if upward else vertical
                if not used[i][j]:
                    stream.append(bit(i, j) ^ MASKS[mask](i, j))
        right_column -= 2
    raw = [int(''.join(str(int(b)) for b in stream[k:k + 8]), 2) for k in range(0, len(stream) // 8 * 8, 8)]

    count, check = BLOCKS[level][version], ECC_PER_BLOCK[level][version]
    short_count, short_length = count - len(raw) % count, len(raw) // count
    blocks = [[] for _ in range(count)]
    lengths = [short_length + (0 if b < short_count else 1) for b in range(count)]
    position = 0
    # Data bytes are interleaved first, then check bytes.
    data_lengths = [length - check for length in lengths]
    for k in range(max(data_lengths)):
        for b in range(count):
            if k < data_lengths[b]:
                blocks[b].append(raw[position])
                position += 1
    for k in range(check):
        for b in range(count):
            blocks[b].append(raw[position])
            position += 1
    data = []
    for b, block in enumerate(blocks):
        assert _check_bytes(block[:data_lengths[b]], check) == block[data_lengths[b]:], 'check bytes do not match'
        data += block[:data_lengths[b]]

    bits = ''.join(f'{byte:08b}' for byte in data)
    position, modes, text, charset = 0, [], '', 'latin-1'

    def take(n):
        nonlocal position
        value = int(bits[position:position + n] or '0', 2)
        position += n
        return value

    band = 0 if version <= 9 else 1 if version <= 26 else 2
    while position + 4 <= len(bits):
        mode = take(4)
        if mode == 0:
            break
        if mode == 7:
            first = take(8)
            designator = first if first < 0x80 else ((first & 0x3F) << 8 | take(8)) if first < 0xC0 else ((first & 0x1F) << 16 | take(16))
            modes.append(f'eci-{designator}')
            charset = {26: 'utf-8', 3: 'latin-1'}.get(designator, charset)
        elif mode == 4:
            length = take([8, 16, 16][band])
            text += bytes(take(8) for _ in range(length)).decode(charset)
            modes.append('byte')
        elif mode == 1:
            length = take([10, 12, 14][band])
            digits = ''
            while len(digits) < length:
                group = min(3, length - len(digits))
                digits += str(take([4, 7, 10][group - 1])).zfill(group)
            text += digits
            modes.append('numeric')
        elif mode == 2:
            length = take([9, 11, 13][band])
            chars = ''
            while len(chars) < length:
                if length - len(chars) >= 2:
                    pair = take(11)
                    chars += ALPHANUMERIC[pair // 45] + ALPHANUMERIC[pair % 45]
                else:
                    chars += ALPHANUMERIC[take(6)]
            text += chars
            modes.append('alphanumeric')
        else:
            raise AssertionError(f'unsupported segment mode {mode}')
    return {'width': width, 'height': height, 'module_pixels': module, 'quiet_zone_pixels': [left, top, width - 1 - right, height - 1 - bottom], 'version': version, 'level': level, 'modes': modes, 'text': text}
