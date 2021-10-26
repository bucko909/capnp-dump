"""
Feed in unpacked capnp to stdin, get JSON back out.
"""

import sys
import struct
import logging
import json

LOGGER = logging.getLogger(__name__)

decode_int32_ = struct.Struct('<I').unpack
decode_int64_ = struct.Struct('<Q').unpack
decode_int32 = lambda x: decode_int32_(x)[0]
decode_int64 = lambda x: decode_int64_(x)[0]

def read_msg():
    got = sys.stdin.buffer.read(4)
    if not got:
        return None
    seg_count = decode_int32(got) + 1
    seg_lengths = []
    for i in range(seg_count):
        seg_lengths.append(decode_int32(sys.stdin.buffer.read(4)))
    if seg_count % 2 == 0:
        sys.stdin.read(4)
    segments = []
    for seg_length in seg_lengths:
        segments.append(sys.stdin.buffer.read(8 * seg_length))
    return segments

def bits(val, offset, count):
    return (val >> offset) & ((1 << count) - 1)

def get_word(segments, segment, offset, length=1):
    return segments[segment][offset<<3:(offset+length)<<3]

def dump_message(segments, segment=0, offset=0):
    LOGGER.debug(f"dump_message({segment}, {offset})")
    data = decode_int64(get_word(segments, segment, offset))
    LOGGER.debug(f"dump_message_raw({segment}, {offset}, {hex(data)})")
    return decode_pointer(segments, segment, offset + 1, data)

def decode_pointer(segments, segment, offset, data):
    LOGGER.debug(f"decode_pointer({segment}, {offset}, {data})")
    if data == 0:
        return {'type': 'null'}
    ptr_type = bits(data, 0, 2)
    if ptr_type == 0:
        # struct
        ptr_offset = bits(data, 2, 30)
        data_words = bits(data, 32, 16)
        ptr_words = bits(data, 48, 16)
        LOGGER.debug(f"decode_struct({ptr_offset}, {data_words}, {ptr_words})")
        data_area = get_word(segments, segment, offset, data_words)
        data_int32 = [decode_int32(data_area[i*4:(i+1)*4]) for i in range(data_words*2)]
        data_int64 = [decode_int64(data_area[i*8:(i+1)*8]) for i in range(data_words)]
        data_float = [struct.Struct('f').unpack(data_area[i*4:(i+1)*4])[0] for i in range(data_words*2)]
        data_double = [struct.Struct('d').unpack(data_area[i*8:(i+1)*8])[0] for i in range(data_words)]
        pointers = [dump_message(segments, segment, offset + data_words + i) for i in range(ptr_words)]
        return {'type': 'struct', 'data_int32': data_int32, 'data_int64': data_int64, 'data_float': data_float, 'data_double': data_double, 'pointers': pointers}
    elif ptr_type == 1:
        # list
        ptr_offset = bits(data, 2, 30)
        ptr_length = bits(data, 35, 29)
        size = bits(data, 32, 3)
        LOGGER.debug(f"decode_list({ptr_offset}, {size}, {ptr_length})")
        ret = {'type': 'list', 'size_tag': size, 'offset': ptr_offset}
        if size == 7:
            word_length = bits(data, 35, 29)
            tag = decode_int64(get_word(segments, segment, offset + ptr_offset))
            length = bits(tag, 2, 30)
            tag -= length >> 2
            if length > 0:
                assert word_length % length == 0, (segment, offset, word_length, length)
                element_size = word_length // length
            else:
                assert word_length == length
                element_size = 0
            element_offset = offset + ptr_offset + 1
            elements = []
            for i in range(length):
                elements.append(decode_pointer(segments, segment, element_offset, tag))
                element_offset += element_size
            ret['element_type'] = 'composite'
            ret['word_length'] = word_length
            ret['length'] = length
            ret['contents'] = elements
        elif size == 6:
            length = bits(data, 35, 29)
            elements = []
            for i in range(length):
                elements.append(dump_message(segments, segment, offset + ptr_offset + i))
            ret['element_type'] = 'pointer'
            ret['length'] = length
            ret['contents'] = elements
        elif size > 1:
            length = bits(data, 35, 29)
            byte_size = {2: 1, 3: 2, 4: 4, 5: 8}[size]
            int_type = {2: 'b', 3: 'h', 4: 'i', 5: 'q'}[size]
            float_type = {4: 'f', 5: 'd'}.get(size)
            inner_data = get_word(segments, segment, offset + ptr_offset, (byte_size * length + 7) >> 3)
            floats = []
            ints = []
            uints = []
            for i in range(length):
                element_data = inner_data[i * byte_size:(i+1) * byte_size]
                if float_type:
                    floats.append(struct.unpack(float_type, element_data)[0])
                ints.append(struct.unpack('<' + int_type, element_data)[0])
                uints.append(struct.unpack('<' + int_type.upper(), element_data)[0])
            ret['element_type'] = 'native'
            ret['length'] = length
            ret['ints'] = ints
            ret['uints'] = uints
            if size == 2:
                ret['text'] = inner_data[:length-1].decode('utf8', 'replace')
            if float_type:
                ret['floats'] = floats
        elif size == 1:
            length = bits(data, 35, 29)
            data_offset = offset + ptr_offset
            i = 0
            word_remain = 0
            inner_data = None
            elements = []
            while i < length:
                if word_remain == 0:
                    inner_data = decode_int64(get_word(segments, segment, data_offset))
                    data_offset += 1
                    word_remain = 64
                elements.append(inner_data & 1)
                word_remain -= 1
                inner_data = inner_data >> 1
                i += 1
            ret['element_type'] = 'bool'
            ret['length'] = length
            ret['contents'] = elements
        elif size == 0:
            length = bits(data, 35, 29)
            ret['element_type'] = 'void'
            ret['length'] = length
        return ret

    elif ptr_type == 2:
        # inter-segment
        pad_size = bits(data, 2, 1) + 1
        ptr_offset = bits(data, 3, 29)
        segment_id = bits(data, 32, 32)
        inner = decode_far_pointer(segments, segment_id, ptr_offset, pad_size)
        return {'type': 'far', 'pad_size': pad_size, 'offset': ptr_offset, 'segment_id': segment_id, 'to': inner}
    elif ptr_type == 3:
        # capability
        reserved = bits(data, 2, 30)
        index = bits(data, 32, 32)
        return {'type': 'capability', 'reserved': reserved, 'index': index}

def decode_far_pointer(segments, segment, offset, pad_size):
    LOGGER.debug(f"decode_far_pointer({segment}, {offset}, {pad_size})")
    if pad_size == 1:
        return dump_message(segments, segment, offset)
    data = decode_int64(get_word(segments, segment, offset))
    pad_size = bits(data, 2, 1) + 1
    assert pad_size == 1, (segment, offset)
    ptr_offset = bits(data, 3, 29)
    segment_id = bits(data, 32, 32)
    tag = decode_int64(get_word(segments, segment, offset))
    tag |= ptr_offset << 2
    inner = decode_pointer(segments, segment_id, ptr_offset - 1, tag)
    return {'type': 'farfar', 'offset': ptr_offset, 'segment_id': segment_id, 'to': inner}

def main():
    logging.basicConfig(level=logging.DEBUG)
    while True:
        msg = read_msg()
        if msg is None:
            break
        print(json.dumps(dump_message(msg)))

if __name__ == '__main__':
    main()
