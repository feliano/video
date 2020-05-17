# MP4 Parser
from datetime import datetime, timedelta
from binascii import unhexlify

SAIO = b'saio'
SAIZ = b'saiz'
SGPD = b'sgpd'
SBGP = b'sbgp'
STYP = b'styp'
FTYP = b'ftyp'
MDAT = b'mdat'
MOOV = b'moov'
MOOF = b'moof'
MFHD = b'mfhd'
MVHD = b'mvhd'
MDAT = b'mdat'
SENC = b'senc'
SIDX = b'sidx'
TRAK = b'trak'
TRAF = b'traf'
TFDT = b'tfdt'
TREX = b'trex'
TKHD = b'tkhd'
MDIA = b'mdia'
MDHD = b'mdhd'
TFHD = b'tfhd'
TRUN = b'trun'
PSSH = b'pssh'


SYSTEM_IDS = {
    unhexlify('1077EFECC0B24D02ACE33C1E52E2FB4B'): 'COMMON',
    unhexlify('9A04F07998404286AB92E65BE0885F95'): 'PLAYREADY',
    unhexlify('EDEF8BA979D64ACEA3C827DCD51D21ED'): 'WIDEVINE',
    'COMMON': unhexlify('1077EFECC0B24D02ACE33C1E52E2FB4B'),
    'PLAYREADY': unhexlify('9A04F07998404286AB92E65BE0885F95'),
    'WIDEVINE': unhexlify('EDEF8BA979D64ACEA3C827DCD51D21ED')
}

MAC_UNIX_TIMESTAMP_DIFFERENCE = 2082844800


def print_matrix(data):
    print('Transformation Matrix:')
    for row in range(0, 3):
        print([uint(data[col * 4 + row * 12: col * 4 + row * 12 +4]) for col in range(0, 3)])


def mac_timestamp_to_human(timestamp):
    return datetime.utcfromtimestamp(
        timestamp - MAC_UNIX_TIMESTAMP_DIFFERENCE
    ).strftime('%Y-%m-%d %H:%M:%S')


def uint(bytestring, endianess='big'):
    return int.from_bytes(bytestring, endianess, signed=False)


def signed_int(bytestring, endianess='big'):
    return int.from_bytes(bytestring, endianess, signed=True)


class Box:
    def __init__(self, size, data):
        self.size = size
        self.data = data
        self.index = 0
        self.type = self.__str__().lower()
        print(self)

    def __str__(self):
        return self.__class__.__name__

    def read_uint(self, length, endianess='big'):
        u = uint(self.data[self.index:self.index + length])
        self.index += length
        return u

    def read_signed_int(self, length, endianess='big'):
        i = signed_int(self.data[self.index:self.index + length], endianess)
        self.index += length
        return i

    def read_bytes(self, length):
        b = self.data[self.index:self.index + length]
        self.index += length
        return b

    def read_utf8_string(self, length):
        s = str(self.data[self.index: self.index + length])
        self.index += length
        return s

    def unpack_language(self, value):
        lang_str = ''
        for i in range(0, 3):
            c = chr(((value >> (i * 5)) & 31) + 0x60)
            lang_str = c + lang_str

        return lang_str


class ContainerBox(Box):
    def __init__(self, size, data):
        super().__init__(size, data)
        self.get_children()

    def get_children(self):
        while self.index + 8 < self.size:
            box_size = uint(self.data[self.index:self.index + 4])
            box_type = self.data[self.index + 4:self.index + 8]
            box_data = self.data[self.index + 8:self.index + box_size]
            BoxParser(box_size, box_type, box_data)
            # TODO: add box to some data structure keeping track of boxes
            self.index += box_size

    def print_box_tree(self):
        raise NotImplementedError  # TODO


class FullBox(Box):
    def __init__(self, size, data):
        super().__init__(size, data)
        self.version = self.read_uint(1)
        self.flags = self.read_bytes(3)


class Moov(ContainerBox):
    def __init__(self, size, data):
        super().__init__(size, data)


class Mvhd(FullBox):
    def __init__(self, size, data):
        super().__init__(size, data)
        '''
        if version is 0 creation_time, modification_time and duration will be
        32 bits. if version == 1 these will be 64 bits
        '''
        self.creation_time = self.read_uint(4) if self.version == 0 else self.read_uint(8)
        self.modification_time = self.read_uint(4) if self.version == 0 else self.read_uint(8)
        self.timescale = self.read_uint(4)
        self.duration = self.read_uint(4) if self.version == 0 else self.read_uint(8)
        self.rate = self.read_uint(4) // 65536
        self.volume = self.read_uint(2) // 256
        self.reserved = self.read_bytes(10)
        self.matrix = self.read_bytes(9 * 4)  # 3x3 matrix * 4 bytes
        self.predef = self.read_bytes(24)
        self.next_track_id = self.read_bytes(4)
        print(f'version: {self.version}')
        print(f'flags: {self.flags}')
        print(f'creation_time: {self.creation_time}')
        print(
            f'modification_time: {self.modification_time}'
        )
        print(f'timescale: {self.timescale}')
        print(f'duration: {self.duration}')
        print(f'duration (seconds): {self.duration/self.timescale}')
        print(f'rate: {self.rate}')
        print(f'volume: {self.volume}')
        print_matrix(self.matrix)
        print(f'next_track_id: {uint(self.next_track_id)}')


class Ftyp(Box):
    def __init__(self, size, data):
        super().__init__(size, data)
        self.major_brand = self.read_utf8_string(4)
        self.minor_brand = self.read_uint(4)
        self.compatible_brands = self.read_utf8_string(12)
        print(f'major_brand: {self.major_brand}')
        print(f'minor_brand: {self.minor_brand}')
        print(f'compatible_brands: {self.compatible_brands}')


class Styp(Box):
    def __init__(self, size, data):
        super().__init__(size, data)
        self.major_brand = self.read_utf8_string(4)
        self.minor_brand = self.read_uint(4)
        self.compatible_brands = self.read_utf8_string(12)
        print(f'major_brand: {self.major_brand}')
        print(f'minor_brand: {self.minor_brand}')
        print(f'compatible_brands: {self.compatible_brands}')


class Trex(FullBox):
    def __init__(self, size, data):
        super().__init__(size, data)
        self.track_id = self.read_uint(4)
        self.default_sample_description_index = self.read_uint(4)
        self.default_sample_duration = self.read_uint(4)
        self.default_sample_size = self.read_uint(4)
        self.default_sample_flags = self.read_uint(4)
        print(f'track_id: {self.track_id}')
        print(f'default_sample_description_index: {self.default_sample_description_index}')
        print(f'default_sample_duration: {self.default_sample_duration}')
        print(f'default_sample_size: {self.default_sample_size}')
        print(f'default_sample_flags: {self.default_sample_flags}')


class Tkhd(FullBox):
    def __init__(self, size, data):
        super().__init__(size, data)
        self.creation_time = self.read_uint(4) if self.version == 0 else self.read_uint(8)
        self.modification_time = self.read_uint(4) if self.version == 0 else self.read_uint(8)
        self.track_id = self.read_uint(4)
        self.read_bytes(4)  # reserved
        self.duration = self.read_uint(4) if self.version == 0 else self.read_uint(8)
        self.read_bytes(8)  # reserved
        self.layer = self.read_uint(2)
        self.alternate_group = self.read_uint(2)
        self.volume = self.read_uint(2)
        self.read_bytes(2)  #reserved
        self.matrix = self.read_uint(3 * 3 * 4)
        self.width = self.read_uint(4) // 65536
        self.height = self.read_uint(4) // 65536
        print(f'duration: {self.duration}')
        print(f'width: {self.width}')
        print(f'height: {self.height}')


class Mdhd(FullBox):
    def __init__(self, size, data):
        super().__init__(size, data)
        self.creation_time = self.read_uint(4) if self.version == 0 else self.read_uint(8)
        self.modification_time = self.read_uint(4) if self.version == 0 else self.read_uint(8)
        self.timescale = self.read_bytes(4)
        self.duration = self.read_uint(4) if self.version == 0 else self.read_uint(8)
        self.language = self.read_uint(2)  # 1 bit padding followed by 5 bits per character
        self.quality = self.read_uint(2)
        print(f'language: {self.unpack_language(self.language)}')
        print(f'quality: {self.quality}')


class Sidx(FullBox):
    def __init__(self, size, data):
        super().__init__(size, data)
        self.reference_id = self.read_uint(4)
        print(f'reference_id: {self.reference_id}')


class Senc(FullBox):
    def __init__(self, size, data):
        super().__init__(size, data)
        self.IV_SIZE = 8  # TODO: could be 16?
        self.sample_count = self.read_uint(4)
        self.sample_encryption_data = []
        for sample in range(0, self.sample_count):
            sample_encryption_data = {
                'initialization_vector': self.read_uint(self.IV_SIZE)
            }
            if int.from_bytes(self.flags, 'big') & 0x000002:
                sample_encryption_data['subsample_data'] = [{
                    'bytes_of_clear_data': self.read_uint(2),
                    'bytes_of_encrypted_data': self.read_uint(4)
                } for _ in range(0, self.read_uint(2))]

            self.sample_encryption_data.append(sample_encryption_data)


class Unwn(Box):
    '''unknown/non implemented box'''
    def __init__(self, size, data):
        super().__init__(size, data)


class Mdia(ContainerBox):
    def __init__(self, size, data):
        super().__init__(size, data)


class Hdlr(Box):
    def __init__(self, size, data):
        super().__init__(size, data)


class Trak(ContainerBox):
    def __init__(self, size, data):
        super().__init__(size, data)


class Saio(FullBox):
    def __init__(self, size, data):
        super().__init__(size, data)
        self.aux_info_type = self.read_utf8_string(4)
        print(self.read_bytes(4))


class Saiz(FullBox):
    def __init__(self, size, data):
        super().__init__(size, data)
        # TODO


class Sgpd(FullBox):
    def __init__(self, size, data):
        super().__init__(size, data)
        # TODO


class Tfdt(FullBox):
    '''Track fragment decode time '''
    def __init__(self, size, data):
        super().__init__(size, data)
        if self.version == 1:
            self.base_media_decode_time = self.read_uint(8)
        else:  # version 0
            self.base_media_decode_time = self.read_uint(4)


class Sbgp(FullBox):
    def __init__(self, size, data):
        super().__init__(size, data)
        # TODO


class Traf(ContainerBox):
    def __init__(self, size, data):
        super().__init__(size, data)


class Pssh(FullBox):
    def __init__(self, size, data):
        super().__init__(size, data)
        self.system_id = self.read_bytes(16)
        print(SYSTEM_IDS.get(self.system_id, 'Unknown System ID'))
        # if widevine
        if SYSTEM_IDS.get(self.system_id) == 'WIDEVINE':
            self.parse_widevine_pssh_data()
        # elif playready
        elif SYSTEM_IDS.get(self.system_id) == 'PLAYREADY':
            self.parse_playready_pssh_data()
        else:
            # TODO
            self.parse_widevine_pssh_data()

    def parse_playready_pssh_data(self):
        # Little-Endian
        self.data_size = self.read_uint(4)
        self.pssh_data = self.read_bytes(self.data_size)
        count = self.read_signed_int(2, 'little')
        print(self.pssh_data)


    def parse_widevine_pssh_data(self):
        if self.version == 0:
            self.data_size = self.read_uint(4)
            self.pssh_data = self.read_bytes(self.data_size)
            print('pssh_data:', self.pssh_data)
        else:
            self.kid_count = self.read_uint(4)
            self.key_ids = []
            for kid in range(0, self.kid_count):
                self.key_ids.append(self.read_bytes(16).hex())

            self.data_size = self.read_uint(4)
            # TODO


class Moof(ContainerBox):
    def __init__(self, size, data):
        super().__init__(size, data)


class Mfhd(FullBox):
    def __init__(self, size, data):
        super().__init__(size, data)
        self.sequence_number = self.read_uint(4)
        print(f'sequence_number: {self.sequence_number}')


class Mdat(Box):
    def __init__(self, size, data):
        super().__init__(size, data)
        print(f'mdat size: {self.size}')
        # TODO


class Tfhd(FullBox):
    def __init__(self, size, data):
        super().__init__(size, data)
        self.track_id = self.read_uint(4)
        self.base_data_offset = self.read_uint(8)
        self.sample_description_index = self.read_uint(4)
        self.default_sample_duration = self.read_uint(4)
        self.default_sample_size = self.read_uint(4)
        self.default_sample_flags = self.read_uint(4)
        print(f'track_id: {self.track_id}')
        print(f'base_data_offset {self.base_data_offset}')


class Trun(FullBox):
    def __init__(self, size, data):
        super().__init__(size, data)
        self.sample_count = self.read_uint(4)
        # the following are optional fields
        self.data_offset = self.read_signed_int(4)
        self.first_sample_flags = self.read_uint(4)

        # all fields in the following array are optional
        self.sample_array = []
        for i in range(0, self.sample_count):
            self.sample_array.append({
                'sample_duration': self.read_uint(4),
                'sample_size': self.read_uint(4),
                'sample_flags': self.read_uint(4),
                'sample_composition_time_offset': self.read_uint(4) if self.version == 0 else self.read_signed_int(4)
            })

        print(f'sample_count: {self.sample_count}')
        print(f'first sample in sample array: {self.sample_array[0]}')


class BoxParser:
    parser = {
        FTYP: Ftyp,
        STYP: Styp,
        MOOV: Moov,
        MVHD: Mvhd,
        SIDX: Sidx,
        TREX: Trex,
        TRAK: Trak,
        TKHD: Tkhd,
        MDIA: Mdia,
        MDHD: Mdhd,
        MOOF: Moof,
        MFHD: Mfhd,
        MDAT: Mdat,
        TFHD: Tfhd,
        TRUN: Trun,
        TRAF: Traf,
        TFDT: Tfdt,
        PSSH: Pssh,
        SENC: Senc,
        SAIO: Saio,
        SAIZ: Saiz,
        SGPD: Sgpd,
        SBGP: Sbgp
    }

    def __init__(self, box_size, box_type, box_data):
        self.parser.get(box_type, Unwn)(box_size, box_data)


def main():
    import sys
    # with open('aws_segment.mp4', 'rb') as f:
    with open(sys.argv[1], 'rb') as f:
        data = f.read()

    class Root(Box):
        '''
            Root box acting as a wrapper for all the other
            boxes that actually constitutes the file.
        '''
        def __init__(self, size, data):
            super().__init__(size, data)
            while self.index < size:
                box_size = int.from_bytes(data[self.index: self.index + 4], 'big')
                box_type = data[self.index + 4: self.index + 8]
                box_data = data[self.index + 8: self.index + box_size]
                BoxParser(box_size, box_type, box_data)
                self.index += box_size

    root = Root(len(data), data)


if __name__ == '__main__':
    main()
