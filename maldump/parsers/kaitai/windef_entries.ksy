meta:
  id: windef_entries
  endian: le
  title: Windows Defender quarantine entries file parser
  license: CC-BY-SA-4.0
  ks-version: 0.9
doc: |
  Creator: Florian Bausch, ERNW Research GmbH, https://ernw-research.de
  License: CC-BY-SA-4.0 https://creativecommons.org/licenses/by-sa/4.0/
  Modified: Nikola Knežević
seq:
  - id: header
    type: rc4encrypted_header
    size: 0x3C
    process: utils.custom_arc4([0x1E, 0x87, 0x78, 0x1B, 0x8D, 0xBA, 0xA8, 0x44, 0xCE, 0x69,
                                           0x70, 0x2C, 0x0C, 0x78, 0xB7, 0x86, 0xA3, 0xF6, 0x23, 0xB7,
                                           0x38, 0xF5, 0xED, 0xF9, 0xAF, 0x83, 0x53, 0x0F, 0xB3, 0xFC,
                                           0x54, 0xFA, 0xA2, 0x1E, 0xB9, 0xCF, 0x13, 0x31, 0xFD, 0x0F,
                                           0x0D, 0xA9, 0x54, 0xF6, 0x87, 0xCB, 0x9E, 0x18, 0x27, 0x96,
                                           0x97, 0x90, 0x0E, 0x53, 0xFB, 0x31, 0x7C, 0x9C, 0xBC, 0xE4,
                                           0x8E, 0x23, 0xD0, 0x53, 0x71, 0xEC, 0xC1, 0x59, 0x51, 0xB8,
                                           0xF3, 0x64, 0x9D, 0x7C, 0xA3, 0x3E, 0xD6, 0x8D, 0xC9, 0x04,
                                           0x7E, 0x82, 0xC9, 0xBA, 0xAD, 0x97, 0x99, 0xD0, 0xD4, 0x58,
                                           0xCB, 0x84, 0x7C, 0xA9, 0xFF, 0xBE, 0x3C, 0x8A, 0x77, 0x52,
                                           0x33, 0x55, 0x7D, 0xDE, 0x13, 0xA8, 0xB1, 0x40, 0x87, 0xCC,
                                           0x1B, 0xC8, 0xF1, 0x0F, 0x6E, 0xCD, 0xD0, 0x83, 0xA9, 0x59,
                                           0xCF, 0xF8, 0x4A, 0x9D, 0x1D, 0x50, 0x75, 0x5E, 0x3E, 0x19,
                                           0x18, 0x18, 0xAF, 0x23, 0xE2, 0x29, 0x35, 0x58, 0x76, 0x6D,
                                           0x2C, 0x07, 0xE2, 0x57, 0x12, 0xB2, 0xCA, 0x0B, 0x53, 0x5E,
                                           0xD8, 0xF6, 0xC5, 0x6C, 0xE7, 0x3D, 0x24, 0xBD, 0xD0, 0x29,
                                           0x17, 0x71, 0x86, 0x1A, 0x54, 0xB4, 0xC2, 0x85, 0xA9, 0xA3,
                                           0xDB, 0x7A, 0xCA, 0x6D, 0x22, 0x4A, 0xEA, 0xCD, 0x62, 0x1D,
                                           0xB9, 0xF2, 0xA2, 0x2E, 0xD1, 0xE9, 0xE1, 0x1D, 0x75, 0xBE,
                                           0xD7, 0xDC, 0x0E, 0xCB, 0x0A, 0x8E, 0x68, 0xA2, 0xFF, 0x12,
                                           0x63, 0x40, 0x8D, 0xC8, 0x08, 0xDF, 0xFD, 0x16, 0x4B, 0x11,
                                           0x67, 0x74, 0xCD, 0x0B, 0x9B, 0x8D, 0x05, 0x41, 0x1E, 0xD6,
                                           0x26, 0x2E, 0x42, 0x9B, 0xA4, 0x95, 0x67, 0x6B, 0x83, 0x98,
                                           0xDB, 0x2F, 0x35, 0xD3, 0xC1, 0xB9, 0xCE, 0xD5, 0x26, 0x36,
                                           0xF2, 0x76, 0x5E, 0x1A, 0x95, 0xCB, 0x7C, 0xA4, 0xC3, 0xDD,
                                           0xAB, 0xDD, 0xBF, 0xF3, 0x82, 0x53
                                          ])
  - id: data1
    size: header.len1
    type: encrypted_data1
    process: utils.custom_arc4([0x1E, 0x87, 0x78, 0x1B, 0x8D, 0xBA, 0xA8, 0x44, 0xCE, 0x69,
                                           0x70, 0x2C, 0x0C, 0x78, 0xB7, 0x86, 0xA3, 0xF6, 0x23, 0xB7,
                                           0x38, 0xF5, 0xED, 0xF9, 0xAF, 0x83, 0x53, 0x0F, 0xB3, 0xFC,
                                           0x54, 0xFA, 0xA2, 0x1E, 0xB9, 0xCF, 0x13, 0x31, 0xFD, 0x0F,
                                           0x0D, 0xA9, 0x54, 0xF6, 0x87, 0xCB, 0x9E, 0x18, 0x27, 0x96,
                                           0x97, 0x90, 0x0E, 0x53, 0xFB, 0x31, 0x7C, 0x9C, 0xBC, 0xE4,
                                           0x8E, 0x23, 0xD0, 0x53, 0x71, 0xEC, 0xC1, 0x59, 0x51, 0xB8,
                                           0xF3, 0x64, 0x9D, 0x7C, 0xA3, 0x3E, 0xD6, 0x8D, 0xC9, 0x04,
                                           0x7E, 0x82, 0xC9, 0xBA, 0xAD, 0x97, 0x99, 0xD0, 0xD4, 0x58,
                                           0xCB, 0x84, 0x7C, 0xA9, 0xFF, 0xBE, 0x3C, 0x8A, 0x77, 0x52,
                                           0x33, 0x55, 0x7D, 0xDE, 0x13, 0xA8, 0xB1, 0x40, 0x87, 0xCC,
                                           0x1B, 0xC8, 0xF1, 0x0F, 0x6E, 0xCD, 0xD0, 0x83, 0xA9, 0x59,
                                           0xCF, 0xF8, 0x4A, 0x9D, 0x1D, 0x50, 0x75, 0x5E, 0x3E, 0x19,
                                           0x18, 0x18, 0xAF, 0x23, 0xE2, 0x29, 0x35, 0x58, 0x76, 0x6D,
                                           0x2C, 0x07, 0xE2, 0x57, 0x12, 0xB2, 0xCA, 0x0B, 0x53, 0x5E,
                                           0xD8, 0xF6, 0xC5, 0x6C, 0xE7, 0x3D, 0x24, 0xBD, 0xD0, 0x29,
                                           0x17, 0x71, 0x86, 0x1A, 0x54, 0xB4, 0xC2, 0x85, 0xA9, 0xA3,
                                           0xDB, 0x7A, 0xCA, 0x6D, 0x22, 0x4A, 0xEA, 0xCD, 0x62, 0x1D,
                                           0xB9, 0xF2, 0xA2, 0x2E, 0xD1, 0xE9, 0xE1, 0x1D, 0x75, 0xBE,
                                           0xD7, 0xDC, 0x0E, 0xCB, 0x0A, 0x8E, 0x68, 0xA2, 0xFF, 0x12,
                                           0x63, 0x40, 0x8D, 0xC8, 0x08, 0xDF, 0xFD, 0x16, 0x4B, 0x11,
                                           0x67, 0x74, 0xCD, 0x0B, 0x9B, 0x8D, 0x05, 0x41, 0x1E, 0xD6,
                                           0x26, 0x2E, 0x42, 0x9B, 0xA4, 0x95, 0x67, 0x6B, 0x83, 0x98,
                                           0xDB, 0x2F, 0x35, 0xD3, 0xC1, 0xB9, 0xCE, 0xD5, 0x26, 0x36,
                                           0xF2, 0x76, 0x5E, 0x1A, 0x95, 0xCB, 0x7C, 0xA4, 0xC3, 0xDD,
                                           0xAB, 0xDD, 0xBF, 0xF3, 0x82, 0x53
                                          ])
  - id: data2
    size: header.len2
    type: encrypted_data2
    process: utils.custom_arc4([0x1E, 0x87, 0x78, 0x1B, 0x8D, 0xBA, 0xA8, 0x44, 0xCE, 0x69,
                                           0x70, 0x2C, 0x0C, 0x78, 0xB7, 0x86, 0xA3, 0xF6, 0x23, 0xB7,
                                           0x38, 0xF5, 0xED, 0xF9, 0xAF, 0x83, 0x53, 0x0F, 0xB3, 0xFC,
                                           0x54, 0xFA, 0xA2, 0x1E, 0xB9, 0xCF, 0x13, 0x31, 0xFD, 0x0F,
                                           0x0D, 0xA9, 0x54, 0xF6, 0x87, 0xCB, 0x9E, 0x18, 0x27, 0x96,
                                           0x97, 0x90, 0x0E, 0x53, 0xFB, 0x31, 0x7C, 0x9C, 0xBC, 0xE4,
                                           0x8E, 0x23, 0xD0, 0x53, 0x71, 0xEC, 0xC1, 0x59, 0x51, 0xB8,
                                           0xF3, 0x64, 0x9D, 0x7C, 0xA3, 0x3E, 0xD6, 0x8D, 0xC9, 0x04,
                                           0x7E, 0x82, 0xC9, 0xBA, 0xAD, 0x97, 0x99, 0xD0, 0xD4, 0x58,
                                           0xCB, 0x84, 0x7C, 0xA9, 0xFF, 0xBE, 0x3C, 0x8A, 0x77, 0x52,
                                           0x33, 0x55, 0x7D, 0xDE, 0x13, 0xA8, 0xB1, 0x40, 0x87, 0xCC,
                                           0x1B, 0xC8, 0xF1, 0x0F, 0x6E, 0xCD, 0xD0, 0x83, 0xA9, 0x59,
                                           0xCF, 0xF8, 0x4A, 0x9D, 0x1D, 0x50, 0x75, 0x5E, 0x3E, 0x19,
                                           0x18, 0x18, 0xAF, 0x23, 0xE2, 0x29, 0x35, 0x58, 0x76, 0x6D,
                                           0x2C, 0x07, 0xE2, 0x57, 0x12, 0xB2, 0xCA, 0x0B, 0x53, 0x5E,
                                           0xD8, 0xF6, 0xC5, 0x6C, 0xE7, 0x3D, 0x24, 0xBD, 0xD0, 0x29,
                                           0x17, 0x71, 0x86, 0x1A, 0x54, 0xB4, 0xC2, 0x85, 0xA9, 0xA3,
                                           0xDB, 0x7A, 0xCA, 0x6D, 0x22, 0x4A, 0xEA, 0xCD, 0x62, 0x1D,
                                           0xB9, 0xF2, 0xA2, 0x2E, 0xD1, 0xE9, 0xE1, 0x1D, 0x75, 0xBE,
                                           0xD7, 0xDC, 0x0E, 0xCB, 0x0A, 0x8E, 0x68, 0xA2, 0xFF, 0x12,
                                           0x63, 0x40, 0x8D, 0xC8, 0x08, 0xDF, 0xFD, 0x16, 0x4B, 0x11,
                                           0x67, 0x74, 0xCD, 0x0B, 0x9B, 0x8D, 0x05, 0x41, 0x1E, 0xD6,
                                           0x26, 0x2E, 0x42, 0x9B, 0xA4, 0x95, 0x67, 0x6B, 0x83, 0x98,
                                           0xDB, 0x2F, 0x35, 0xD3, 0xC1, 0xB9, 0xCE, 0xD5, 0x26, 0x36,
                                           0xF2, 0x76, 0x5E, 0x1A, 0x95, 0xCB, 0x7C, 0xA4, 0xC3, 0xDD,
                                           0xAB, 0xDD, 0xBF, 0xF3, 0x82, 0x53
                                          ])
types:
  rc4encrypted_header:
    seq:
      - id: magic
        size: 0x10
        contents: [0xdb, 0xe8, 0xc5, 0x01, 0x01, 0, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0]
      - id: unknown1
        size: 0x18
      - id: len1
        type: u4
      - id: len2
        type: u4
      - id: unknown2
        size: 0x0C
  encrypted_data1:
    seq:
      - id: guid
        type: guid
      - id: unknown3
        size: 16
      - id: time
        type: winfiletime
      - id: id11
        type: u4
      - id: id12
        type: u2
      - id: id13
        type: u2
      - id: number_of_strings
        type: u4
      - id: mal_type
        type: str
        encoding: UTF-8
        terminator: 0
  encrypted_data2:
    seq:
      - id: number_of_entries
        type: u4
      - id: offset
        type: u4
        repeat: expr
        repeat-expr: number_of_entries
    instances:
      entries:
        pos: offset[0]
        repeat: expr
        repeat-expr: number_of_entries
        type:
          switch-on: _index != number_of_entries-1
          cases:
            true: entrys(_index)
            false: entrye
    types:
      entrys:
        params:
          - id: i
            type: u4
        seq:
          - id: entry
            size: _parent.offset[i + 1] - _parent.offset[i]
            type: entry
      entrye:
        seq:
          - id: entry
            type: entry
  entry:
    seq:
      - id: path
        type: null_terminated_utf16le
      - id: number_of_elements
        type: u2
      - id: typestr
        type: str
        encoding: UTF8
        terminator: 0x00
      - id: padding
        size: (4 - _io.pos) % 4
      - id: element
        type: listelement
        repeat: expr
        repeat-expr: number_of_elements
  null_terminated_utf16le:
    seq:
      - id: character
        type: u2
        repeat: until
        repeat-until: character[_index] == 0x0000
  listelement:
    seq:
      - id: length
        type: u2
      - id: elementsubtype
        type: u1
      - id: elementtype
        type: u1
        enum: elementtypes
      - id: content
        size: length
        type:
          switch-on: elementtype
          cases:
            elementtypes::hash: hash
            elementtypes::winfiletime: winfiletime
            elementtypes::uint4: u4
            elementtypes::utf16: str_utf16le
      - id: padding
        size: (4 - _io.pos) % 4
    enums:
      elementtypes:
        0x20: utf16
        0x30: uint4
        0x40: hash
        0x60: winfiletime
  str_utf16le:
    seq:
      - id: value
        type: str
        encoding: UTF-16LE
        size-eos: true
  hash:
    seq:
      - id: value
        size: 20
  guid:
    seq:
      - id: id1
        type: u4
      - id: id2
        type: u2
      - id: id3
        type: u2
      - id: id4
        size: 2
      - id: id5
        size: 6
  winfiletime:
    # timestamp: timestamp * (1e-07) --> seconds
    # offset: 11644473600
    seq:
      - id: ts
        type: u8
    instances:
      unixts:
        value: (ts * 1e-07) - 11644473600
