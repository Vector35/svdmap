import math
from typing import Optional

import binaryninja
import svd2py
from binaryninja import BinaryView, Settings, StructureBuilder, Type, StructureMember, StructureType, StructureVariant, \
    SectionSemantics, SegmentFlag, Symbol, SymbolType

BYTE_SIZE = 8

def import_svd(bv: BinaryView, file_path: str):
    binaryninja.log_info(f'parsing svd file... {file_path}')
    parser = svd2py.SvdParser()
    result = parser.convert(file_path)
    assert result['device'] is not None
    device = result['device']
    device_name: str = device['name']
    binaryninja.log_info(f'parsing device... {device_name}')
    peripherals = device['peripherals']['peripheral']
    dev_size = device.get('size')

    show_comments = Settings().get_bool("SVDMapper.enableComments")
    structure_bitfields = Settings().get_bool("SVDMapper.enableBitfieldStructuring")

    for peripheral in peripherals:
        per_name: str = peripheral['name']
        per_desc: Optional[str] = peripheral.get('description')
        per_base_addr: int = peripheral['baseAddress']
        per_registers = []
        if 'registers' in peripheral:
            per_registers = peripheral['registers']['register']
        per_attributes = peripheral.get('attributes')
        if per_attributes and 'derivedFrom' in per_attributes:
            # Copy over from the derived peripheral.
            per_derived_from_name: str = per_attributes['derivedFrom']
            per_derived_from = next(p for p in peripherals if p['name'] == per_derived_from_name)
            if per_derived_from is None:
                binaryninja.log_error(
                    f"peripheral {per_name} @ {per_base_addr:#x} derives from unknown peripheral {per_derived_from_name}")
                continue
            peripheral['addressBlock'] = per_derived_from['addressBlock']
            per_registers.extend(per_derived_from['registers']['register'])

        per_struct = StructureBuilder.create()

        # the registers block is an optional 0..1 field in the SVD spec. Even
        # if we don't get individual register definitions, we can create a
        # memory region for a peripheral
        for reg_index, register in enumerate(per_registers):
            reg_missing: set[str] = {'name', 'addressOffset', 'size'}
            reg_missing -= set(register)
            if dev_size is not None:
                reg_missing -= {'size'}
            if reg_missing:
                binaryninja.log_warn(
                    f"peripheral {per_name} @ {per_base_addr:#x} register #{reg_index} ({register['name'] or '<no name>'}) is missing required tags: {', '.join(reg_missing)}")
                continue

            reg_name: str = register['name']
            reg_desc: Optional[str] = register.get('description')
            reg_addr_offset: int = register['addressOffset']
            reg_size: int = register.get('size', dev_size)
            reg_size_b = int(reg_size / BYTE_SIZE)
            reg_addr = per_base_addr + reg_addr_offset
            reg_struct = StructureBuilder.create(width=reg_size_b)

            # Add the register description as a comment
            if show_comments and reg_desc:
                bv.set_comment_at(reg_addr, reg_desc.splitlines()[0])

            if 'fields' not in register or 'field' not in register['fields']:
                continue

            reg_fields = register['fields']['field']
            for field in reg_fields:
                field_name: str = field['name']
                # one of the three following field bit specifications must be provided
                if 'lsb' in field and 'msb' in field:
                    field_lsb: int = field['lsb']
                    field_msb: int = field['msb']
                elif 'bitOffset' in field:
                    field_lsb: int = field['bitOffset']
                    # The bitWidth field is optional
                    if 'bitWidth' in field:
                        field_msb: int = field['bitOffset'] + field['bitWidth'] - 1
                    else:
                        field_msb: int = field['bitOffset']
                elif 'bitRange' in field:
                    msb_str, lsb_str = field['bitRange'].split(':', 1)
                    field_lsb: int = int(lsb_str[:-1])
                    field_msb: int = int(msb_str[1:])
                else:
                    binaryninja.log_error(f"register field with no location... {reg_addr} {field_name}")
                    continue
                field_lsb_b: float = field_lsb / BYTE_SIZE
                field_msb_b: float = field_msb / BYTE_SIZE

                # If the field is byte aligned we can add a field to the register struct.
                if field_lsb_b.is_integer() and field_msb_b.is_integer():
                    # Insert named struct field.
                    # TODO: Check if struct field is overlapping existing struct field. (Can this even happen?)
                    field_bounds: tuple[int, int] = (int(field_lsb_b), int(field_msb_b))
                    reg_struct.insert(field_bounds[0], Type.int((field_bounds[1] + 1) - field_bounds[0], False),
                                      field_name)
                elif structure_bitfields:
                    # Only structure bitfields if setting is enabled.
                    # TODO: This bugs out for n fields there will be n bytes padding at the front of the union
                    field_bounds: tuple[int, int] = (math.floor(field_lsb_b), math.ceil(field_msb_b))
                    field_addr = reg_addr + field_bounds[0]
                    if show_comments:
                        bv.set_comment_at(field_addr, f'{field_name} {field_msb}:{field_lsb}')
                    # The bitfield will be use the field bounds as we cannot address bits as size
                    bitfield_ty = Type.int((field_bounds[1] + 1) - field_bounds[0], False)
                    bitfield_member = StructureMember(bitfield_ty, field_name, field_bounds[0])
                    # Create or update the bitfield union with new bitfield
                    existing_bitfield = reg_struct.member_at_offset(field_bounds[0])
                    if existing_bitfield is None:
                        reg_struct.insert(field_bounds[0], Type.union([bitfield_member]), overwrite_existing=False)
                    elif isinstance(existing_bitfield.type,
                                    StructureType) and existing_bitfield.type.type is StructureVariant.UnionStructureType:
                        bitfield_members = existing_bitfield.type.members
                        bitfield_members.append(bitfield_member)
                        reg_struct.insert(existing_bitfield.offset, Type.union(bitfield_members))

            # TODO: This is displayed really poorly
            # Define the register type in the binary view.
            reg_struct_ty = Type.structure_type(reg_struct)
            bv.define_user_type(f'{per_name}_{reg_name}', reg_struct_ty)
            # Add the register to the peripheral type
            per_struct.insert(reg_addr_offset, bv.get_type_by_name(f'{per_name}_{reg_name}'), reg_name,
                              overwrite_existing=False)

        # Get the peripheral memory range
        per_size = 0
        per_addr_blocks = peripheral['addressBlock']
        for addr_block in per_addr_blocks:
            ablk_offset: int = addr_block['offset']
            ablk_size: int = addr_block['size']
            per_size += (ablk_offset - per_size) + ablk_size

        if per_size < per_struct.width:
            binaryninja.log_warn(
                f"peripheral {per_name} @ {per_base_addr:#x} size is less than struct size... adjusting size to fit struct")
            per_size = per_struct.width

        # Add entire peripheral range
        bv.add_user_segment(per_base_addr, per_size, 0, 0, SegmentFlag.SegmentReadable | SegmentFlag.SegmentWritable)
        bv.add_user_section(per_name, per_base_addr, per_size, SectionSemantics.ReadWriteDataSectionSemantics)
        bv.memory_map.add_memory_region(per_name, per_base_addr, bytearray(per_size))

        # Add the peripheral description as a comment
        if show_comments and per_desc:
            bv.set_comment_at(per_base_addr, per_desc)
        # Define the peripheral type and data var in the binary view.
        per_struct_ty = Type.structure_type(per_struct)
        bv.define_user_type(per_name, per_struct_ty)
        bv.define_user_symbol(Symbol(SymbolType.ImportedDataSymbol, per_base_addr, per_name))
        bv.define_user_data_var(per_base_addr, bv.get_type_by_name(per_name), per_name)