import math
from typing import Optional

import binaryninja
import svd2py
from binaryninja import (
    BinaryView,
    Settings,
    StructureBuilder,
    Type,
    StructureMember,
    StructureType,
    StructureVariant,
    SectionSemantics,
    SegmentFlag,
    Symbol,
    SymbolType,
)

BYTE_SIZE = 8


# TODO: Where is this used?
def dim_get_list(dimable):
    if "dim" not in dimable or "dimIndex" not in dimable:
        return None
    stride: int = dimable["dimIncrement"]
    dim_index = dimable["dimIndex"]
    dim_elements = []
    if "-" in dim_index:
        start, end = dim_index.split("-", 1)
        dim_elements = list(range(int(start), int(end) + 1))
    elif "," in dim_index:
        dim_elements = dim_index.split(",")
    dim_map = {}
    for idx, elem in range(dim_elements):
        dim_map[idx * stride] = dimable["name"].replace("%s", str(elem))
    return dim_map


# duplicates the object to a list of objects
def dim_duplicate_object(dimable):
    if "dim" not in dimable or "resolved" in dimable:
        return None
    dim_len = dimable["dim"]
    dim_increment = dimable["dimIncrement"]
    entries = []
    for i in range(dim_len):
        new_entry = dimable.copy()
        new_entry["name"] = dimable["name"].replace("%s", str(i))
        new_entry["addressOffset"] = dimable["addressOffset"] + i * dim_increment
        new_entry["resolved"] = True
        entries.append(new_entry)
    return entries


def is_array_elem(elem):
    return "dim" in elem and "dimIndex" not in elem


def array_len(elem):
    return elem["dim"]


def cluster_get_registers(cluster):
    cluster_registers = []
    # Handle dim arrays
    cluster_entries = dim_duplicate_object(cluster)
    if cluster_entries is not None:
        for cluster_entry in cluster_entries:
            cluster_registers.extend(cluster_get_registers(cluster_entry))
        return cluster_registers

    # Pre-compute the cluster address offset for each register
    cluster_address_offset = cluster["addressOffset"]
    for clustered_register in cluster["register"]:
        clustered_register["structure"] = cluster["name"]
        clustered_register["name"] = f"{cluster['name']}_{clustered_register['name']}"
        clustered_register["addressOffset"] += cluster_address_offset
        cluster_registers.append(clustered_register)

    sub_clusters = []
    if "cluster" in cluster:
        sub_clusters = cluster["cluster"]
    for sub_cluster in sub_clusters:
        binaryninja.log_info(f'found sub cluster... {sub_cluster["name"]}')
        cluster_registers.extend(cluster_get_registers(sub_cluster))
    return cluster_registers


def per_get_registers(peripherals, peripheral):
    per_registers = []
    per_clusters = []
    if "registers" in peripheral:
        if "register" in peripheral["registers"]:
            per_registers = peripheral["registers"]["register"]
        if "cluster" in peripheral["registers"]:
            per_clusters = peripheral["registers"]["cluster"]
    for cluster in per_clusters:
        per_registers.extend(cluster_get_registers(cluster))
    per_attributes = None
    if "attributes" in peripheral:
        per_attributes = peripheral["attributes"]
    if per_attributes is not None and "derivedFrom" in per_attributes:
        # Copy over from the derived peripheral.
        per_derived_from_name = per_attributes["derivedFrom"]
        per_derived_from = next(
            p for p in peripherals if p["name"] == per_derived_from_name
        )
        if per_derived_from is not None:
            peripheral["addressBlock"] = per_derived_from["addressBlock"]
            per_registers.extend(per_get_registers(peripherals, per_derived_from))
    return per_registers


def field_get_lsb_msb(field):
    # one of the three following field bit specifications must be provided
    if "lsb" in field and "msb" in field:
        field_lsb: int = field["lsb"]
        field_msb: int = field["msb"]
    elif "bitOffset" in field:
        field_lsb: int = field["bitOffset"]
        # The bitWidth field is optional
        if "bitWidth" in field:
            field_msb: int = field["bitOffset"] + field["bitWidth"] - 1
        else:
            field_msb: int = field["bitOffset"]
    elif "bitRange" in field:
        msb_str, lsb_str = field["bitRange"].split(":", 1)
        field_lsb: int = int(lsb_str[:-1])
        field_msb: int = int(msb_str[1:])
    else:
        raise ValueError("Unhandled field sizing")
    return field_msb, field_lsb


def import_svd(bv: BinaryView, file_path: str):
    binaryninja.log_info(f"parsing svd file... {file_path}")
    parser = svd2py.SvdParser()
    result = parser.convert(file_path)
    assert result["device"] is not None
    device = result["device"]
    device_name: str = device["name"]
    binaryninja.log_info(f"parsing device... {device_name}")
    peripherals = device["peripherals"]["peripheral"]

    show_comments = Settings().get_bool("SVDMapper.enableComments")
    structure_bitfields = Settings().get_bool("SVDMapper.enableBitfieldStructuring")

    for peripheral in peripherals:
        per_name: str = peripheral["name"]
        per_desc: Optional[str] = peripheral.get("description")
        per_base_addr: int = peripheral["baseAddress"]
        per_array_len = None
        if is_array_elem(peripheral):
            per_array_len = array_len(peripheral)
            per_name.replace("[%s]", "")
            binaryninja.log_info(
                f"{per_name} is array, typing it with len {per_array_len}"
            )
        per_registers = per_get_registers(peripherals, peripheral)

        per_struct = StructureBuilder.create()

        # the registers block is an optional 0..1 field in the SVD spec. Even
        # if we don't get individual register definitions, we can create a
        # memory region for a peripheral
        for register in per_registers:
            reg_name: str = register["name"]
            reg_desc: str = register.get("description")
            reg_addr_offset: int = register["addressOffset"]
            reg_size: int = register["size"]
            reg_size_b = int(reg_size / BYTE_SIZE)
            reg_addr = per_base_addr + reg_addr_offset
            reg_struct = StructureBuilder.create(width=reg_size_b)

            # Add the register description as a comment
            if show_comments and reg_desc:
                bv.set_comment_at(reg_addr, reg_desc.splitlines()[0])

            if "fields" not in register or "field" not in register["fields"]:
                continue

            reg_fields = register["fields"]["field"]
            for field in reg_fields:
                field_name: str = field["name"]
                field_msb, field_lsb = field_get_lsb_msb(field)
                field_msb_b: float = field_msb / BYTE_SIZE
                field_lsb_b: float = field_lsb / BYTE_SIZE

                # If the field is byte aligned we can add a field to the register struct.
                if field_lsb_b.is_integer() and field_msb_b.is_integer():
                    # Insert named struct field.
                    # TODO: Check if struct field is overlapping existing struct field. (Can this even happen?)
                    field_bounds: tuple[int, int] = (int(field_lsb_b), int(field_msb_b))
                    reg_struct.insert(
                        field_bounds[0],
                        Type.int((field_bounds[1] + 1) - field_bounds[0], False),
                        field_name,
                    )
                elif structure_bitfields:
                    # Only structure bitfields if setting is enabled.
                    # TODO: This bugs out for n fields there will be n bytes padding at the front of the union
                    field_bounds: tuple[int, int] = (
                        math.floor(field_lsb_b),
                        math.ceil(field_msb_b),
                    )
                    field_addr = reg_addr + field_bounds[0]
                    if show_comments:
                        bv.set_comment_at(
                            field_addr, f"{field_name} {field_msb}:{field_lsb}"
                        )
                    # The bitfield will be use the field bounds as we cannot address bits as size
                    bitfield_ty = Type.int(
                        (field_bounds[1] + 1) - field_bounds[0], False
                    )
                    bitfield_member = StructureMember(
                        bitfield_ty, field_name, field_bounds[0]
                    )
                    # Create or update the bitfield union with new bitfield
                    existing_bitfield = reg_struct.member_at_offset(field_bounds[0])
                    if existing_bitfield is None:
                        reg_struct.insert(
                            field_bounds[0],
                            Type.union([bitfield_member]),
                            overwrite_existing=False,
                        )
                    elif (
                        isinstance(existing_bitfield.type, StructureType)
                        and existing_bitfield.type.type
                        is StructureVariant.UnionStructureType
                    ):
                        bitfield_members = existing_bitfield.type.members
                        bitfield_members.append(bitfield_member)
                        reg_struct.insert(
                            existing_bitfield.offset, Type.union(bitfield_members)
                        )

            # TODO: This is displayed really poorly
            # Define the register type in the binary view.
            reg_struct_ty = Type.structure_type(reg_struct)
            bv.define_user_type(f"{per_name}_{reg_name}", reg_struct_ty)
            # Add the register to the peripheral type
            per_struct.insert(
                reg_addr_offset,
                bv.get_type_by_name(f"{per_name}_{reg_name}"),
                reg_name,
                overwrite_existing=False,
            )

        # Get the peripheral memory range
        per_size = 0
        per_addr_blocks = peripheral["addressBlock"]
        for addr_block in per_addr_blocks:
            ablk_offset: int = addr_block["offset"]
            ablk_size: int = addr_block["size"]
            per_size += (ablk_offset - per_size) + ablk_size

        if per_size < per_struct.width:
            binaryninja.log_warn(
                f"peripheral {per_name} @ {per_base_addr} size is less than struct size... adjusting size to fit struct"
            )
            per_size = per_struct.width

        # Add entire peripheral range
        bv.add_user_segment(
            per_base_addr,
            per_size,
            0,
            0,
            SegmentFlag.SegmentReadable | SegmentFlag.SegmentWritable,
        )
        bv.add_user_section(
            per_name,
            per_base_addr,
            per_size,
            SectionSemantics.ReadWriteDataSectionSemantics,
        )
        bv.memory_map.add_memory_region(per_name, per_base_addr, bytearray(per_size))

        # Add the peripheral description as a comment
        if show_comments and per_desc:
            bv.set_comment_at(per_base_addr, per_desc)
        # Define the peripheral type and data var in the binary view.
        per_struct_ty = Type.structure_type(per_struct)
        if per_array_len is not None:
            bv.define_user_type(per_name, Type.array(per_struct_ty, per_array_len))
        else:
            bv.define_user_type(per_name, per_struct_ty)
        bv.define_user_symbol(
            Symbol(SymbolType.ImportedDataSymbol, per_base_addr, per_name)
        )
        bv.define_user_data_var(per_base_addr, bv.get_type_by_name(per_name), per_name)
